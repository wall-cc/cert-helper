// test_request_router.cpp
//
// П0 плана доработки, пункт 2.6: дедлок в singleflight-дедупликации
// RequestRouter, если "лидер" (поток, который реально выполняет
// impl_fn()) падает с исключением. До фикса — "последователи" (другие
// потоки, пришедшие с тем же ключом, пока лидер ещё не закончил) ждут
// state->cv.wait(..., [state] { return state->done; }) вечно, а запись в
// inflight_ map никогда не удаляется, так что и ВСЕ БУДУЩИЕ запросы с тем
// же ключом тоже зависают навсегда — один транзиентный сбой перманентно
// выводит из строя обработку конкретного URL, пока демон не перезапустят.
//
// Эти тесты запускают "последователя" в отдельном потоке и ждут его
// результата с ограниченным таймаутом: если фикс не применён (или
// регрессировал), тест ЯВНО падает с понятным сообщением, а не зависает
// сам (поток-ожидающий в этом случае отсоединяется и не мешает процессу
// теста завершиться).

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "request_router.hpp"
#include "test_util.hpp"

using namespace cert_helper;

namespace {

// Кэш, который всегда промахивается — тесты сосредоточены на сетевом
// пути и поведении singleflight, не на кэшировании.
class MemoryCache : public cache::ICacheStore {
public:
    std::optional<cache::CacheEntry> get(cache::EntryKind,
                                         std::string const&) override {
        return std::nullopt;
    }
    void put(cache::EntryKind, std::string const&,
             cache::CacheEntry const&) override {}
    cache::CacheStats stats() override { return {}; }
};

// На первых throw_count вызовах бросает исключение (имитация
// транспортного сбоя — ровно то, что раньше вешало singleflight), затем
// отвечает успешно. before_responding — искусственная задержка перед
// ответом/броском, чтобы дать последователю гарантированное окно
// зарегистрироваться, пока "лидер" ещё не вернулся из fetch().
class ThrowingHttpFetcher : public http::IHttpFetcher {
public:
    std::atomic<int> calls{0};
    std::atomic<int> throw_count{0};
    std::chrono::milliseconds before_responding{0};

    http::HttpResult fetch(http::Method, std::string const&,
                           std::vector<uint8_t> const&, std::string const&,
                           uint32_t, size_t) override {
        int const call_number = calls.fetch_add(1) + 1;
        if (before_responding.count() > 0) {
            std::this_thread::sleep_for(before_responding);
        }
        if (call_number <= throw_count.load()) {
            throw std::runtime_error("simulated transport failure");
        }
        http::HttpResult result;
        result.ok = true;
        result.status_code = 200;
        result.body = {0x30, 0x03, 0x02, 0x01,
                       0x01};  // содержимое тела здесь не важно
        return result;
    }
};

RequestRouter::Config test_config() {
    RequestRouter::Config config;
    config.max_retries = 0;  // фокус теста — singleflight, а не retry-логика
    return config;
}

// Выполняет f() в отдельном потоке и ждёт готовности не дольше timeout.
// true — f() успела отработать вовремя; false — не успела (подозрение на
// зависание). В случае false поток ОТСОЕДИНЯЕТСЯ: тестовый процесс не
// обязан ждать поток, который, возможно, завис навсегда из-за
// регрессии — он должен корректно завершиться и сообщить о провале, а
// не сам повиснуть вместе с багом, который проверяет.
template <class F>
bool completes_within(F&& f, std::chrono::milliseconds timeout) {
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread worker([f = std::forward<F>(f), done] {
        f();
        done->store(true);
    });
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (!done->load()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            worker.detach();
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    worker.join();
    return true;
}

// Последователь не должен ждать вечно, если лидер упал с исключением.
void test_follower_does_not_hang_when_leader_throws() {
    MemoryCache cache;
    ThrowingHttpFetcher fetcher;
    fetcher.throw_count = 1;  // первый вызов (лидер) бросает, остальные — успех
    fetcher.before_responding = std::chrono::milliseconds(150);
    RequestRouter router(cache, fetcher, test_config());

    proto::FetchCrlRequest req;
    req.distribution_point_url = "http://ca.example/intermediate.crl";

    std::atomic<bool> leader_threw{false};
    std::thread leader([&] {
        try {
            router.handle_crl(req);
        } catch (...) {
            leader_threw = true;
        }
    });

    // Даём лидеру время войти в fetch() (и там — в искусственную задержку)
    // и зарегистрироваться в inflight_ map ДО того, как последователь
    // придёт с тем же ключом — иначе последователь сам стал бы лидером, и
    // тест ничего бы не проверял.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    std::atomic<bool> follower_threw{false};
    bool const follower_finished = completes_within(
        [&] {
            try {
                router.handle_crl(req);
            } catch (...) {
                follower_threw = true;
            }
        },
        std::chrono::milliseconds(3000));

    leader.join();
    TEST_CHECK(leader_threw.load());
    TEST_CHECK(follower_finished);
    // Последователь ждал тот же "раунд", что и упавший лидер — он должен
    // увидеть то же самое исключение, а не тихо получить пустой/дефолтный
    // FetchResponse, который замаскировал бы реальный сбой.
    TEST_CHECK(follower_threw.load());
}

// После падения лидера запись о "в полёте" запросе не должна оставаться
// в map навечно: следующий запрос с тем же ключом обязан запустить
// РЕАЛЬНЫЙ новый сетевой вызов (стать новым лидером), а не висеть на
// результате уже не существующего (и так и не завершившегося успехом)
// предыдущего раунда.
void test_inflight_entry_is_cleaned_up_after_leader_exception() {
    MemoryCache cache;
    ThrowingHttpFetcher fetcher;
    fetcher.throw_count = 1;
    RequestRouter router(cache, fetcher, test_config());

    proto::FetchCrlRequest req;
    req.distribution_point_url = "http://ca.example/other.crl";

    bool first_threw = false;
    try {
        router.handle_crl(req);
    } catch (...) {
        first_threw = true;
    }
    TEST_CHECK(first_threw);
    TEST_CHECK_EQ(fetcher.calls.load(), 1);

    // Второй вызов с тем же URL должен дойти до fetch() заново (а не
    // зависнуть и не тихо вернуть что-то без обращения в сеть).
    // throw_count = 1, так что этот, второй по счёту вызов fetch() —
    // настоящий успешный ответ, исключения не ожидается.
    bool second_threw = false;
    bool const second_completed = completes_within(
        [&] {
            try {
                router.handle_crl(req);
            } catch (...) {
                second_threw = true;
            }
        },
        std::chrono::milliseconds(3000));
    TEST_CHECK(second_completed);
    TEST_CHECK(!second_threw);
    TEST_CHECK_EQ(fetcher.calls.load(), 2);
}

// Регрессионная защита обычного пути: при конкурентных запросах с
// одинаковым ключом сеть дёргается РОВНО один раз (singleflight
// продолжает работать как раньше, когда исключений нет).
void test_concurrent_identical_requests_share_one_fetch() {
    MemoryCache cache;
    ThrowingHttpFetcher fetcher;
    fetcher.before_responding = std::chrono::milliseconds(100);
    RequestRouter router(cache, fetcher, test_config());

    proto::FetchCrlRequest req;
    req.distribution_point_url = "http://ca.example/shared.crl";

    constexpr int CONCURRENT_REQUESTS = 6;
    std::vector<std::thread> threads;
    for (int i = 0; i < CONCURRENT_REQUESTS; ++i) {
        threads.emplace_back([&] { router.handle_crl(req); });
    }
    for (auto& t : threads) {
        t.join();
    }

    TEST_CHECK_EQ(fetcher.calls.load(), 1);
}

}  // namespace

int main() {
    RUN_TEST(test_follower_does_not_hang_when_leader_throws);
    RUN_TEST(test_inflight_entry_is_cleaned_up_after_leader_exception);
    RUN_TEST(test_concurrent_identical_requests_share_one_fetch);
    TEST_MAIN_EXIT();
}
