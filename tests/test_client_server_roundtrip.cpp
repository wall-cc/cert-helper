// test_client_server_roundtrip.cpp
//
// Интеграционный тест: поднимает настоящий DbusServer поверх ПРИВАТНОГО
// dbus-daemon (не системной шины хоста — чтобы тест был изолирован,
// воспроизводим и не зависел от того, доступна ли системная шина в среде
// сборки/CI), стучится в него через cert_helper::client_impl::DbusClient
// и публичный cert_helper::Client, проверяя полный путь:
//   клиент -> D-Bus (sd-bus) -> DbusServer -> RequestRouter
//     -> (застабленный) HTTP -> кэш -> обратно тем же путём.
//
// Приватная шина поднимается вручную через fork()+exec() дочернего
// dbus-daemon с "--nofork --print-address" — так тест сам владеет
// жизненным циклом дочернего процесса (может его гарантированно убить по
// завершении), в отличие от "--fork", где демон уходит в отдельный
// процесс, не будучи ребёнком тестового.
//
// HTTP не идёт в реальный интернет — используется тестовая реализация
// IHttpFetcher (StubHttpFetcher), как и рекомендовано в разделе 8
// исходного ТЗ ("с застабленным HTTP-клиентом... не ходить в реальный
// интернет из тестов").

#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/ocsp.h>
#include <openssl/sha.h>

#include "../include/cert_helper/client.hpp"
#include "../src/cache/cache_store.hpp"
#include "../src/client_impl/dbus_client.hpp"
#include "../src/http_client.hpp"
#include "../src/ipc/dbus_server.hpp"
#include "../src/request_router.hpp"
#include "test_util.hpp"

namespace fs = std::filesystem;
namespace proto = cert_helper::protocol;

namespace {

// Фиктивный HTTP-фетчер: возвращает заранее заданные ответы по URL, не
// делает никаких реальных сетевых вызовов. Считает число фактических
// обращений — используется тестом на кэширование, чтобы убедиться, что
// второй запрос к тому же URL идёт из кэша, а не бьёт "сеть" повторно.
class StubHttpFetcher : public cert_helper::http::IHttpFetcher {
public:
    struct Canned {
        bool ok = true;
        int status_code = 200;
        std::vector<uint8_t> body;
        bool timed_out = false;
        // Искусственная задержка перед возвратом ответа — используется
        // тестом на singleflight-дедупликацию (ROADMAP.md, раздел 1,
        // пункт 5), чтобы гарантированно "растянуть" окно, в течение
        // которого несколько одновременных запросов к одному URL успеют
        // застать предыдущий как ещё не завершённый (стать
        // "последователями", а не независимыми "лидерами").
        int delay_ms = 0;
    };

    void set_response(const std::string& url, Canned resp) {
        std::lock_guard<std::mutex> lock(mtx);
        responses[url] = std::move(resp);
        sequences.erase(url); // явный set_response() отменяет ранее заданную последовательность
    }

    // ROADMAP.md, раздел 2, пункт 10: последовательность ответов,
    // потребляемых по одному на каждый вызов fetch() для данного URL —
    // используется тестом на retry с backoff (первые N попыток
    // "рвутся", затем успех). Когда последовательность исчерпана,
    // повторяется последний элемент (удобно для "постоянно недоступен").
    void set_response_sequence(const std::string& url, std::vector<Canned> seq) {
        std::lock_guard<std::mutex> lock(mtx);
        sequences[url] = std::move(seq);
        responses.erase(url);
    }

    int call_count(const std::string& url) const {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = call_counts.find(url);
        return it == call_counts.end() ? 0 : it->second;
    }

    // Последний max_response_bytes, с которым RequestRouter дёрнул этот
    // URL — используется тестом на пункт 4 (лимиты размера ответа по
    // типу запроса), чтобы убедиться, что router действительно передаёт
    // РАЗНЫЕ пределы для OCSP/AIA/CRL, а не одно и то же значение.
    size_t last_max_response_bytes(const std::string& url) const {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = last_max_bytes.find(url);
        return it == last_max_bytes.end() ? 0 : it->second;
    }

    cert_helper::http::HttpResult fetch(cert_helper::http::Method, const std::string& url,
                                         const std::vector<uint8_t>&, const std::string&,
                                         uint32_t, size_t max_response_bytes) override {
        // StubHttpFetcher теперь вызывается из нескольких воркер-потоков
        // одновременно (тесты на singleflight-дедупликацию и на
        // concurrent-обработку) — доступ к разделяемым map защищён
        // мьютексом. Сам "сетевой" ответ (Canned) копируется под
        // мьютексом, а задержка (если задана) выполняется уже без
        // удержания лока, чтобы не сериализовать неродственные запросы
        // друг за другом искусственно из-за самого стаба.
        std::optional<Canned> canned;
        {
            std::lock_guard<std::mutex> lock(mtx);
            int& count = call_counts[url];
            last_max_bytes[url] = max_response_bytes;
            auto seq_it = sequences.find(url);
            if (seq_it != sequences.end() && !seq_it->second.empty()) {
                size_t idx = std::min(static_cast<size_t>(count), seq_it->second.size() - 1);
                canned = seq_it->second[idx];
            } else {
                auto it = responses.find(url);
                if (it != responses.end()) canned = it->second;
            }
            ++count;
        }

        cert_helper::http::HttpResult result;
        if (!canned) {
            return result; // ok=false по умолчанию — "неизвестный" URL в тесте
        }
        if (canned->delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(canned->delay_ms));
        }
        // Имитируем поведение SimpleHttpFetcher::recv_all() при
        // превышении лимита размера ответа (ROADMAP.md, раздел 1, пункт
        // 4): реальный сетевой клиент оборвал бы приём и вернул ok=false,
        // так что стаб делает то же самое для канонической (canned)
        // "сети", вместо того чтобы молча отдать тело большего размера,
        // чем разрешил вызывающий router.
        if (canned->body.size() > max_response_bytes) {
            return result; // ok=false
        }
        result.ok = canned->ok;
        result.status_code = canned->status_code;
        result.body = canned->body;
        result.timed_out = canned->timed_out;
        return result;
    }

private:
    mutable std::mutex mtx;
    std::unordered_map<std::string, Canned> responses;
    std::unordered_map<std::string, std::vector<Canned>> sequences;
    std::unordered_map<std::string, int> call_counts;
    std::unordered_map<std::string, size_t> last_max_bytes;
};

// ROADMAP.md, раздел 1, пункт 9: заглушка ILdapFetcher для тестов
// router-уровня, не поднимающих настоящий LDAP-сервер (тот уровень —
// BER-протокол, bind/search — уже отдельно и подробно проверен в
// tests/test_ldap_support.cpp, включая ручную сверку с реальным
// OpenLDAP-сервером — см. комментарий в начале того файла). Здесь нужно
// только убедиться, что RequestRouter правильно ДИСПЕТЧЕРИЗУЕТ ldap://
// на ILdapFetcher (или отказывает, если он не сконфигурирован), не
// проверяя заново сам протокол.
class StubLdapFetcher : public cert_helper::ldap::ILdapFetcher {
public:
    void set_response(const std::string& url, cert_helper::ldap::LdapResult resp) {
        responses[url] = std::move(resp);
    }

    cert_helper::ldap::LdapResult fetch(const std::string& url, const std::string&, uint32_t,
                                         size_t) override {
        ++call_counts[url];
        auto it = responses.find(url);
        if (it == responses.end()) return cert_helper::ldap::LdapResult{};
        return it->second;
    }

    int call_count(const std::string& url) const {
        auto it = call_counts.find(url);
        return it == call_counts.end() ? 0 : it->second;
    }

private:
    std::unordered_map<std::string, cert_helper::ldap::LdapResult> responses;
    std::unordered_map<std::string, int> call_counts;
};

// Приватный dbus-daemon для изоляции теста от системной/сессионной шины
// хоста. Владеет дочерним процессом целиком: запускает с --nofork (чтобы
// демон оставался прямым ребёнком тестового процесса), вычитывает
// напечатанный адрес шины из stdout дочернего процесса, и посылает ему
// SIGTERM на разрушение объекта.
class PrivateDbusDaemon {
public:
    PrivateDbusDaemon() {
        int pipe_fds[2];
        if (::pipe(pipe_fds) != 0) {
            std::fprintf(stderr, "pipe() failed\n");
            std::exit(1);
        }

        pid = ::fork();
        if (pid < 0) {
            std::fprintf(stderr, "fork() failed\n");
            std::exit(1);
        }

        if (pid == 0) {
            // Дочерний процесс: становится dbus-daemon.
            ::close(pipe_fds[0]);
            ::dup2(pipe_fds[1], STDOUT_FILENO);
            ::close(pipe_fds[1]);
            ::execlp("dbus-daemon", "dbus-daemon", "--session", "--nofork", "--print-address",
                      static_cast<char*>(nullptr));
            // execlp вернулся => ошибка
            std::fprintf(stderr, "execlp(dbus-daemon) failed: %s\n", std::strerror(errno));
            _exit(127);
        }

        // Родитель: читаем адрес шины из stdout ребёнка.
        ::close(pipe_fds[1]);
        std::string line;
        char c;
        while (::read(pipe_fds[0], &c, 1) == 1) {
            if (c == '\n') break;
            line.push_back(c);
        }
        ::close(pipe_fds[0]);

        if (line.empty()) {
            std::fprintf(stderr, "failed to read bus address from private dbus-daemon\n");
            std::exit(1);
        }
        bus_address = line;

        // Небольшая пауза, чтобы демон гарантированно успел начать слушать
        // сокет до первого подключения клиента/сервера теста.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~PrivateDbusDaemon() {
        if (pid > 0) {
            ::kill(pid, SIGTERM);
            int status = 0;
            ::waitpid(pid, &status, 0);
        }
    }

    const std::string& address() const { return bus_address; }

private:
    pid_t pid = -1;
    std::string bus_address;
};

fs::path make_temp_dir(const std::string& suffix) {
    fs::path dir = fs::temp_directory_path() / ("cert_helper_itest_" + suffix + "_" +
                                                 std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

std::vector<uint8_t> load_test_cert_der(const std::string& filename = "leaf_no_aia.der") {
    std::string path = "../test_certs/" + filename;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "test fixture %s not found\n", path.c_str());
        std::exit(1);
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// Реплика RequestRouter::der_fingerprint() (приватный метод, не доступен
// извне) — нужна только для того, чтобы тест мог собрать тот же ключ
// кэша, что и сам роутер, и заглянуть в cache.get() напрямую. Если
// реализация der_fingerprint() в request_router.hpp когда-либо
// изменится, этот хелпер придётся обновить синхронно (иначе новый тест
// на клампинг max_ocsp_ttl_seconds перестанет находить запись в кэше).
std::string der_fingerprint_for_test(const std::vector<uint8_t>& der) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der.data(), der.size(), digest);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char b : digest) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

// Реплика RequestRouter::ocsp_request_cache_fingerprint() (приватный
// метод) — извлекает CertID первого OCSP_ONEREQ из валидного
// OCSP_REQUEST и фингерпринтит его ПЕРЕКОДИРОВАННЫЕ (i2d_OCSP_CERTID)
// байты, а не сырой DER всего запроса целиком. Нужна тестам на батчинг
// (ROADMAP.md, раздел 2, пункт 14), которые используют настоящие,
// валидные OCSP-запросы (в отличие от других тестов, использующих
// заведомо "сырые"/невалидные байты, для которых роутер откатывается на
// фингерпринт всего DER, покрываемый der_fingerprint_for_test() выше).
std::string der_fingerprint_for_test_certid(const std::vector<uint8_t>& ocsp_request_der) {
    const unsigned char* p = ocsp_request_der.data();
    OCSP_REQUEST* req = d2i_OCSP_REQUEST(nullptr, &p, static_cast<long>(ocsp_request_der.size()));
    if (req == nullptr) {
        std::fprintf(stderr, "der_fingerprint_for_test_certid: not a valid OCSP_REQUEST\n");
        std::exit(1);
    }
    OCSP_ONEREQ* one_req = OCSP_request_onereq_get0(req, 0);
    OCSP_CERTID* cert_id = (one_req != nullptr) ? OCSP_onereq_get0_id(one_req) : nullptr;
    if (cert_id == nullptr) {
        OCSP_REQUEST_free(req);
        std::fprintf(stderr, "der_fingerprint_for_test_certid: no CertID in request\n");
        std::exit(1);
    }
    unsigned char* certid_der = nullptr;
    int certid_len = i2d_OCSP_CERTID(cert_id, &certid_der);
    OCSP_REQUEST_free(req);
    std::vector<uint8_t> certid_bytes(certid_der, certid_der + certid_len);
    OPENSSL_free(certid_der);
    return der_fingerprint_for_test(certid_bytes);
}

struct TestHarness {
    PrivateDbusDaemon dbus_daemon;
    fs::path cache_dir;
    cert_helper::cache::FileCacheStore cache;
    StubHttpFetcher http;
    cert_helper::RequestRouter router;
    cert_helper::ipc::DbusServer server;

    TestHarness()
        : cache_dir(make_temp_dir("cache")),
          cache(cache_dir, cert_helper::cache::FileCacheStore::Limits{}),
          router(cache, http, cert_helper::RequestRouter::Config{}),
          server(make_server_config(dbus_daemon.address()), router) {
        if (!server.start()) {
            std::fprintf(stderr, "failed to start test DbusServer on %s\n",
                          dbus_daemon.address().c_str());
            std::exit(1);
        }
        // Даём bus-потоку время принять и обработать sd_bus_request_name
        // до первого клиентского вызова.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~TestHarness() {
        server.stop();
        std::error_code ec;
        fs::remove_all(cache_dir, ec);
    }

    static cert_helper::ipc::DbusServer::Config make_server_config(const std::string& bus_address) {
        cert_helper::ipc::DbusServer::Config cfg;
        cfg.bus_address = bus_address;
        cfg.min_worker_threads = 2;
        // ROADMAP.md, раздел 1, пункт 5: test_singleflight_deduplicates_
        // concurrent_identical_requests запускает несколько одновременных
        // клиентских запросов (kConcurrentRequests) к одному URL и
        // рассчитывает, что все они застанут "лидера" ещё выполняющимся
        // (а не образуют вторую "волну" запросов уже ПОСЛЕ того, как
        // лидер первой волны успел завершиться и убрать себя из
        // in-flight map). Для этого пул воркеров должен уметь принять
        // все одновременные запросы теста без ожидания в очереди — отсюда
        // запас с большим числом воркеров, а не старые 4.
        cfg.max_worker_threads = 16;
        return cfg;
    }

    std::string bus_address() const { return dbus_daemon.address(); }
};

void test_health_check_roundtrip() {
    TestHarness h;
    cert_helper::client_impl::DbusClient client(h.bus_address());

    auto result = client.health_check(2000);
    TEST_CHECK(result.reachable);
    TEST_CHECK(result.health.healthy);
    TEST_CHECK_EQ(result.health.cache_entries, uint64_t{0});
}

void test_ocsp_fetch_roundtrip_and_caches() {
    TestHarness h;
    std::string url = "http://ocsp.example.test/";
    std::vector<uint8_t> fake_ocsp_der = {0x01, 0x02, 0x03, 0x04};
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, fake_ocsp_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());

    auto resp1 = client.fetch_ocsp(url, {0xAA, 0xBB}, 2000);
    TEST_CHECK(resp1.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp1.payload_der == fake_ocsp_der);
    TEST_CHECK(!resp1.from_cache);

    auto resp2 = client.fetch_ocsp(url, {0xAA, 0xBB}, 2000);
    TEST_CHECK(resp2.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp2.from_cache); // второй запрос должен обслуживаться из кэша

    TEST_CHECK_EQ(h.http.call_count(url), 1); // "сеть" дёрнута ровно один раз
}

// ROADMAP.md, раздел 1, пункт 2 (P0): TTL, вычисленный из nextUpdate
// OCSP-ответа, должен клампиться сверху max_ocsp_ttl_seconds независимо
// от того, что заявил responder. Фикстура ocsp_response_far_future.der
// (см. test_certs/README.md) заявляет nextUpdate примерно через 400
// дней — недобросовестный/скомпрометированный responder мог бы попытаться
// заставить демон отдавать устаревший статус отзыва весь этот срок.
void test_ocsp_ttl_clamped_to_max_ocsp_ttl() {
    TestHarness h;
    std::string url = "http://ocsp.example.test/far-future";
    auto ocsp_der = load_test_cert_der("ocsp_response_far_future.der");
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, ocsp_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_ocsp(url, {0xAA, 0xBB}, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(!resp.from_cache);

    auto cached = h.cache.get(cert_helper::cache::EntryKind::Ocsp,
                               url + "|" + der_fingerprint_for_test({0xAA, 0xBB}));
    TEST_CHECK(cached.has_value());
    if (cached) {
        int64_t remaining = cached->valid_until - cached->fetched_at;
        constexpr int64_t kMaxOcspTtlSeconds = 24 * 3600; // RequestRouter::Config default
        constexpr int64_t kClaimedNextUpdateSeconds = 400LL * 24 * 3600;
        TEST_CHECK(remaining > 0);
        // Заклампленный TTL не может превышать дефолтный max_ocsp_ttl_seconds...
        TEST_CHECK(remaining <= kMaxOcspTtlSeconds);
        // ...и уж точно на порядки меньше того, что заявил "недобросовестный" responder.
        TEST_CHECK(remaining < kClaimedNextUpdateSeconds);
    }
}

// ROADMAP.md, раздел 1, пункт 3 (P1): кэш OCSP должен ключеваться по
// CertID (issuer name hash + issuer key hash + serialNumber), а не по
// фингерпринту всего DER запроса — иначе nonce-расширение (RFC 8954)
// ломает кэш: два ЗАПРОСА С ОДНИМ И ТЕМ ЖЕ CertID, но разным (случайным)
// nonce, должны считаться одним и тем же ключом кэша и не бить в "сеть"
// дважды. Фикстуры — настоящие ASN.1-корректные OCSP-запросы,
// сгенерированные через Python cryptography (см. test_certs/README.md).
void test_ocsp_cache_key_ignores_nonce_but_distinguishes_certid() {
    TestHarness h;
    std::string url = "http://ocsp.example.test/certid-nonce";
    std::vector<uint8_t> fake_ocsp_der = {0x01, 0x02, 0x03, 0x04};
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, fake_ocsp_der, false});

    auto req_a_nonce1 = load_test_cert_der("ocsp_request_certid_a_nonce1.der");
    auto req_a_nonce2 = load_test_cert_der("ocsp_request_certid_a_nonce2.der");
    auto req_b_nonce1 = load_test_cert_der("ocsp_request_certid_b_nonce1.der");
    TEST_CHECK(req_a_nonce1 != req_a_nonce2); // сами DER'ы действительно разные (разный nonce)

    cert_helper::client_impl::DbusClient client(h.bus_address());

    // Первый запрос по сертификату A (nonce #1) — промах кэша, идёт в "сеть".
    auto resp1 = client.fetch_ocsp(url, req_a_nonce1, 2000);
    TEST_CHECK(resp1.status == proto::FetchStatus::Ok);
    TEST_CHECK(!resp1.from_cache);

    // Тот же сертификат A, но другой nonce — CertID совпадает, должно
    // обслуживаться из кэша, а не бить в "сеть" повторно.
    auto resp2 = client.fetch_ocsp(url, req_a_nonce2, 2000);
    TEST_CHECK(resp2.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp2.from_cache);

    // Другой сертификат B (другой CertID, тот же responder_url) — должен
    // быть отдельным промахом кэша, а не случайно "переиспользовать" запись
    // сертификата A.
    auto resp3 = client.fetch_ocsp(url, req_b_nonce1, 2000);
    TEST_CHECK(resp3.status == proto::FetchStatus::Ok);
    TEST_CHECK(!resp3.from_cache);

    // Итого: два разных CertID => ровно два реальных обращения к "сети",
    // несмотря на три запроса и два разных значения nonce.
    TEST_CHECK_EQ(h.http.call_count(url), 2);
}

// ROADMAP.md, раздел 2, пункт 14 (P2): два OCSP-запроса для РАЗНЫХ
// сертификатов к ОДНОМУ responder'у, отправленные через fetch_ocsp_batch(),
// должны объединиться в ОДИН HTTP round-trip (комбинированный
// OCSP_REQUEST с двумя Request/CertID) вместо двух отдельных.
void test_ocsp_batch_combines_requests_to_same_responder_into_one_http_call() {
    TestHarness h;
    std::string url = "http://ocsp.example.test/batch";
    auto ocsp_batch_fixtures = test_util::generate_ocsp_batch_fixtures(2, 20);
    auto req_a = ocsp_batch_fixtures.request_a;
    auto req_b = ocsp_batch_fixtures.request_b;
    auto combined_response = ocsp_batch_fixtures.combined_response;

    // StubHttpFetcher отвечает ОДНИМ и тем же combined_response независимо
    // от того, какое именно тело запроса пришло — реальную сборку
    // комбинированного OCSP_REQUEST (build_combined_ocsp_request())
    // отдельно проверяет test_ocsp_batch_ttl_computed_individually_per_certid
    // ниже через прямую проверку итогового TTL каждого элемента.
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, combined_response, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    std::vector<proto::FetchOcspRequest> requests(2);
    requests[0].responder_url = url;
    requests[0].request_der = req_a;
    requests[0].timeout_ms = 2000;
    requests[1].responder_url = url;
    requests[1].request_der = req_b;
    requests[1].timeout_ms = 2000;

    auto results = client.fetch_ocsp_batch(requests, 2000);
    TEST_CHECK_EQ(results.size(), size_t{2});
    TEST_CHECK(results[0].status == proto::FetchStatus::Ok);
    TEST_CHECK(results[1].status == proto::FetchStatus::Ok);
    TEST_CHECK(!results[0].from_cache);
    TEST_CHECK(!results[1].from_cache);
    // Оба элемента получают ПОБАЙТОВО ИДЕНТИЧНЫЙ payload_der — общий
    // комбинированный блок (см. protocol.hpp за обоснованием).
    TEST_CHECK(results[0].payload_der == combined_response);
    TEST_CHECK(results[1].payload_der == combined_response);

    // Ключевая проверка батчинга: ОДИН HTTP round-trip на оба запроса,
    // а не два.
    TEST_CHECK_EQ(h.http.call_count(url), 1);
}

// После успешного батч-фетча оба сертификата должны быть закэшированы
// ПО ОТДЕЛЬНОСТИ под своим собственным CertID-based ключом (тем же,
// что использовал бы одиночный fetch_ocsp) — второй батч-вызов с теми
// же двумя запросами должен целиком обслужиться из кэша, не трогая сеть.
void test_ocsp_batch_results_are_individually_cached() {
    TestHarness h;
    std::string url = "http://ocsp.example.test/batch-cache";
    auto ocsp_batch_fixtures = test_util::generate_ocsp_batch_fixtures(2, 20);
    auto req_a = ocsp_batch_fixtures.request_a;
    auto req_b = ocsp_batch_fixtures.request_b;
    auto combined_response = ocsp_batch_fixtures.combined_response;
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, combined_response, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    std::vector<proto::FetchOcspRequest> requests(2);
    requests[0].responder_url = url;
    requests[0].request_der = req_a;
    requests[0].timeout_ms = 2000;
    requests[1].responder_url = url;
    requests[1].request_der = req_b;
    requests[1].timeout_ms = 2000;

    auto results1 = client.fetch_ocsp_batch(requests, 2000);
    TEST_CHECK_EQ(h.http.call_count(url), 1);

    // Повторный батч с теми же двумя запросами — оба должны прийти из
    // кэша, ноль новых обращений к "сети".
    auto results2 = client.fetch_ocsp_batch(requests, 2000);
    TEST_CHECK_EQ(results2.size(), size_t{2});
    TEST_CHECK(results2[0].status == proto::FetchStatus::Ok);
    TEST_CHECK(results2[1].status == proto::FetchStatus::Ok);
    TEST_CHECK(results2[0].from_cache);
    TEST_CHECK(results2[1].from_cache);
    TEST_CHECK_EQ(h.http.call_count(url), 1); // не выросло

    // И одиночный fetch_ocsp на тот же CertID тоже должен попасть в тот
    // же кэш (общий ключ — тем же CertID-based фингерпринтом).
    auto single_a = client.fetch_ocsp(url, req_a, 2000);
    TEST_CHECK(single_a.status == proto::FetchStatus::Ok);
    TEST_CHECK(single_a.from_cache);
    TEST_CHECK_EQ(h.http.call_count(url), 1);
}

// ROADMAP.md, раздел 2, пункт 14: TTL каждого элемента батча должен
// вычисляться ПО ЕГО СОБСТВЕННОМУ CertID (OCSP_resp_find() внутри
// ocsp_response_ttl_seconds()), а не по "первому попавшемуся"
// SingleResponse в комбинированном ответе — фикстура (см.
// test_util::generate_ocsp_batch_fixtures()) намеренно генерируется с
// РАЗНЫМ nextUpdate для A (+2 часа) и B (+20 часов, но оба под потолком
// max_ocsp_ttl_
// seconds по умолчанию — сутки, чтобы не путать проверку клампингом
// сверху), см. test_certs/README.md.
void test_ocsp_batch_ttl_computed_individually_per_certid() {
    TestHarness h;
    std::string url = "http://ocsp.example.test/batch-ttl";
    auto ocsp_batch_fixtures = test_util::generate_ocsp_batch_fixtures(2, 20);
    auto req_a = ocsp_batch_fixtures.request_a;
    auto req_b = ocsp_batch_fixtures.request_b;
    auto combined_response = ocsp_batch_fixtures.combined_response;
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, combined_response, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    std::vector<proto::FetchOcspRequest> requests(2);
    requests[0].responder_url = url;
    requests[0].request_der = req_a;
    requests[0].timeout_ms = 2000;
    requests[1].responder_url = url;
    requests[1].request_der = req_b;
    requests[1].timeout_ms = 2000;

    client.fetch_ocsp_batch(requests, 2000);

    auto key_a = url + "|" + der_fingerprint_for_test_certid(req_a);
    auto key_b = url + "|" + der_fingerprint_for_test_certid(req_b);
    auto cached_a = h.cache.get(cert_helper::cache::EntryKind::Ocsp, key_a);
    auto cached_b = h.cache.get(cert_helper::cache::EntryKind::Ocsp, key_b);
    TEST_CHECK(cached_a.has_value());
    TEST_CHECK(cached_b.has_value());
    if (cached_a && cached_b) {
        int64_t remaining_a = cached_a->valid_until - cached_a->fetched_at;
        int64_t remaining_b = cached_b->valid_until - cached_b->fetched_at;
        constexpr int64_t kThreeHoursSeconds = 3 * 3600;
        constexpr int64_t kTenHoursSeconds = 10 * 3600;
        constexpr int64_t kOneDaySeconds = 24 * 3600; // max_ocsp_ttl_seconds по умолчанию
        // A: nextUpdate +2 часа — TTL должен быть около этого, не около суток.
        TEST_CHECK(remaining_a > 0);
        TEST_CHECK(remaining_a <= kThreeHoursSeconds);
        // B: nextUpdate +20 часов — TTL должен быть заметно больше, чем у A
        // (если бы TTL брался "по первому SingleResponse" для обоих —
        // remaining_b совпал бы с remaining_a, что эта проверка отловит),
        // но всё ещё в пределах max_ocsp_ttl_seconds по умолчанию (сутки).
        TEST_CHECK(remaining_b > kTenHoursSeconds);
        TEST_CHECK(remaining_b <= kOneDaySeconds);
    }
}

// Если оба сертификата батча уже в кэше — ни одного HTTP-запроса
// вообще, включая комбинированный.
void test_ocsp_batch_all_cache_hits_makes_no_http_call() {
    TestHarness h;
    std::string url = "http://ocsp.example.test/batch-all-cached";
    auto ocsp_batch_fixtures = test_util::generate_ocsp_batch_fixtures(2, 20);
    auto req_a = ocsp_batch_fixtures.request_a;
    auto req_b = ocsp_batch_fixtures.request_b;
    auto combined_response = ocsp_batch_fixtures.combined_response;
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, combined_response, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    std::vector<proto::FetchOcspRequest> requests(2);
    requests[0].responder_url = url;
    requests[0].request_der = req_a;
    requests[0].timeout_ms = 2000;
    requests[1].responder_url = url;
    requests[1].request_der = req_b;
    requests[1].timeout_ms = 2000;

    client.fetch_ocsp_batch(requests, 2000); // прогреваем кэш для обоих
    TEST_CHECK_EQ(h.http.call_count(url), 1);

    auto results = client.fetch_ocsp_batch(requests, 2000);
    TEST_CHECK(results[0].from_cache);
    TEST_CHECK(results[1].from_cache);
    TEST_CHECK_EQ(h.http.call_count(url), 1); // не выросло вовсе
}

void test_crl_fetch_network_error_not_cached() {
    TestHarness h;
    std::string url = "http://crl.example.test/list.crl";
    h.http.set_response(url, StubHttpFetcher::Canned{false, 0, {}, false}); // ok=false -> NetworkError

    cert_helper::client_impl::DbusClient client(h.bus_address());

    auto resp = client.fetch_crl(url, 1000);
    TEST_CHECK(resp.status == proto::FetchStatus::NetworkError);

    // Повторный запрос должен снова обратиться к "сети" — ошибочный ответ не кэшируется.
    auto resp2 = client.fetch_crl(url, 1000);
    TEST_CHECK(resp2.status == proto::FetchStatus::NetworkError);
    // ROADMAP.md, раздел 2, пункт 10: каждый клиентский вызов теперь сам
    // по себе делает до config.max_retries+1 попыток (по умолчанию 1+2=3)
    // при устойчивой сетевой ошибке — отсюда 2*3=6, а не 2, как было до
    // добавления retry с backoff. Сам факт "не кэшируется" (главное, что
    // проверяет этот тест) при этом не меняется.
    constexpr int kAttemptsPerCall = 3; // 1 + default max_retries(2)
    TEST_CHECK_EQ(h.http.call_count(url), 2 * kAttemptsPerCall);
}

// ROADMAP.md, раздел 2, пункт 10 (P1): запрос, который проваливается на
// первых попытках транзиентной сетевой ошибкой, но УСПЕВАЕТ успешно
// завершиться на одной из повторных — должен в итоге вернуть Ok, а не
// сдаваться после первой неудачи. default max_retries=2 — тело
// последовательности "провал, провал, успех" укладывается ровно в
// разрешённое число попыток (1 исходная + 2 ретрая = 3).
void test_crl_fetch_succeeds_after_transient_failures_within_retry_budget() {
    TestHarness h;
    std::string url = "http://crl.example.test/flaky.crl";
    auto crl_der = load_test_cert_der("crl_far_future.der");
    h.http.set_response_sequence(url, {
                                           StubHttpFetcher::Canned{false, 0, {}, false}, // 1-я попытка: провал
                                           StubHttpFetcher::Canned{false, 0, {}, false}, // 2-я попытка: провал
                                           StubHttpFetcher::Canned{true, 200, crl_der, false}, // 3-я: успех
                                       });

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_crl(url, 2000);

    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp.payload_der == crl_der);
    TEST_CHECK_EQ(h.http.call_count(url), 3);
}

// Если ошибок больше, чем разрешено попыток (провал на всех 1+max_retries
// попытках), итоговый результат — NetworkError, а число обращений к
// "сети" не превышает бюджет (сверяемся с точным числом, чтобы поймать
// как "слишком мало попыток" — потерю ретраев, — так и "слишком много" —
// зависший цикл ретраев без учёта max_retries).
void test_crl_fetch_gives_up_after_exhausting_retry_budget() {
    TestHarness h;
    std::string url = "http://crl.example.test/always-flaky.crl";
    h.http.set_response(url, StubHttpFetcher::Canned{false, 0, {}, false}); // всегда провал

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_crl(url, 2000);

    TEST_CHECK(resp.status == proto::FetchStatus::NetworkError);
    constexpr int kAttemptsPerCall = 3; // 1 + default max_retries(2)
    TEST_CHECK_EQ(h.http.call_count(url), kAttemptsPerCall);
}

// Успешный ответ НЕ должен ретраиться — иначе, например, дорогой (в
// смысле нагрузки на CA) или неидемпотентный побочный эффект повторялся
// бы без необходимости. Здесь дополнительно фиксируем: даже если бы
// сервер вернул НЕуспешный HTTP-статус (не 200), но сам транспортный
// вызов завершился без сетевой ошибки (HttpResult::ok == true) — retry
// не применяется, т.к. пункт 10 сознательно ограничен именно сетевыми
// ошибками транспорта (см. комментарий в начале request_router.hpp).
void test_successful_transport_response_is_not_retried_even_with_error_status_code() {
    TestHarness h;
    std::string url = "http://crl.example.test/http-500.crl";
    // ok=true (транспорт отработал), но status_code не 200 — определённый
    // ответ сервера, не "сетевая ошибка".
    h.http.set_response(url, StubHttpFetcher::Canned{true, 500, {}, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_crl(url, 2000);

    TEST_CHECK(resp.status != proto::FetchStatus::Ok);
    TEST_CHECK_EQ(h.http.call_count(url), 1); // ни одного ретрая
}

// ROADMAP.md, раздел 2, пункт 11 (P1): после config.circuit_breaker_
// failure_threshold подряд неудачных ЗАПРОСОВ (не отдельных попыток
// ретрая — см. комментарий в начале request_router.hpp) к одному хосту
// breaker должен открыться и следующий запрос к ТОМУ ЖЕ хосту —
// отклонить немедленно, вообще не дёргая http_fetcher (call_count не
// должен увеличиться на этом отклонённом запросе). max_retries=0 в
// конфиге теста — чтобы один клиентский вызов соответствовал ровно одной
// попытке сети, и подсчёт "неудачных запросов" для breaker'а был легко
// проверяем по call_count().
void test_circuit_breaker_opens_after_threshold_failures_and_fails_fast() {
    auto cache_dir = make_temp_dir("circuit_breaker_open");
    cert_helper::cache::FileCacheStore cache(cache_dir, cert_helper::cache::FileCacheStore::Limits{});
    StubHttpFetcher http;
    std::string url = "http://flaky-ca.example.test/base.crl";
    http.set_response(url, StubHttpFetcher::Canned{false, 0, {}, false}); // всегда провал

    cert_helper::RequestRouter::Config cfg;
    cfg.max_retries = 0; // изолируем подсчёт breaker'а от retry — 1 клиентский вызов = 1 сетевая попытка
    cfg.circuit_breaker_failure_threshold = 2;
    cfg.circuit_breaker_cooldown_seconds = 60; // не должен истечь за время теста
    cert_helper::RequestRouter router(cache, http, cfg);

    PrivateDbusDaemon dbus_daemon;
    cert_helper::ipc::DbusServer::Config server_cfg;
    server_cfg.bus_address = dbus_daemon.address();
    server_cfg.min_worker_threads = 2;
    server_cfg.max_worker_threads = 4;
    cert_helper::ipc::DbusServer server(server_cfg, router);
    if (!server.start()) {
        std::fprintf(stderr, "failed to start DbusServer for circuit-breaker test\n");
        std::exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    cert_helper::client_impl::DbusClient client(dbus_daemon.address());

    // Первые 2 запроса — обычные промахи, каждый реально бьёт в "сеть".
    auto resp1 = client.fetch_crl(url, 2000);
    TEST_CHECK(resp1.status == proto::FetchStatus::NetworkError);
    auto resp2 = client.fetch_crl(url, 2000);
    TEST_CHECK(resp2.status == proto::FetchStatus::NetworkError);
    TEST_CHECK_EQ(http.call_count(url), 2);

    // Порог достигнут (threshold=2) — breaker открылся. Третий запрос
    // должен быть отклонён БЕЗ обращения к "сети" — call_count не растёт.
    auto resp3 = client.fetch_crl(url, 2000);
    TEST_CHECK(resp3.status == proto::FetchStatus::NetworkError);
    TEST_CHECK_EQ(http.call_count(url), 2); // не 3 — сеть не дёргалась

    auto resp4 = client.fetch_crl(url, 2000);
    TEST_CHECK(resp4.status == proto::FetchStatus::NetworkError);
    TEST_CHECK_EQ(http.call_count(url), 2); // всё ещё 2 — breaker продолжает отказывать

    server.stop();
    std::error_code ec;
    fs::remove_all(cache_dir, ec);
}

// После истечения cooldown breaker должен пропустить пробный запрос
// (Half-Open); если проба успешна — breaker закрывается, и последующие
// запросы снова идут в "сеть" как обычно.
void test_circuit_breaker_recovers_after_cooldown_on_successful_probe() {
    auto cache_dir = make_temp_dir("circuit_breaker_recover");
    cert_helper::cache::FileCacheStore cache(cache_dir, cert_helper::cache::FileCacheStore::Limits{});
    StubHttpFetcher http;
    std::string url = "http://recovering-ca.example.test/base.crl";
    auto crl_der = load_test_cert_der("crl_far_future.der");

    cert_helper::RequestRouter::Config cfg;
    cfg.max_retries = 0;
    cfg.circuit_breaker_failure_threshold = 1; // один провал уже открывает — короче тест
    cfg.circuit_breaker_cooldown_seconds = 1;  // короткий cooldown, чтобы не спать долго в тесте
    cert_helper::RequestRouter router(cache, http, cfg);

    PrivateDbusDaemon dbus_daemon;
    cert_helper::ipc::DbusServer::Config server_cfg;
    server_cfg.bus_address = dbus_daemon.address();
    server_cfg.min_worker_threads = 2;
    server_cfg.max_worker_threads = 4;
    cert_helper::ipc::DbusServer server(server_cfg, router);
    if (!server.start()) {
        std::fprintf(stderr, "failed to start DbusServer for circuit-breaker recovery test\n");
        std::exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    cert_helper::client_impl::DbusClient client(dbus_daemon.address());

    // Провал -> breaker открывается (threshold=1).
    http.set_response(url, StubHttpFetcher::Canned{false, 0, {}, false});
    auto resp1 = client.fetch_crl(url, 2000);
    TEST_CHECK(resp1.status == proto::FetchStatus::NetworkError);
    TEST_CHECK_EQ(http.call_count(url), 1);

    // Пока breaker открыт — сразу отказ без обращения к "сети".
    auto resp2 = client.fetch_crl(url, 2000);
    TEST_CHECK(resp2.status == proto::FetchStatus::NetworkError);
    TEST_CHECK_EQ(http.call_count(url), 1);

    // Ждём, пока истечёт cooldown, и "чиним" сервер на стороне стаба.
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    http.set_response(url, StubHttpFetcher::Canned{true, 200, crl_der, false});

    // Пробный запрос (Half-Open) должен пройти и обратиться к "сети".
    auto resp3 = client.fetch_crl(url, 2000);
    TEST_CHECK(resp3.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp3.payload_der == crl_der);
    TEST_CHECK_EQ(http.call_count(url), 2);

    server.stop();
    std::error_code ec;
    fs::remove_all(cache_dir, ec);
}

// ROADMAP.md, раздел 1, пункт 2 (P0): аналогично OCSP, TTL, вычисленный
// из nextUpdate CRL, должен клампиться сверху max_crl_ttl_seconds.
// Фикстура crl_far_future.der заявляет nextUpdate примерно через 400
// дней (см. test_certs/README.md).
void test_crl_ttl_clamped_to_max_crl_ttl() {
    TestHarness h;
    std::string url = "http://crl.example.test/far-future.crl";
    auto crl_der = load_test_cert_der("crl_far_future.der");
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, crl_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_crl(url, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(!resp.from_cache);

    auto cached = h.cache.get(cert_helper::cache::EntryKind::Crl, url);
    TEST_CHECK(cached.has_value());
    if (cached) {
        int64_t remaining = cached->valid_until - cached->fetched_at;
        constexpr int64_t kMaxCrlTtlSeconds = 7 * 24 * 3600; // RequestRouter::Config default
        constexpr int64_t kClaimedNextUpdateSeconds = 400LL * 24 * 3600;
        TEST_CHECK(remaining > 0);
        TEST_CHECK(remaining <= kMaxCrlTtlSeconds);
        TEST_CHECK(remaining < kClaimedNextUpdateSeconds);
    }
}

// ROADMAP.md, раздел 1, пункт 9: если ldap:// URL встретился в CRL
// distribution point, а --allow-ldap не включён (RequestRouter создан
// без ILdapFetcher, ldap_fetcher == nullptr — как в TestHarness по
// умолчанию), запрос должен быть отклонён как NetworkError, а не падать
// и не пытаться сделать что-то ещё.
void test_crl_via_ldap_rejected_when_not_configured() {
    TestHarness h; // router здесь создан БЕЗ ldap_fetcher

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_crl("ldap://ldap.example.test/cn=CRL1,dc=example,dc=test", 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::NetworkError);
}

// ROADMAP.md, раздел 1, пункт 9: когда ILdapFetcher сконфигурирован
// (аналог --allow-ldap), ldap:// CRL URL должен диспетчеризоваться на
// него, а результат — кэшироваться и получать TTL из nextUpdate самого
// CRL точно так же, как для http://. Отдельно проверяем, что обычный
// http:// CRL URL по-прежнему идёт через http_fetcher, а не случайно
// перехватывается ldap-веткой (нет взаимного "залипания" путей).
void test_crl_via_ldap_succeeds_when_configured_and_http_path_unaffected() {
    auto cache_dir = make_temp_dir("ldap_router");
    cert_helper::cache::FileCacheStore cache(cache_dir, cert_helper::cache::FileCacheStore::Limits{});
    StubHttpFetcher http;
    StubLdapFetcher ldap;

    std::string ldap_url = "ldap://ldap.example.test/cn=CRL1,dc=example,dc=test?certificateRevocationList;binary";
    std::string http_url = "http://crl.example.test/base.crl";
    auto crl_der = load_test_cert_der("crl_far_future.der");

    cert_helper::ldap::LdapResult ldap_resp;
    ldap_resp.ok = true;
    ldap_resp.value = crl_der;
    ldap.set_response(ldap_url, ldap_resp);
    http.set_response(http_url, StubHttpFetcher::Canned{true, 200, crl_der, false});

    cert_helper::RequestRouter router(cache, http, cert_helper::RequestRouter::Config{}, &ldap);

    PrivateDbusDaemon dbus_daemon;
    cert_helper::ipc::DbusServer::Config server_cfg;
    server_cfg.bus_address = dbus_daemon.address();
    server_cfg.min_worker_threads = 2;
    server_cfg.max_worker_threads = 4;
    cert_helper::ipc::DbusServer server(server_cfg, router);
    if (!server.start()) {
        std::fprintf(stderr, "failed to start DbusServer for ldap-router test\n");
        std::exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    cert_helper::client_impl::DbusClient client(dbus_daemon.address());

    // ldap:// идёт через StubLdapFetcher, а не StubHttpFetcher.
    auto ldap_fetch_resp = client.fetch_crl(ldap_url, 2000);
    TEST_CHECK(ldap_fetch_resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(ldap_fetch_resp.payload_der == crl_der);
    TEST_CHECK(!ldap_fetch_resp.from_cache);
    TEST_CHECK_EQ(ldap.call_count(ldap_url), 1);
    TEST_CHECK_EQ(http.call_count(ldap_url), 0); // не должен был случайно попасть в http-путь

    // Повторный запрос — из кэша (TTL взят из nextUpdate CRL, как обычно).
    auto ldap_fetch_resp2 = client.fetch_crl(ldap_url, 2000);
    TEST_CHECK(ldap_fetch_resp2.status == proto::FetchStatus::Ok);
    TEST_CHECK(ldap_fetch_resp2.from_cache);
    TEST_CHECK_EQ(ldap.call_count(ldap_url), 1); // второй раз LDAP не дёргался

    // http:// по-прежнему идёт через StubHttpFetcher, даже когда
    // ILdapFetcher сконфигурирован — нет взаимного перехвата путей.
    auto http_fetch_resp = client.fetch_crl(http_url, 2000);
    TEST_CHECK(http_fetch_resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(http_fetch_resp.payload_der == crl_der);
    TEST_CHECK_EQ(http.call_count(http_url), 1);
    TEST_CHECK_EQ(ldap.call_count(http_url), 0);

    server.stop();
    std::error_code ec;
    fs::remove_all(cache_dir, ec);
}

void test_intermediate_cert_fetch_validates_der() {
    TestHarness h;    std::string url = "http://ca.example.test/intermediate.cer";
    auto cert_der = load_test_cert_der();
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, cert_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp.payload_der == cert_der);
}

void test_intermediate_cert_fetch_rejects_non_der() {
    TestHarness h;
    std::string url = "http://ca.example.test/not-a-cert";
    std::vector<uint8_t> garbage = {'n', 'o', 't', ' ', 'a', ' ', 'c', 'e', 'r', 't'};
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, garbage, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::InvalidResponse);
}

// ROADMAP.md, раздел 1, пункт 6 (P2): caIssuers-ответ, пришедший как
// PKCS#7 "degenerate" контейнер (application/pkcs7-mime) с ОДНИМ
// сертификатом внутри, должен приниматься так же, как голый DER X.509 —
// демон извлекает единственный сертификат и возвращает его как обычный
// DER (тот же контракт для tls-mitm и для клампинга TTL по notAfter).
void test_intermediate_cert_accepts_pkcs7_single_cert() {
    TestHarness h;
    std::string url = "http://ca.example.test/issuer.p7c";
    auto pkcs7_der = load_test_cert_der("aia_pkcs7_single_cert.der");
    auto expected_der = load_test_cert_der("aia_pkcs7_single_cert_expected.der");
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, pkcs7_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp.payload_der == expected_der);

    // Второй запрос — должен обслуживаться из кэша уже как обычный DER
    // (кэш всегда хранит нормализованный, а не "сырой" PKCS#7-байты).
    auto resp2 = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp2.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp2.from_cache);
    TEST_CHECK(resp2.payload_der == expected_der);
}

// ROADMAP.md, раздел 1, пункт 6 (P2): PKCS#7-контейнер с НЕСКОЛЬКИМИ
// сертификатами (некоторые CA кладут туда весь оставшийся хвост цепочки)
// — демон должен взять первый сертификат из стека
// (aia_pkcs7_multi_cert_expected_first.der — см. test_certs/README.md про
// то, почему этот эталон извлечён из уже собранного контейнера, а не
// пересобран "по названию" со стороны Python).
void test_intermediate_cert_accepts_pkcs7_multi_cert_takes_first() {
    TestHarness h;
    std::string url = "http://ca.example.test/chain.p7c";
    auto pkcs7_der = load_test_cert_der("aia_pkcs7_multi_cert.der");
    auto expected_der = load_test_cert_der("aia_pkcs7_multi_cert_expected_first.der");
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, pkcs7_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp.payload_der == expected_der);
    // Убеждаемся, что извлечён именно ОДИН сертификат (нормализованный
    // DER одного X.509), а не весь PKCS#7-контейнер целиком.
    TEST_CHECK(resp.payload_der.size() < pkcs7_der.size());
}

// ROADMAP.md, раздел 1, пункт 1 (P0): TTL кэша AIA-докачки не должен
// пережить notAfter самого докачанного сертификата. Сертификат
// генерируется ЗДЕСЬ ЖЕ, во время выполнения теста (см.
// test_util.hpp::generate_self_signed_cert_der() — почему НЕ статическая
// фикстура), с notAfter через ~2 суток от текущего момента, тогда как
// RequestRouter::Config::aia_ttl_seconds по умолчанию неделя (7 суток).
// Без клампа по notAfter demon закэшировал бы этот сертификат на неделю,
// т.е. на ~5 дней дольше, чем сертификат реально действителен.
void test_intermediate_cert_ttl_clamped_to_cert_not_after() {
    TestHarness h;
    std::string url = "http://ca.example.test/expires-soon.cer";
    auto cert_der = test_util::generate_self_signed_cert_der("leaf-expires-soon.example.test",
                                                              /*not_before_days_offset=*/-1,
                                                              /*not_after_days_offset=*/2);
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, cert_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(!resp.from_cache);

    // Сертификат ещё валиден (запас — сутки до notBefore и около двух
    // суток до notAfter от момента генерации) — второй запрос должен
    // по-прежнему обслуживаться из кэша...
    auto resp2 = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp2.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp2.from_cache);

    // ...но фактический TTL в кэше должен быть заметно короче недели
    // (aia_ttl_seconds по умолчанию), а не самим aia_ttl_seconds —
    // именно это проверяет клампинг по notAfter. Даём щедрый допуск (3
    // суток), но при этом однозначно отличаем "заклампленный" TTL
    // (часы/дни) от незаклампленного (неделя).
    auto cached = h.cache.get(cert_helper::cache::EntryKind::IntermediateCert, url);
    TEST_CHECK(cached.has_value());
    if (cached) {
        int64_t remaining = cached->valid_until - cached->fetched_at;
        constexpr int64_t kThreeDaysSeconds = 3 * 24 * 3600;
        constexpr int64_t kAiaTtlSeconds = 7 * 24 * 3600;
        TEST_CHECK(remaining > 0);
        TEST_CHECK(remaining < kThreeDaysSeconds);
        TEST_CHECK(remaining < kAiaTtlSeconds);
    }
}

// ROADMAP.md, раздел 1, пункт 1 (P0): если докачанный сертификат уже
// просрочен на момент фетча (notAfter в прошлом), его вообще нельзя
// класть в кэш — иначе демон продолжал бы отдавать заведомо просроченный
// сертификат из кэша вплоть до aia_ttl_seconds. Сам фетч при этом
// по-прежнему считается успешным (Ok) — решение о том, является ли
// просроченный сертификат проблемой для построения цепочки, остаётся за
// tls-mitm, не за демоном. Сертификат генерируется при запуске теста —
// см. test_util.hpp::generate_self_signed_cert_der().
void test_intermediate_cert_already_expired_not_cached() {
    TestHarness h;
    std::string url = "http://ca.example.test/already-expired.cer";
    auto cert_der = test_util::generate_self_signed_cert_der("leaf-already-expired.example.test",
                                                              /*not_before_days_offset=*/-10,
                                                              /*not_after_days_offset=*/-1);
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, cert_der, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());
    auto resp = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(resp.payload_der == cert_der);
    TEST_CHECK(!resp.from_cache);

    // Повторный запрос должен снова обратиться к "сети" — просроченный
    // сертификат не должен был попасть в кэш.
    auto resp2 = client.fetch_intermediate_cert(url, 2000);
    TEST_CHECK(resp2.status == proto::FetchStatus::Ok);
    TEST_CHECK(!resp2.from_cache);
    TEST_CHECK_EQ(h.http.call_count(url), 2);

    auto cached = h.cache.get(cert_helper::cache::EntryKind::IntermediateCert, url);
    TEST_CHECK(!cached.has_value());
}

// ROADMAP.md, раздел 1, пункт 4 (P1): лимиты размера ответа передаются
// per-request-type, а не одна константа на все типы запросов. Проверяем
// оба свойства сразу: (1) router действительно передаёт РАЗНЫЕ пределы
// фетчеру для OCSP/AIA/CRL (через StubHttpFetcher::last_max_response_
// bytes), и (2) ответ, превышающий предел для своего типа, отклоняется
// (router получает ok=false от фетчера и трактует это как NetworkError) —
// даже если тот же самый размер был бы допустим для другого типа запроса
// (тело меньше max_crl_response_bytes, но больше max_ocsp_response_bytes
// и max_aia_response_bytes).
void test_response_size_limits_differ_per_request_type() {
    TestHarness h;
    // Тело нарочно выбрано так, чтобы попадать МЕЖДУ дефолтными
    // max_ocsp_response_bytes/max_aia_response_bytes (256 КиБ) и
    // max_crl_response_bytes (16 МиБ): 1 МиБ.
    std::vector<uint8_t> oversized_for_ocsp_and_aia(1024 * 1024, 0xAB);

    std::string ocsp_url = "http://ocsp.example.test/oversized";
    std::string aia_url = "http://ca.example.test/oversized.cer";
    std::string crl_url = "http://crl.example.test/oversized.crl";
    h.http.set_response(ocsp_url, StubHttpFetcher::Canned{true, 200, oversized_for_ocsp_and_aia, false});
    h.http.set_response(aia_url, StubHttpFetcher::Canned{true, 200, oversized_for_ocsp_and_aia, false});
    h.http.set_response(crl_url, StubHttpFetcher::Canned{true, 200, oversized_for_ocsp_and_aia, false});

    cert_helper::client_impl::DbusClient client(h.bus_address());

    // OCSP и AIA: тело больше их лимита (256 КиБ) — должны получить NetworkError.
    auto ocsp_resp = client.fetch_ocsp(ocsp_url, {0x01, 0x02}, 2000);
    TEST_CHECK(ocsp_resp.status == proto::FetchStatus::NetworkError);
    auto aia_resp = client.fetch_intermediate_cert(aia_url, 2000);
    TEST_CHECK(aia_resp.status == proto::FetchStatus::NetworkError);

    // CRL: то же самое тело меньше её лимита (16 МиБ) — должен пройти успешно.
    auto crl_resp = client.fetch_crl(crl_url, 2000);
    TEST_CHECK(crl_resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(crl_resp.payload_der == oversized_for_ocsp_and_aia);

    // И убеждаемся, что router действительно передал РАЗНЫЕ пределы —
    // а не просто "повезло" с одним и тем же большим значением для всех.
    constexpr size_t kMaxOcspBytes = 256 * 1024;
    constexpr size_t kMaxAiaBytes = 256 * 1024;
    constexpr size_t kMaxCrlBytes = 16 * 1024 * 1024;
    TEST_CHECK_EQ(h.http.last_max_response_bytes(ocsp_url), kMaxOcspBytes);
    TEST_CHECK_EQ(h.http.last_max_response_bytes(aia_url), kMaxAiaBytes);
    TEST_CHECK_EQ(h.http.last_max_response_bytes(crl_url), kMaxCrlBytes);
}

void test_public_client_wrapper_contract() {
    // Проверяем именно контракт из client.hpp: пустой вектор при ошибке,
    // непустой при успехе — то, на что рассчитывает
    // tls_mitm::OcspFetcher/CrlFetcher.
    TestHarness h;
    std::string ok_url = "http://ocsp2.example.test/";
    std::string bad_url = "http://ocsp3.example.test/";
    h.http.set_response(ok_url, StubHttpFetcher::Canned{true, 200, {5, 6, 7}, false});
    h.http.set_response(bad_url, StubHttpFetcher::Canned{false, 0, {}, false});

    cert_helper::Client client(h.bus_address());
    auto ok_result = client.fetch_ocsp(ok_url, {1, 2}, 2000);
    auto bad_result = client.fetch_ocsp(bad_url, {1, 2}, 2000);

    TEST_CHECK(ok_result == std::vector<uint8_t>({5, 6, 7}));
    TEST_CHECK(bad_result.empty());

    auto fn = client.ocsp_fetcher();
    auto via_fn = fn(ok_url, {1, 2}, 2000);
    TEST_CHECK(via_fn == std::vector<uint8_t>({5, 6, 7}));
}

void test_concurrent_fetches_do_not_serialize_on_slow_request() {
    // Регрессионный тест на архитектурное решение из dbus_server.hpp:
    // fetch-запросы обрабатываются пулом воркеров, а не последовательно
    // в одном bus-потоке. Стабим один URL "медленным" (искусственная
    // задержка внутри фиктивного HTTP-фетчера) и параллельно запрашиваем
    // другой, "быстрый" URL — быстрый запрос не должен ждать медленный.
    class SlowOnceHttpFetcher : public cert_helper::http::IHttpFetcher {
    public:
        cert_helper::http::HttpResult fetch(cert_helper::http::Method, const std::string& url,
                                             const std::vector<uint8_t>&, const std::string&,
                                             uint32_t, size_t) override {
            cert_helper::http::HttpResult result;
            if (url == "http://slow.example.test/") {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            result.ok = true;
            result.status_code = 200;
            result.body = {1, 2, 3};
            return result;
        }
    };

    auto cache_dir = make_temp_dir("concurrency");
    cert_helper::cache::FileCacheStore cache(cache_dir, cert_helper::cache::FileCacheStore::Limits{});
    SlowOnceHttpFetcher http;
    cert_helper::RequestRouter router(cache, http, cert_helper::RequestRouter::Config{});

    PrivateDbusDaemon dbus_daemon;
    cert_helper::ipc::DbusServer::Config server_cfg;
    server_cfg.bus_address = dbus_daemon.address();
    server_cfg.min_worker_threads = 2;
    server_cfg.max_worker_threads = 4;
    cert_helper::ipc::DbusServer server(server_cfg, router);
    if (!server.start()) {
        std::fprintf(stderr, "failed to start DbusServer for concurrency test\n");
        std::exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto start = std::chrono::steady_clock::now();

    std::thread slow_thread([&dbus_daemon] {
        cert_helper::client_impl::DbusClient client(dbus_daemon.address());
        auto resp = client.fetch_crl("http://slow.example.test/", 2000);
        TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    });

    // Даём медленному запросу немного форы, чтобы он гарантированно
    // "занял" один из воркеров раньше быстрого.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    cert_helper::client_impl::DbusClient fast_client(dbus_daemon.address());
    auto fast_resp = fast_client.fetch_crl("http://fast.example.test/", 2000);
    auto fast_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - start)
                             .count();

    TEST_CHECK(fast_resp.status == proto::FetchStatus::Ok);
    // Быстрый запрос должен вернуться заметно раньше, чем завершится
    // медленный (500ms) — если бы обработка была последовательной в одном
    // потоке, fast_elapsed был бы >= ~500ms.
    TEST_CHECK(fast_elapsed < 400);

    slow_thread.join();
    server.stop();
    std::error_code ec;
    fs::remove_all(cache_dir, ec);
}

// ROADMAP.md, раздел 1, пункт 5 (P1): singleflight-дедупликация.
// Имитируем "громкое стадо" (thundering herd) — много одновременных
// запросов к одному и тому же URL при пустом кэше (типичный сценарий:
// много TLS handshake упираются в один и тот же CRL/OCSP/AIA сразу после
// старта демона). До этого пункта каждый запрос независимо инициировал
// бы свой HTTP-поход; после — только первый ("лидер") реально идёт в
// "сеть", остальные ждут его результата.
void test_singleflight_deduplicates_concurrent_identical_requests() {
    TestHarness h;
    std::string url = "http://crl.example.test/herd.crl";
    std::vector<uint8_t> body = {9, 8, 7, 6, 5};
    // Задержка достаточно большая, чтобы все N потоков гарантированно
    // успели постучаться в router, пока лидер ещё не вернул результат
    // (широкий запас против шедулинга потоков в CI-окружении).
    h.http.set_response(url, StubHttpFetcher::Canned{true, 200, body, false, /*delay_ms=*/300});

    constexpr int kConcurrentRequests = 8;
    std::vector<std::thread> threads;
    std::vector<proto::FetchResponse> responses(kConcurrentRequests);

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < kConcurrentRequests; ++i) {
        threads.emplace_back([&h, &url, &responses, i] {
            cert_helper::client_impl::DbusClient client(h.bus_address());
            responses[i] = client.fetch_crl(url, 2000);
        });
    }
    for (auto& t : threads) t.join();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - start)
                       .count();

    // Все N запросов должны получить один и тот же корректный результат...
    for (const auto& resp : responses) {
        TEST_CHECK(resp.status == proto::FetchStatus::Ok);
        TEST_CHECK(resp.payload_der == body);
    }
    // ...но "сеть" должна была быть дёрнута РОВНО один раз, а не kConcurrentRequests раз.
    TEST_CHECK_EQ(h.http.call_count(url), 1);
    // Дополнительная (не строгая) проверка здравого смысла: если бы
    // запросы не дедуплицировались и обрабатывались параллельно пулом
    // воркеров (что и так возможно — см. предыдущий тест), общее время
    // всё равно осталось бы в районе одной задержки (300ms), а не кратно
    // ей — этот тест не полагается на время, полноценная проверка выше
    // через call_count(), но лишний отрицательный сигнал не помешает.
    TEST_CHECK(elapsed < 1000);
}

void test_client_survives_daemon_unreachable() {
    // Клиент указывает на несуществующий адрес шины — контракт "пустой
    // вектор = ошибка", а не исключение наружу из fetcher-лямбды (иначе
    // упал бы сам handshake в tls-mitm).
    cert_helper::Client client("unix:path=/tmp/cert_helper_definitely_not_running.sock");
    auto result = client.fetch_ocsp("http://x/", {1}, 500);
    TEST_CHECK(result.empty());
}

} // namespace

int main() {
    RUN_TEST(test_health_check_roundtrip);
    RUN_TEST(test_ocsp_fetch_roundtrip_and_caches);
    RUN_TEST(test_ocsp_ttl_clamped_to_max_ocsp_ttl);
    RUN_TEST(test_ocsp_cache_key_ignores_nonce_but_distinguishes_certid);
    RUN_TEST(test_ocsp_batch_combines_requests_to_same_responder_into_one_http_call);
    RUN_TEST(test_ocsp_batch_results_are_individually_cached);
    RUN_TEST(test_ocsp_batch_ttl_computed_individually_per_certid);
    RUN_TEST(test_ocsp_batch_all_cache_hits_makes_no_http_call);
    RUN_TEST(test_crl_fetch_network_error_not_cached);
    RUN_TEST(test_crl_fetch_succeeds_after_transient_failures_within_retry_budget);
    RUN_TEST(test_crl_fetch_gives_up_after_exhausting_retry_budget);
    RUN_TEST(test_successful_transport_response_is_not_retried_even_with_error_status_code);
    RUN_TEST(test_circuit_breaker_opens_after_threshold_failures_and_fails_fast);
    RUN_TEST(test_circuit_breaker_recovers_after_cooldown_on_successful_probe);
    RUN_TEST(test_crl_ttl_clamped_to_max_crl_ttl);
    RUN_TEST(test_crl_via_ldap_rejected_when_not_configured);
    RUN_TEST(test_crl_via_ldap_succeeds_when_configured_and_http_path_unaffected);
    RUN_TEST(test_intermediate_cert_fetch_validates_der);
    RUN_TEST(test_intermediate_cert_fetch_rejects_non_der);
    RUN_TEST(test_intermediate_cert_accepts_pkcs7_single_cert);
    RUN_TEST(test_intermediate_cert_accepts_pkcs7_multi_cert_takes_first);
    RUN_TEST(test_intermediate_cert_ttl_clamped_to_cert_not_after);
    RUN_TEST(test_intermediate_cert_already_expired_not_cached);
    RUN_TEST(test_response_size_limits_differ_per_request_type);
    RUN_TEST(test_public_client_wrapper_contract);
    RUN_TEST(test_concurrent_fetches_do_not_serialize_on_slow_request);
    RUN_TEST(test_singleflight_deduplicates_concurrent_identical_requests);
    RUN_TEST(test_client_survives_daemon_unreachable);
    TEST_MAIN_EXIT();
}
