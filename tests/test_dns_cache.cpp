// test_dns_cache.cpp — юнит-тесты кэша DNS-резолвинга (ROADMAP.md,
// раздел 2, пункт 13). Использует внедряемый ResolverFn (см.
// dns_cache.hpp) вместо реального getaddrinfo() — детерминированная
// проверка самой логики кэша (попадание/промах, истечение TTL, отказ не
// кэшируется) без зависимости от реальной сети/DNS.

#include <atomic>
#include <chrono>
#include <thread>

#include "../src/dns_cache.hpp"
#include "test_util.hpp"

using namespace cert_helper::net;

namespace {

ResolvedAddress make_addr(uint8_t last_octet) {
    ResolvedAddress addr;
    addr.family = AF_INET;
    addr.bytes = {127, 0, 0, last_octet};
    return addr;
}

// Первый resolve() — промах кэша, обращается к резолверу; второй
// (в пределах TTL) — попадание, резолвер больше не вызывается.
void test_second_resolve_within_ttl_is_cache_hit() {
    std::atomic<int> call_count{0};
    DnsCache cache(/*ttl_seconds=*/60, [&](const std::string&) {
        ++call_count;
        return std::vector<ResolvedAddress>{make_addr(1)};
    });

    auto r1 = cache.resolve("ocsp.example.test");
    TEST_CHECK_EQ(call_count.load(), 1);
    TEST_CHECK_EQ(r1.size(), size_t{1});

    auto r2 = cache.resolve("ocsp.example.test");
    TEST_CHECK_EQ(call_count.load(), 1); // резолвер НЕ вызван повторно — попадание в кэш
    TEST_CHECK_EQ(r2.size(), size_t{1});
    TEST_CHECK(r2[0].bytes == r1[0].bytes);
}

// После истечения TTL следующий resolve() должен снова обратиться к
// резолверу — короткий TTL (по умолчанию), а не бессрочное кэширование.
void test_resolve_after_ttl_expiry_hits_resolver_again() {
    std::atomic<int> call_count{0};
    DnsCache cache(/*ttl_seconds=*/1, [&](const std::string&) {
        ++call_count;
        return std::vector<ResolvedAddress>{make_addr(1)};
    });

    cache.resolve("crl.example.test");
    TEST_CHECK_EQ(call_count.load(), 1);

    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    cache.resolve("crl.example.test");
    TEST_CHECK_EQ(call_count.load(), 2); // TTL истёк — резолвинг повторился
}

// Неудачный резолв (пустой результат — имитация ошибки DNS) не должен
// кэшироваться: следующий вызов сразу пробует снова, а не ждёт TTL после
// сбоя, чтобы транзиентная ошибка резолвера не блокировала все
// последующие попытки на целый TTL.
void test_failed_resolve_is_not_cached() {
    std::atomic<int> call_count{0};
    DnsCache cache(/*ttl_seconds=*/60, [&](const std::string&) {
        ++call_count;
        return std::vector<ResolvedAddress>{}; // имитация ошибки DNS
    });

    auto r1 = cache.resolve("broken.example.test");
    TEST_CHECK(r1.empty());
    TEST_CHECK_EQ(call_count.load(), 1);

    auto r2 = cache.resolve("broken.example.test");
    TEST_CHECK(r2.empty());
    TEST_CHECK_EQ(call_count.load(), 2); // не ждали TTL — сразу повторная попытка
}

// Разные хосты кэшируются независимо — резолв одного не должен влиять на
// кэш другого, и оба должны корректно попадать в кэш по отдельности.
void test_different_hosts_cached_independently() {
    std::atomic<int> call_count_a{0};
    std::atomic<int> call_count_b{0};
    DnsCache cache(/*ttl_seconds=*/60, [&](const std::string& host) {
        if (host == "a.example.test") {
            ++call_count_a;
            return std::vector<ResolvedAddress>{make_addr(1)};
        }
        ++call_count_b;
        return std::vector<ResolvedAddress>{make_addr(2)};
    });

    cache.resolve("a.example.test");
    cache.resolve("b.example.test");
    cache.resolve("a.example.test");
    cache.resolve("b.example.test");

    TEST_CHECK_EQ(call_count_a.load(), 1);
    TEST_CHECK_EQ(call_count_b.load(), 1);
}

// make_sockaddr() должен корректно собрать sockaddr_storage для AF_INET
// (порт в сетевом порядке байт, адрес побайтово совпадает).
void test_make_sockaddr_builds_correct_ipv4_address() {
    ResolvedAddress addr = make_addr(42);
    struct sockaddr_storage ss;
    socklen_t len = 0;
    make_sockaddr(addr, 8080, ss, len);

    TEST_CHECK_EQ(static_cast<size_t>(len), sizeof(struct sockaddr_in));
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&ss);
    TEST_CHECK_EQ(static_cast<int>(sin->sin_family), AF_INET);
    TEST_CHECK_EQ(static_cast<int>(ntohs(sin->sin_port)), 8080);
    TEST_CHECK_EQ(static_cast<int>(reinterpret_cast<uint8_t*>(&sin->sin_addr)[3]), 42);
}

// default_resolver() — реальный getaddrinfo() — должен как минимум
// корректно резолвить "localhost" в loopback, без падений/исключений.
// Единственный тест в этом файле, трогающий настоящий системный резолвер
// (localhost не требует сети — резолвится из /etc/hosts или NSS-модуля
// без выхода за пределы хоста).
void test_default_resolver_resolves_localhost() {
    auto addrs = DnsCache::default_resolver("localhost");
    TEST_CHECK(!addrs.empty());
}

} // namespace

int main() {
    RUN_TEST(test_second_resolve_within_ttl_is_cache_hit);
    RUN_TEST(test_resolve_after_ttl_expiry_hits_resolver_again);
    RUN_TEST(test_failed_resolve_is_not_cached);
    RUN_TEST(test_different_hosts_cached_independently);
    RUN_TEST(test_make_sockaddr_builds_correct_ipv4_address);
    RUN_TEST(test_default_resolver_resolves_localhost);
    TEST_MAIN_EXIT();
}
