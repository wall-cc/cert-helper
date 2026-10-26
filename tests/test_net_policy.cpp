// test_net_policy.cpp — юнит-тесты NetworkPolicy: дефолтный deny-список
// (loopback/link-local/private/CGNAT/multicast), явные allow/deny
// дополнения, порт-фильтрация. Пункт 3 из анализа Squid (SSRF-защита для
// "сертификатного" трафика, инициируемого содержимым чужого сертификата).

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "../src/net_policy.hpp"
#include "test_util.hpp"

using namespace cert_helper::net;

namespace {

struct sockaddr_in make_v4(char const* ip) {
    struct sockaddr_in sin {};
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sin.sin_addr);
    return sin;
}

struct sockaddr_in6 make_v6(char const* ip) {
    struct sockaddr_in6 sin6 {};
    sin6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &sin6.sin6_addr);
    return sin6;
}

bool allowed_v4(NetworkPolicy const& policy, char const* ip) {
    auto sin = make_v4(ip);
    return policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin));
}

bool allowed_v6(NetworkPolicy const& policy, char const* ip) {
    auto sin6 = make_v6(ip);
    return policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin6));
}

void test_default_policy_blocks_loopback_and_private() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    TEST_CHECK(!allowed_v4(policy, "127.0.0.1"));
    TEST_CHECK(!allowed_v4(policy, "10.1.2.3"));
    TEST_CHECK(!allowed_v4(policy, "172.16.0.5"));
    TEST_CHECK(!allowed_v4(policy, "192.168.1.1"));
    TEST_CHECK(
        !allowed_v4(policy, "169.254.169.254"));    // cloud metadata endpoint
    TEST_CHECK(!allowed_v4(policy, "100.64.0.1"));  // CGNAT
    TEST_CHECK(!allowed_v6(policy, "::1"));
    TEST_CHECK(!allowed_v6(policy, "fe80::1"));
    TEST_CHECK(!allowed_v6(policy, "fc00::1"));
}

void test_default_policy_allows_public_addresses() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    TEST_CHECK(allowed_v4(policy, "8.8.8.8"));
    TEST_CHECK(
        allowed_v4(policy, "93.184.216.34"));  // example.com-ish public range
    TEST_CHECK(allowed_v6(policy, "2001:4860:4860::8888"));
}

void test_block_private_by_default_can_be_disabled() {
    NetworkPolicy::Config cfg;
    cfg.block_private_by_default = false;
    NetworkPolicy policy(cfg);
    TEST_CHECK(allowed_v4(policy, "127.0.0.1"));
    TEST_CHECK(allowed_v4(policy, "192.168.1.1"));
}

void test_explicit_allow_overrides_default_deny() {
    NetworkPolicy::Config cfg;
    cfg.allow_cidrs = {"10.5.0.0/16"};
    NetworkPolicy policy(cfg);
    TEST_CHECK(allowed_v4(
        policy, "10.5.1.1"));  // явно разрешённая подсеть внутри 10.0.0.0/8
    TEST_CHECK(!allowed_v4(
        policy, "10.6.1.1"));  // остальной 10.0.0.0/8 всё ещё заблокирован
}

void test_extra_deny_adds_to_default() {
    NetworkPolicy::Config cfg;
    cfg.extra_deny_cidrs = {"8.8.8.0/24"};
    NetworkPolicy policy(cfg);
    TEST_CHECK(!allowed_v4(policy,
                           "8.8.8.8"));  // заблокирован дополнительным правилом
    TEST_CHECK(allowed_v4(
        policy, "8.8.4.4"));  // соседний публичный адрес всё ещё разрешён
}

void test_port_allowlist_default_only_80() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    TEST_CHECK(policy.is_port_allowed(80));
    TEST_CHECK(!policy.is_port_allowed(443));
    TEST_CHECK(!policy.is_port_allowed(22));
}

void test_port_allowlist_configurable() {
    NetworkPolicy::Config cfg;
    cfg.allowed_ports = {80, 8080};
    NetworkPolicy policy(cfg);
    TEST_CHECK(policy.is_port_allowed(80));
    TEST_CHECK(policy.is_port_allowed(8080));
    TEST_CHECK(!policy.is_port_allowed(443));
}

void test_cidr_range_parsing_rejects_garbage() {
    TEST_CHECK(!CidrRange::parse("not-an-ip").has_value());
    TEST_CHECK(!CidrRange::parse("10.0.0.0/33")
                    .has_value());  // некорректная длина префикса для v4
    TEST_CHECK(!CidrRange::parse("::1/129")
                    .has_value());  // некорректная длина префикса для v6
    TEST_CHECK(CidrRange::parse("10.0.0.0/8").has_value());
    TEST_CHECK(CidrRange::parse("::1/128").has_value());
}

// ПУНКТ 2.1 ПЛАНА ДОРАБОТКИ (P0): IPv4-mapped IPv6 и родственные формы
// обходили деним-список. ::ffff:a.b.c.d (RFC 4291, 2.5.5.2) — тот же
// самый IPv4-адрес a.b.c.d, обёрнутый в IPv6-синтаксис. Деним-список
// по умолчанию содержит отдельные IPv4- и IPv6-диапазоны, не
// нормализуя одно к другому: is_address_allowed() сравнивал такой
// адрес ТОЛЬКО с IPv6-диапазонами (::1/128, fe80::/10, fc00::/7,
// ff00::/8, ::/128, 64:ff9b::/96) — ни один из них не матчит
// ::ffff:127.0.0.1, так что адрес проходил как разрешённый. В URL
// такой литерал не вставить (парсер URL отклоняет IPv6 в скобках), но
// AIA/CRL distribution point/OCSP responder URL в сертификате
// указывается ИМЕНЕМ ХОСТА, которое резолвится через DNS — и любой,
// кто контролирует DNS-ответ для этого имени (владелец домена из
// сертификата, DNS rebinding), может вернуть AAAA-запись с таким
// адресом. Проверка "после резолва" (см. комментарий в заголовке
// файла) защищает от rebinding ТОЛЬКО если сама проверка адреса
// полная — этот баг был дырой именно в ней.
void test_ipv4_mapped_loopback_is_blocked() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    auto sin6 = make_v6("::ffff:127.0.0.1");
    TEST_CHECK(!policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin6)));
}

void test_ipv4_mapped_cloud_metadata_is_blocked() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    auto sin6 = make_v6("::ffff:169.254.169.254");
    TEST_CHECK(!policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin6)));
}

void test_ipv4_mapped_private_range_is_blocked() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    for (char const* ip :
         {"::ffff:10.0.0.5", "::ffff:192.168.1.1", "::ffff:172.16.0.1"}) {
        auto sin6 = make_v6(ip);
        TEST_CHECK(!policy.is_address_allowed(
            reinterpret_cast<struct sockaddr const*>(&sin6)));
    }
}

// IPv4-compatible (устаревшая форма, RFC 4291 2.5.5.1: первые 96 бит
// нулевые, в отличие от IPv4-mapped у неё НЕ 0xFFFF перед встроенным
// v4-адресом) — тот же принцип встраивания, другой битовый маркер.
void test_ipv4_compatible_loopback_is_blocked() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    auto sin6 = make_v6("::127.0.0.1");
    TEST_CHECK(!policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin6)));
}

// 6to4 (RFC 3056, 2002::/16): встроенный IPv4-адрес лежит в следующих
// после префикса 2 байтах (2002:AABB:CCDD::/48 <=> v4 AA.BB.CC.DD).
// 2002:7f00:1:: встраивает 127.0.0.1 (0x7f=127, 0x00=0, 0x01=... —
// здесь 2002:7f00:0001:: => байты 2..5 = 7f 00 00 01 = 127.0.0.1).
void test_6to4_embedded_loopback_is_blocked() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    auto sin6 = make_v6("2002:7f00:1::");
    TEST_CHECK(!policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin6)));
}

// Негативный контроль: обычный публичный IPv4-mapped адрес (НЕ в
// деним-списке) по-прежнему разрешён — фикс не должен запрещать всё
// подряд, только реально приватные/служебные диапазоны.
void test_ipv4_mapped_public_address_still_allowed() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    auto sin6 = make_v6("::ffff:8.8.8.8");
    TEST_CHECK(policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin6)));
}

// Явный allow для IPv4-диапазона должен работать и через
// IPv4-mapped-спеллинг того же адреса — нормализация означает, что обе
// записи одного и того же адреса назначения принимают ОДНО решение, а
// не два разных в зависимости от того, как DNS-ответ его закодировал.
void test_explicit_ipv4_allow_also_covers_ipv4_mapped_spelling() {
    NetworkPolicy::Config cfg;
    cfg.allow_cidrs = {"10.1.2.3/32"};
    NetworkPolicy policy(cfg);
    auto sin6 = make_v6("::ffff:10.1.2.3");
    TEST_CHECK(policy.is_address_allowed(
        reinterpret_cast<struct sockaddr const*>(&sin6)));
}

}  // namespace

int main() {
    RUN_TEST(test_default_policy_blocks_loopback_and_private);
    RUN_TEST(test_default_policy_allows_public_addresses);
    RUN_TEST(test_block_private_by_default_can_be_disabled);
    RUN_TEST(test_explicit_allow_overrides_default_deny);
    RUN_TEST(test_extra_deny_adds_to_default);
    RUN_TEST(test_port_allowlist_default_only_80);
    RUN_TEST(test_port_allowlist_configurable);
    RUN_TEST(test_cidr_range_parsing_rejects_garbage);
    RUN_TEST(test_ipv4_mapped_loopback_is_blocked);
    RUN_TEST(test_ipv4_mapped_cloud_metadata_is_blocked);
    RUN_TEST(test_ipv4_mapped_private_range_is_blocked);
    RUN_TEST(test_ipv4_compatible_loopback_is_blocked);
    RUN_TEST(test_6to4_embedded_loopback_is_blocked);
    RUN_TEST(test_ipv4_mapped_public_address_still_allowed);
    RUN_TEST(test_explicit_ipv4_allow_also_covers_ipv4_mapped_spelling);
    TEST_MAIN_EXIT();
}
