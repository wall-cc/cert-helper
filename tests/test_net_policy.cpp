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

struct sockaddr_in make_v4(const char* ip) {
    struct sockaddr_in sin{};
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sin.sin_addr);
    return sin;
}

struct sockaddr_in6 make_v6(const char* ip) {
    struct sockaddr_in6 sin6{};
    sin6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &sin6.sin6_addr);
    return sin6;
}

bool allowed_v4(const NetworkPolicy& policy, const char* ip) {
    auto sin = make_v4(ip);
    return policy.is_address_allowed(reinterpret_cast<const struct sockaddr*>(&sin));
}

bool allowed_v6(const NetworkPolicy& policy, const char* ip) {
    auto sin6 = make_v6(ip);
    return policy.is_address_allowed(reinterpret_cast<const struct sockaddr*>(&sin6));
}

void test_default_policy_blocks_loopback_and_private() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    TEST_CHECK(!allowed_v4(policy, "127.0.0.1"));
    TEST_CHECK(!allowed_v4(policy, "10.1.2.3"));
    TEST_CHECK(!allowed_v4(policy, "172.16.0.5"));
    TEST_CHECK(!allowed_v4(policy, "192.168.1.1"));
    TEST_CHECK(!allowed_v4(policy, "169.254.169.254")); // cloud metadata endpoint
    TEST_CHECK(!allowed_v4(policy, "100.64.0.1"));       // CGNAT
    TEST_CHECK(!allowed_v6(policy, "::1"));
    TEST_CHECK(!allowed_v6(policy, "fe80::1"));
    TEST_CHECK(!allowed_v6(policy, "fc00::1"));
}

void test_default_policy_allows_public_addresses() {
    NetworkPolicy policy(NetworkPolicy::Config{});
    TEST_CHECK(allowed_v4(policy, "8.8.8.8"));
    TEST_CHECK(allowed_v4(policy, "93.184.216.34")); // example.com-ish public range
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
    TEST_CHECK(allowed_v4(policy, "10.5.1.1"));  // явно разрешённая подсеть внутри 10.0.0.0/8
    TEST_CHECK(!allowed_v4(policy, "10.6.1.1")); // остальной 10.0.0.0/8 всё ещё заблокирован
}

void test_extra_deny_adds_to_default() {
    NetworkPolicy::Config cfg;
    cfg.extra_deny_cidrs = {"8.8.8.0/24"};
    NetworkPolicy policy(cfg);
    TEST_CHECK(!allowed_v4(policy, "8.8.8.8"));  // заблокирован дополнительным правилом
    TEST_CHECK(allowed_v4(policy, "8.8.4.4"));   // соседний публичный адрес всё ещё разрешён
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
    TEST_CHECK(!CidrRange::parse("10.0.0.0/33").has_value()); // некорректная длина префикса для v4
    TEST_CHECK(!CidrRange::parse("::1/129").has_value());     // некорректная длина префикса для v6
    TEST_CHECK(CidrRange::parse("10.0.0.0/8").has_value());
    TEST_CHECK(CidrRange::parse("::1/128").has_value());
}

} // namespace

int main() {
    RUN_TEST(test_default_policy_blocks_loopback_and_private);
    RUN_TEST(test_default_policy_allows_public_addresses);
    RUN_TEST(test_block_private_by_default_can_be_disabled);
    RUN_TEST(test_explicit_allow_overrides_default_deny);
    RUN_TEST(test_extra_deny_adds_to_default);
    RUN_TEST(test_port_allowlist_default_only_80);
    RUN_TEST(test_port_allowlist_configurable);
    RUN_TEST(test_cidr_range_parsing_rejects_garbage);
    TEST_MAIN_EXIT();
}
