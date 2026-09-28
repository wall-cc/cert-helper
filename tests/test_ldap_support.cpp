// test_ldap_support.cpp — тесты поддержки ldap:// для CRL (ROADMAP.md,
// раздел 1, пункт 9).
//
// ВАЖНО про методологию проверки корректности протокола: перед тем, как
// писать этот файл, реализация SimpleLdapFetcher была вручную проверена
// в реальном сеансе разработки против НАСТОЯЩЕГО OpenLDAP-сервера
// (`slapd` из пакета Ubuntu `slapd`/`ldap-utils`) — создана тестовая
// база (`dc=example,dc=test`), в неё через `ldapadd` добавлена запись с
// атрибутом `certificateRevocationList;binary`, после чего
// `SimpleLdapFetcher::fetch()` выполнил anonymous bind + baseObject
// search и получил ЗНАЧЕНИЕ, побайтово совпадающее с оригинальным CRL
// DER (`cmp` подтвердил идентичность). Отдельно проверены: equality- и
// AND-фильтры (совпадающие и несовпадающие), запрос несуществующего DN
// (resultCode=32 noSuchObject), запрос отсутствующего атрибута — во всех
// случаях поведение соответствовало ожиданиям резюме выше.
//
// Этот тестовый файл, в отличие от той разовой ручной проверки,
// поднимает лёгкий встроенный C++ "поддельный" LDAP-сервер
// (OneShotLdapServer ниже) — чтобы автоматический прогон тестов не
// зависел от установленного в окружении `slapd` (не входит в основные
// зависимости сборки cert-helper). Он использует низкоуровневые
// BER-примитивы из ldap_client.hpp (encode_tlv/encode_integer/...) — это
// общие, простые, не специфичные для LDAP функции кодирования TLV, а не
// протокольную логику SimpleLdapFetcher (bind/search составляются здесь
// заново, независимо от do_bind()/do_search() клиента), так что тест
// остаётся содержательной проверкой протокола, а не тавтологией.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/ldap_client.hpp"
#include "../src/net_policy.hpp"
#include "test_util.hpp"

using namespace cert_helper::ldap;
using namespace cert_helper::net;

namespace {

enum class Scenario {
    kSuccess,
    kBindFails,
    kSearchNoSuchObject,
    kSearchEntryWithoutAttr,
    kMalformedBer,
};

class OneShotLdapServer {
public:
    OneShotLdapServer(Scenario scenario, std::string attribute_name, std::vector<uint8_t> attribute_value)
        : scenario_(scenario), attribute_name_(std::move(attribute_name)),
          attribute_value_(std::move(attribute_value)) {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

        socklen_t addr_len = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), &addr_len);
        listening_port = ntohs(addr.sin_port);

        listen(listen_fd, 1);

        server_thread = std::thread([this] { run(); });
    }

    ~OneShotLdapServer() {
        if (server_thread.joinable()) server_thread.join();
        ::close(listen_fd);
    }

    uint16_t port() const { return listening_port; }

private:
    void run() {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_fd, &read_fds);
        struct timeval tv{};
        tv.tv_sec = 2;
        int sel = select(listen_fd + 1, &read_fds, nullptr, nullptr, &tv);
        if (sel <= 0) return;

        int fd = accept(listen_fd, nullptr, nullptr);
        if (fd < 0) return;

        if (scenario_ == Scenario::kMalformedBer) {
            std::vector<uint8_t> garbage = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            ::send(fd, garbage.data(), garbage.size(), 0);
            ::close(fd);
            return;
        }

        auto bind_req = recv_one_message(fd);
        if (!bind_req) {
            ::close(fd);
            return;
        }
        bool bind_ok = (scenario_ != Scenario::kBindFails);
        auto bind_resp = make_ldap_result_message(1, 0x61, bind_ok ? 0 : 49);
        ::send(fd, bind_resp.data(), bind_resp.size(), 0);
        if (!bind_ok) {
            ::close(fd);
            return;
        }

        auto search_req = recv_one_message(fd);
        if (!search_req) {
            ::close(fd);
            return;
        }

        if (scenario_ == Scenario::kSearchNoSuchObject) {
            auto done = make_ldap_result_message(2, 0x65, 32);
            ::send(fd, done.data(), done.size(), 0);
            ::close(fd);
            return;
        }

        std::string sent_attr_name =
            (scenario_ == Scenario::kSearchEntryWithoutAttr) ? "someOtherAttribute" : attribute_name_;
        auto entry =
            make_search_result_entry(2, "cn=Test,dc=example,dc=test", sent_attr_name, attribute_value_);
        ::send(fd, entry.data(), entry.size(), 0);
        auto done = make_ldap_result_message(2, 0x65, 0);
        ::send(fd, done.data(), done.size(), 0);
        ::close(fd);
    }

    static std::optional<std::vector<uint8_t>> recv_one_message(int fd) {
        std::vector<uint8_t> buffer;
        while (true) {
            size_t consumed = 0;
            bool malformed = false;
            auto tlv = ber::try_read_tlv(buffer, 0, consumed, malformed);
            if (malformed) return std::nullopt;
            if (tlv) return std::vector<uint8_t>(buffer.begin(), buffer.begin() + consumed);
            char chunk[4096];
            ssize_t r = ::recv(fd, chunk, sizeof(chunk), 0);
            if (r <= 0) return std::nullopt;
            buffer.insert(buffer.end(), chunk, chunk + r);
        }
    }

    static std::vector<uint8_t> make_ldap_result_message(int64_t message_id, uint8_t op_tag,
                                                            int result_code) {
        auto op_body = ber::concat({
            ber::encode_enumerated(result_code),
            ber::encode_octet_string(""),
            ber::encode_octet_string(""),
        });
        auto op = ber::encode_tlv(op_tag, op_body);
        return ber::encode_sequence(ber::concat({ber::encode_integer(message_id), op}));
    }

    static std::vector<uint8_t> make_search_result_entry(int64_t message_id, const std::string& dn,
                                                            const std::string& attr_name,
                                                            const std::vector<uint8_t>& attr_value) {
        auto value_tlv = ber::encode_tlv(ber::kTagOctetString, attr_value);
        auto vals_set = ber::encode_tlv(ber::kTagSet, value_tlv);
        auto partial_attr =
            ber::encode_sequence(ber::concat({ber::encode_octet_string(attr_name), vals_set}));
        auto attributes_seq = ber::encode_sequence(partial_attr);
        auto entry_body = ber::concat({ber::encode_octet_string(dn), attributes_seq});
        constexpr uint8_t kTagSearchResultEntry = 0x64;
        auto op = ber::encode_tlv(kTagSearchResultEntry, entry_body);
        return ber::encode_sequence(ber::concat({ber::encode_integer(message_id), op}));
    }

    Scenario scenario_;
    std::string attribute_name_;
    std::vector<uint8_t> attribute_value_;
    int listen_fd = -1;
    uint16_t listening_port = 0;
    std::thread server_thread;
};

NetworkPolicy make_permissive_policy(uint16_t port) {
    NetworkPolicy::Config cfg;
    cfg.block_private_by_default = false;
    cfg.allowed_ports = {port};
    return NetworkPolicy(cfg);
}

void test_parses_typical_cdp_ldap_url() {
    auto u = parse_ldap_url(
        "ldap://dc1.example.test:389/CN=CRL1,CN=exampleCA,CN=CDP,CN=Public%20Key%20Services,"
        "CN=Services,CN=Configuration,DC=example,DC=test?certificateRevocationList;binary");
    TEST_CHECK(u.has_value());
    if (!u) return;
    TEST_CHECK_EQ(u->host, std::string("dc1.example.test"));
    TEST_CHECK_EQ(static_cast<int>(u->port), 389);
    TEST_CHECK(u->dn.find("Public Key Services") != std::string::npos);
    TEST_CHECK_EQ(u->attributes.size(), size_t{1});
    TEST_CHECK_EQ(u->attributes[0], std::string("certificateRevocationList;binary"));
    TEST_CHECK_EQ(u->filter, std::string("(objectClass=*)"));
}

void test_rejects_empty_host_url() {
    TEST_CHECK(!parse_ldap_url("ldap:///CN=x,DC=example,DC=test").has_value());
}

void test_rejects_non_ldap_scheme() { TEST_CHECK(!parse_ldap_url("http://example.test/").has_value()); }

void test_filter_rejects_unsupported_constructs() {
    TEST_CHECK(!filter::encode_top_level("(cn>=foo)").has_value());
    TEST_CHECK(!filter::encode_top_level("(cn=foo*bar)").has_value());
    TEST_CHECK(filter::encode_top_level("(objectClass=*)").has_value());
    TEST_CHECK(filter::encode_top_level("(&(a=1)(b=2))").has_value());
}

void test_fetches_attribute_value_on_success() {
    std::vector<uint8_t> crl_der = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03};
    OneShotLdapServer server(Scenario::kSuccess, "certificateRevocationList;binary", crl_der);

    SimpleLdapFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "ldap://127.0.0.1:" + std::to_string(server.port()) +
                       "/cn=Test,dc=example,dc=test?certificateRevocationList;binary";
    auto result = fetcher.fetch(url, "certificateRevocationList;binary", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(result.value == crl_der);
}

void test_attribute_name_matching_is_case_and_option_insensitive() {
    std::vector<uint8_t> crl_der = {0x01, 0x02, 0x03};
    OneShotLdapServer server(Scenario::kSuccess, "CertificateRevocationList", crl_der);

    SimpleLdapFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "ldap://127.0.0.1:" + std::to_string(server.port()) + "/cn=Test,dc=example,dc=test";
    auto result = fetcher.fetch(url, "certificateRevocationList;binary", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(result.value == crl_der);
}

void test_bind_failure_results_in_not_ok() {
    OneShotLdapServer server(Scenario::kBindFails, "certificateRevocationList;binary", {1, 2, 3});
    SimpleLdapFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "ldap://127.0.0.1:" + std::to_string(server.port()) + "/cn=Test,dc=example,dc=test";
    auto result = fetcher.fetch(url, "certificateRevocationList;binary", 2000, 1024 * 1024);
    TEST_CHECK(!result.ok);
}

void test_no_such_object_results_in_not_ok() {
    OneShotLdapServer server(Scenario::kSearchNoSuchObject, "certificateRevocationList;binary", {});
    SimpleLdapFetcher fetcher(make_permissive_policy(server.port()));
    std::string url =
        "ldap://127.0.0.1:" + std::to_string(server.port()) + "/cn=NoSuchThing,dc=example,dc=test";
    auto result = fetcher.fetch(url, "certificateRevocationList;binary", 2000, 1024 * 1024);
    TEST_CHECK(!result.ok);
}

void test_entry_without_requested_attribute_results_in_not_ok() {
    OneShotLdapServer server(Scenario::kSearchEntryWithoutAttr, "certificateRevocationList;binary",
                              {1, 2, 3});
    SimpleLdapFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "ldap://127.0.0.1:" + std::to_string(server.port()) + "/cn=Test,dc=example,dc=test";
    auto result = fetcher.fetch(url, "certificateRevocationList;binary", 2000, 1024 * 1024);
    TEST_CHECK(!result.ok);
}

void test_malformed_ber_from_server_results_in_not_ok() {
    OneShotLdapServer server(Scenario::kMalformedBer, "certificateRevocationList;binary", {});
    SimpleLdapFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "ldap://127.0.0.1:" + std::to_string(server.port()) + "/cn=Test,dc=example,dc=test";
    auto result = fetcher.fetch(url, "certificateRevocationList;binary", 2000, 1024 * 1024);
    TEST_CHECK(!result.ok);
}

} // namespace

int main() {
    RUN_TEST(test_parses_typical_cdp_ldap_url);
    RUN_TEST(test_rejects_empty_host_url);
    RUN_TEST(test_rejects_non_ldap_scheme);
    RUN_TEST(test_filter_rejects_unsupported_constructs);
    RUN_TEST(test_fetches_attribute_value_on_success);
    RUN_TEST(test_attribute_name_matching_is_case_and_option_insensitive);
    RUN_TEST(test_bind_failure_results_in_not_ok);
    RUN_TEST(test_no_such_object_results_in_not_ok);
    RUN_TEST(test_entry_without_requested_attribute_results_in_not_ok);
    RUN_TEST(test_malformed_ber_from_server_results_in_not_ok);
    TEST_MAIN_EXIT();
}
