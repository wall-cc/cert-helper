// test_aia_extraction.cpp — юнит-тесты извлечения caIssuers URL из
// AIA-расширения сертификата. Использует тестовые сертификаты из
// ../test_certs/, сгенерированные openssl req -x509 с заданными
// authorityInfoAccess (см. test_certs/README.md).

#include <cstdio>
#include <fstream>
#include <vector>

#include "../src/aia.hpp"
#include "test_util.hpp"

namespace {

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "cannot open test fixture: %s\n", path.c_str());
        std::exit(1);
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::string fixture_path(const std::string& name) {
    // Тесты запускаются из build-директории — путь относительный к корню репозитория.
    return "../test_certs/" + name;
}

void test_extracts_ca_issuers_url_when_present() {
    auto der = read_file(fixture_path("leaf_with_aia.der"));
    auto url = cert_helper::aia::extract_ca_issuers_url_der(der);
    TEST_CHECK(url.has_value());
    TEST_CHECK_EQ(*url, std::string("http://ca.example.test/intermediate.cer"));
}

void test_returns_nullopt_when_no_aia_extension() {
    auto der = read_file(fixture_path("leaf_no_aia.der"));
    auto url = cert_helper::aia::extract_ca_issuers_url_der(der);
    TEST_CHECK(!url.has_value());
}

void test_returns_nullopt_when_aia_has_only_ocsp() {
    // AIA-расширение присутствует, но содержит только OCSP-запись, без
    // caIssuers — граничный случай, который легко перепутать с "AIA нет
    // вовсе" при небрежном парсинге.
    auto der = read_file(fixture_path("leaf_ocsp_only.der"));
    auto url = cert_helper::aia::extract_ca_issuers_url_der(der);
    TEST_CHECK(!url.has_value());
}

void test_handles_malformed_der_gracefully() {
    std::vector<uint8_t> garbage = {0x00, 0x01, 0x02, 0xFF, 0xFE};
    auto url = cert_helper::aia::extract_ca_issuers_url_der(garbage);
    TEST_CHECK(!url.has_value()); // не должно бросать исключение или падать
}

void test_handles_empty_input() {
    std::vector<uint8_t> empty;
    auto url = cert_helper::aia::extract_ca_issuers_url_der(empty);
    TEST_CHECK(!url.has_value());
}

} // namespace

int main() {
    RUN_TEST(test_extracts_ca_issuers_url_when_present);
    RUN_TEST(test_returns_nullopt_when_no_aia_extension);
    RUN_TEST(test_returns_nullopt_when_aia_has_only_ocsp);
    RUN_TEST(test_handles_malformed_der_gracefully);
    RUN_TEST(test_handles_empty_input);
    TEST_MAIN_EXIT();
}
