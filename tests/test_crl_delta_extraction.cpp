// test_crl_delta_extraction.cpp — юнит-тесты извлечения расширений,
// связанных с Delta CRL (ROADMAP.md, раздел 1, пункт 8): freshestCRL
// (на сертификате и на полном CRL) и deltaCRLIndicator (на самой delta
// CRL). Использует тестовые фикстуры из ../test_certs/, сгенерированные
// через Python cryptography (см. test_certs/README.md).

#include <cstdio>
#include <fstream>
#include <vector>

#include "../src/crl_delta.hpp"
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

// --- freshestCRL на полном CRL ---

void test_extracts_freshest_crl_url_from_crl_when_present() {
    auto der = read_file(fixture_path("crl_with_freshest_crl_ext.der"));
    auto url = cert_helper::crl::extract_freshest_crl_url_from_crl_der(der);
    TEST_CHECK(url.has_value());
    TEST_CHECK_EQ(*url, std::string("http://crl.example.test/delta.crl"));
}

void test_returns_nullopt_when_crl_has_no_freshest_crl_extension() {
    // crl_far_future.der (см. test_certs/README.md, пункт 2) — обычный
    // полный CRL без расширений, связанных с delta CRL вообще.
    auto der = read_file(fixture_path("crl_far_future.der"));
    auto url = cert_helper::crl::extract_freshest_crl_url_from_crl_der(der);
    TEST_CHECK(!url.has_value());
}

// --- freshestCRL на сертификате (альтернативное место по RFC 5280) ---

void test_extracts_freshest_crl_url_from_cert_when_present() {
    auto der = read_file(fixture_path("leaf_with_freshest_crl.der"));
    auto url = cert_helper::crl::extract_freshest_crl_url_from_cert_der(der);
    TEST_CHECK(url.has_value());
    TEST_CHECK_EQ(*url, std::string("http://crl.example.test/delta.crl"));
}

void test_returns_nullopt_when_cert_has_no_freshest_crl_extension() {
    auto der = read_file(fixture_path("leaf_no_aia.der"));
    auto url = cert_helper::crl::extract_freshest_crl_url_from_cert_der(der);
    TEST_CHECK(!url.has_value());
}

// --- deltaCRLIndicator (подтверждение, что CRL действительно delta) ---

void test_extracts_base_crl_number_from_delta_crl() {
    auto der = read_file(fixture_path("delta_crl.der"));
    auto base_number = cert_helper::crl::extract_delta_crl_base_number_der(der);
    TEST_CHECK(base_number.has_value());
    TEST_CHECK_EQ(*base_number, int64_t{42});
}

void test_returns_nullopt_for_full_crl_without_delta_indicator() {
    // Полный CRL (не delta) не должен ошибочно распознаваться как delta —
    // это ключевая проверка перед тем, как применять скачанный CRL как
    // delta поверх уже имеющегося полного.
    auto der = read_file(fixture_path("crl_far_future.der"));
    auto base_number = cert_helper::crl::extract_delta_crl_base_number_der(der);
    TEST_CHECK(!base_number.has_value());
}

// --- устойчивость к некорректному вводу ---

void test_handles_malformed_der_gracefully() {
    std::vector<uint8_t> garbage = {0x00, 0x01, 0x02, 0xFF, 0xFE};
    TEST_CHECK(!cert_helper::crl::extract_freshest_crl_url_from_crl_der(garbage).has_value());
    TEST_CHECK(!cert_helper::crl::extract_freshest_crl_url_from_cert_der(garbage).has_value());
    TEST_CHECK(!cert_helper::crl::extract_delta_crl_base_number_der(garbage).has_value());
}

void test_handles_empty_input() {
    std::vector<uint8_t> empty;
    TEST_CHECK(!cert_helper::crl::extract_freshest_crl_url_from_crl_der(empty).has_value());
    TEST_CHECK(!cert_helper::crl::extract_freshest_crl_url_from_cert_der(empty).has_value());
    TEST_CHECK(!cert_helper::crl::extract_delta_crl_base_number_der(empty).has_value());
}

} // namespace

int main() {
    RUN_TEST(test_extracts_freshest_crl_url_from_crl_when_present);
    RUN_TEST(test_returns_nullopt_when_crl_has_no_freshest_crl_extension);
    RUN_TEST(test_extracts_freshest_crl_url_from_cert_when_present);
    RUN_TEST(test_returns_nullopt_when_cert_has_no_freshest_crl_extension);
    RUN_TEST(test_extracts_base_crl_number_from_delta_crl);
    RUN_TEST(test_returns_nullopt_for_full_crl_without_delta_indicator);
    RUN_TEST(test_handles_malformed_der_gracefully);
    RUN_TEST(test_handles_empty_input);
    TEST_MAIN_EXIT();
}
