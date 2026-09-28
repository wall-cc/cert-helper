// test_util.hpp
//
// Минимальная замена тестового фреймворка: не тянем gtest как зависимость
// ради нескольких десятков ASSERT'ов в юнит-тестах демона. Если проект
// вырастет — переезд на gtest/catch2 тривиален, т.к. это единственное
// место, которое пришлось бы менять.

#pragma once

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace test_util {

inline int& failure_count() {
    static int count = 0;
    return count;
}

inline void report_failure(const std::string& expr, const char* file, int line) {
    std::fprintf(stderr, "FAIL: %s (%s:%d)\n", expr.c_str(), file, line);
    ++failure_count();
}

inline void report_pass(const std::string& name) {
    std::fprintf(stdout, "PASS: %s\n", name.c_str());
}

// Генерирует самоподписанный сертификат со сроком действия ОТНОСИТЕЛЬНО
// текущего момента (not_before_days_offset/not_after_days_offset — сдвиг
// в сутках от "сейчас", может быть отрицательным).
//
// ПОЧЕМУ ЭТО ЖИВЁТ ЗДЕСЬ, А НЕ КАК СТАТИЧЕСКАЯ ФИКСТУРА В test_certs/:
// несколько фикстур в test_certs/ (leaf_expires_soon.der,
// leaf_already_expired.der) были сгенерированы СТАТИЧЕСКИ с датами
// "относительно момента генерации" (например, "+2 дня от того момента,
// когда я это сгенерировал") — и с каждой новой рабочей сессией,
// разделённой реальными днями, эти фикстуры естественным образом СТАРЕЮТ
// и в какой-то момент перестают быть "скоро истекающими" или становятся
// "уже истёкшими не в том смысле, что было задумано". Это уже дважды
// приводило к ложным падениям тестов между сессиями (не баг в коде,
// баг в дизайне фикстуры). Для тестов, которым нужен сертификат с
// валидностью ОТНОСИТЕЛЬНО момента запуска теста — как раз этот случай —
// правильное решение: генерировать его in-process при каждом запуске
// через OpenSSL C API напрямую (без внешних зависимостей вроде Python),
// а не полагаться на статический файл с датами, вычисленными когда-то в
// прошлом.
inline std::vector<uint8_t> generate_self_signed_cert_der(const std::string& common_name,
                                                            int not_before_days_offset,
                                                            int not_after_days_offset) {
    EVP_PKEY* pkey = EVP_RSA_gen(2048); // OpenSSL 3.0+ non-deprecated one-shot keygen

    X509* cert = X509_new();
    X509_set_version(cert, 2); // X.509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 60L * 60 * 24 * not_before_days_offset);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60 * 24 * not_after_days_offset);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>(common_name.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, name); // самоподписанный — issuer == subject

    X509_sign(cert, pkey, EVP_sha256());

    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    std::vector<uint8_t> result(der, der + len);
    OPENSSL_free(der);

    X509_free(cert);
    EVP_PKEY_free(pkey);
    return result;
}

// Генерирует фикстуры для теста батчинга OCSP-запросов (ROADMAP.md,
// раздел 2, пункт 14): два ОДИНОЧНЫХ OCSP-запроса для двух разных
// сертификатов (разные CertID) к одному условному responder'у, и ОДИН
// комбинированный ответ (OCSP_BASICRESP с ДВУМЯ SingleResponse,
// подписанный целиком) — ровно то, что реальный responder вернул бы на
// комбинированный запрос с двумя Request.
//
// ПОЧЕМУ ЭТО ГЕНЕРИРУЕТСЯ ЗДЕСЬ, А НЕ КАК СТАТИЧЕСКАЯ ФИКСТУРА В
// test_certs/: как и generate_self_signed_cert_der() выше — nextUpdate
// в этой фикстуре осмыслен только ОТНОСИТЕЛЬНО момента генерации
// (тест проверяет, что TTL в кэше соответствует "часам до nextUpdate"),
// а статический файл с такими датами неизбежно стареет между рабочими
// сессиями, разделёнными реальными часами/днями (см. подробное
// объяснение у generate_self_signed_cert_der() — эта же проблема уже
// дважды проявлялась для других фикстур). Изначально эта фикстура была
// сгенерирована статически через отдельный C++-скрипт и закоммичена в
// test_certs/ — и, как и предсказывалось, тест на её основе тоже
// сломался спустя часы реального времени. Перенесено на генерацию at
// runtime по тому же принципу.
//
// ПОЧЕМУ НЕ ЧЕРЕЗ Python `cryptography`, как большинство фикстур в
// test_certs/: `cryptography.x509.ocsp.OCSPResponseBuilder` на уровне
// библиотеки запрещает несколько add_response() на один билдер
// ("Only one response per OCSPResponse"), хотя RFC 6960 разрешает
// несколько SingleResponse в одном ответе — поэтому используется
// OpenSSL C API напрямую (OCSP_basic_add1_status() дважды на один
// OCSP_BASICRESP, один OCSP_basic_sign() на весь объединённый блок).
struct OcspBatchFixtures {
    std::vector<uint8_t> request_a;
    std::vector<uint8_t> request_b;
    std::vector<uint8_t> combined_response;
};

inline OcspBatchFixtures generate_ocsp_batch_fixtures(int next_update_a_hours_offset,
                                                       int next_update_b_hours_offset) {
    auto gen_key = [] { return EVP_RSA_gen(2048); };
    auto make_cert = [](const char* cn, X509* issuer_cert, EVP_PKEY* issuer_key, EVP_PKEY* subject_key,
                        long serial, int not_before_days, int not_after_days, bool is_ca) {
        X509* cert = X509_new();
        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
        X509_gmtime_adj(X509_getm_notBefore(cert), 60L * 60 * 24 * not_before_days);
        X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60 * 24 * not_after_days);
        X509_set_pubkey(cert, subject_key);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
        X509_set_issuer_name(cert, issuer_cert ? X509_get_subject_name(issuer_cert) : name);
        if (is_ca) {
            X509_EXTENSION* ext =
                X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        X509_sign(cert, issuer_key ? issuer_key : subject_key, EVP_sha256());
        return cert;
    };

    EVP_PKEY* ca_key = gen_key();
    X509* ca_cert = make_cert("test-issuer-ocsp-batch.example.test", nullptr, ca_key, ca_key, 1, -1, 3650, true);
    EVP_PKEY* leaf_a_key = gen_key();
    X509* leaf_a = make_cert("leaf-ocsp-batch-a.example.test", ca_cert, ca_key, leaf_a_key, 100, -1, 365, false);
    EVP_PKEY* leaf_b_key = gen_key();
    X509* leaf_b = make_cert("leaf-ocsp-batch-b.example.test", ca_cert, ca_key, leaf_b_key, 101, -1, 365, false);

    OCSP_CERTID* certid_a = OCSP_cert_to_id(EVP_sha1(), leaf_a, ca_cert);
    OCSP_CERTID* certid_b = OCSP_cert_to_id(EVP_sha1(), leaf_b, ca_cert);

    OcspBatchFixtures out;

    OCSP_REQUEST* req_a = OCSP_REQUEST_new();
    OCSP_request_add0_id(req_a, OCSP_CERTID_dup(certid_a));
    {
        unsigned char* der = nullptr;
        int len = i2d_OCSP_REQUEST(req_a, &der);
        out.request_a.assign(der, der + len);
        OPENSSL_free(der);
    }
    OCSP_REQUEST_free(req_a);

    OCSP_REQUEST* req_b = OCSP_REQUEST_new();
    OCSP_request_add0_id(req_b, OCSP_CERTID_dup(certid_b));
    {
        unsigned char* der = nullptr;
        int len = i2d_OCSP_REQUEST(req_b, &der);
        out.request_b.assign(der, der + len);
        OPENSSL_free(der);
    }
    OCSP_REQUEST_free(req_b);

    OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
    ASN1_TIME* this_update = ASN1_TIME_adj(nullptr, time(nullptr), 0, 0);
    ASN1_TIME* next_update_a = ASN1_TIME_adj(nullptr, time(nullptr), 0, 60 * 60 * next_update_a_hours_offset);
    ASN1_TIME* next_update_b = ASN1_TIME_adj(nullptr, time(nullptr), 0, 60 * 60 * next_update_b_hours_offset);
    OCSP_basic_add1_status(basic, certid_a, V_OCSP_CERTSTATUS_GOOD, 0, nullptr, this_update, next_update_a);
    OCSP_basic_add1_status(basic, certid_b, V_OCSP_CERTSTATUS_GOOD, 0, nullptr, this_update, next_update_b);
    OCSP_basic_sign(basic, ca_cert, ca_key, EVP_sha256(), nullptr, 0);
    OCSP_RESPONSE* ocsp_resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    {
        unsigned char* der = nullptr;
        int len = i2d_OCSP_RESPONSE(ocsp_resp, &der);
        out.combined_response.assign(der, der + len);
        OPENSSL_free(der);
    }

    ASN1_TIME_free(this_update);
    ASN1_TIME_free(next_update_a);
    ASN1_TIME_free(next_update_b);
    OCSP_RESPONSE_free(ocsp_resp);
    OCSP_BASICRESP_free(basic);
    OCSP_CERTID_free(certid_a);
    OCSP_CERTID_free(certid_b);
    X509_free(leaf_a);
    X509_free(leaf_b);
    X509_free(ca_cert);
    EVP_PKEY_free(leaf_a_key);
    EVP_PKEY_free(leaf_b_key);
    EVP_PKEY_free(ca_key);

    return out;
}

} // namespace test_util

#define TEST_CHECK(cond)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            test_util::report_failure(#cond, __FILE__, __LINE__);               \
        }                                                                       \
    } while (0)

#define TEST_CHECK_EQ(a, b)                                                     \
    do {                                                                        \
        auto va = (a);                                                         \
        auto vb = (b);                                                         \
        if (!(va == vb)) {                                                      \
            std::ostringstream oss;                                             \
            oss << #a " == " #b " (got " << va << " vs " << vb << ")";          \
            test_util::report_failure(oss.str(), __FILE__, __LINE__);           \
        }                                                                       \
    } while (0)

#define RUN_TEST(fn)                                                            \
    do {                                                                        \
        fn();                                                                   \
        test_util::report_pass(#fn);                                            \
    } while (0)

#define TEST_MAIN_EXIT()                                                        \
    return test_util::failure_count() == 0 ? 0 : 1
