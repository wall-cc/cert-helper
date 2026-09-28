// crl_delta.hpp
//
// ROADMAP.md, раздел 1, пункт 8: разбор ASN.1-расширений, связанных с
// Delta CRL (RFC 5280 §5.2.4 и §4.2.1.15).
//
// ВАЖНО — что именно закрывает этот пункт, и что НЕ требуется менять:
// докачка delta-CRL по HTTP — это буквально то же самое, что докачка
// обычного (полного) CRL: GET по URL, разбор X509_CRL, TTL по nextUpdate,
// кэш по URL, лимит размера ответа. RequestRouter::handle_crl() (и
// протокольный FetchCrlRequest/FetchResponse) уже умеют это без единого
// изменения — отдельный "FetchDeltaCrl"-путь не нужен: с точки зрения
// HTTP-докачки delta-CRL от обычного CRL неотличим. Единственное, чего
// раньше не хватало — это способа НАЙТИ URL delta-CRL (разбор расширения
// freshestCRL) и УБЕДИТЬСЯ, что скачанный по этому URL CRL действительно
// является delta (расширение deltaCRLIndicator), а не, скажем, обычным
// полным CRL, случайно оказавшимся по тому же URL.
//
// По аналогии с aia.hpp (та же логика для caIssuers URL сертификата):
// функции здесь — самостоятельные, тестируемые утилиты разбора ASN.1,
// доступные для переиспользования вызывающей стороной (tls-mitm), а не
// часть основного пути RequestRouter — ровно так же, как
// extract_ca_issuers_url() не встроена в handle_intermediate_cert_impl()
// (URL туда приходит уже готовым в самом запросе). Реальный поток
// использования: tls-mitm скачивает полный CRL через fetch_crl(cdp_url),
// парсит его через extract_freshest_crl_url_from_crl_der(), при наличии
// URL — докачивает delta тем же самым fetch_crl(delta_url), затем
// опционально проверяет через extract_delta_crl_base_number_der(), что
// это действительно delta CRL, и на какой BaseCRLNumber он ссылается,
// прежде чем применять его поверх уже имеющегося полного CRL.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace cert_helper::crl {

namespace detail {

// Общая логика для freshestCRL (id-ce-freshestCRL, RFC 5280 §4.2.1.15) —
// расширение имеет тот же ASN.1-тип (CRL_DIST_POINTS), что и обычный
// cRLDistributionPoints, и может встречаться как на сертификате, так и на
// самом (полном) CRL. Возвращает первый найденный URI среди fullName
// GENERAL_NAME-записей типа GEN_URI — как и в aia.hpp, теоретически
// возможны и другие типы имён (relativeName, DN и т.д.), в проде
// встречаются только URI, остальные пропускаются, а не считаются ошибкой.
inline std::optional<std::string> first_uri_from_dist_points(CRL_DIST_POINTS* dist_points) {
    if (dist_points == nullptr) return std::nullopt;

    std::optional<std::string> result;
    int count = sk_DIST_POINT_num(dist_points);
    for (int i = 0; i < count && !result; ++i) {
        DIST_POINT* dp = sk_DIST_POINT_value(dist_points, i);
        if (dp == nullptr || dp->distpoint == nullptr) continue;
        if (dp->distpoint->type != 0) continue; // 0 == fullName (GENERAL_NAMES); пропускаем relativeName
        GENERAL_NAMES* names = dp->distpoint->name.fullname;
        if (names == nullptr) continue;

        int name_count = sk_GENERAL_NAME_num(names);
        for (int j = 0; j < name_count; ++j) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(names, j);
            if (name == nullptr || name->type != GEN_URI) continue;
            const ASN1_IA5STRING* uri = name->d.uniformResourceIdentifier;
            if (uri == nullptr || uri->data == nullptr || uri->length <= 0) continue;
            result = std::string(reinterpret_cast<const char*>(uri->data),
                                  static_cast<size_t>(uri->length));
            break;
        }
    }
    return result;
}

} // namespace detail

// --- freshestCRL на СЕРТИФИКАТЕ (альтернативное место размещения по RFC
// 5280 — позволяет обнаружить delta-CRL, не скачивая сначала базовый CRL
// целиком). ---
inline std::optional<std::string> extract_freshest_crl_url_from_cert(X509* cert) {
    if (cert == nullptr) return std::nullopt;
    auto* dist_points =
        static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(cert, NID_freshest_crl, nullptr, nullptr));
    auto result = detail::first_uri_from_dist_points(dist_points);
    if (dist_points) sk_DIST_POINT_pop_free(dist_points, DIST_POINT_free);
    return result;
}

inline std::optional<std::string> extract_freshest_crl_url_from_cert_der(
    const std::vector<uint8_t>& cert_der) {
    if (cert_der.empty()) return std::nullopt;
    const unsigned char* p = cert_der.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()));
    if (cert == nullptr) return std::nullopt;
    auto result = extract_freshest_crl_url_from_cert(cert);
    X509_free(cert);
    return result;
}

// --- freshestCRL на самом (полном) CRL — типичное место в реальных PKI:
// CA публикует его прямо в базовом CRL, который клиент и так скачал. ---
inline std::optional<std::string> extract_freshest_crl_url_from_crl(X509_CRL* crl) {
    if (crl == nullptr) return std::nullopt;
    auto* dist_points = static_cast<CRL_DIST_POINTS*>(
        X509_CRL_get_ext_d2i(crl, NID_freshest_crl, nullptr, nullptr));
    auto result = detail::first_uri_from_dist_points(dist_points);
    if (dist_points) sk_DIST_POINT_pop_free(dist_points, DIST_POINT_free);
    return result;
}

inline std::optional<std::string> extract_freshest_crl_url_from_crl_der(
    const std::vector<uint8_t>& crl_der) {
    if (crl_der.empty()) return std::nullopt;
    const unsigned char* p = crl_der.data();
    X509_CRL* crl = d2i_X509_CRL(nullptr, &p, static_cast<long>(crl_der.size()));
    if (crl == nullptr) return std::nullopt;
    auto result = extract_freshest_crl_url_from_crl(crl);
    X509_CRL_free(crl);
    return result;
}

// --- Delta CRL Indicator (id-ce-deltaCRLIndicator, RFC 5280 §5.2.4) ---
// Присутствует ТОЛЬКО в самой delta CRL (не в базовом CRL и не в
// сертификате) и содержит номер БАЗОВОГО CRL (BaseCRLNumber), на который
// эта delta ссылается. Отсутствие расширения означает "это обычный
// полный CRL, а не delta" — не ошибка, а содержательный ответ (nullopt),
// который вызывающей стороне стоит явно проверить перед тем, как
// применять скачанный CRL как delta поверх уже имеющегося полного.
inline std::optional<int64_t> extract_delta_crl_base_number(X509_CRL* crl) {
    if (crl == nullptr) return std::nullopt;
    auto* base_number =
        static_cast<ASN1_INTEGER*>(X509_CRL_get_ext_d2i(crl, NID_delta_crl, nullptr, nullptr));
    if (base_number == nullptr) return std::nullopt;

    int64_t value = 0;
    bool ok = (ASN1_INTEGER_get_int64(&value, base_number) == 1);
    ASN1_INTEGER_free(base_number);
    if (!ok) return std::nullopt;
    return value;
}

inline std::optional<int64_t> extract_delta_crl_base_number_der(const std::vector<uint8_t>& crl_der) {
    if (crl_der.empty()) return std::nullopt;
    const unsigned char* p = crl_der.data();
    X509_CRL* crl = d2i_X509_CRL(nullptr, &p, static_cast<long>(crl_der.size()));
    if (crl == nullptr) return std::nullopt;
    auto result = extract_delta_crl_base_number(crl);
    X509_CRL_free(crl);
    return result;
}

} // namespace cert_helper::crl
