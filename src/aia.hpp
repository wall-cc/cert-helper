// aia.hpp
//
// Извлечение caIssuers URL (Authority Information Access, RFC 5280 §4.2.2.1)
// из DER-кодированного X.509-сертификата.
//
// По аналогии с get_ocsp_responder_url() в tls-mitm/src/revocation_checker.cpp
// (см. раздел 7.2 ТЗ), но для NID_ad_ca_issuers вместо NID_ad_OCSP. В OpenSSL
// нет готовой узкоспециализированной обёртки для caIssuers (в отличие от
// X509_get1_ocsp() для OCSP-ветки) — расширение AUTHORITY_INFO_ACCESS
// разбирается вручную через X509_get_ext_d2i(cert, NID_info_access, ...) и
// перебор ACCESS_DESCRIPTION с фильтром по OBJ_obj2nid(ad->method).
//
// Эта функция используется демоном ТОЛЬКО на входе FETCH_INTERMEDIATE_CERT —
// то есть клиент (NGFW/tls-mitm) уже прислал URL явно в запросе (см.
// протокол в protocol.hpp: FetchIntermediateCertRequest::aia_url). Данная
// функция дублирована здесь как самостоятельная утилита на случай, если
// демону когда-нибудь передадут не URL, а сам сертификат с неполной цепочкой
// (например, для варианта API "вот сертификат, найди и скачай недостающего
// издателя сам") — а также для юнит-теста test_aia_extraction.cpp, который
// должен проверять именно эту логику разбора ASN.1, а не транспорт.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace cert_helper::aia {

// Возвращает первый найденный caIssuers URI из AIA-расширения сертификата,
// либо nullopt, если расширения нет или в нём нет caIssuers-записи с
// типом имени GEN_URI (в проде встречаются только URI-варианты, но
// теоретически ASN.1 допускает и другие GENERAL_NAME-типы — их мы
// пропускаем, а не считаем ошибкой парсинга).
inline std::optional<std::string> extract_ca_issuers_url(X509* cert) {
    if (cert == nullptr) return std::nullopt;

    AUTHORITY_INFO_ACCESS* aia = static_cast<AUTHORITY_INFO_ACCESS*>(
        X509_get_ext_d2i(cert, NID_info_access, nullptr, nullptr));
    if (aia == nullptr) return std::nullopt;

    std::optional<std::string> result;
    int count = sk_ACCESS_DESCRIPTION_num(aia);
    for (int i = 0; i < count; ++i) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (ad == nullptr || ad->method == nullptr || ad->location == nullptr) continue;

        if (OBJ_obj2nid(ad->method) != NID_ad_ca_issuers) continue;
        if (ad->location->type != GEN_URI) continue;

        const ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
        if (uri == nullptr || uri->data == nullptr || uri->length <= 0) continue;

        result = std::string(reinterpret_cast<const char*>(uri->data),
                              static_cast<size_t>(uri->length));
        break; // берём первый — если понадобится fallback на несколько
               // caIssuers-записей, это расширение интерфейса, не сейчас
               // (YAGNI, см. открытый вопрос №6 ТЗ)
    }

    AUTHORITY_INFO_ACCESS_free(aia);
    return result;
}

// Удобный вариант поверх DER-байт (то, что реально ходит по проводу/из кэша).
inline std::optional<std::string> extract_ca_issuers_url_der(const std::vector<uint8_t>& cert_der) {
    if (cert_der.empty()) return std::nullopt;
    const unsigned char* p = cert_der.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()));
    if (cert == nullptr) return std::nullopt;
    auto result = extract_ca_issuers_url(cert);
    X509_free(cert);
    return result;
}

} // namespace cert_helper::aia
