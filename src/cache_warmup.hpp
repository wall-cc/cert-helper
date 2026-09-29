// cache_warmup.hpp
//
// ROADMAP.md, раздел 2, пункт 15 (P3): прогрев кэша при старте демона —
// читает список часто используемых OCSP-responder/CDP/AIA из файла и
// проактивно наполняет кэш, сокращая "холодный" период сразу после
// рестарта/деплоя (первые запросы после старта иначе всегда бьют в сеть).
//
// ФОРМАТ ФАЙЛА ПРОГРЕВА (простой построчный текст, см. пример ниже):
//   # Комментарии и пустые строки игнорируются.
//   crl:<url>
//   aia:<url>
//   ocsp:<responder_url>:<путь к DER/PEM сертификата>:<путь к DER/PEM issuer'а>
//
// ПОЧЕМУ ocsp: ТРЕБУЕТ ДВА ФАЙЛА СЕРТИФИКАТОВ, А НЕ ПРОСТО URL (в отличие
// от crl:/aia:): OCSP-запрос — это не просто "GET по URL", это POST с
// телом, которое содержит CertID (issuer name hash + issuer key hash +
// serialNumber) конкретного проверяемого сертификата (RFC 6960 §4.1).
// URL одного responder'а сам по себе не говорит, СТАТУС КАКОГО именно
// сертификата нужно прогреть — cert-helper строит CertID сам через
// OCSP_cert_to_id(), но для этого ему нужны оба сертификата (subject +
// issuer), а не только URL. Это не забытый край, а прямое следствие
// самого протокола OCSP.
//
// Файлы сертификатов принимаются и в PEM, и в DER — пробуем PEM первым
// (у него распознаваемый текстовый заголовок, быстрый и однозначный
// отказ на не-PEM данных), при неудаче — DER.
//
// Прогрев выполняется В ФОНОВОМ ПОТОКЕ, запущенном ПОСЛЕ старта D-Bus
// сервера (см. daemon_main.cpp) — не блокирует готовность демона
// принимать обычные запросы: warm-up — это "постепенно догрузить кэш",
// а не "заставить клиентов ждать, пока прогрузится список URL". Ошибки
// по отдельным записям (недоступный сервер, битый файл сертификата и
// т.п.) не прерывают прогрев остальных записей — печатаются в stderr и
// учитываются в итоговой сводке.

#pragma once

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../include/cert_helper/protocol.hpp"
#include "logging.hpp"
#include "request_router.hpp"

namespace cert_helper::warmup {

namespace detail {

// Пробует PEM, затем DER — см. обоснование в комментарии в начале файла.
inline X509* load_cert_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return nullptr;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (data.empty()) return nullptr;

    BIO* bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (cert != nullptr) return cert;

    const unsigned char* p = data.data();
    return d2i_X509(nullptr, &p, static_cast<long>(data.size()));
}

// Строит одиночный OCSP_REQUEST (один Request/CertID) для cert/issuer —
// та же операция, что client-side код (tls-mitm) выполнял бы сам при
// обычном (не прогревочном) запросе; здесь дублируется только ради
// прогрева, т.к. cert-helper в остальных случаях НЕ строит OCSP-запросы
// сам — он только докачивает УЖЕ построенные вызывающей стороной.
inline std::optional<std::vector<uint8_t>> build_ocsp_request_der(const std::string& cert_path,
                                                                    const std::string& issuer_path) {
    X509* cert = load_cert_file(cert_path);
    if (cert == nullptr) return std::nullopt;
    X509* issuer = load_cert_file(issuer_path);
    if (issuer == nullptr) {
        X509_free(cert);
        return std::nullopt;
    }

    OCSP_CERTID* certid = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    X509_free(cert);
    X509_free(issuer);
    if (certid == nullptr) return std::nullopt;

    OCSP_REQUEST* req = OCSP_REQUEST_new();
    if (OCSP_request_add0_id(req, certid) == nullptr) { // владение certid переходит req при успехе
        OCSP_CERTID_free(certid);
        OCSP_REQUEST_free(req);
        return std::nullopt;
    }

    unsigned char* der = nullptr;
    int len = i2d_OCSP_REQUEST(req, &der);
    OCSP_REQUEST_free(req);
    if (len <= 0 || der == nullptr) return std::nullopt;

    std::vector<uint8_t> result(der, der + len);
    OPENSSL_free(der);
    return result;
}

} // namespace detail

struct WarmupStats {
    int succeeded = 0;
    int failed = 0;
    int skipped_malformed_lines = 0;
};

// Выполняет прогрев синхронно (вызывающий код — обычно фоновый поток,
// см. комментарий в начале файла) с использованием уже
// сконфигурированного router — та же самая точка входа
// (handle_ocsp/handle_crl/handle_intermediate_cert), что и обычные
// D-Bus-запросы, так что прогретые записи оказываются в ТОМ ЖЕ кэше, с
// теми же TTL-правилами, что и всё остальное.
inline WarmupStats run(const std::string& warmup_file_path, cert_helper::RequestRouter& router,
                        uint32_t timeout_ms = 5000) {
    WarmupStats stats;

    std::ifstream in(warmup_file_path);
    if (!in) {
        log::error("warmup", "не удалось открыть файл прогрева", {log::field("file", warmup_file_path)});
        return stats;
    }

    std::string line;
    while (std::getline(in, line)) {
        // Обрезаем пробелы по краям (в т.ч. \r от файлов с Windows-переносами строк).
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) continue; // пустая строка
        line = line.substr(start, end - start + 1);
        if (line.empty() || line[0] == '#') continue;

        size_t colon = line.find(':');
        if (colon == std::string::npos) {
            log::warn("warmup", "не распознана строка (нет ':')", {log::field("line", line)});
            ++stats.skipped_malformed_lines;
            continue;
        }
        std::string kind = line.substr(0, colon);
        std::string rest = line.substr(colon + 1);

        if (kind == "crl") {
            proto::FetchCrlRequest req;
            req.distribution_point_url = rest;
            req.timeout_ms = timeout_ms;
            auto resp = router.handle_crl(req);
            if (resp.status == proto::FetchStatus::Ok) ++stats.succeeded; else ++stats.failed;
        } else if (kind == "aia") {
            proto::FetchIntermediateCertRequest req;
            req.aia_url = rest;
            req.timeout_ms = timeout_ms;
            auto resp = router.handle_intermediate_cert(req);
            if (resp.status == proto::FetchStatus::Ok) ++stats.succeeded; else ++stats.failed;
        } else if (kind == "ocsp") {
            // ЗАМЕТЬТЕ: responder_url сам по себе содержит ':' (схема
            // "http://...") — наивный split(rest, ':') на ВСЕ двоеточия
            // разрезал бы его неправильно. Парсим справа: последние два
            // сегмента, разделённые ':', — это cert_path и issuer_path
            // (пути в файловой системе на практике не содержат ':' на
            // Linux — единственной целевой платформе этого проекта), а
            // всё, что осталось слева — responder_url целиком, включая
            // его собственные ':'.
            size_t last_colon = rest.rfind(':');
            size_t second_last_colon =
                (last_colon == std::string::npos) ? std::string::npos : rest.rfind(':', last_colon - 1);
            if (last_colon == std::string::npos || second_last_colon == std::string::npos ||
                second_last_colon == 0) {
                log::warn("warmup", "ocsp: ожидается responder_url:cert_path:issuer_path",
                          {log::field("got", rest)});
                ++stats.skipped_malformed_lines;
                continue;
            }
            std::string responder_url = rest.substr(0, second_last_colon);
            std::string cert_path = rest.substr(second_last_colon + 1, last_colon - second_last_colon - 1);
            std::string issuer_path = rest.substr(last_colon + 1);

            auto request_der = detail::build_ocsp_request_der(cert_path, issuer_path);
            if (!request_der) {
                log::warn("warmup", "ocsp: не удалось построить запрос",
                          {log::field("cert_path", cert_path), log::field("issuer_path", issuer_path)});
                ++stats.failed;
                continue;
            }
            proto::FetchOcspRequest req;
            req.responder_url = responder_url;
            req.request_der = std::move(*request_der);
            req.timeout_ms = timeout_ms;
            auto resp = router.handle_ocsp(req);
            if (resp.status == proto::FetchStatus::Ok) ++stats.succeeded; else ++stats.failed;
        } else {
            log::warn("warmup", "неизвестный тип записи",
                      {log::field("kind", kind), log::field("line", line)});
            ++stats.skipped_malformed_lines;
        }
    }

    log::info("warmup", "завершён",
              {log::field("succeeded", stats.succeeded), log::field("failed", stats.failed),
               log::field("malformed_lines", stats.skipped_malformed_lines)});
    return stats;
}

} // namespace cert_helper::warmup
