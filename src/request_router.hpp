// request_router.hpp
//
// Маршрутизатор запросов демона: получает cert_helper::protocol::Request,
// решает, обращаться ли к кэшу, при необходимости выполняет реальный
// сетевой запрос через IHttpFetcher, обновляет кэш и строит ответ.
//
// Намеренно НИЧЕГО не знает про UDS/framing (это ipc/uds_server.hpp) и
// ничего не знает про TLS-сессии/handshake — только "дай мне байты по
// этому URL, с кэшированием", как и требует раздел 3 ТЗ.
//
// TTL-политика (раздел 5 исходного ТЗ, дополнено пунктом 1 из анализа
// демона докачки сертификатов в Squid):
//   - OCSP: TTL = nextUpdate из самого OCSP-ответа (если поле присутствует;
//     если nextUpdate отсутствует в ответе — используем короткий дефолтный
//     TTL, см. kDefaultOcspTtlSeconds, т.к. RFC 6960 не требует nextUpdate).
//     Дополнительно клампится сверху max_ocsp_ttl_seconds (ROADMAP.md,
//     раздел 1, пункт 2) — недобросовестный/скомпрометированный responder
//     не может продлить себе кэш дольше этого предела, указав заведомо
//     далёкий nextUpdate.
//   - CRL: TTL = nextUpdate самого CRL, аналогично клампится сверху
//     max_crl_ttl_seconds.
//   - AIA (промежуточный сертификат): TTL = фиксированный
//     aia_fetch_cache_ttl_seconds, по умолчанию неделя — согласовано с
//     tls-mitm/include/tls_mitm/config.hpp::aia_fetch_cache_ttl_seconds.
//   - Во всех трёх случаях полученный TTL дополнительно ограничивается
//     сверху HTTP-заголовками самого ответа (Cache-Control: no-store/
//     no-cache/max-age, Expires) — см. http_client.hpp::CacheHints и
//     apply_http_cache_hints() ниже. Сервер может только УКОРОТИТЬ наш
//     TTL, никогда не удлинить его сверх вычисленного из nextUpdate/
//     aia_ttl_seconds — этим TTL-политика отличается от "чистого" HTTP
//     кэша (где Cache-Control мог бы разрешить кэшировать и дольше, чем
//     мы сами считаем безопасным для отзыва/докачки сертификатов).
//   - Дополнительно для AIA: TTL клампится сверху сроком действия самого
//     докачанного сертификата (`notAfter`), см.
//     clamp_ttl_to_cert_not_after() — ROADMAP.md, раздел 1, пункт 1.
//     Без этого клампа `aia_ttl_seconds` (по умолчанию неделя) мог бы
//     пережить собственный `notAfter` сертификата: если сертификат
//     истекает раньше, чем истёк бы TTL кэша, демон продолжал бы отдавать
//     уже просроченный сертификат вплоть до `aia_ttl_seconds`. Если
//     `notAfter` уже в прошлом на момент докачки — сертификат вообще не
//     кладётся в кэш (но всё равно возвращается вызвавшему клиенту: сама
//     докачка была успешной, а является ли просроченный сертификат
//     проблемой для построения цепочки — решает tls-mitm, не демон).
//
// Retry с backoff (ROADMAP.md, раздел 2, пункт 10):
//   Все три HTTP-based fetch'а (OCSP/CRL/AIA — не ldap://, см. ниже)
//   идут через retry_with_backoff()/fetch_with_retry(): при транзиентной
//   сетевой ошибке (HttpResult::ok == false — отказ соединения, таймаут,
//   TLS-хендшейк, превышение лимита размера ответа и т.п.) запрос
//   повторяется до config.max_retries раз с экспоненциальным backoff и
//   full jitter, но НЕ дольше общего таймаута, который передал вызвавший
//   клиент (req.timeout_ms) — retry-бюджет вписывается внутрь этого
//   таймаута, а не умножает его: иначе D-Bus-вызов клиента (который сам
//   использует req.timeout_ms как таймаут всего sd_bus_call(), см.
//   dbus_client.hpp) истёк бы раньше, чем демон успел бы отретраить.
//   Retry делается ТОЛЬКО для сетевых ошибок транспорта, не для
//   завершённых HTTP-ответов с кодом ошибки (4xx/5xx) — это осознанная
//   граница пункта 10: определённый ответ сервера "нет" — не то же
//   самое, что оборванное соединение, и его ретраить бессмысленно (и
//   потенциально вредно для перегруженного сервера — см. пункт 11,
//   circuit breaker, тоже раздел 2).
//   ЯВНОЕ ОГРАНИЧЕНИЕ: путь ldap:// (пункт 9) НЕ обёрнут в retry — пункт
//   10 в ROADMAP.md описан именно для HTTP-based GET/POST; аналогичное
//   расширение на LDAP-путь несложно добавить отдельно, если понадобится.
//
// Circuit breaker per-host (ROADMAP.md, раздел 2, пункт 11):
//   Дополняет retry, а не дублирует его: retry борется с ОДИНОЧНЫМИ
//   транзиентными сбоями одного запроса (дропнутый пакет и т.п.), circuit
//   breaker — с УСТОЙЧИВО недоступным или систематически отвечающим
//   ошибками хостом на протяжении МНОГИХ запросов. Ключуется по
//   "host:port" из URL (см. host_port_key()) — если конкретный
//   OCSP-responder/CDP-хост подряд отказал config.circuit_breaker_
//   failure_threshold раз (после исчерпания retry на каждый запрос — т.е.
//   breaker считает провалившиеся ЗАПРОСЫ целиком, а не отдельные попытки
//   ретрая внутри одного запроса, иначе он срабатывал бы после первого же
//   запроса), breaker переходит в состояние Open: следующие
//   circuit_breaker_cooldown_seconds все запросы к этому хосту отклоняются
//   немедленно (NetworkError) без единой попытки соединения — экономит и
//   задержку для пользователя, и нагрузку на и так проблемный хост. По
//   истечении cooldown breaker переходит в Half-Open и пропускает
//   запрос(ы) как пробу: успех закрывает breaker (сброс счётчика), неудача
//   открывает его снова с новым cooldown.
//   УПРОЩЕНИЕ (сознательное, не забытый край): Half-Open пропускает ВСЕ
//   конкурентные запросы к хосту, пришедшиеся на этот момент, а не строго
//   один пробный запрос, как в классическом паттерне — под нагрузкой это
//   означает, что несколько параллельных проб могут уйти одновременно
//   вместо одной; если хост действительно ещё недоступен, они просто все
//   провалятся и снова откроют breaker с свежим cooldown, поэтому это не
//   меняет корректность, только чуть смягчает "экономию" в первый момент
//   half-open. Полная реализация с ровно одним пробным запросом требует
//   отдельного состояния "проба уже в полёте" и его синхронизации —
//   сложность, не оправданная для этого случая.
//   Карта breaker'ов НЕ ограничена по размеру строгим LRU (в отличие от
//   FileCacheStore::Limits) — при достижении circuit_breaker_max_tracked_
//   hosts новый хост вытесняет произвольную (не обязательно наименее
//   используемую) существующую запись. URL-и приходят из AIA/OCSP/CDP
//   расширений сертификата, который предъявляет потенциально
//   недобросовестный сервер при перехвате TLS — то есть ключ карты
//   частично под контролем атакующего, и без какого-либо предела карта
//   росла бы неограниченно. Точная LRU здесь избыточна: это не
//   производительный кэш, а лишь защита от неограниченного роста памяти.
//   Path ldap:// (пункт 9), как и в retry, НЕ покрыт circuit breaker'ом —
//   та же осознанная граница scope.
//
//   Ключуется по CertID (issuer name hash + issuer key hash +
//   serialNumber), разобранному из тела OCSP-запроса, а не по
//   фингерпринту всего DER целиком — см.
//   ocsp_request_cache_fingerprint() ниже. Фингерпринт всего DER ломается,
//   если tls-mitm добавит nonce-расширение (RFC 8954, защита от replay):
//   nonce меняется на каждый запрос, поэтому фингерпринт всего DER тоже
//   меняется каждый раз и кэш перестаёт срабатывать вообще, хотя
//   проверяемый сертификат (CertID) один и тот же.
//
// Лимиты размера ответа (ROADMAP.md, раздел 1, пункт 4):
//   max_ocsp_response_bytes/max_aia_response_bytes/max_crl_response_bytes
//   передаются в IHttpFetcher::fetch() по типу запроса, а не общая
//   константа на всё (как было раньше — фиксированные 32 МиБ для любого
//   ответа). OCSP-ответ и AIA-сертификат легитимно весят единицы-сотни
//   КБ; разрешать им 32 МиБ — лишняя поверхность для исчерпания
//   памяти/диска ответом от недобросовестного/скомпрометированного
//   сервера. CRL, наоборот, легитимно может быть большим — для него
//   лимит выше на порядок.
//
// Singleflight-дедупликация (ROADMAP.md, раздел 1, пункт 5):
//   handle_ocsp()/handle_crl()/handle_intermediate_cert() оборачивают
//   свою impl-реализацию в singleflight_execute() ниже: если запрос к
//   тому же ключу (тип + cache_key) уже выполняется в другом
//   воркер-потоке, новый вызов не инициирует ещё один HTTP-поход, а ждёт
//   результата уже выполняющегося запроса и получает его копию. Первый
//   вызвавший поток ("лидер") выполняет обычную impl-логику (проверка
//   кэша, сетевой запрос при промахе, запись в кэш) без изменений; все
//   остальные потоки ("последователи"), пришедшие с тем же ключом, пока
//   лидер ещё не закончил, блокируются на condition_variable и получают
//   тот же proto::FetchResponse, что и лидер, — включая его from_cache
//   (обычно false, т.к. лидер увидел промах кэша, иначе сам синглфлайт
//   бы не потребовался). Это не подменяет и не дублирует функциональность
//   кэша: кэш экономит повторные СЕТЕВЫЕ запросы РАЗНЕСЁННЫЕ ВО ВРЕМЕНИ,
//   а singleflight — повторные запросы, пришедшие ОДНОВРЕМЕННО, пока
//   первый ещё не успел долететь до кэша (typичный сценарий — "громкое
//   стадо" из многих TLS handshake на один и тот же CA/OCSP-URL сразу
//   после старта демона, когда кэш ещё пуст).
//
// Валидация ответов (что именно считается InvalidResponse):
//   - Для FETCH_OCSP: демон НЕ делает криптографическую проверку подписи
//     OCSP-ответа — это сознательно оставлено библиотеке tls-mitm (у неё
//     уже есть доверенные корни/промежуточные сертификаты в контексте
//     TLS-сессии, у демона таких сведений нет и заводить их здесь —
//     дублирование state и лишняя поверхность для рассинхрона доверия).
//     Демон проверяет только "похоже ли это на валидный DER OCSPResponse"
//     (базовый ASN.1-парсинг) и извлекает nextUpdate, если получится.
//   - Аналогично для CRL: базовый ASN.1-парсинг ради TTL, подпись CRL
//     проверяет tls-mitm.
//   - Для FETCH_INTERMEDIATE_CERT: демон проверяет, что тело — валидный DER
//     X.509-сертификат (d2i_X509 не падает). Дальше — задача tls-mitm
//     решить, является ли скачанный сертификат нужным издателем (сверка
//     subject/issuer, построение цепочки) — демон в этом не участвует,
//     он лишь гарантирует "то, что отдано клиенту, разбирается как
//     сертификат", не более.

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>

#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "aia.hpp"
#include "cache/cache_store.hpp"
#include "http_client.hpp"
#include "ldap_client.hpp"
#include "../include/cert_helper/protocol.hpp"

namespace cert_helper {

namespace proto = cert_helper::protocol;

class RequestRouter {
public:
    struct Config {
        uint32_t default_ocsp_ttl_seconds = 300;       // если nextUpdate отсутствует
        uint32_t default_crl_ttl_seconds = 3600;        // если nextUpdate не удалось разобрать
        uint32_t aia_ttl_seconds = 7 * 24 * 3600;        // согласовано с tls-mitm config.hpp
        // ROADMAP.md, раздел 1, пункт 2 (P0): верхняя граница TTL для
        // OCSP/CRL, не зависящая от того, что заявил responder/CA в
        // nextUpdate. Без неё недобросовестный/скомпрометированный
        // responder может указать nextUpdate через год, и демон год будет
        // отдавать устаревший статус отзыва (cache poisoning с очень
        // долгим действием) — см. clamp_ocsp_ttl()/clamp_crl_ttl() ниже.
        uint32_t max_ocsp_ttl_seconds = 24 * 3600;       // 24 часа
        uint32_t max_crl_ttl_seconds = 7 * 24 * 3600;    // 7 дней

        // ROADMAP.md, раздел 1, пункт 4 (P1): лимиты размера ответа по
        // типу запроса, а не одна константа на всё. OCSP-ответ и
        // докачанный промежуточный сертификат весят единицы-сотни КБ;
        // разрешать им те же 32 МиБ, что разумны для CRL, — лишняя
        // поверхность для исчерпания памяти/диска ответом от
        // недобросовестного/скомпрометированного сервера. CRL, наоборот,
        // легитимно может быть большим (крупные CA — единицы-десятки МБ).
        uint32_t max_ocsp_response_bytes = 256 * 1024;        // 256 КиБ
        uint32_t max_aia_response_bytes = 256 * 1024;         // 256 КиБ
        uint32_t max_crl_response_bytes = 16 * 1024 * 1024;   // 16 МиБ

        // ROADMAP.md, раздел 2, пункт 10 (P1): retry с backoff для
        // транзиентных сетевых ошибок (одиночный дропнутый пакет/RST и
        // т.п.) — см. retry_with_backoff() ниже. max_retries — число
        // ПОВТОРНЫХ попыток сверх первой (т.е. итого до max_retries+1
        // реальных обращений к сети на один запрос tls-mitm).
        // retry_base_delay_ms — базовая задержка экспоненциального
        // backoff с джиттером (full jitter, см. AWS Architecture Blog
        // "Exponential Backoff And Jitter").
        uint32_t max_retries = 2;
        uint32_t retry_base_delay_ms = 100;

        // ROADMAP.md, раздел 2, пункт 11 (P1): circuit breaker per-host —
        // см. подробный комментарий в начале файла.
        uint32_t circuit_breaker_failure_threshold = 5;   // подряд неудачных ЗАПРОСОВ до открытия
        uint32_t circuit_breaker_cooldown_seconds = 30;   // время в открытом состоянии
        uint32_t circuit_breaker_max_tracked_hosts = 10000; // защита от неограниченного роста карты
    };

    RequestRouter(cache::ICacheStore& cache_store, http::IHttpFetcher& http_fetcher, Config config,
                  ldap::ILdapFetcher* ldap_fetcher = nullptr)
        : cache_store(cache_store), http_fetcher(http_fetcher), config(config), ldap_fetcher(ldap_fetcher) {}

    proto::FetchResponse handle_ocsp(const proto::FetchOcspRequest& req) {
        std::string key = "ocsp|" + req.responder_url + "|" + ocsp_request_cache_fingerprint(req.request_der);
        proto::FetchResponse resp = singleflight_execute(key, [this, &req] { return handle_ocsp_impl(req); });
        record_stats(ocsp_stats, resp);
        return resp;
    }

    // ROADMAP.md, раздел 2, пункт 14 (P2): батчинг OCSP-запросов — см.
    // подробное обоснование формата ответа в protocol.hpp::
    // FetchOcspBatchResponse. Алгоритм:
    //   1. Проверяем кэш для КАЖДОГО запроса индивидуально (тем же
    //      CertID-based ключом, что и одиночный handle_ocsp) — попадания
    //      обслуживаются немедленно, без какого-либо сетевого похода.
    //   2. Промахи группируем по responder_url. Группа из ОДНОГО элемента
    //      — обычный одиночный путь (через singleflight+handle_ocsp_impl,
    //      как handle_ocsp() выше — только без двойной записи статистики,
    //      см. ниже). Группа из НЕСКОЛЬКИХ элементов — один комбинированный
    //      OCSP_REQUEST (build_combined_ocsp_request()), один HTTP POST
    //      через тот же fetch_with_retry_and_circuit_breaker(), что и для
    //      одиночных запросов (тот же host — то же состояние circuit
    //      breaker'а, общее для батчевых и обычных запросов к нему).
    //   3. При успехе — кэшируем ОБЩИЙ полученный блок под СОБСТВЕННЫМ
    //      cache_key каждого исходного запроса группы, с ИНДИВИДУАЛЬНЫМ
    //      TTL, вычисленным через его же CertID (см. ocsp_response_ttl_
    //      seconds(..., certid) с OCSP_resp_find() внутри — простой TTL с
    //      certid=nullptr взял бы nextUpdate только первого SingleResponse,
    //      что было бы неверно для второго и далее сертификата группы).
    //   4. Если build_combined_ocsp_request() не смог собрать
    //      комбинированный запрос (например, один из request_der не
    //      разобрался) — откатываемся на независимые одиночные fetch для
    //      каждого элемента ЭТОЙ группы, а не проваливаем батч целиком.
    // Статистика (record_stats) считается один раз в конце для КАЖДОГО
    // элемента батча одинаково, независимо от того, каким путём он был
    // обслужен (кэш/одиночный/батчевый) — поэтому здесь используется
    // singleflight_execute()+handle_ocsp_impl() напрямую, а не публичный
    // handle_ocsp() (который сам уже вызывает record_stats — вызов его
    // здесь привёл бы к двойному учёту для элементов-одиночек).
    proto::FetchOcspBatchResponse handle_ocsp_batch(const proto::FetchOcspBatchRequest& batch_req) {
        proto::FetchOcspBatchResponse batch_resp;
        batch_resp.responses.resize(batch_req.requests.size());

        std::unordered_map<std::string, std::vector<size_t>> miss_indices_by_url;
        for (size_t i = 0; i < batch_req.requests.size(); ++i) {
            const auto& req = batch_req.requests[i];
            std::string cache_key = req.responder_url + "|" + ocsp_request_cache_fingerprint(req.request_der);
            if (auto cached = cache_store.get(cache::EntryKind::Ocsp, cache_key)) {
                proto::FetchResponse resp;
                resp.status = proto::FetchStatus::Ok;
                resp.payload_der = cached->payload;
                resp.from_cache = true;
                batch_resp.responses[i] = std::move(resp);
            } else {
                miss_indices_by_url[req.responder_url].push_back(i);
            }
        }

        for (const auto& [responder_url, indices] : miss_indices_by_url) {
            if (indices.size() == 1) {
                fetch_single_ocsp_into_batch(batch_req.requests[indices[0]], batch_resp.responses[indices[0]]);
                continue;
            }

            std::vector<std::vector<uint8_t>> request_ders;
            request_ders.reserve(indices.size());
            for (size_t i : indices) request_ders.push_back(batch_req.requests[i].request_der);

            auto combined_der = build_combined_ocsp_request(request_ders);
            if (!combined_der) {
                // Не удалось собрать комбинированный запрос — не проваливаем
                // весь батч, обслуживаем эту группу как N независимых
                // одиночных запросов.
                for (size_t i : indices) fetch_single_ocsp_into_batch(batch_req.requests[i], batch_resp.responses[i]);
                continue;
            }

            uint32_t combined_timeout_ms = 0;
            for (size_t i : indices) {
                combined_timeout_ms = std::max(combined_timeout_ms, batch_req.requests[i].timeout_ms);
            }

            auto http_result = fetch_with_retry_and_circuit_breaker(
                http::Method::Post, responder_url, *combined_der, "application/ocsp-request",
                combined_timeout_ms, config.max_ocsp_response_bytes);
            proto::FetchResponse combined_resp = classify_http_result(http_result);

            if (combined_resp.status != proto::FetchStatus::Ok) {
                // Единственный round-trip был общим — его исход общий для
                // всех участников группы.
                for (size_t i : indices) batch_resp.responses[i] = combined_resp;
                continue;
            }

            for (size_t i : indices) {
                const auto& req = batch_req.requests[i];
                std::string cache_key =
                    req.responder_url + "|" + ocsp_request_cache_fingerprint(req.request_der);

                OCSP_CERTID* certid = extract_certid_dup(req.request_der);
                int64_t ttl = ocsp_response_ttl_seconds(combined_resp.payload_der, certid);
                if (certid != nullptr) OCSP_CERTID_free(certid);
                ttl = apply_http_cache_hints(ttl, http_result.cache_hints);
                store_in_cache(cache::EntryKind::Ocsp, cache_key, combined_resp.payload_der, ttl);

                batch_resp.responses[i] = combined_resp; // тот же payload_der для каждого — см. protocol.hpp
            }
        }

        for (const auto& resp : batch_resp.responses) {
            record_stats(ocsp_stats, resp);
        }
        return batch_resp;
    }

    proto::FetchResponse handle_crl(const proto::FetchCrlRequest& req) {
        std::string key = "crl|" + req.distribution_point_url;
        proto::FetchResponse resp = singleflight_execute(key, [this, &req] { return handle_crl_impl(req); });
        record_stats(crl_stats, resp);
        return resp;
    }

    proto::FetchResponse handle_intermediate_cert(const proto::FetchIntermediateCertRequest& req) {
        std::string key = "aia|" + req.aia_url;
        proto::FetchResponse resp =
            singleflight_execute(key, [this, &req] { return handle_intermediate_cert_impl(req); });
        record_stats(intermediate_cert_stats, resp);
        return resp;
    }

    proto::HealthCheckResponse handle_health_check() {
        auto stats = cache_store.stats();
        proto::HealthCheckResponse resp;
        resp.healthy = true;
        resp.cache_entries = stats.entries;
        resp.cache_size_bytes = stats.size_bytes;
        resp.memory_cache_entries = stats.memory_entries;
        resp.memory_cache_size_bytes = stats.memory_size_bytes;
        resp.ocsp = snapshot(ocsp_stats);
        resp.crl = snapshot(crl_stats);
        resp.intermediate_cert = snapshot(intermediate_cert_stats);
        return resp;
    }

private:
    // Счётчики наблюдаемости по типу запроса (пункт 5 из анализа Squid).
    // std::memory_order_relaxed достаточно — это просто счётчики для
    // диагностики/мониторинга, не синхронизационный примитив; нам не
    // важен строгий порядок между обновлением счётчика и остальными
    // операциями, только то, что инкременты в конце концов видны при
    // чтении из HealthCheck.
    struct AtomicTypeStats {
        std::atomic<uint64_t> requests{0};
        std::atomic<uint64_t> cache_hits{0};
        std::atomic<uint64_t> errors{0};
    };

    static void record_stats(AtomicTypeStats& stats, const proto::FetchResponse& resp) {
        stats.requests.fetch_add(1, std::memory_order_relaxed);
        if (resp.from_cache) stats.cache_hits.fetch_add(1, std::memory_order_relaxed);
        if (resp.status != proto::FetchStatus::Ok) stats.errors.fetch_add(1, std::memory_order_relaxed);
    }

    static proto::RequestTypeStats snapshot(const AtomicTypeStats& stats) {
        proto::RequestTypeStats out;
        out.requests = stats.requests.load(std::memory_order_relaxed);
        out.cache_hits = stats.cache_hits.load(std::memory_order_relaxed);
        out.errors = stats.errors.load(std::memory_order_relaxed);
        return out;
    }

    // ROADMAP.md, раздел 1, пункт 5 (P1): singleflight-дедупликация.
    // Состояние одного "в полёте" запроса, разделяемое между лидером
    // (потоком, который реально выполняет impl_fn) и последователями
    // (потоками, пришедшими с тем же ключом, пока лидер ещё не закончил).
    struct InFlightState {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        proto::FetchResponse result;
    };

    // Выполняет impl_fn() ровно один раз на все одновременные вызовы с
    // одинаковым key: первый вызвавший поток становится "лидером" и
    // реально выполняет impl_fn (обычная логика "кэш -> сеть -> запись в
    // кэш" из handle_*_impl), остальные блокируются и получают копию его
    // результата. inflight_mutex_ держится только на короткие операции с
    // самой map (найти/вставить/удалить запись) — не на время выполнения
    // impl_fn(), иначе несвязанные ключи сериализовались бы друг за
    // другом (регрессия на test_concurrent_fetches_do_not_serialize_
    // on_slow_request).
    proto::FetchResponse singleflight_execute(const std::string& key,
                                               const std::function<proto::FetchResponse()>& impl_fn) {
        std::shared_ptr<InFlightState> state;
        bool is_leader = false;

        {
            std::lock_guard<std::mutex> lock(inflight_mutex_);
            auto it = inflight_.find(key);
            if (it != inflight_.end()) {
                state = it->second;
            } else {
                state = std::make_shared<InFlightState>();
                inflight_.emplace(key, state);
                is_leader = true;
            }
        }

        if (!is_leader) {
            std::unique_lock<std::mutex> lock(state->mtx);
            state->cv.wait(lock, [&state] { return state->done; });
            return state->result;
        }

        // Лидер выполняет реальную работу ВНЕ inflight_mutex_ — это
        // именно то, что позволяет несвязанным ключам не сериализоваться.
        proto::FetchResponse result = impl_fn();

        {
            std::lock_guard<std::mutex> lock(state->mtx);
            state->result = result;
            state->done = true;
        }
        state->cv.notify_all();

        {
            // Убираем запись из map ПОСЛЕ того, как результат уже
            // выставлен и последователи разбужены — иначе новый запрос,
            // пришедший в узком окне между erase() и notify_all(), не
            // нашёл бы ни существующую in-flight запись (стал бы новым
            // лидером и продублировал сетевой запрос), ни готовый ответ
            // лидера. Последователи, уже держащие свой shared_ptr<state>,
            // не пострадают от удаления записи из map — сам объект state
            // жив, пока жив хотя бы один shared_ptr на него.
            std::lock_guard<std::mutex> lock(inflight_mutex_);
            auto it = inflight_.find(key);
            if (it != inflight_.end() && it->second == state) {
                inflight_.erase(it);
            }
        }

        return result;
    }

    // ROADMAP.md, раздел 2, пункт 10 (P1): экспоненциальный backoff с
    // full jitter — случайная задержка равномерно между 0 и
    // base*2^(attempt-1) (капнутым сверху kMaxBackoffMs), а не сама
    // экспонента без джиттера: full jitter лучше "размазывает" повторные
    // попытки многих одновременных клиентов по времени и не создаёт
    // синхронизированных "волн" ретраев на восстанавливающийся сервер
    // (см. AWS Architecture Blog, "Exponential Backoff And Jitter").
    // thread_local генератор — RequestRouter вызывается из нескольких
    // воркер-потоков одновременно, а std::mt19937 не потокобезопасен для
    // конкурентных вызовов у одного и того же экземпляра.
    static uint32_t compute_backoff_ms(uint32_t attempt, uint32_t base_delay_ms) {
        constexpr uint32_t kMaxBackoffMs = 5000; // разумный потолок независимо от конфигурации
        uint64_t exp_delay = static_cast<uint64_t>(base_delay_ms) << (attempt - 1);
        exp_delay = std::min<uint64_t>(exp_delay, kMaxBackoffMs);

        thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<uint32_t> dist(0, static_cast<uint32_t>(exp_delay));
        return dist(rng);
    }

    // Универсальный retry-цикл: attempt_fn(per_attempt_timeout_ms) должен
    // вернуть значение с полем `bool ok` (совместимо и с http::HttpResult,
    // и с ldap::LdapResult — используется дуктайпингом через шаблон, без
    // общего базового класса). Общий бюджет времени на ВСЕ попытки —
    // overall_timeout_ms (обычно req.timeout_ms от вызвавшего клиента);
    // retry не может растянуть суммарное время сверх этого бюджета —
    // см. комментарий в начале файла про то, почему это важно
    // (D-Bus-вызов клиента сам таймаутится по этому же значению).
    template <typename ResultT, typename AttemptFn>
    ResultT retry_with_backoff(uint32_t overall_timeout_ms, AttemptFn&& attempt_fn) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(overall_timeout_ms);
        ResultT result{};

        for (uint32_t attempt = 0;; ++attempt) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            uint32_t remaining_ms = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());

            result = attempt_fn(remaining_ms);
            if (result.ok) return result;

            if (attempt >= config.max_retries) break;

            now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            uint32_t remaining_before_sleep = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            uint32_t backoff = compute_backoff_ms(attempt + 1, config.retry_base_delay_ms);
            if (backoff >= remaining_before_sleep) break; // бюджета на осмысленный повтор уже не осталось

            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }
        return result;
    }

    http::HttpResult fetch_with_retry(http::Method method, const std::string& url,
                                       const std::vector<uint8_t>& post_body,
                                       const std::string& post_content_type, uint32_t overall_timeout_ms,
                                       size_t max_response_bytes) {
        return retry_with_backoff<http::HttpResult>(
            overall_timeout_ms, [&](uint32_t per_attempt_timeout_ms) {
                return http_fetcher.fetch(method, url, post_body, post_content_type,
                                           per_attempt_timeout_ms, max_response_bytes);
            });
    }

    // ROADMAP.md, раздел 2, пункт 11 (P1): circuit breaker per-host — см.
    // подробный комментарий в начале файла. Три состояния классического
    // паттерна (Closed/Open/HalfOpen).
    enum class CircuitState { Closed, Open, HalfOpen };

    struct CircuitBreakerState {
        std::mutex mtx;
        CircuitState state = CircuitState::Closed;
        uint32_t consecutive_failures = 0;
        std::chrono::steady_clock::time_point opened_at;
    };

    // "host:port" из URL — то, чем ключуется breaker. Работает для
    // http(s):// (через http::parse_http_url, который уже умеет оба
    // варианта — см. http_client.hpp). Для URL, не начинающихся с http(s)
    // (сейчас — ldap://), возвращает nullopt: см. комментарий в начале
    // файла про то, что ldap:// сознательно не покрыт circuit breaker'ом.
    static std::optional<std::string> host_port_key(const std::string& url) {
        auto parsed = http::parse_http_url(url);
        if (!parsed) return std::nullopt;
        return parsed->host + ":" + std::to_string(parsed->port);
    }

    std::shared_ptr<CircuitBreakerState> get_or_create_breaker(const std::string& host_port) {
        std::lock_guard<std::mutex> lock(breakers_mutex_);
        auto it = breakers_.find(host_port);
        if (it != breakers_.end()) return it->second;

        if (breakers_.size() >= config.circuit_breaker_max_tracked_hosts) {
            // Простая защита от неограниченного роста, не строгий LRU —
            // см. комментарий в начале файла про то, почему это
            // достаточно для этого случая.
            breakers_.erase(breakers_.begin());
        }
        auto state = std::make_shared<CircuitBreakerState>();
        breakers_.emplace(host_port, state);
        return state;
    }

    // true => отказать немедленно, без попытки соединения. Если хост ещё
    // не встречался — breaker неявно Closed (не создаём запись только
    // ради чтения, чтобы просмотр "проходного" хоста не грел карту).
    // Если cooldown уже истёк — переводит breaker в Half-Open и
    // пропускает вызвавшего как пробу (см. упрощение в комментарии в
    // начале файла: несколько конкурентных вызовов могут пройти как
    // "пробные" одновременно).
    bool circuit_should_fail_fast(const std::string& host_port) {
        std::shared_ptr<CircuitBreakerState> state;
        {
            std::lock_guard<std::mutex> lock(breakers_mutex_);
            auto it = breakers_.find(host_port);
            if (it == breakers_.end()) return false;
            state = it->second;
        }

        std::lock_guard<std::mutex> lock(state->mtx);
        if (state->state != CircuitState::Open) return false;

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now() - state->opened_at)
                           .count();
        if (elapsed < static_cast<int64_t>(config.circuit_breaker_cooldown_seconds)) {
            return true; // всё ещё открыт — отказываем без попытки соединения
        }
        state->state = CircuitState::HalfOpen; // cooldown истёк — пропускаем как пробу
        return false;
    }

    void circuit_record_success(const std::string& host_port) {
        auto state = get_or_create_breaker(host_port);
        std::lock_guard<std::mutex> lock(state->mtx);
        state->consecutive_failures = 0;
        state->state = CircuitState::Closed;
    }

    void circuit_record_failure(const std::string& host_port) {
        auto state = get_or_create_breaker(host_port);
        std::lock_guard<std::mutex> lock(state->mtx);
        ++state->consecutive_failures;

        if (state->state == CircuitState::HalfOpen) {
            // Пробный запрос после cooldown не удался — открываем снова
            // со свежим cooldown, не дожидаясь повторного накопления
            // failure_threshold с нуля (хост подтвердил, что всё ещё плох).
            state->state = CircuitState::Open;
            state->opened_at = std::chrono::steady_clock::now();
            return;
        }
        if (state->consecutive_failures >= config.circuit_breaker_failure_threshold) {
            state->state = CircuitState::Open;
            state->opened_at = std::chrono::steady_clock::now();
        }
    }

    // Оборачивает fetch_with_retry() гейтом circuit breaker'а: если хост
    // сейчас Open — немедленный NetworkError-подобный HttpResult{ok=false}
    // без единой попытки соединения; иначе выполняет обычный
    // fetch_with_retry() и по его ИТОГОВОМУ результату (уже после всех
    // внутренних retry) обновляет состояние breaker'а — см. комментарий в
    // начале файла про то, почему breaker считает ЗАПРОСЫ, а не отдельные
    // попытки ретрая внутри одного запроса.
    http::HttpResult fetch_with_retry_and_circuit_breaker(http::Method method, const std::string& url,
                                                            const std::vector<uint8_t>& post_body,
                                                            const std::string& post_content_type,
                                                            uint32_t overall_timeout_ms,
                                                            size_t max_response_bytes) {
        auto host_port = host_port_key(url);
        if (host_port && circuit_should_fail_fast(*host_port)) {
            return http::HttpResult{}; // ok=false по умолчанию
        }

        auto result =
            fetch_with_retry(method, url, post_body, post_content_type, overall_timeout_ms, max_response_bytes);

        if (host_port) {
            if (result.ok) {
                circuit_record_success(*host_port);
            } else {
                circuit_record_failure(*host_port);
            }
        }
        return result;
    }

    // Обслуживает ОДИН OCSP-запрос как часть батча (см. handle_ocsp_batch()
    // выше) — та же singleflight-обёртка, что и в публичном handle_ocsp(),
    // но БЕЗ record_stats() (батч сам записывает статистику один раз в
    // конце для всех своих элементов одинаково — см. комментарий там).
    void fetch_single_ocsp_into_batch(const proto::FetchOcspRequest& req, proto::FetchResponse& out) {
        std::string key = "ocsp|" + req.responder_url + "|" + ocsp_request_cache_fingerprint(req.request_der);
        out = singleflight_execute(key, [this, &req] { return handle_ocsp_impl(req); });
    }

    proto::FetchResponse handle_ocsp_impl(const proto::FetchOcspRequest& req) {
        std::string cache_key = req.responder_url + "|" + ocsp_request_cache_fingerprint(req.request_der);

        if (auto cached = cache_store.get(cache::EntryKind::Ocsp, cache_key)) {
            proto::FetchResponse resp;
            resp.status = proto::FetchStatus::Ok;
            resp.payload_der = cached->payload;
            resp.from_cache = true;
            return resp;
        }

        auto http_result = fetch_with_retry_and_circuit_breaker(http::Method::Post, req.responder_url, req.request_der,
                                        "application/ocsp-request", req.timeout_ms,
                                        config.max_ocsp_response_bytes);
        proto::FetchResponse resp = classify_http_result(http_result);
        if (resp.status != proto::FetchStatus::Ok) return resp;

        int64_t ttl = ocsp_response_ttl_seconds(resp.payload_der);
        ttl = apply_http_cache_hints(ttl, http_result.cache_hints);
        store_in_cache(cache::EntryKind::Ocsp, cache_key, resp.payload_der, ttl);
        return resp;
    }

    proto::FetchResponse handle_crl_impl(const proto::FetchCrlRequest& req) {
        std::string cache_key = req.distribution_point_url;

        if (auto cached = cache_store.get(cache::EntryKind::Crl, cache_key)) {
            proto::FetchResponse resp;
            resp.status = proto::FetchStatus::Ok;
            resp.payload_der = cached->payload;
            resp.from_cache = true;
            return resp;
        }

        // ROADMAP.md, раздел 1, пункт 9 (P3): CRL distribution point может
        // быть опубликован через ldap://, а не http:// — типичный случай
        // Active Directory Certificate Services и других корпоративных
        // PKI. Кэш (по URL) и TTL-политика (по nextUpdate самого CRL)
        // одинаковы для обоих транспортов — разница только в том, КАК
        // получить байты CRL. См. ldap_client.hpp за подробным описанием
        // ограничений (anonymous-only bind, без TLS, без пустого host,
        // ограниченное подмножество Filter).
        if (req.distribution_point_url.compare(0, 7, "ldap://") == 0) {
            return handle_crl_via_ldap(req, cache_key);
        }

        auto http_result = fetch_with_retry_and_circuit_breaker(http::Method::Get, req.distribution_point_url, {}, "",
                                        req.timeout_ms, config.max_crl_response_bytes);
        proto::FetchResponse resp = classify_http_result(http_result);
        if (resp.status != proto::FetchStatus::Ok) return resp;

        int64_t ttl = crl_ttl_seconds(resp.payload_der);
        ttl = apply_http_cache_hints(ttl, http_result.cache_hints);
        store_in_cache(cache::EntryKind::Crl, cache_key, resp.payload_der, ttl);
        return resp;
    }

    proto::FetchResponse handle_crl_via_ldap(const proto::FetchCrlRequest& req, const std::string& cache_key) {
        proto::FetchResponse resp;
        if (ldap_fetcher == nullptr) {
            // --allow-ldap не включён (см. daemon_main.cpp) — тот же
            // осознанный "fail closed по умолчанию", что и для https://
            // (ROADMAP.md п.7): новая, неаудированная поверхность разбора
            // BER от недоверенного сервера не включается неявно.
            resp.status = proto::FetchStatus::NetworkError;
            return resp;
        }

        // certificateRevocationList;binary — стандартное имя атрибута для
        // бинарного DER-значения CRL в LDAP-схеме (RFC 4523 §2.2,
        // используется во всех практических реализациях LDAP CDP,
        // включая Active Directory). Если URL сам перечисляет атрибуты
        // (?attr вместо пустого списка) — ILdapFetcher::fetch() всё равно
        // ищет именно это имя среди возвращённых сервером значений
        // (сравнение регистронезависимое, без учёта суффикса ";binary" —
        // см. ldap_client.hpp::detail::attrs_match()).
        auto ldap_result =
            ldap_fetcher->fetch(req.distribution_point_url, "certificateRevocationList;binary",
                                 req.timeout_ms, config.max_crl_response_bytes);
        if (!ldap_result.ok) {
            resp.status = proto::FetchStatus::NetworkError;
            return resp;
        }

        resp.status = proto::FetchStatus::Ok;
        resp.payload_der = std::move(ldap_result.value);

        int64_t ttl = crl_ttl_seconds(resp.payload_der);
        // LDAP-ответы не несут HTTP Cache-Control/Expires семантику —
        // apply_http_cache_hints() здесь неприменим, TTL определяется
        // только nextUpdate самого CRL (и max_crl_ttl_seconds сверху,
        // как обычно — clamp уже встроен в crl_ttl_seconds()).
        store_in_cache(cache::EntryKind::Crl, cache_key, resp.payload_der, ttl);
        return resp;
    }

    proto::FetchResponse handle_intermediate_cert_impl(const proto::FetchIntermediateCertRequest& req) {
        std::string cache_key = req.aia_url;

        if (auto cached = cache_store.get(cache::EntryKind::IntermediateCert, cache_key)) {
            proto::FetchResponse resp;
            resp.status = proto::FetchStatus::Ok;
            resp.payload_der = cached->payload;
            resp.from_cache = true;
            return resp;
        }

        auto http_result = fetch_with_retry_and_circuit_breaker(http::Method::Get, req.aia_url, {}, "", req.timeout_ms,
                                        config.max_aia_response_bytes);
        proto::FetchResponse resp = classify_http_result(http_result);
        if (resp.status != proto::FetchStatus::Ok) return resp;

        // caIssuers-ответ иногда приходит как application/pkcs7-mime
        // (PKCS#7 "degenerate" контейнер с сертификатами) вместо голого
        // DER-сертификата — сервера расходятся в поведении (ROADMAP.md,
        // раздел 1, пункт 6). extract_single_der_certificate() принимает
        // оба формата и всегда возвращает ОДИН сертификат в чистом DER;
        // если распознать не удалось ни как X.509, ни как PKCS#7 —
        // InvalidResponse.
        auto extracted = extract_single_der_certificate(resp.payload_der);
        if (!extracted) {
            proto::FetchResponse invalid;
            invalid.status = proto::FetchStatus::InvalidResponse;
            return invalid;
        }
        resp.payload_der = std::move(*extracted);

        int64_t ttl = apply_http_cache_hints(config.aia_ttl_seconds, http_result.cache_hints);
        ttl = clamp_ttl_to_cert_not_after(ttl, resp.payload_der);
        store_in_cache(cache::EntryKind::IntermediateCert, cache_key, resp.payload_der, ttl);
        return resp;
    }

    // Комбинирует вычисленный нами TTL с подсказками из HTTP-заголовков
    // ответа сервера (Cache-Control/Expires) — сервер может TTL только
    // укоротить, см. комментарий над классом. no-store/no-cache приводят
    // к ttl=0, что store_in_cache() трактует как "вообще не кэшировать".
    static int64_t apply_http_cache_hints(int64_t computed_ttl, const http::CacheHints& hints) {
        if (hints.no_store || hints.no_cache) return 0;

        int64_t ttl = computed_ttl;
        if (hints.max_age_seconds) {
            ttl = std::min(ttl, *hints.max_age_seconds);
        }
        if (hints.expires_unix) {
            int64_t remaining = *hints.expires_unix - now_seconds();
            ttl = std::min(ttl, remaining);
        }
        return ttl;
    }
    static proto::FetchResponse classify_http_result(const http::HttpResult& r) {
        proto::FetchResponse resp;
        if (r.timed_out) {
            resp.status = proto::FetchStatus::Timeout;
            return resp;
        }
        if (!r.ok) {
            resp.status = proto::FetchStatus::NetworkError;
            return resp;
        }
        if (r.status_code < 200 || r.status_code >= 300) {
            resp.status = proto::FetchStatus::NetworkError;
            return resp;
        }
        if (r.body.empty()) {
            resp.status = proto::FetchStatus::InvalidResponse;
            return resp;
        }
        resp.status = proto::FetchStatus::Ok;
        resp.payload_der = r.body;
        resp.from_cache = false;
        return resp;
    }

    void store_in_cache(cache::EntryKind kind, const std::string& key,
                         const std::vector<uint8_t>& payload, int64_t ttl_seconds) {
        if (ttl_seconds <= 0) return; // отрицательный/нулевой TTL — не кэшируем вовсе
        cache::CacheEntry entry;
        entry.payload = payload;
        entry.fetched_at = now_seconds();
        entry.valid_until = now_seconds() + ttl_seconds;
        cache_store.put(kind, key, entry);
    }

    static int64_t now_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    // Дешёвый идентификатор конкретного OCSP-запроса (не криптографический
    // хеш безопасности ради — нужен только чтобы разные serialNumber на
    // одном responder_url не путались в кэше). SHA-256 тут просто удобная
    // готовая функция, а не защита от подмены.
    static std::string der_fingerprint(const std::vector<uint8_t>& der) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(der.data(), der.size(), digest);
        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(SHA256_DIGEST_LENGTH * 2);
        for (unsigned char b : digest) {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 0xF]);
        }
        return out;
    }

    // ROADMAP.md, раздел 1, пункт 3 (P1): ключ OCSP-кэша через CertID
    // (issuer name hash + issuer key hash + serialNumber), а не через
    // фингерпринт сырых байт всего запроса. Фингерпринт всего DER ломает
    // кэш, если tls-mitm добавит nonce-расширение в OCSP-запрос (RFC 8954,
    // рекомендуемая защита от replay) — тогда каждый запрос по одному и
    // тому же сертификату даёт разный DER целиком (nonce меняется каждый
    // раз), и кэш никогда не срабатывает, хотя сертификат/CertID
    // одинаковый. Разбираем OCSP_REQUEST, достаём OCSP_CERTID первого
    // OCSP_ONEREQ (демон пока не поддерживает батчинг из пункта 14 — на
    // практике в запросе ровно один OCSP_ONEREQ) и повторно кодируем его в
    // DER: сам CertID лежит вне nonce-расширения (то расширение — на
    // уровне tbsRequest.requestExtensions всего OCSP_REQUEST, не внутри
    // CertID), так что этот фингерпринт по построению не видит nonce.
    //
    // Если request_der не разбирается как валидный OCSP_REQUEST (не
    // должно случаться при нормальной работе tls-mitm, но, например,
    // юнит-тесты кое-где посылают "сырые" байты вместо настоящего ASN.1) —
    // откатываемся на прежнее поведение (фингерпринт всего DER), чтобы не
    // ломать кэширование для таких клиентов: они не добавляют nonce, так
    // что старая стратегия для них и так корректна.
    static std::string ocsp_request_cache_fingerprint(const std::vector<uint8_t>& request_der) {
        const unsigned char* p = request_der.data();
        OCSP_REQUEST* ocsp_req = d2i_OCSP_REQUEST(nullptr, &p, static_cast<long>(request_der.size()));
        if (ocsp_req == nullptr) {
            return der_fingerprint(request_der);
        }

        int count = OCSP_request_onereq_count(ocsp_req);
        if (count <= 0) {
            OCSP_REQUEST_free(ocsp_req);
            return der_fingerprint(request_der);
        }

        OCSP_ONEREQ* one_req = OCSP_request_onereq_get0(ocsp_req, 0);
        OCSP_CERTID* cert_id = (one_req != nullptr) ? OCSP_onereq_get0_id(one_req) : nullptr;
        if (cert_id == nullptr) {
            OCSP_REQUEST_free(ocsp_req);
            return der_fingerprint(request_der);
        }

        unsigned char* cert_id_der = nullptr;
        int cert_id_len = i2d_OCSP_CERTID(cert_id, &cert_id_der);
        OCSP_REQUEST_free(ocsp_req); // cert_id указывал внутрь ocsp_req — освобождать после i2d, не раньше

        if (cert_id_len <= 0 || cert_id_der == nullptr) {
            return der_fingerprint(request_der);
        }
        std::vector<uint8_t> cert_id_bytes(cert_id_der, cert_id_der + cert_id_len);
        OPENSSL_free(cert_id_der);
        return der_fingerprint(cert_id_bytes);
    }

    // ROADMAP.md, раздел 2, пункт 14 (P2): извлекает CertID первого
    // OCSP_ONEREQ из тела одиночного OCSP-запроса — та же логика поиска,
    // что и в ocsp_request_cache_fingerprint() выше, но здесь нужен сам
    // CertID (для сборки комбинированного батч-запроса и для точного
    // поиска TTL в комбинированном ответе через OCSP_resp_find()), а не
    // его фингерпринт. Возвращает НОВУЮ дублированную копию
    // (OCSP_CERTID_dup) — исходный OCSP_REQUEST, из которого CertID
    // извлекается, освобождается сразу после вызова, так что вызывающий
    // код обязан сам освободить результат через OCSP_CERTID_free().
    static OCSP_CERTID* extract_certid_dup(const std::vector<uint8_t>& request_der) {
        const unsigned char* p = request_der.data();
        OCSP_REQUEST* ocsp_req = d2i_OCSP_REQUEST(nullptr, &p, static_cast<long>(request_der.size()));
        if (ocsp_req == nullptr) return nullptr;

        OCSP_CERTID* result = nullptr;
        if (OCSP_request_onereq_count(ocsp_req) > 0) {
            OCSP_ONEREQ* one_req = OCSP_request_onereq_get0(ocsp_req, 0);
            OCSP_CERTID* cert_id = (one_req != nullptr) ? OCSP_onereq_get0_id(one_req) : nullptr;
            if (cert_id != nullptr) result = OCSP_CERTID_dup(cert_id);
        }
        OCSP_REQUEST_free(ocsp_req);
        return result;
    }

    // ROADMAP.md, раздел 2, пункт 14 (P2): строит ОДИН комбинированный
    // OCSP_REQUEST (RFC 6960 §4.1 допускает несколько Request/CertID в
    // одном OCSPRequest) из нескольких отдельных одиночных OCSP-запросов
    // — извлекает CertID каждого через extract_certid_dup() и добавляет
    // в общий запрос через OCSP_request_add0_id() (владение дублированным
    // CertID переходит комбинированному запросу — "0" в имени функции по
    // конвенции OpenSSL означает именно это). Возвращает DER
    // комбинированного запроса, либо nullopt, если хотя бы один из
    // входных request_der не разобрался или в нём нет CertID — батчинг в
    // этом случае не применяется вовсе (см. handle_ocsp_batch(): при
    // nullopt группа обрабатывается как набор независимых одиночных
    // запросов, не как ошибка всего батча).
    static std::optional<std::vector<uint8_t>> build_combined_ocsp_request(
        const std::vector<std::vector<uint8_t>>& request_ders) {
        OCSP_REQUEST* combined = OCSP_REQUEST_new();
        bool ok = true;
        for (const auto& der : request_ders) {
            OCSP_CERTID* dup = extract_certid_dup(der);
            if (dup == nullptr) {
                ok = false;
                break;
            }
            if (OCSP_request_add0_id(combined, dup) == nullptr) {
                OCSP_CERTID_free(dup); // add0_id не принял — владение НЕ перешло, освобождаем сами
                ok = false;
                break;
            }
        }

        if (!ok) {
            OCSP_REQUEST_free(combined);
            return std::nullopt;
        }

        unsigned char* out_der = nullptr;
        int len = i2d_OCSP_REQUEST(combined, &out_der);
        OCSP_REQUEST_free(combined);
        if (len <= 0 || out_der == nullptr) return std::nullopt;

        std::vector<uint8_t> result(out_der, out_der + len);
        OPENSSL_free(out_der);
        return result;
    }

    // ROADMAP.md, раздел 2, пункт 14 (P2): certid — опциональный
    // указатель на конкретный CertID, чей SingleResponse нужно найти
    // внутри ocsp_resp (через OCSP_resp_find()) для вычисления TTL. Это
    // важно для батчинга: комбинированный ответ на несколько CertID
    // содержит несколько SingleResponse с потенциально РАЗНЫМИ nextUpdate
    // (разные сертификаты, разная свежесть у самого CA), так что нельзя
    // просто взять "первый попавшийся" SingleResponse для КАЖДОГО из
    // исходных батч-запросов — нужно найти именно СВОЙ. certid == nullptr
    // (одиночный, небатчевый fetch_ocsp) сохраняет прежнее поведение —
    // берём первый (и обычно единственный) SingleResponse.
    int64_t ocsp_response_ttl_seconds(const std::vector<uint8_t>& der, const OCSP_CERTID* certid = nullptr) {
        const unsigned char* p = der.data();
        OCSP_RESPONSE* ocsp_resp = d2i_OCSP_RESPONSE(nullptr, &p, static_cast<long>(der.size()));
        if (ocsp_resp == nullptr) {
            return clamp_ocsp_ttl(config.default_ocsp_ttl_seconds); // не разобрали — короткий дефолтный TTL
        }

        int64_t ttl = config.default_ocsp_ttl_seconds;
        OCSP_BASICRESP* basic = OCSP_response_get1_basic(ocsp_resp);
        if (basic != nullptr) {
            int index = 0;
            if (certid != nullptr) {
                int found = OCSP_resp_find(basic, const_cast<OCSP_CERTID*>(certid), -1);
                if (found >= 0) index = found;
                // Не нашли (не должно случаться, если ответ реально
                // содержит статус запрошенного сертификата) — остаёмся на
                // index 0, тот же fallback, что и для certid == nullptr.
            }
            OCSP_SINGLERESP* single = OCSP_resp_get0(basic, index);
            if (single != nullptr) {
                ASN1_GENERALIZEDTIME* next_update = nullptr;
                if (OCSP_single_get0_status(single, nullptr, nullptr, nullptr, &next_update) >= 0 &&
                    next_update != nullptr) {
                    auto parsed = asn1_time_to_unix(next_update);
                    if (parsed) {
                        int64_t seconds_from_now = *parsed - now_seconds();
                        if (seconds_from_now > 0) ttl = seconds_from_now;
                    }
                }
            }
            OCSP_BASICRESP_free(basic);
        }
        OCSP_RESPONSE_free(ocsp_resp);
        return clamp_ocsp_ttl(ttl);
    }

    int64_t crl_ttl_seconds(const std::vector<uint8_t>& der) {
        const unsigned char* p = der.data();
        X509_CRL* crl = d2i_X509_CRL(nullptr, &p, static_cast<long>(der.size()));
        if (crl == nullptr) {
            return clamp_crl_ttl(config.default_crl_ttl_seconds);
        }
        int64_t ttl = config.default_crl_ttl_seconds;
        const ASN1_TIME* next_update = X509_CRL_get0_nextUpdate(crl);
        if (next_update != nullptr) {
            auto parsed = asn1_time_to_unix(next_update);
            if (parsed) {
                int64_t seconds_from_now = *parsed - now_seconds();
                if (seconds_from_now > 0) ttl = seconds_from_now;
            }
        }
        X509_CRL_free(crl);
        return clamp_crl_ttl(ttl);
    }

    // ROADMAP.md, раздел 1, пункт 2 (P0): верхняя граница TTL для
    // OCSP/CRL, независимая от того, что responder/CA заявил в
    // nextUpdate. Клампит только сверху — короткий/отсутствующий
    // nextUpdate (наш собственный default_*_ttl_seconds) не удлиняется.
    int64_t clamp_ocsp_ttl(int64_t ttl) const {
        return std::min(ttl, static_cast<int64_t>(config.max_ocsp_ttl_seconds));
    }
    int64_t clamp_crl_ttl(int64_t ttl) const {
        return std::min(ttl, static_cast<int64_t>(config.max_crl_ttl_seconds));
    }

    static std::optional<int64_t> asn1_time_to_unix(const ASN1_TIME* t) {
        if (t == nullptr) return std::nullopt;
        struct tm tm_val{};
        if (ASN1_TIME_to_tm(t, &tm_val) != 1) return std::nullopt;
        time_t result = timegm(&tm_val);
        if (result == static_cast<time_t>(-1)) return std::nullopt;
        return static_cast<int64_t>(result);
    }

    // ROADMAP.md, раздел 1, пункт 6 (P2): caIssuers-ответ иногда приходит
    // как PKCS#7 "degenerate" контейнер (ContentInfo/SignedData без
    // подписи — просто обёртка вокруг набора сертификатов) вместо голого
    // DER X.509 — сервера расходятся в поведении, RFC 4325 не диктует
    // формат. Разбираем ASN.1-структуру напрямую (не смотрим
    // Content-Type из ответа — заголовок, присланный сервером, доверия не
    // заслуживает больше, чем само тело, а структурная проверка и надёжнее,
    // и проще: d2i_X509/d2i_PKCS7 сами по себе взаимно исключающи, т.к.
    // верхнеуровневые ASN.1-структуры Certificate и PKCS#7 ContentInfo
    // различаются). Если контейнер содержит несколько сертификатов (может
    // случиться — некоторые CA кладут туда весь оставшийся хвост цепочки,
    // а не только непосредственного эмитента) — берём первый: на практике
    // те CA, что вообще используют PKCS#7 для caIssuers, кладут
    // непосредственного эмитента первым (тот же порядок, что и в TLS
    // Certificate message). У демона нет информации об ожидаемом issuer,
    // чтобы выбрать точнее (FetchIntermediateCertRequest её не передаёт —
    // это осознанное ограничение этой версии, а не забытый край).
    //
    // Возвращает DER-байты ОДНОГО сертификата (после i2d_X509, т.е. заново
    // закодированные, а не байты, вырезанные из контейнера вручную) — это
    // сохраняет контракт handle_intermediate_cert_impl() и всего, что
    // ниже по цепочке (клампинг TTL по notAfter, D-Bus payload_der и т.д.):
    // ровно один сертификат в чистом DER, независимо от того, как он был
    // упакован в HTTP-ответе.
    static std::optional<std::vector<uint8_t>> extract_single_der_certificate(
        const std::vector<uint8_t>& payload) {
        if (payload.empty()) return std::nullopt;

        // Случай 1 (наиболее распространённый): голый DER X.509 как есть.
        {
            const unsigned char* p = payload.data();
            X509* cert = d2i_X509(nullptr, &p, static_cast<long>(payload.size()));
            if (cert != nullptr) {
                X509_free(cert);
                return payload; // уже в нужном виде, повторное кодирование не нужно
            }
        }

        // Случай 2: PKCS#7 "degenerate" контейнер.
        const unsigned char* p = payload.data();
        PKCS7* p7 = d2i_PKCS7(nullptr, &p, static_cast<long>(payload.size()));
        if (p7 == nullptr) return std::nullopt;

        STACK_OF(X509)* certs = nullptr;
        int nid = OBJ_obj2nid(p7->type);
        if (nid == NID_pkcs7_signed && p7->d.sign != nullptr) {
            certs = p7->d.sign->cert;
        } else if (nid == NID_pkcs7_signedAndEnveloped && p7->d.signed_and_enveloped != nullptr) {
            certs = p7->d.signed_and_enveloped->cert;
        }

        if (certs == nullptr || sk_X509_num(certs) <= 0) {
            PKCS7_free(p7);
            return std::nullopt;
        }

        X509* chosen = sk_X509_value(certs, 0); // см. комментарий выше про выбор первого
        unsigned char* der_out = nullptr;
        int der_len = i2d_X509(chosen, &der_out);
        PKCS7_free(p7); // chosen указывал внутрь p7 — освобождать после i2d, не раньше

        if (der_len <= 0 || der_out == nullptr) return std::nullopt;
        std::vector<uint8_t> result(der_out, der_out + der_len);
        OPENSSL_free(der_out);
        return result;
    }

    // Возвращает notAfter докачанного сертификата в unix-времени, если
    // сертификат разбирается и поле корректно парсится. handle_
    // intermediate_cert_impl() уже вызвал extract_single_der_certificate()
    // раньше — здесь намеренно разбираем DER повторно, а не протаскиваем
    // X509* наружу: так handle_intermediate_cert_impl() не обязан знать
    // про управление временем жизни OpenSSL-объекта.
    static std::optional<int64_t> cert_not_after_unix(const std::vector<uint8_t>& der) {
        const unsigned char* p = der.data();
        X509* cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
        if (cert == nullptr) return std::nullopt;
        const ASN1_TIME* not_after = X509_get0_notAfter(cert);
        auto result = asn1_time_to_unix(not_after);
        X509_free(cert);
        return result;
    }

    // ROADMAP.md, раздел 1, пункт 1 (P0): TTL кэша для докачанного
    // промежуточного сертификата не должен пережить собственный notAfter
    // сертификата — иначе демон способен ещё долго (вплоть до
    // aia_ttl_seconds) отдавать уже просроченный сертификат из кэша.
    // Клампим только сверху (аналогично apply_http_cache_hints выше) —
    // никогда не удлиняем TTL, если notAfter окажется дальше в будущем,
    // чем computed_ttl.
    int64_t clamp_ttl_to_cert_not_after(int64_t ttl, const std::vector<uint8_t>& cert_der) const {
        if (ttl <= 0) return ttl; // уже не кэшируем (see apply_http_cache_hints) — клампить нечего

        auto not_after = cert_not_after_unix(cert_der);
        if (!not_after) {
            // Не смогли распарсить notAfter отдельно, хотя чуть раньше
            // extract_single_der_certificate() уже вернула валидный DER
            // X.509 (то же самое d2i_X509) — на практике не должно
            // происходить, но на случай экзотического ASN1_TIME, который
            // ASN1_TIME_to_tm() не берёт, ведём себя консервативно: не
            // удлиняем и не укорачиваем TTL сверх того, что уже посчитано
            // по aia_ttl_seconds/HTTP cache hints.
            return ttl;
        }

        int64_t remaining = *not_after - now_seconds();
        if (remaining <= 0) return 0; // сертификат уже просрочен — вообще не кэшировать
        return std::min(ttl, remaining);
    }

    cache::ICacheStore& cache_store;
    http::IHttpFetcher& http_fetcher;
    Config config;
    // ROADMAP.md, раздел 1, пункт 9: nullptr по умолчанию (--allow-ldap
    // не включён в daemon_main.cpp) — ldap:// CRL URL в этом случае
    // трактуются как NetworkError, а не как что-то, требующее отдельной
    // обработки. Не владеющий указатель — время жизни управляется
    // daemon_main.cpp (или тестом), как и для http_fetcher/cache_store.
    ldap::ILdapFetcher* ldap_fetcher = nullptr;

    // Счётчики наблюдаемости по типу запроса (пункт 5 из анализа Squid) —
    // живут с момента старта процесса, не персистентны между рестартами
    // демона (в отличие от самого кэша, который переживает рестарт).
    AtomicTypeStats ocsp_stats;
    AtomicTypeStats crl_stats;
    AtomicTypeStats intermediate_cert_stats;

    // ROADMAP.md, раздел 1, пункт 5 (P1): singleflight-дедупликация.
    // См. singleflight_execute() выше. Отдельная от inflight_ мьютекс:
    // защищает только саму map (поиск/вставку/удаление записей), не
    // выполнение impl_fn() — см. комментарий внутри singleflight_execute.
    std::mutex inflight_mutex_;
    std::unordered_map<std::string, std::shared_ptr<InFlightState>> inflight_;

    // ROADMAP.md, раздел 2, пункт 11 (P1): circuit breaker per-host. См.
    // подробный комментарий в начале файла. breakers_mutex_ защищает
    // только саму map (тот же принцип, что inflight_mutex_ выше) — сама
    // работа с конкретным CircuitBreakerState синхронизируется его
    // собственным state->mtx.
    std::mutex breakers_mutex_;
    std::unordered_map<std::string, std::shared_ptr<CircuitBreakerState>> breakers_;
};

} // namespace cert_helper
