// protocol.hpp
//
// Плоские структуры запросов/ответов, которыми оперирует RequestRouter.
//
// ИСТОРИЯ ИЗМЕНЕНИЙ: до перехода на D-Bus этот файл также содержал
// самодельный бинарный формат сериализации (Reader/Writer/encode_*/
// decode_*) для транспорта поверх Unix domain socket. После перехода на
// D-Bus (см. src/ipc/dbus_interface.hpp, src/ipc/dbus_server.hpp,
// src/client_impl/dbus_client.hpp) маршалинг сообщений на проводе делает
// сама библиотека D-Bus (sd-bus) по стандартному D-Bus wire-протоколу —
// самодельная сериализация стала не нужна и была убрана, чтобы не
// поддерживать два параллельных представления одних и тех же данных.
//
// Эти структуры остаются как удобный внутренний контракт между
// транспортным слоем (dbus_server.hpp) и бизнес-логикой
// (request_router.hpp) — RequestRouter ничего не знает о D-Bus, только о
// этих POD-структурах.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cert_helper::protocol {

enum class FetchStatus : uint8_t {
    Ok = 0,
    Timeout = 1,
    NetworkError = 2,
    InvalidResponse = 3, // сервер ответил, но данные не разобрать / не прошли проверку
};

struct FetchOcspRequest {
    std::string responder_url;
    std::vector<uint8_t> request_der;
    uint32_t timeout_ms = 5000;
};

struct FetchCrlRequest {
    std::string distribution_point_url;
    uint32_t timeout_ms = 5000;
};

struct FetchIntermediateCertRequest {
    std::string aia_url;
    uint32_t timeout_ms = 5000;
};

struct FetchResponse {
    FetchStatus status = FetchStatus::NetworkError;
    std::vector<uint8_t> payload_der;
    bool from_cache = false;
};

// ROADMAP.md, раздел 2, пункт 14 (P2): батчинг OCSP-запросов. RFC 6960
// §4.1 допускает несколько Request (CertID) в одном OCSPRequest — если
// tls-mitm запрашивает статус нескольких сертификатов цепочки почти
// одновременно (типичный случай: вся цепочка, полученная за один TLS
// handshake), можно объединить их в один HTTP round-trip к общему
// responder'у вместо одного round-trip'а на каждый сертификат.
//
// Элементы requests могут указывать РАЗНЫЕ responder_url — RequestRouter
// сам группирует их по responder_url и объединяет в один OCSP_REQUEST
// только запросы с одинаковым responder_url; для остальных выполняется
// обычный одиночный fetch. Результат (FetchOcspBatchResponse::responses)
// имеет тот же размер и порядок, что и requests — responses[i]
// соответствует requests[i].
//
// ВАЖНО: responses[i].payload_der для нескольких запросов, объединённых
// в одну группу, — это ОДИН И ТОТ ЖЕ (побайтово идентичный) блок DER —
// весь комбинированный OCSPResponse со всеми SingleResponse сразу, а НЕ
// синтезированный "персональный" ответ на каждый сертификат по
// отдельности. Это не упрощение, а необходимость: подпись responder'а
// покрывает tbsResponseData целиком (все SingleResponse вместе), так что
// вырезать один SingleResponse в отдельный "поддельный" OCSPResponse
// сделало бы его подпись невалидной. Вызывающая сторона (tls-mitm) и так
// умеет находить нужный SingleResponse внутри ответа по своему CertID
// (та же логика, что и для одиночного fetch_ocsp, если бы responder сам
// решил вернуть несколько SingleResponse на один Request — RFC 6960 это
// не запрещает) — получать общий блок для всех батч-запросов из одной
// группы для неё ничем не отличается от одиночного ответа с несколькими
// SingleResponse.
struct FetchOcspBatchRequest {
    std::vector<FetchOcspRequest> requests;
};

struct FetchOcspBatchResponse {
    std::vector<FetchResponse> responses; // тот же размер/порядок, что и requests
};

// Разбивка наблюдаемости по типу запроса (пункт 5: "раздельная
// наблюдаемость по типам", по аналогии с тем, что Squid маркирует
// AIA-докачку отдельным transaction_initiator=certificate-fetching и даёт
// админу видеть/фильтровать этот класс трафика отдельно). requests —
// общее число запросов этого типа с момента старта демона; cache_hits —
// сколько из них обслужено из кэша; errors — сумма
// Timeout+NetworkError+InvalidResponse (детализация по подтипу ошибки —
// возможное будущее расширение, для первой версии агрегата достаточно).
struct RequestTypeStats {
    uint64_t requests = 0;
    uint64_t cache_hits = 0;
    uint64_t errors = 0;
};

struct HealthCheckResponse {
    bool healthy = true;
    uint64_t cache_entries = 0;
    uint64_t cache_size_bytes = 0;
    // Заполняются, только если демон настроен с in-memory слоем поверх
    // диска (пункт 2 из анализа Squid, см. cache/two_tier_cache.hpp).
    // Остаются нулями, если работает "голый" FileCacheStore.
    uint64_t memory_cache_entries = 0;
    uint64_t memory_cache_size_bytes = 0;
    RequestTypeStats ocsp;
    RequestTypeStats crl;
    RequestTypeStats intermediate_cert;
};

} // namespace cert_helper::protocol
