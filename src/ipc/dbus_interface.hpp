// dbus_interface.hpp
//
// Общие константы D-Bus интерфейса cert-helper — единственное место,
// которое должны использовать и сервер (dbus_server.hpp), и клиент
// (client_impl/dbus_client.hpp), чтобы имена не могли разойтись.
//
// Именование выбрано по конвенции reversed-DNS, принятой в экосистеме
// D-Bus (org.freedesktop.*, org.freedesktop.NetworkManager и т.п.):
// домен вымышленный (org.certhelper), суффикс "1" в имени интерфейса и
// объекта — по конвенции systemd/D-Bus API-версионирования (аналогично
// org.freedesktop.systemd1) — позволяет в будущем ввести
// org.certhelper.CertHelper2 с несовместимым интерфейсом, не трогая
// первую версию.
//
// Метод API (сигнатуры — D-Bus type strings):
//   FetchOcsp(s responder_url, ay request_der, u timeout_ms)
//       -> (y status, ay payload_der, b from_cache)
//   FetchOcspBatch(a(sayu) requests)
//       -> (a(yayb) responses)
//       ROADMAP.md, раздел 2, пункт 14: батчинг нескольких OCSP-запросов
//       в один вызов — requests/responses один-к-одному по индексу (см.
//       protocol.hpp::FetchOcspBatchRequest/Response за подробностями,
//       включая важное объяснение того, почему несколько ответов из
//       одной группы могут получить ПОБАЙТОВО ИДЕНТИЧНЫЙ payload_der).
//   FetchCrl(s distribution_point_url, u timeout_ms)
//       -> (y status, ay payload_der, b from_cache)
//   FetchIntermediateCert(s aia_url, u timeout_ms)
//       -> (y status, ay payload_der, b from_cache)
//   HealthCheck()
//       -> (b healthy,
//           t cache_entries, t cache_size_bytes,
//           t memory_cache_entries, t memory_cache_size_bytes,
//           t ocsp_requests, t ocsp_cache_hits, t ocsp_errors,
//           t crl_requests, t crl_cache_hits, t crl_errors,
//           t aia_requests, t aia_cache_hits, t aia_errors)
//
// status (y/byte) кодирует cert_helper::protocol::FetchStatus:
//   0 = Ok, 1 = Timeout, 2 = NetworkError, 3 = InvalidResponse.
//
// Разбивка HealthCheck по типам запроса (ocsp/crl/aia) и по уровню кэша
// (memory/disk) — счётчики с момента старта процесса демона (не
// персистентны между рестартами), см.
// cert_helper::protocol::RequestTypeStats, cache/two_tier_cache.hpp и
// обоснование в request_router.hpp.

#pragma once

namespace cert_helper::ipc {

inline constexpr const char* kServiceName = "org.certhelper.CertHelper1";
inline constexpr const char* kObjectPath = "/org/certhelper/CertHelper1";
inline constexpr const char* kInterfaceName = "org.certhelper.CertHelper1";

inline constexpr const char* kMethodFetchOcsp = "FetchOcsp";
inline constexpr const char* kMethodFetchOcspBatch = "FetchOcspBatch";
inline constexpr const char* kMethodFetchCrl = "FetchCrl";
inline constexpr const char* kMethodFetchIntermediateCert = "FetchIntermediateCert";
inline constexpr const char* kMethodHealthCheck = "HealthCheck";

} // namespace cert_helper::ipc
