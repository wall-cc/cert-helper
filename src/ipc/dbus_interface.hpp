// dbus_interface.hpp
//
// Общие константы D-Bus интерфейса cert-helper — единственное место,
// которое должны использовать и сервер (dbus_server.hpp), и клиент
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
    /// TODO: Возможно `char const*` лучше заменить на `std::string_view`

    /**
     * @brief Well-known имя D-Bus-сервиса cert-helper на системной шине.
     * @details Регистрируется сервером через sd_bus_request_name() в
     *          DbusServer::start(); клиенты используют его как адрес сервиса
     *          при вызове sd_bus_call_method(). Совпадает с INTERFACE_NAME —
     *          сделано намеренно, чтобы сервис, объект и интерфейс
     *          именовались одинаково (упрощает диагностику `busctl
     *          introspect org.certhelper.CertHelper1 /org/certhelper/CertHelper1`).
     */
    inline constexpr char const* SERVICE_NAME = "org.certhelper.CertHelper1";

    /**
     * @brief Путь объекта (object path), на котором регистрируется vtable
     *        интерфейса (см. sd_bus_add_object_vtable в DbusServer::start()).
     * @details Соответствует конвенции: обратный DNS-домен в виде сегментов
     *          пути + суффикс версии API.
     */
    inline constexpr char const* OBJECT_PATH = "/org/certhelper/CertHelper1";

    /**
     * @brief Имя интерфейса D-Bus (последний аргумент
     *        sd_bus_add_object_vtable()).
     * @details Именно это имя клиент передаёт вторым аргументом
     *          sd_bus_call_method() вместе с SERVICE_NAME и OBJECT_PATH.
     *          Совпадает с SERVICE_NAME — см. выше пояснение про одинаковое
     *          именование.
     */
    inline constexpr char const* INTERFACE_NAME = "org.certhelper.CertHelper1";

    /**
     * @brief Имя метода FetchOcsp (одиночный OCSP-запрос).
     * @details Сигнатура D-Bus: "sayu" -> "yayb" (см. VTABLE в
     *          dbus_server.cpp). Используется и сервером (в SD_BUS_METHOD),
     *          и клиентом (в sd_bus_call_method).
     */
    inline constexpr char const* METHOD_FETCH_OCSP = "FetchOcsp";

    /**
     * @brief Имя метода FetchOcspBatch (пакетный OCSP-запрос).
     * @details Сигнатура: "a(sayu)" -> "a(yayb)". Позволяет клиенту одним
     *          round-trip'ом отправить N независимых OCSP-запросов (например
     *          для цепочки сертификатов при TLS handshake) — см.
     *          on_fetch_ocsp_batch в dbus_server.cpp.
     */
    inline constexpr char const* METHOD_FETCH_OCSP_BATCH = "FetchOcspBatch";

    /**
     * @brief Имя метода FetchCrl (запрос CRL по distribution point).
     * @details Сигнатура: "su" -> "yayb".
     */
    inline constexpr char const* METHOD_FETCH_CRL = "FetchCrl";

    /**
     * @brief Имя метода FetchIntermediateCert (запрос промежуточного
     *        сертификата через AIA-URL).
     * @details Сигнатура: "su" -> "yayb".
     */
    inline constexpr char const* METHOD_FETCH_INTERMEDIATE_CERT = "FetchIntermediateCert";

    /**
     * @brief Имя метода HealthCheck (телеметрия/health-проба демона).
     * @details Сигнатура: "" -> "bttttttttttttt" (b + 13 полей t). Выполняется
     *          синхронно в bus-потоке: не делает сети и не блокирует пул
     *          воркеров (см. on_health_check в dbus_server.cpp).
     */
    inline constexpr char const* METHOD_HEALTH_CHECK = "HealthCheck";

    /**
     * @brief Имя D-Bus-ошибки, которой отвечает сервер при неожиданном
     *        C++-исключении внутри обработчика запроса.
     * @details Отправляется через sd_bus_message_new_method_errorf() из
     *          send_internal_error_reply() (dbus_server.cpp). Соглашение об
     *          именовании — тем же reversed-DNS-префиксом, что и сам
     *          интерфейс, плюс ".Error.<Класс>". Клиенты могут
     *          различать эту ошибку и штатные FetchStatus (последние
     *          приходят как обычный ответ с полем status).
     */
    inline constexpr char const* ERROR_INTERNAL_FAILURE = "org.certhelper.CertHelper1.Error.InternalFailure";

}  // namespace cert_helper::ipc