// dbus_client.hpp
//
// Синхронный клиент cert-helper поверх D-Bus (sd-bus). Каждый вызов
// использует sd_bus_call() — блокирующий синхронный метод-вызов с
// явным таймаутом, что соответствует требованию раздела 2.3
// первоначального ТЗ: вызывающая сторона (внутри receive() библиотеки
// tls-mitm, во время приостановленного TLS handshake) ждёт ответа
// блокирующе.
//
// Соединение (sd_bus*) устанавливается лениво при первом вызове и
// переиспользуется для последующих — держать одно соединение вместо
// "одно соединение на вызов" здесь дешевле и естественнее, чем было бы
// для сырого UDS: D-Bus и так мультиплексирует несколько одновременных
// pending-вызовов на одном соединении на уровне протокола (serial
// numbers), так что переиспользование не жертвует параллelizmом там, где
// он был важен раньше.

#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <systemd/sd-bus.h>

#include "../ipc/dbus_interface.hpp"
#include "../../include/cert_helper/protocol.hpp"

namespace cert_helper::client_impl {

namespace proto = cert_helper::protocol;

class DbusClientError : public std::runtime_error {
public:
    explicit DbusClientError(const std::string& what) : std::runtime_error(what) {}
};

class DbusClient {
public:
    // ВАЖНО (контракт исключений): ни один из публичных методов этого
    // класса не бросает наружу DbusClientError — сбой подключения к шине
    // трактуется как обычная сетевая ошибка (FetchStatus::NetworkError /
    // HealthResult::reachable=false), а не как исключительная ситуация.
    // Это соответствует контракту tls_mitm::OcspFetcher/CrlFetcher выше
    // по стеку (client.hpp): вызывающая сторона (handshake в tls-mitm) не
    // должна упасть из-за недоступности демона.

    // bus_address пустой => системная шина (sd_bus_open_system). Непустой
    // => подключение к указанному адресу (используется в тестах —
    // приватный dbus-daemon на своём сокете).
    explicit DbusClient(std::string bus_address = {}) : bus_address(std::move(bus_address)) {}

    ~DbusClient() {
        if (bus != nullptr) sd_bus_unref(bus);
    }

    DbusClient(const DbusClient&) = delete;
    DbusClient& operator=(const DbusClient&) = delete;

    proto::FetchResponse fetch_ocsp(const std::string& responder_url,
                                     const std::vector<uint8_t>& request_der, uint32_t timeout_ms) {
        proto::FetchResponse failure;
        failure.status = proto::FetchStatus::NetworkError;
        try {
            ensure_connected();
        } catch (const DbusClientError&) {
            return failure; // шина недоступна — тот же контракт, что и у router'а на сетевую ошибку
        }
        sd_bus_message* msg = nullptr;
        int r = sd_bus_message_new_method_call(bus, &msg, ipc::kServiceName, ipc::kObjectPath,
                                                ipc::kInterfaceName, ipc::kMethodFetchOcsp);
        if (r >= 0) r = sd_bus_message_append(msg, "s", responder_url.c_str());
        if (r >= 0) {
            const void* data = request_der.empty() ? nullptr : request_der.data();
            r = sd_bus_message_append_array(msg, 'y', data, request_der.size());
        }
        if (r >= 0) r = sd_bus_message_append(msg, "u", timeout_ms);
        return call_and_parse_fetch(r, msg, timeout_ms);
    }

    // ROADMAP.md, раздел 2, пункт 14 (P2): батчинг OCSP-запросов — один
    // D-Bus вызов вместо N, cert-helper сам решает, объединять ли их в
    // один HTTP round-trip (см. RequestRouter::handle_ocsp_batch()).
    // Результат — тот же размер/порядок, что и requests; при ошибке
    // связи с демоном (шина недоступна, вызов оборван) ВСЕ элементы
    // получают одинаковый NetworkError/Timeout — тот же принцип "ошибка
    // канала связи одинакова для всех, кто через него общался", что и у
    // одиночных fetch_*.
    std::vector<proto::FetchResponse> fetch_ocsp_batch(
        const std::vector<proto::FetchOcspRequest>& requests, uint32_t timeout_ms) {
        auto failure_for_all = [&] {
            proto::FetchResponse failure;
            failure.status = proto::FetchStatus::NetworkError;
            return std::vector<proto::FetchResponse>(requests.size(), failure);
        };

        try {
            ensure_connected();
        } catch (const DbusClientError&) {
            return failure_for_all();
        }

        sd_bus_message* msg = nullptr;
        int r = sd_bus_message_new_method_call(bus, &msg, ipc::kServiceName, ipc::kObjectPath,
                                                ipc::kInterfaceName, ipc::kMethodFetchOcspBatch);
        if (r >= 0) r = sd_bus_message_open_container(msg, SD_BUS_TYPE_ARRAY, "(sayu)");
        if (r >= 0) {
            for (const auto& req : requests) {
                r = sd_bus_message_open_container(msg, SD_BUS_TYPE_STRUCT, "sayu");
                if (r < 0) break;
                r = sd_bus_message_append(msg, "s", req.responder_url.c_str());
                if (r >= 0) {
                    const void* data = req.request_der.empty() ? nullptr : req.request_der.data();
                    r = sd_bus_message_append_array(msg, 'y', data, req.request_der.size());
                }
                if (r >= 0) r = sd_bus_message_append(msg, "u", req.timeout_ms);
                if (r >= 0) r = sd_bus_message_close_container(msg); // закрывает этот STRUCT
                if (r < 0) break;
            }
        }
        if (r >= 0) r = sd_bus_message_close_container(msg); // закрывает ARRAY

        if (r < 0) {
            if (msg != nullptr) sd_bus_message_unref(msg);
            return failure_for_all();
        }

        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        r = sd_bus_call(bus, msg, timeout_ms_to_usec(timeout_ms), &error, &reply);
        sd_bus_message_unref(msg);
        sd_bus_error_free(&error);
        if (r < 0) {
            return failure_for_all();
        }

        std::vector<proto::FetchResponse> results;
        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(yayb)");
        if (r < 0) {
            sd_bus_message_unref(reply);
            return failure_for_all();
        }

        while (true) {
            r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_STRUCT, "yayb");
            if (r < 0) {
                sd_bus_message_unref(reply);
                return failure_for_all();
            }
            if (r == 0) break; // элементы кончились

            uint8_t status_byte = static_cast<uint8_t>(proto::FetchStatus::InvalidResponse);
            const void* payload_ptr = nullptr;
            size_t payload_len = 0;
            int from_cache_int = 0;

            r = sd_bus_message_read(reply, "y", &status_byte);
            if (r >= 0) r = sd_bus_message_read_array(reply, 'y', &payload_ptr, &payload_len);
            if (r >= 0) r = sd_bus_message_read(reply, "b", &from_cache_int);

            proto::FetchResponse resp;
            if (r >= 0) {
                // См. call_and_parse_fetch() ниже про то, почему payload
                // копируется ДО закрытия контейнера/unref сообщения —
                // тот же риск use-after-free на указателе внутрь буфера
                // sd_bus_message.
                if (payload_len > 0) {
                    resp.payload_der.assign(static_cast<const uint8_t*>(payload_ptr),
                                             static_cast<const uint8_t*>(payload_ptr) + payload_len);
                }
                resp.status = static_cast<proto::FetchStatus>(status_byte);
                resp.from_cache = from_cache_int != 0;
            } else {
                resp.status = proto::FetchStatus::InvalidResponse;
            }
            results.push_back(std::move(resp));

            r = sd_bus_message_exit_container(reply); // закрывает STRUCT этого элемента
            if (r < 0) {
                sd_bus_message_unref(reply);
                return failure_for_all();
            }
        }
        sd_bus_message_exit_container(reply); // закрывает ARRAY
        sd_bus_message_unref(reply);

        // Контракт с вызывающей стороной (RequestRouter): один элемент
        // ответа на каждый элемент запроса, в том же порядке — если
        // сервер почему-то прислал другое количество (не должно
        // случаться при исправной реализации по обе стороны), безопаснее
        // вернуть равномерный NetworkError для всех, чем молча
        // рассинхронизировать индексы между requests и results.
        if (results.size() != requests.size()) {
            return failure_for_all();
        }
        return results;
    }

    proto::FetchResponse fetch_crl(const std::string& distribution_point_url, uint32_t timeout_ms) {
        proto::FetchResponse failure;
        failure.status = proto::FetchStatus::NetworkError;
        try {
            ensure_connected();
        } catch (const DbusClientError&) {
            return failure;
        }
        sd_bus_message* msg = nullptr;
        int r = sd_bus_message_new_method_call(bus, &msg, ipc::kServiceName, ipc::kObjectPath,
                                                ipc::kInterfaceName, ipc::kMethodFetchCrl);
        if (r >= 0) r = sd_bus_message_append(msg, "s", distribution_point_url.c_str());
        if (r >= 0) r = sd_bus_message_append(msg, "u", timeout_ms);
        return call_and_parse_fetch(r, msg, timeout_ms);
    }

    proto::FetchResponse fetch_intermediate_cert(const std::string& aia_url, uint32_t timeout_ms) {
        proto::FetchResponse failure;
        failure.status = proto::FetchStatus::NetworkError;
        try {
            ensure_connected();
        } catch (const DbusClientError&) {
            return failure;
        }
        sd_bus_message* msg = nullptr;
        int r = sd_bus_message_new_method_call(bus, &msg, ipc::kServiceName, ipc::kObjectPath,
                                                ipc::kInterfaceName, ipc::kMethodFetchIntermediateCert);
        if (r >= 0) r = sd_bus_message_append(msg, "s", aia_url.c_str());
        if (r >= 0) r = sd_bus_message_append(msg, "u", timeout_ms);
        return call_and_parse_fetch(r, msg, timeout_ms);
    }

    struct HealthResult {
        bool reachable = false;
        proto::HealthCheckResponse health;
    };

    HealthResult health_check(uint32_t timeout_ms) {
        HealthResult result;
        try {
            ensure_connected();
        } catch (const DbusClientError&) {
            return result; // reachable остаётся false
        }

        sd_bus_message* msg = nullptr;
        int r = sd_bus_message_new_method_call(bus, &msg, ipc::kServiceName, ipc::kObjectPath,
                                                ipc::kInterfaceName, ipc::kMethodHealthCheck);
        if (r < 0) return result;

        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        r = sd_bus_call(bus, msg, timeout_ms_to_usec(timeout_ms), &error, &reply);
        sd_bus_message_unref(msg);
        sd_bus_error_free(&error);
        if (r < 0) return result;

        int healthy_int = 0;
        uint64_t cache_entries = 0, cache_size_bytes = 0;
        uint64_t mem_entries = 0, mem_size_bytes = 0;
        uint64_t ocsp_requests = 0, ocsp_hits = 0, ocsp_errors = 0;
        uint64_t crl_requests = 0, crl_hits = 0, crl_errors = 0;
        uint64_t aia_requests = 0, aia_hits = 0, aia_errors = 0;

        r = sd_bus_message_read(reply, "bttttttttttttt", &healthy_int, &cache_entries,
                                 &cache_size_bytes, &mem_entries, &mem_size_bytes, &ocsp_requests,
                                 &ocsp_hits, &ocsp_errors, &crl_requests, &crl_hits, &crl_errors,
                                 &aia_requests, &aia_hits, &aia_errors);
        sd_bus_message_unref(reply);
        if (r < 0) return result;

        result.reachable = true;
        result.health.healthy = healthy_int != 0;
        result.health.cache_entries = cache_entries;
        result.health.cache_size_bytes = cache_size_bytes;
        result.health.memory_cache_entries = mem_entries;
        result.health.memory_cache_size_bytes = mem_size_bytes;
        result.health.ocsp = {ocsp_requests, ocsp_hits, ocsp_errors};
        result.health.crl = {crl_requests, crl_hits, crl_errors};
        result.health.intermediate_cert = {aia_requests, aia_hits, aia_errors};
        return result;
    }

private:
    static uint64_t timeout_ms_to_usec(uint32_t timeout_ms) {
        // Небольшой запас поверх заявленного таймаута запроса — сам
        // D-Bus round-trip (сериализация, доставка демону, планирование
        // ответа воркером) добавляет какую-то долю миллисекунд сверху
        // "чистого" сетевого таймаута, который отсчитывает cert-helper
        // внутри себя (http_client.hpp). Без запаса D-Bus мог бы оборвать
        // вызов чуть раньше, чем демон успеет отдать уже готовый ответ.
        constexpr uint64_t kIpcOverheadUsec = 500'000; // 500ms
        return static_cast<uint64_t>(timeout_ms) * 1000ull + kIpcOverheadUsec;
    }

    void ensure_connected() {
        if (bus != nullptr) return;
        int r;
        if (bus_address.empty()) {
            r = sd_bus_open_system(&bus);
        } else {
            r = sd_bus_new(&bus);
            if (r >= 0) r = sd_bus_set_address(bus, bus_address.c_str());
            if (r >= 0) r = sd_bus_set_bus_client(bus, 1);
            if (r >= 0) r = sd_bus_start(bus);
        }
        if (r < 0) {
            if (bus != nullptr) {
                sd_bus_unref(bus);
                bus = nullptr;
            }
            throw DbusClientError(std::string("failed to connect to D-Bus: ") + std::strerror(-r));
        }
    }

    proto::FetchResponse call_and_parse_fetch(int build_result, sd_bus_message* msg,
                                               uint32_t timeout_ms) {
        proto::FetchResponse result;
        result.status = proto::FetchStatus::NetworkError;

        if (build_result < 0) {
            if (msg != nullptr) sd_bus_message_unref(msg);
            return result;
        }

        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message* reply = nullptr;
        int r = sd_bus_call(bus, msg, timeout_ms_to_usec(timeout_ms), &error, &reply);
        sd_bus_message_unref(msg);

        if (r < 0) {
            // Сбой на уровне самого IPC (демон недоступен, вызов оборван
            // по таймауту D-Bus и т.п.) — отличаем таймаут от прочих
            // ошибок, чтобы вызывающий код (client.hpp) мог при желании
            // разделить их, хотя контракт OcspFetcher/CrlFetcher в итоге
            // всё равно сворачивает оба случая в "пустой вектор".
            result.status = (r == -ETIMEDOUT) ? proto::FetchStatus::Timeout
                                                : proto::FetchStatus::NetworkError;
            sd_bus_error_free(&error);
            return result;
        }
        sd_bus_error_free(&error);

        uint8_t status_byte = static_cast<uint8_t>(proto::FetchStatus::InvalidResponse);
        const void* payload_ptr = nullptr;
        size_t payload_len = 0;
        int from_cache_int = 0;

        r = sd_bus_message_read(reply, "y", &status_byte);
        if (r >= 0) r = sd_bus_message_read_array(reply, 'y', &payload_ptr, &payload_len);
        if (r >= 0) r = sd_bus_message_read(reply, "b", &from_cache_int);

        // ВАЖНО: payload_ptr указывает внутрь буфера самого sd_bus_message
        // (sd_bus_message_read_array не копирует данные — только отдаёт
        // указатель). Копируем его в result.payload_der ДО sd_bus_message_
        // unref(reply) ниже — если unref опустит refcount до нуля, память
        // сообщения освобождается и payload_ptr становится висячим
        // указателем. Для маленьких ответов (единицы байт, как в старых
        // тестах) это могло годами оставаться незамеченным — освобождённая
        // память часто ещё не успевает быть переиспользована другим
        // выделением к моменту assign(); но при типичном для CRL размере
        // (сотни КБ — единицы МБ) это воспроизводится надёжно и даёт
        // молчаливую порчу данных (не падение, не ошибку — просто другие
        // байты), что гораздо опаснее падения.
        if (r >= 0 && payload_len > 0) {
            result.payload_der.assign(static_cast<const uint8_t*>(payload_ptr),
                                       static_cast<const uint8_t*>(payload_ptr) + payload_len);
        }

        sd_bus_message_unref(reply);

        if (r < 0) {
            result.status = proto::FetchStatus::InvalidResponse;
            result.payload_der.clear(); // не отдавать частично скопированный или неполный payload
            return result;
        }

        result.status = static_cast<proto::FetchStatus>(status_byte);
        result.from_cache = from_cache_int != 0;
        return result;
    }

    std::string bus_address;
    sd_bus* bus = nullptr;
};

} // namespace cert_helper::client_impl
