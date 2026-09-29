// dbus_server.cpp — реализация DbusServer (см. обоснование архитектуры в
// dbus_server.hpp).

#include "dbus_server.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>

#include "../logging.hpp"

namespace cert_helper::ipc {

namespace proto = cert_helper::protocol;

namespace {

// Статический vtable D-Bus интерфейса cert-helper. Без SD_BUS_METHOD_WITH_NAMES
// (именование параметров в интроспекции) — сознательно, ради простоты; сигнатуры
// типов уже задают контракт однозначно, см. dbus_interface.hpp.
const sd_bus_vtable kVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD(kMethodFetchOcsp, "sayu", "yayb", &DbusServer::on_fetch_ocsp,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD(kMethodFetchOcspBatch, "a(sayu)", "a(yayb)", &DbusServer::on_fetch_ocsp_batch,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD(kMethodFetchCrl, "su", "yayb", &DbusServer::on_fetch_crl,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD(kMethodFetchIntermediateCert, "su", "yayb",
                  &DbusServer::on_fetch_intermediate_cert, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD(kMethodHealthCheck, "", "bttttttttttttt", &DbusServer::on_health_check,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END,
};

// Общий хвост для трёх Fetch*-методов: строит и отправляет ответ вида
// (y status, ay payload_der, b from_cache) для уже выполненного
// proto::FetchResponse, на входящее (взятое в ref) сообщение call.
// Вызывается из воркер-потока, не из bus-потока.
void send_fetch_reply(sd_bus* bus, sd_bus_message* call, const proto::FetchResponse& resp) {
    sd_bus_message* reply = nullptr;
    int r = sd_bus_message_new_method_return(call, &reply);
    if (r >= 0) {
        r = sd_bus_message_append(reply, "y", static_cast<uint8_t>(resp.status));
    }
    if (r >= 0) {
        const void* data = resp.payload_der.empty() ? nullptr : resp.payload_der.data();
        r = sd_bus_message_append_array(reply, 'y', data, resp.payload_der.size());
    }
    if (r >= 0) {
        r = sd_bus_message_append(reply, "b", resp.from_cache ? 1 : 0);
    }
    if (r >= 0) {
        sd_bus_send(bus, reply, nullptr);
    }
    if (reply != nullptr) sd_bus_message_unref(reply);
    sd_bus_message_unref(call);
}

} // namespace

DbusServer::DbusServer(Config config, RequestRouter& router)
    : config(std::move(config)), router(router) {}

DbusServer::~DbusServer() { stop(); }

bool DbusServer::start() {
    int r;
    if (config.bus_address.empty()) {
        r = sd_bus_open_system(&bus);
    } else {
        r = sd_bus_new(&bus);
        if (r >= 0) r = sd_bus_set_address(bus, config.bus_address.c_str());
        if (r >= 0) r = sd_bus_set_bus_client(bus, 1);
        if (r >= 0) r = sd_bus_start(bus);
    }
    if (r < 0) {
        log::error("dbus", "failed to connect to D-Bus", {log::field("error", std::strerror(-r))});
        return false;
    }

    r = sd_bus_add_object_vtable(bus, &slot, kObjectPath, kInterfaceName, kVtable, this);
    if (r < 0) {
        log::error("dbus", "failed to register D-Bus object", {log::field("error", std::strerror(-r))});
        return false;
    }

    r = sd_bus_request_name(bus, config.well_known_name.c_str(), 0);
    if (r < 0) {
        log::error("dbus", "failed to acquire bus name",
                   {log::field("bus_name", config.well_known_name), log::field("error", std::strerror(-r))});
        return false;
    }

    running = true;
    for (int i = 0; i < config.min_worker_threads; ++i) {
        active_workers.fetch_add(1, std::memory_order_relaxed);
        workers.emplace_back([this] { worker_loop(); });
    }
    bus_thread = std::thread([this] { bus_loop(); });
    return true;
}

void DbusServer::stop() {
    if (!running.exchange(false)) return;

    if (bus_thread.joinable()) bus_thread.join();

    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        stopping = true;
    }
    queue_cv.notify_all();
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }
    workers.clear();

    if (slot != nullptr) {
        sd_bus_slot_unref(slot);
        slot = nullptr;
    }
    if (bus != nullptr) {
        sd_bus_unref(bus);
        bus = nullptr;
    }
}

void DbusServer::wait_until_stopped() {
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void DbusServer::bus_loop() {
    while (running.load()) {
        int r = sd_bus_process(bus, nullptr);
        if (r < 0) {
            // Соединение развалилось — не пытаемся оживить его молча,
            // просто останавливаем демон (systemd/эксплуатация поднимет
            // заново по Restart=on-failure).
            log::error("dbus", "sd_bus_process() failed, stopping", {log::field("error", std::strerror(-r))});
            running = false;
            break;
        }
        if (r > 0) continue; // обработали событие — сразу проверяем следующее, не ждём

        // Короткий таймаут (не бесконечный sd_bus_wait), чтобы periodически
        // перепроверять running и штатно завершиться при остановке демона.
        r = sd_bus_wait(bus, 200000 /* 200ms в микросекундах */);
        if (r < 0 && r != -EINTR) {
            log::error("dbus", "sd_bus_wait() failed, stopping", {log::field("error", std::strerror(-r))});
            running = false;
            break;
        }
    }
}

void DbusServer::worker_loop() {
    using namespace std::chrono_literals;
    const auto idle_timeout = std::chrono::milliseconds(config.worker_idle_timeout_ms);

    while (true) {
        PendingJob job;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            bool got_job = queue_cv.wait_for(lock, idle_timeout,
                                                [this] { return stopping || !jobs.empty(); });
            if (stopping && jobs.empty()) {
                active_workers.fetch_sub(1, std::memory_order_relaxed);
                return;
            }
            if (!got_job || jobs.empty()) {
                // Простаивали дольше worker_idle_timeout_ms без работы —
                // самозавершаемся, но только если это не опустит пул
                // ниже минимума (пункт 4: "startup" воркеров всегда
                // остаются в строю, "лишние" под нагрузкой — уходят).
                if (active_workers.load(std::memory_order_relaxed) > config.min_worker_threads) {
                    active_workers.fetch_sub(1, std::memory_order_relaxed);
                    return;
                }
                continue; // остаёмся в пуле как часть минимума, ждём дальше
            }
            job = std::move(jobs.front());
            jobs.pop_front();
        }
        job.run();
    }
}

void DbusServer::enqueue(std::function<void()> job) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        jobs.push_back(PendingJob{std::move(job)});
    }
    queue_cv.notify_one();
    maybe_spawn_worker();
}

void DbusServer::maybe_spawn_worker() {
    // Эвристика намеренно простая: если после постановки задачи в
    // очередь там остаётся больше одной ожидающей записи (т.е. свободных
    // воркеров, похоже, не осталось — иначе кто-то уже забрал бы её) и
    // мы не достигли потолка — добавляем ещё один поток. Это не идеальный
    // сигнал занятости (нет отдельного счётчика "воркеров, ждущих на
    // condition_variable"), но для цели "не упираться в фиксированный
    // размер пула под всплеском" этого достаточно и не требует
    // дополнительной синхронизации сверх уже имеющегося queue_mutex.
    std::size_t queue_len;
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        queue_len = jobs.size();
    }
    if (queue_len <= 1) return;
    if (active_workers.load(std::memory_order_relaxed) >= config.max_worker_threads) return;

    active_workers.fetch_add(1, std::memory_order_relaxed);
    workers.emplace_back([this] { worker_loop(); });
}

int DbusServer::on_fetch_ocsp(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    const char* url = nullptr;
    const void* der_ptr = nullptr;
    size_t der_len = 0;
    uint32_t timeout_ms = 0;

    int r = sd_bus_message_read(m, "s", &url);
    if (r < 0) return r;
    r = sd_bus_message_read_array(m, 'y', &der_ptr, &der_len);
    if (r < 0) return r;
    r = sd_bus_message_read(m, "u", &timeout_ms);
    if (r < 0) return r;

    proto::FetchOcspRequest req;
    req.responder_url = url;
    if (der_len > 0) {
        req.request_der.assign(static_cast<const uint8_t*>(der_ptr),
                                static_cast<const uint8_t*>(der_ptr) + der_len);
    }
    req.timeout_ms = timeout_ms;

    sd_bus_message* call = sd_bus_message_ref(m);
    sd_bus* bus = sd_bus_message_get_bus(m);

    self->enqueue([self, bus, call, req = std::move(req)]() mutable {
        auto resp = self->router.handle_ocsp(req);
        send_fetch_reply(bus, call, resp);
    });
    return 1; // ответ будет отправлен асинхронно из воркера
}

// ROADMAP.md, раздел 2, пункт 14: FetchOcspBatch(a(sayu)) -> a(yayb).
// Читает массив структур {responder_url, request_der, timeout_ms} через
// sd_bus_message_enter_container/sd_bus_message_read по одному элементу
// за раз — sd-bus не даёт "прочитать весь массив структур одним вызовом"
// для неоднородных по типам структур (в отличие от 'ay', это не простой
// массив байт), только поэлементный обход контейнера.
int DbusServer::on_fetch_ocsp_batch(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    proto::FetchOcspBatchRequest batch_req;

    int r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sayu)");
    if (r < 0) return r;

    while (true) {
        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_STRUCT, "sayu");
        if (r < 0) return r;
        if (r == 0) break; // элементы массива кончились

        const char* url = nullptr;
        const void* der_ptr = nullptr;
        size_t der_len = 0;
        uint32_t timeout_ms = 0;

        r = sd_bus_message_read(m, "s", &url);
        if (r < 0) return r;
        r = sd_bus_message_read_array(m, 'y', &der_ptr, &der_len);
        if (r < 0) return r;
        r = sd_bus_message_read(m, "u", &timeout_ms);
        if (r < 0) return r;

        proto::FetchOcspRequest req;
        req.responder_url = url;
        if (der_len > 0) {
            req.request_der.assign(static_cast<const uint8_t*>(der_ptr),
                                    static_cast<const uint8_t*>(der_ptr) + der_len);
        }
        req.timeout_ms = timeout_ms;
        batch_req.requests.push_back(std::move(req));

        r = sd_bus_message_exit_container(m); // закрывает STRUCT этого элемента
        if (r < 0) return r;
    }
    r = sd_bus_message_exit_container(m); // закрывает ARRAY
    if (r < 0) return r;

    sd_bus_message* call = sd_bus_message_ref(m);
    sd_bus* bus = sd_bus_message_get_bus(m);

    self->enqueue([self, bus, call, batch_req = std::move(batch_req)]() mutable {
        auto batch_resp = self->router.handle_ocsp_batch(batch_req);

        sd_bus_message* reply = nullptr;
        int rr = sd_bus_message_new_method_return(call, &reply);
        if (rr >= 0) rr = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "(yayb)");
        if (rr >= 0) {
            for (const auto& resp : batch_resp.responses) {
                rr = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "yayb");
                if (rr < 0) break;
                rr = sd_bus_message_append(reply, "y", static_cast<uint8_t>(resp.status));
                if (rr >= 0) {
                    const void* data = resp.payload_der.empty() ? nullptr : resp.payload_der.data();
                    rr = sd_bus_message_append_array(reply, 'y', data, resp.payload_der.size());
                }
                if (rr >= 0) rr = sd_bus_message_append(reply, "b", resp.from_cache ? 1 : 0);
                if (rr >= 0) rr = sd_bus_message_close_container(reply); // закрывает этот STRUCT
                if (rr < 0) break;
            }
        }
        if (rr >= 0) rr = sd_bus_message_close_container(reply); // закрывает ARRAY
        if (rr >= 0) sd_bus_send(bus, reply, nullptr);
        if (reply != nullptr) sd_bus_message_unref(reply);
        sd_bus_message_unref(call);
    });
    return 1;
}

int DbusServer::on_fetch_crl(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    const char* url = nullptr;
    uint32_t timeout_ms = 0;
    int r = sd_bus_message_read(m, "s", &url);
    if (r < 0) return r;
    r = sd_bus_message_read(m, "u", &timeout_ms);
    if (r < 0) return r;

    proto::FetchCrlRequest req;
    req.distribution_point_url = url;
    req.timeout_ms = timeout_ms;

    sd_bus_message* call = sd_bus_message_ref(m);
    sd_bus* bus = sd_bus_message_get_bus(m);

    self->enqueue([self, bus, call, req = std::move(req)]() mutable {
        auto resp = self->router.handle_crl(req);
        send_fetch_reply(bus, call, resp);
    });
    return 1;
}

int DbusServer::on_fetch_intermediate_cert(sd_bus_message* m, void* userdata,
                                            sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    const char* url = nullptr;
    uint32_t timeout_ms = 0;
    int r = sd_bus_message_read(m, "s", &url);
    if (r < 0) return r;
    r = sd_bus_message_read(m, "u", &timeout_ms);
    if (r < 0) return r;

    proto::FetchIntermediateCertRequest req;
    req.aia_url = url;
    req.timeout_ms = timeout_ms;

    sd_bus_message* call = sd_bus_message_ref(m);
    sd_bus* bus = sd_bus_message_get_bus(m);

    self->enqueue([self, bus, call, req = std::move(req)]() mutable {
        auto resp = self->router.handle_intermediate_cert(req);
        send_fetch_reply(bus, call, resp);
    });
    return 1;
}

int DbusServer::on_health_check(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    // Health-check не делает сети и не бьёт в кэш дольше, чем на разовое
    // чтение статистики — можно смело выполнить синхронно прямо в
    // bus-потоке, не занимая пул воркеров и не блокируя надолго.
    auto resp = self->router.handle_health_check();

    sd_bus_message* reply = nullptr;
    int r = sd_bus_message_new_method_return(m, &reply);
    if (r >= 0) r = sd_bus_message_append(reply, "b", resp.healthy ? 1 : 0);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.cache_entries);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.cache_size_bytes);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.memory_cache_entries);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.memory_cache_size_bytes);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.ocsp.requests);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.ocsp.cache_hits);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.ocsp.errors);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.crl.requests);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.crl.cache_hits);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.crl.errors);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.intermediate_cert.requests);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.intermediate_cert.cache_hits);
    if (r >= 0) r = sd_bus_message_append(reply, "t", resp.intermediate_cert.errors);
    if (r >= 0) r = sd_bus_send(sd_bus_message_get_bus(m), reply, nullptr);
    if (reply != nullptr) sd_bus_message_unref(reply);
    return 1;
}

} // namespace cert_helper::ipc
