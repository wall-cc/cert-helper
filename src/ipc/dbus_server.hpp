// dbus_server.hpp
//
// Серверная часть транспорта cert-helper поверх D-Bus (sd-bus, часть
// libsystemd). Заменяет прежний Unix-domain-socket + самодельный
// бинарный протокол (см. историю в protocol.hpp) на стандартный D-Bus
// сервис — по требованию: "с клиентами приложение должно общаться через
// DBus".
//
// АРХИТЕКТУРА КОНКУРЕНТНОСТИ (важно, т.к. отличается от UDS-версии):
// sd-bus требует, чтобы конкретное соединение (sd_bus*) обслуживалось
// (sd_bus_process()/sd_bus_wait()) из ОДНОГО потока — это не то же самое,
// что "один запрос на поток", как было в UdsServer. Поэтому:
//   - Один выделенный поток (bus-поток) крутит цикл sd_bus_process/wait
//     и только ДИСПЕТЧЕРИЗУЕТ входящие вызовы методов.
//   - Сам вызов метода (vtable-обработчик) НЕ делает сетевой запрос
//     синхронно — иначе на время одного OCSP/CRL/AIA-запроса блокировался
//     бы весь bus-поток, и все остальные конкурентные вызовы простаивали
//     бы в очереди друг за другом (регресс по сравнению с пулом потоков
//     UDS-версии). Вместо этого обработчик:
//       1. Разбирает аргументы сообщения.
//       2. Берёт ссылку на входящее sd_bus_message (sd_bus_message_ref) —
//          чтобы ответить на него позже, из другого потока.
//       3. Кладёт задачу в очередь пула воркеров и возвращает 1 (заявка
//          принята к обработке, ответ будет отправлен асинхронно —
//          именно такой паттерн поддерживается sd-bus, см.
//          sd_bus_message_new_method_return()/sd_bus_send() в документации
//          systemd: "It is generally OK to send the reply from a
//          different thread than the one processing the bus, as long as
//          sd_bus_process() itself isn't called concurrently").
//   - Воркер делает реальную работу (RequestRouter, включая HTTP/кэш) и
//     шлёт ответ через sd_bus_send() — это единственная операция, которую
//     можно безопасно делать из стороннего потока, пока bus-поток занят
//     обработкой чего-то ещё.
//
// ПУНКТ 4 ИЗ АНАЛИЗА SQUID: эластичный пул воркеров, а не фиксированный
// размер.
//
// У хелперов Squid задаются `children N startup=... idle=...` — минимум
// процессов на старте и допустимое число простаивающих; под всплесковую
// нагрузку пул может расти. Раньше здесь был фиксированный
// worker_threads — теперь это диапазон [min_worker_threads,
// max_worker_threads]: демон стартует с min_worker_threads, при
// накоплении очереди задач (все текущие воркеры заняты) добавляет новые
// потоки вплоть до max_worker_threads, а простаивающие сверх минимума
// потоки самозавершаются по worker_idle_timeout_ms. Это не блокирует
// корректность (очередь задач работает одинаково при любом числе
// воркеров) — только позволяет не держать (или наоборот, не жалеть)
// лишние потоки постоянно.
//
// Права доступа контролируются не файлом сокета (как было для UDS), а
// D-Bus policy-файлом на системной шине — см. deploy/org.certhelper.CertHelper1.conf.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <systemd/sd-bus.h>

#include "../request_router.hpp"
#include "dbus_interface.hpp"

namespace cert_helper::ipc {

class DbusServer {
public:
    struct Config {
        // Пусто — подключаться к системной шине (sd_bus_open_system).
        // Непусто — подключаться к указанному адресу (используется в
        // тестах: приватный dbus-daemon на своём сокете, см.
        // tests/test_client_server_roundtrip.cpp).
        std::string bus_address;
        std::string well_known_name = kServiceName;

        // Эластичный пул воркеров (пункт 4 из анализа Squid, см. выше).
        int min_worker_threads = 2;
        int max_worker_threads = 16;
        int worker_idle_timeout_ms = 30000; // после простоя дольше этого — поток завершается,
                                              // если текущее число воркеров выше min_worker_threads
    };

    DbusServer(Config config, RequestRouter& router);
    ~DbusServer();

    // Возвращает false при любой ошибке подключения/регистрации на шине.
    bool start();
    void stop();

    // Блокирует вызывающий поток, пока демон не будет остановлен извне.
    void wait_until_stopped();

    // Текущее число живых воркеров — только для тестов/диагностики,
    // отражает эластичное масштабирование пула (пункт 4).
    int worker_count() const { return active_workers.load(); }

    // vtable-обработчики методов (реализация — dbus_server.cpp). Публичные,
    // т.к. на них берутся адреса функций из статического sd_bus_vtable[]
    // в анонимном namespace в .cpp — сами обработчики не являются частью
    // публичного API класса в смысловом плане (никто, кроме sd-bus
    // vtable-машинерии, не должен вызывать их напрямую).
    static int on_fetch_ocsp(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    static int on_fetch_ocsp_batch(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    static int on_fetch_crl(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    static int on_fetch_intermediate_cert(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);
    static int on_health_check(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

private:
    struct PendingJob {
        std::function<void()> run;
    };

    void bus_loop();
    void worker_loop();
    void enqueue(std::function<void()> job);
    void maybe_spawn_worker(); // вызывается из enqueue() под queue_mutex

    Config config;
    RequestRouter& router;

    sd_bus* bus = nullptr;
    sd_bus_slot* slot = nullptr;

    std::atomic<bool> running{false};
    std::thread bus_thread;

    // active_workers считает живые (ещё не вышедшие из worker_loop)
    // потоки — используется и для решения "спавнить ли ещё один", и для
    // решения "можно ли этому воркеру самозавершиться, не уйдя ниже
    // минимума". workers хранит std::thread-объекты только для join() при
    // остановке демона — поток, решивший завершиться из-за простоя,
    // просто выходит из функции; его thread-объект остаётся в векторе до
    // stop() (join на уже завершённом потоке возвращается мгновенно).
    std::atomic<int> active_workers{0};
    std::vector<std::thread> workers;

    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    std::deque<PendingJob> jobs;
    bool stopping = false;
};

} // namespace cert_helper::ipc
