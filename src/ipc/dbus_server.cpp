// dbus_server.cpp — реализация DbusServer (см. обоснование архитектуры в
// dbus_server.hpp).

#include "dbus_server.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>

#include "../logging.hpp"

namespace cert_helper::ipc {

// Псевдоним для cert_helper::protocol — чтобы не писать полное имя в
// сигнатурах локальных функций и в разборе сообщений.
namespace proto = cert_helper::protocol;

namespace {

// ----------------------------------------------------------------------------
// VTABLE — описание D-Bus-интерфейса для sd_bus_add_object_vtable().
//
// Структура sd_bus_vtable — это массив записей, который sd-bus читает при
// регистрации объекта (sd_bus_add_object_vtable). Каждая запись — либо
// граница таблицы (START/END), либо описание метода (SD_BUS_METHOD).
// Порядок записей важен: START ... методы ... END.
// ----------------------------------------------------------------------------
sd_bus_vtable const VTABLE[] = {
    // SD_BUS_VTABLE_START(flags) — открывает таблицу. flags=0 значит
    // "без особых опций". Альтернативно здесь мог бы быть
    // SD_BUS_VTABLE_DEPRECATED или SD_BUS_VTABLE_HIDDEN, но нам это не нужно.
    SD_BUS_VTABLE_START(0),

    // SD_BUS_METHOD(name, in_signature, out_signature, handler, flags):
    //   name          — имя метода D-Bus (FetchOcsp);
    //   in_signature  — D-Bus type-string входящих аргументов "sayu" =
    //                   s(string URL) + ay(array of bytes, DER) + u(uint32 timeout);
    //   out_signature — type-string ответа "yayb" = y(byte status) +
    //                   ay(array DER) + b(bool from_cache);
    //   handler       — C-колбэк, вызываемый sd-bus при входящем вызове
    //                   этого метода; тип — int(*)(sd_bus_message*, void*, sd_bus_error*);
    //   flags         — SD_BUS_VTABLE_UNPRIVILEGED: "не требует привилегий
    //                   по умолчанию". Реальные ограничения — в policy-файле
    //                   deploy/org.certhelper.CertHelper1.conf.
    SD_BUS_METHOD(METHOD_FETCH_OCSP, "sayu", "yayb", &DbusServer::on_fetch_ocsp, SD_BUS_VTABLE_UNPRIVILEGED),

    // FetchOcspBatch: in "a(sayu)" = array of struct{string, ay, uint32},
    // out "a(yayb)" = array of struct{byte, ay, bool}.
    SD_BUS_METHOD(METHOD_FETCH_OCSP_BATCH, "a(sayu)", "a(yayb)", &DbusServer::on_fetch_ocsp_batch, SD_BUS_VTABLE_UNPRIVILEGED),

    // FetchCrl: in "su" = string(URL distribution point) + uint32 timeout,
    // out "yayb" — тот же формат, что и у FetchOcsp.
    SD_BUS_METHOD(METHOD_FETCH_CRL, "su", "yayb", &DbusServer::on_fetch_crl, SD_BUS_VTABLE_UNPRIVILEGED),

    // FetchIntermediateCert: in "su" = string(AIA URL) + uint32 timeout,
    // out "yayb".
    SD_BUS_METHOD(METHOD_FETCH_INTERMEDIATE_CERT, "su", "yayb", &DbusServer::on_fetch_intermediate_cert, SD_BUS_VTABLE_UNPRIVILEGED),

    // HealthCheck: in "" = нет аргументов,
    // out "bttttttttttttt" = b(bool healthy) + 13 полей t(uint64).
    // Порядок t-полей соответствует порядку sd_bus_message_append в
    // on_health_check(): cache_entries, cache_size_bytes,
    // memory_cache_entries, memory_cache_size_bytes,
    // ocsp.requests, ocsp.cache_hits, ocsp.errors,
    // crl.requests, crl.cache_hits, crl.errors,
    // intermediate_cert.requests, intermediate_cert.cache_hits,
    // intermediate_cert.errors.
    SD_BUS_METHOD(METHOD_HEALTH_CHECK, "", "bttttttttttttt", &DbusServer::on_health_check, SD_BUS_VTABLE_UNPRIVILEGED),

    // SD_BUS_VTABLE_END — обязательный закрывающий маркер таблицы.
    SD_BUS_VTABLE_END,
};

// ----------------------------------------------------------------------------
// send_fetch_reply() — единая точка сборки/отправки ответа Fetch* методов.
//
// Аргументы:
//   bus   — соединение sd-bus, полученное в обработчике через
//           sd_bus_message_get_bus(m). Нужно, чтобы отправить ответ из
//           воркер-потока (не из bus-потока).
//   call  — входящее сообщение, взятое в ref (sd_bus_message_ref) в
//           on_fetch_*; после отправки ответа функция снимает этот ref.
//   resp  — готовый proto::FetchResponse (status, payload_der, from_cache).
//
// Помечен noexcept: все операции внутри — либо C-функции sd-bus (не бросают
// C++-исключений), либо noexcept-операции std::vector<uint8_t>/
// std::string (мы их не создаём здесь, а только читаем).
// ----------------------------------------------------------------------------
void send_fetch_reply(sd_bus* bus, sd_bus_message* call, proto::FetchResponse const& resp) noexcept {
    // reply — указатель на исходящее сообщение; изначально nullptr,
    // заполняется sd_bus_message_new_method_return().
    sd_bus_message* reply = nullptr;

    // sd_bus_message_new_method_return(call, &reply):
    //   - Создаёт НОВОЕ исходящее сообщение типа METHOD_RETURN, привязанное
    //     к входящему call (берёт у call серийный номер, отправителя, путь
    //     объекта, имя интерфейса и метода). Именно это sd-bus ожидает в
    //     качестве ответа на вызов;
    //   - Возврат: >=0 при успехе (в т.ч. 0), <0 — ошибка (например,
    //     -ENOMEM, -EINVAL). При ошибке reply остаётся nullptr.
    int r = sd_bus_message_new_method_return(call, &reply);

    // sd_bus_message_append(reply, "y", value):
    //   - Дописывает в конец сообщения простое значение типа "y" (byte).
    //   - Не открывает/закрывает контейнеры — здесь мы пишем "плоские"
    //     поля верхнего уровня, которые сами по себе не контейнер;
    //   - Возврат: >=0 успех, <0 ошибка (например, -ENOMEM при расширении
    //     буфера сообщения). При ошибке — прерываем дальнейшую сборку.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "y", static_cast<uint8_t>(resp.status));
    } else {}

    // sd_bus_message_append_array(reply, 'y', data, len):
    //   - Дописывает массив байт (D-Bus тип "ay"). data — указатель на
    //     начало данных, len — их количество. Для пустого массива
    //     корректно передавать data=nullptr, len=0 (это валидный пустой ay);
    //   - В отличие от append(reply, "ay", ...), который принимает пару
    //     (ptr, len) через varargs, append_array — специализированный и
    //     типобезопасный вариант именно для массивов.
    //   - Возврат: >=0 успех, <0 ошибка.
    if (r >= 0) {
        void const* data = resp.payload_der.empty() ? nullptr : resp.payload_der.data();
        r = sd_bus_message_append_array(reply, 'y', data, resp.payload_der.size());
    } else {}

    // sd_bus_message_append(reply, "b", bool_value):
    //   - "b" — D-Bus boolean. В C++ это int (0/1); sd-bus ожидает именно
    //     int, не bool, поэтому пишем тернарник;
    //   - Возврат: >=0 успех, <0 ошибка.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "b", resp.from_cache ? 1 : 0);
    } else {}

    // sd_bus_send(bus, reply, nullptr):
    //   - Отправляет готовое сообщение reply в шину через соединение bus.
    //     Третий аргумент — out-параметр uint64_t* для cookie (может быть
    //     nullptr, если cookie нам не нужен);
    //   - В отличие от sd_bus_call(), НЕ ждёт никакого ответа — это
    //     "one-way send", что нам и нужно: мы отправляем METHOD_RETURN,
    //     ответ на который никто не ждёт (клиент просто получит его сам);
    //   - Из воркер-потока вызывать можно (это и есть официально
    //     поддерживаемый паттерн systemd: "It is generally OK to send the
    //     reply from a different thread..."), пока bus-поток не вызывает
    //     sd_bus_process() параллельно на этом же соединении;
    //   - Возврат игнорируем: если отправка провалилась (например, шина
    //     отвалилась) — клиент получит D-Bus-ошибку на уровне транспорта,
    //     а мы не должны падать/бросать из noexcept-функции.
    if (r >= 0) {
        sd_bus_send(bus, reply, nullptr);
    } else {}

    // sd_bus_message_unref(reply):
    //   - Уменьшает refcount на reply. sd_bus_message_new_method_return
    //     вернул нам владение с refcount=1; после отправки сообщение уже
    //     скопировано в исходящий буфер соединения, поэтому локальный
    //     указатель можно/нужно отпустить.
    //   - Возврат: sd_bus_message* — тот же указатель (после unref он
    //     может стать висячим, поэтому результат не используем).
    if (reply != nullptr) {
        sd_bus_message_unref(reply);
    } else {}

    // sd_bus_message_unref(call):
    //   - Снимает ref, взятый в on_fetch_* через sd_bus_message_ref(m).
    //     Это важно: sd-bus не даёт хранить входящее сообщение между
    //     вызовами без явного ref, а мы как раз хранили его до момента
    //     отправки ответа из воркер-потока.
    //   - После этого указатель call больше не валиден — повторно
    //     использовать его нельзя.
    sd_bus_message_unref(call);
}

// ----------------------------------------------------------------------------
// send_internal_error_reply() — отправка D-Bus-ошибки
// ERROR_INTERNAL_FAILURE, если обработчик неожиданно бросил C++-исключение.
//
// В отличие от send_fetch_reply(), здесь НЕТ `noexcept`: std::string what
// создаётся/копируется, log::error() потенциально бросает — формально
// noexcept не гарантируется. На практике бросание здесь всё равно приведёт
// к std::terminate (мы в catch-блоке), но формально мы это не обещаем.
// ----------------------------------------------------------------------------
void send_internal_error_reply(sd_bus* bus, sd_bus_message* call, std::exception_ptr error) {
    // what — текст ошибки для логирования и для тела D-Bus error-reply.
    // Начинаем с "unknown error" на случай, если error пуст или брошен
    // объект не-наследник std::exception.
    std::string what = "unknown error";

    // std::rethrow_exception(error):
    //   - "Перебрасывает" сохранённое в std::exception_ptr исключение,
    //     чтобы его можно было поймать по конкретному типу в catch-блоке.
    //   - Если error пуст (nullptr) — поведение неопределено, поэтому
    //     предполагается, что вызывающий код всегда передаёт валидный
    //     current_exception(). В нашем коде это так (см. catch(...) в
    //     лямбдах on_fetch_*).
    try {
        std::rethrow_exception(error);
    } catch (std::exception const& e) {
        // Стандартное исключение — берём what() как текст.
        what = e.what();
    } catch (...) {
        // Не std::exception — оставляем "unknown error".
    }

    // log::error — пишем диагностику. log::field("error", what) — это
    // структурированное поле; конкретный механизм — в logging.hpp.
    log::error("dbus", "request handler threw an unexpected exception", {log::field("error", what)});

    // reply — исходящее сообщение с ошибкой; заполняется ниже.
    sd_bus_message* reply = nullptr;

    // sd_bus_message_new_method_errorf(call, &reply, error_name, format, ...):
    //   - Создаёт METHOD_ERROR-сообщение, привязанное к входящему call.
    //     error_name — D-Bus-имя ошибки (должно быть в формате
    //     reversed-DNS с точками, у нас ERROR_INTERNAL_FAILURE);
    //   - format + args — printf-style текст ошибки; попадёт в поле
    //     "message" тела D-Bus-ошибки (то, что клиент видит при разборе
    //     sd_bus_error.message);
    //   - Возврат: >=0 успех, <0 ошибка (например, -ENOMEM).
    int r = sd_bus_message_new_method_errorf(call, &reply, ERROR_INTERNAL_FAILURE, "cert-helper: %s", what.c_str());

    // sd_bus_send(bus, reply, nullptr): отправляем error-reply клиенту.
    // Семантика та же, что в send_fetch_reply: one-way, без ожидания
    // подтверждения; код возврата игнорируем осознанно — мы уже в
    // catch-обработчике, падение здесь никому не поможет.
    if (r >= 0) {
        sd_bus_send(bus, reply, nullptr);
    } else {}

    // sd_bus_message_unref(reply): отпускаем локальный ref на error-reply.
    if (reply != nullptr) {
        sd_bus_message_unref(reply);
    } else {}

    // sd_bus_message_unref(call): снимаем ref на входящее сообщение,
    // взятый в on_fetch_* при sd_bus_message_ref(m).
    sd_bus_message_unref(call);
}

}  // namespace

// ----------------------------------------------------------------------------
// DbusServer::DbusServer — конструктор.
// ----------------------------------------------------------------------------
DbusServer::DbusServer(Config config, RequestRouter& router)
    // std::move(config) — конфиг передаётся по значению, чтобы можно было
    // переместить его внутрь объекта без лишнего копирования.
    // router(router) — сохраняем ССЫЛКУ (не владеем; см. .hpp).
    : config(std::move(config)), router(router) {}

// Деструктор: гарантирует остановку потоков и освобождение sd-bus
// ресурсов, даже если пользователь не вызвал stop() явно.
DbusServer::~DbusServer() { stop(); }

// ----------------------------------------------------------------------------
// DbusServer::start — подключение к шине, регистрация объекта и имени,
// запуск потоков.
// ----------------------------------------------------------------------------
bool DbusServer::start() {
    int r;

    // ---- Шаг 1: подключение к шине ----
    if (config.bus_address.empty()) {
        // sd_bus_open_system(&bus):
        //   - Открывает соединение с СИСТЕМНОЙ шиной D-Bus
        //     (обычно /run/dbus/system_bus_socket);
        //   - Внутри: sd_bus_new + sd_bus_set_address(UNIX_SOCKET) +
        //     sd_bus_set_bus_client(1) + sd_bus_start — т.е. то же самое,
        //     что мы делаем вручную в else-ветке, но с дефолтным адресом;
        //   - Возврат: >=0 успех (bus заполнен), <0 ошибка.
        r = sd_bus_open_system(&bus);
    } else {
        // Ручной путь для тестов: подключаемся к приватному dbus-daemon,
        // у которого свой сокет и адрес.
        //
        // sd_bus_new(&bus): создаёт объект sd_bus в памяти, ещё НЕ
        // подключаясь к шине. Возврат: >=0 успех, <0 -ENOMEM и т.п.
        r = sd_bus_new(&bus);
        if (r >= 0) {
            // sd_bus_set_address(bus, addr): сохраняет строку адреса
            // (например, "unix:path=/tmp/test-dbus.sock"), к которому
            // нужно подключиться при sd_bus_start.
            // Возврат: >=0 успех, <0 ошибка (невалидный адрес и т.п.).
            r = sd_bus_set_address(bus, config.bus_address.c_str());
        } else {}
        if (r >= 0) {
            // sd_bus_set_bus_client(bus, 1): помечает соединение как
            // "клиент шины" (не сервер и не peer-to-peer). Влияет на то,
            // как sd-bus обрабатывает начальное рукопожатие и приветствие
            // сервера (Hello). Возврат: >=0 успех, <0 ошибка.
            r = sd_bus_set_bus_client(bus, 1);
        } else {}
        if (r >= 0) {
            // sd_bus_start(bus): фактически открывает сокет и делает
            // начальный handshake (Hello). Возврат: >=0 успех, <0 ошибка.
            r = sd_bus_start(bus);
        } else {}
    }
    if (r < 0) {
        // std::strerror(-r): sd-bus возвращает отрицательные errno-коды
        // (например, -ENOMEM, -ECONNREFUSED); берём их по модулю и
        // получаем человекочитаемое описание.
        log::error("dbus", "failed to connect to D-Bus", {log::field("error", std::strerror(-r))});
        return false;
    } else {}

    // ---- Шаг 2: регистрация vtable ----
    // sd_bus_add_object_vtable(bus, &slot, path, interface, vtable, userdata):
    //   - Регистрирует на соединении bus объект по пути OBJECT_PATH
    //     (/org/certhelper/CertHelper1) с интерфейсом INTERFACE_NAME
    //     и таблицей методов VTABLE;
    //   - &slot — out-параметр: sd-bus вернёт сюда sd_bus_slot*, который
    //     нужно будет sd_bus_slot_unref() при остановке (см. stop());
    //   - userdata=this — этот указатель будет передан первым аргументом
    //     в каждый статический обработчик (on_fetch_*); так обработчики
    //     получают доступ к роутеру и пулу воркеров;
    //   - Возврат: >=0 успех, <0 ошибка (например, -EEXIST при повторной
    //     регистрации того же объекта/интерфейса).
    r = sd_bus_add_object_vtable(bus, &slot, OBJECT_PATH, INTERFACE_NAME, VTABLE, this);
    if (r < 0) {
        log::error("dbus", "failed to register D-Bus object", {log::field("error", std::strerror(-r))});
        return false;
    } else {}

    // ---- Шаг 3: запрос well-known имени ----
    // sd_bus_request_name(bus, name, flags):
    //   - Просит у шины "закрепить" за нами имя SERVICE_NAME
    //     (org.certhelper.CertHelper1), чтобы клиенты могли обращаться к
    //     сервису по имени, а не по уникальному ":1.N"-адресу;
    //   - flags=0 — обычное поведение: если имя уже занято другим
    //     процессом, start() упадёт с -EADDRINUSE. Альтернативно можно
    //     было бы передать SD_BUS_NAME_REPLACE_EXISTING или
    //     SD_BUS_NAME_QUEUE, но для демона это не нужно;
    //   - Возврат: >=0 успех (в т.ч. 1 = имя уже было нашим, идемпотентно),
    //     <0 ошибка (занято/нет прав/...).
    r = sd_bus_request_name(bus, config.well_known_name.c_str(), 0);
    if (r < 0) {
        log::error("dbus", "failed to acquire bus name", {log::field("bus_name", config.well_known_name), log::field("error", std::strerror(-r))});
        return false;
    } else {}

    // ---- Шаг 4: запуск потоков ----
    // running=true — единый флаг "демон работает", проверяемый в bus_loop,
    // worker_loop (через stopping) и wait_until_stopped.
    running = true;

    // Стартовый минимум воркеров. active_workers инкрементируем ДО создания
    // потока, чтобы новый worker_loop сразу видел корректное значение при
    // проверке "могу ли я самозавершиться по idle-таймауту".
    for (int i = 0; i < config.worker_threads.min; ++i) {
        // std::atomic<int>::fetch_add — атомарный инкремент; relaxed —
        // потому что нам не нужна синхронизация с другими полями, только
        // монотонный счётчик.
        active_workers.fetch_add(1, std::memory_order_relaxed);
        // std::thread ctor — создаёт поток; может бросить std::system_error
        // при нехватке ресурсов ОС.
        workers.emplace_back([this] { worker_loop(); });
    }

    // Bus-поток запускаем последним: к этому моменту пул воркеров уже
    // готов принимать задачи, которые bus_loop начнёт диспетчеризовать.
    // std::thread ctor может бросить std::system_error.
    bus_thread = std::thread([this] { bus_loop(); });
    return true;
}

// ----------------------------------------------------------------------------
// DbusServer::stop — идемпотентная остановка.
// ----------------------------------------------------------------------------
void DbusServer::stop() {
    // std::atomic_bool::exchange(false): атомарно "прочитать и записать
    // false". Если running уже был false (никогда не стартовали или уже
    // остановились) — повторный вызов no-op, просто return.
    if (!running.exchange(false)) {
        return;
    } else {}

    // std::thread::joinable(): true, если поток был запущен и ещё не
    // присоединён. join() дождётся завершения bus_loop() — после этого
    // гарантированно никто не вызовет sd_bus_process()/sd_bus_wait() и
    // не будет плодить задачи из bus-потока.
    // join() может бросить std::system_error (например, при deadlock-
    // детекте, если поток join'ит сам себя).
    if (bus_thread.joinable()) {
        bus_thread.join();
    } else {}

    // Под queue_mutex выставляем stopping=true. Это "флаг завершения"
    // для воркеров: они проснутся на condition_variable и выйдут из
    // worker_loop.
    {
        // std::lock_guard — RAII-обёртка над std::mutex; блокирует до
        // выхода из scope, гарантированно разблокирует даже при исключении.
        std::lock_guard<std::mutex> lock(queue_mutex);
        stopping = true;
    }
    // std::condition_variable::notify_all() — будим ВСЕ воркеры, ждущие
    // в queue_cv.wait_for. Одного notify_one() было бы недостаточно:
    // хотим, чтобы проснулись все и увидели stopping==true.
    queue_cv.notify_all();

    // Джойним всех воркеров. Каждый join() ждёт, пока соответствующий
    // worker_loop завершится; может бросить std::system_error.
    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        } else {}
    }
    // Очищаем вектор потоков — после join они уже не "живые", хранить
    // их незачем (освобождаем память и обнуляем размер).
    workers.clear();

    // ---- Освобождение sd-bus ресурсов (в обратном порядке регистрации) ----

    // sd_bus_slot_unref(slot): освобождает слот, возвращённый нам
    // sd_bus_add_object_vtable в start(). Это снимает регистрацию vtable
    // с соединения; после этого входящие вызовы методов на этом пути
    // приходить не будут.
    if (slot != nullptr) {
        sd_bus_slot_unref(slot);
        slot = nullptr;
    } else {}

    // sd_bus_unref(bus): уменьшает refcount соединения. При достижении
    // нуля sd-bus закрывает сокет и освобождает ресурсы. После этого
    // указатель bus больше не валиден.
    if (bus != nullptr) {
        sd_bus_unref(bus);
        bus = nullptr;
    } else {}
}

// ----------------------------------------------------------------------------
// DbusServer::wait_until_stopped — polling-ожидание внешней остановки.
// ----------------------------------------------------------------------------
void DbusServer::wait_until_stopped() noexcept {
    // std::atomic_bool::load(): атомарное чтение без модификации;
    // relaxed-семантика по умолчанию достаточна, т.к. нам нужен только
    // сам факт "running всё ещё true".
    // sleep_for(200ms) — шаг polling'а; noexcept.
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

// ----------------------------------------------------------------------------
// DbusServer::bus_loop — цикл обработки событий sd-bus.
// ----------------------------------------------------------------------------
void DbusServer::bus_loop() {
    while (running.load()) {
        // sd_bus_process(bus, nullptr):
        //   - Извлекает из внутренней очереди соединения ОДНО входящее
        //     сообщение и обрабатывает его: если это METHOD_CALL и он
        //     матчится на зарегистрированный vtable — вызывает
        //     соответствующий C-обработчик (on_fetch_*/on_health_check),
        //     который мы передали через SD_BUS_METHOD;
        //   - Второй аргумент nullptr — out-параметр sd_bus_message*, который
        //     нам не нужен (sd-bus сам раздиспетчеризует вызовы);
        //   - Возврат:
        //       >0 — обработано >=1 событие (продолжаем цикл без ожидания);
        //        0 — очередь пуста (надо звать sd_bus_wait);
        //       <0 — ошибка соединения/протокола (фатально).
        int r = sd_bus_process(bus, nullptr);
        if (r < 0) {
            // Фатальная ошибка sd-bus (например, -ECONNRESET, -EPIPE).
            // Не пытаемся оживить соединение молча — выставляем
            // running=false, чтобы stop()/wait_until_stopped() увидели
            // остановку; systemd поднимет демон заново по
            // Restart=on-failure.
            log::error("dbus", "sd_bus_process() failed, stopping", {log::field("error", std::strerror(-r))});
            // std::atomic_bool::operator= — атомарная запись false.
            running = false;
            break;
        } else {}
        if (r > 0) {
            // Есть ещё события в очереди — сразу следующая итерация,
            // без sd_bus_wait (это важно для пропускной способности:
            // под нагрузкой не ждём таймаута между сообщениями).
            continue;
        } else {}

        // sd_bus_wait(bus, usec):
        //   - Блокирует поток, пока на соединении не появится активность
        //     (входящее сообщение, готовность сокета) ИЛИ не истечёт
        //     таймаут usec микросекунд;
        //   - usec=200000 — 200 мс: короткий таймаут нужен, чтобы
        //     периодически просыпаться и перепроверять running. Бесконечный
        //     wait (UINT64_MAX) усложнил бы штатную остановку (пришлось бы
        //     "дёргать" соединение из stop() событием);
        //   - Возврат:
        //       >=0 — есть активность (или таймаут, 0);
        //       -EINTR — проснулись по сигналу (штатно, не ошибка);
        //       <0 (кроме -EINTR) — фатальная ошибка.
        r = sd_bus_wait(bus, 200000 /* 200ms в микросекундах */);
        if (r < 0 && r != -EINTR) {
            // Фатальная ошибка ожидания — останавливаемся аналогично
            // обработке ошибки sd_bus_process выше.
            log::error("dbus", "sd_bus_wait() failed, stopping", {log::field("error", std::strerror(-r))});
            running = false;
            break;
        } else {}
    }
}

// ----------------------------------------------------------------------------
// DbusServer::worker_loop — рабочий цикл одного воркера.
// ----------------------------------------------------------------------------
void DbusServer::worker_loop() {
    // chrono_literals — чтобы писать `30000ms` вместо
    // std::chrono::milliseconds(30000) в теле; здесь используем явный тип,
    // но `using` оставляем для читаемости последующих правок.
    using namespace std::chrono_literals;
    // std::chrono::milliseconds из int (конфиг) — явное преобразование,
    // чтобы дальше сравнивать с wait_for корректно.
    auto const idle_timeout = std::chrono::milliseconds(config.worker_idle_timeout_ms);

    while (true) {
        PendingJob job;
        {
            // std::unique_lock — умеет блокироваться на condition_variable
            // (в отличие от lock_guard). Блокируется до выхода из scope.
            std::unique_lock<std::mutex> lock(queue_mutex);

            // std::condition_variable::wait_for(lock, timeout, pred):
            //   - Атомарно отпускает mutex и засыпает;
            //   - Просыпается по notify_one/notify_all ИЛИ по таймауту;
            //   - При пробуждении заново берёт mutex и проверяет pred;
            //   - Возврат: true — pred стал true (проснулись по условию,
            //     т.е. есть задача или stopping); false — истёк таймаут,
            //     pred всё ещё false (простой);
            //   - Может бросить std::system_error при сбое ОС, а также
            //     std::bad_alloc — но в штатной работе не бросает.
            bool got_job = queue_cv.wait_for(
                lock, idle_timeout, [this] {
                    return stopping || !jobs.empty();
                }
            );

            // Если объявлена остановка И очередь пуста — завершаемся.
            // Важно сначала проверить оба условия: если stopping=true,
            // но в очереди остались задачи, доработаем их (graceful
            // shutdown) и завершимся на следующей итерации.
            if (stopping && jobs.empty()) {
                // Уменьшаем счётчик живых воркеров — для worker_count()
                // и логики расширения пула в maybe_spawn_worker().
                active_workers.fetch_sub(1, std::memory_order_relaxed);
                return;
            } else {}

            // Если проснулись по таймауту и работы нет — возможно,
            // пора самозавершиться (эластичный пул, пункт 4 плана).
            if (!got_job || jobs.empty()) {
                // Проверяем, не опустимся ли ниже минимума. Если
                // active_workers > min — мы "лишний" воркер, можно уйти;
                // если равен min — обязаны остаться (иначе пул деградирует
                // до 0 и новые задачи некому будет брать).
                if (active_workers.load(std::memory_order_relaxed) >
                    config.worker_threads.min) {
                    active_workers.fetch_sub(1, std::memory_order_relaxed);
                    return;
                } else {}
                // Остаёмся в пуле как часть минимума — продолжаем ждать.
                continue;
            } else {}

            // Забираем самую старую задачу (FIFO) и снимаем мьютекс
            // (unique_lock разрушится при выходе из scope) до фактического
            // выполнения — job.run() может быть долгим (сеть + кэш).
            job = std::move(jobs.front());
            jobs.pop_front();
        }

        // Защита последней линии (ПУНКТ 2.6 ПЛАНА ДОРАБОТКИ, P0): каждый
        // из четырёх on_fetch_*-обработчиков уже оборачивает свою работу
        // в try/catch и отвечает ERROR_INTERNAL_FAILURE по D-Bus (см.
        // send_internal_error_reply). Этот catch — НЕ замена тому, а
        // подстраховка: необработанное исключение здесь означало бы
        // std::terminate() этого потока, а поскольку это точка входа
        // std::thread — не просто поток, а ВЕСЬ ПРОЦЕСС демона целиком,
        // без шанса на graceful restart. Раз уж сюда дошло — ответ
        // клиенту по D-Bus отправить уже некем (bus/call в этой лямбде
        // не видны), так что остаётся только залогировать и не дать
        // процессу упасть.
        try {
            job.run();
        } catch (std::exception const& e) {
            log::error("dbus", "unhandled exception escaped worker job", {log::field("error", e.what())});
        } catch (...) {
            log::error("dbus", "unhandled exception escaped worker job", {log::field("error", "unknown")});
        }
    }
}

// ----------------------------------------------------------------------------
// DbusServer::enqueue — постановка задачи в очередь и попытка расширения.
// ----------------------------------------------------------------------------
void DbusServer::enqueue(std::function<void()> job) {
    {
        // std::lock_guard блокирует queue_mutex до конца scope; внутри —
        // только push_back, чтобы критическая секция была минимальной.
        std::lock_guard<std::mutex> lock(queue_mutex);
        // std::deque::push_back — может бросить std::bad_alloc при
        // нехватке памяти; в этом случае задача просто не будет поставлена
        // (исключение уйдёт наверх по стеку вызова).
        jobs.push_back(PendingJob{std::move(job)});
    }
    // std::condition_variable::notify_one(): будим ОДИН воркер — он
    // заберёт задачу. Остальные продолжат спать; они будут разбужены
    // последующими вызовами enqueue/notify или таймаутом.
    queue_cv.notify_one();
    // Пытаемся расширить пул, если очередь уже "подперла" — см. ниже.
    maybe_spawn_worker();
}

// ----------------------------------------------------------------------------
// DbusServer::maybe_spawn_worker — эвристическое расширение пула.
// ----------------------------------------------------------------------------
void DbusServer::maybe_spawn_worker() {
    std::size_t queue_len;
    {
        // Читаем длину очереди под тем же мьютексом, что и push_back в
        // enqueue — чтобы увидеть актуальное значение без гонок.
        std::lock_guard<std::mutex> lock(queue_mutex);
        queue_len = jobs.size();
    }
    // <=1 — считаем, что свободный воркер уже "подхватил" задачу (или
    // очередь пуста) — расширение не нужно. Это эвристика, а не точный
    // счётчик "воркеров, ждущих на condition_variable", но для целей
    // "не упираться в фиксированный размер под всплеском" её достаточно
    // (подробнее — в комментарии в шапке dbus_server.hpp).
    if (queue_len <= 1) {
        return;
    } else {}

    // active_workers.load — атомарное чтение; relaxed достаточно, т.к.
    // нам нужна только "свежая" оценка, без семантики синхронизации.
    if (active_workers.load(std::memory_order_relaxed) >= config.worker_threads.max) {
        return;
    } else {}

    // Атомарно инкрементим счётчик ДО создания потока, чтобы новый
    // worker_loop при входе уже видел корректное active_workers (это
    // важно для self-terminate по idle-таймауту внутри worker_loop).
    active_workers.fetch_add(1, std::memory_order_relaxed);
    // std::thread ctor — создаёт поток; может бросить std::system_error.
    workers.emplace_back([this] { worker_loop(); });
}

// ----------------------------------------------------------------------------
// DbusServer::on_fetch_ocsp — статический обработчик D-Bus-метода FetchOcsp.
// ----------------------------------------------------------------------------
int DbusServer::on_fetch_ocsp(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    // userdata — тот указатель, который мы передали в
    // sd_bus_add_object_vtable (там был this). Так обработчик находит
    // экземпляр DbusServer, чтобы дёргать router и enqueue.
    auto* self = static_cast<DbusServer*>(userdata);

    // Локальные переменные под аргументы. sd-bus вернёт указатели внутрь
    // сообщения m; строки/массивы валидны до sd_bus_message_unref(call)
    // (call = ref(m), так что живут, пока мы не отпустим call).
    char const* url = nullptr;
    void const* der_ptr = nullptr;
    size_t der_len = 0;
    uint32_t timeout_ms = 0;

    // sd_bus_message_read(m, "s", &url):
    //   - Читает из сообщения один аргумент-строку (D-Bus тип "s").
    //     url получает указатель на NUL-terminated строку внутри буфера
    //     сообщения (владеть не нужно);
    //   - Возврат: >=0 успех, <0 ошибка (-EINVAL если тип не совпал,
    //     -ENXIO если сообщение кончилось раньше).
    int r = sd_bus_message_read(m, "s", &url);
    if (r < 0) {
        // Возвращаем отрицательный код sd-bus — он автоматически
        // превратится в D-Bus error клиенту.
        return r;
    } else {}

    // sd_bus_message_read_array(m, 'y', &der_ptr, &der_len):
    //   - Читает из сообщения массив байт (D-Bus тип "ay"). der_ptr/der_len
    //     указывают на данные ВНУТРИ буфера сообщения (владеть не нужно,
    //     данные живут, пока живёт сообщение m/call);
    //   - Возврат: >=0 успех, <0 ошибка.
    r = sd_bus_message_read_array(m, 'y', &der_ptr, &der_len);
    if (r < 0) {
        return r;
    } else {}

    // sd_bus_message_read(m, "u", &timeout_ms):
    //   - Читает uint32 (D-Bus тип "u");
    //   - Возврат: >=0 успех, <0 ошибка.
    r = sd_bus_message_read(m, "u", &timeout_ms);
    if (r < 0) {
        return r;
    } else {}

    // Собираем proto::FetchOcspRequest из разобранных аргументов.
    proto::FetchOcspRequest req;
    // std::string::operator=(char const*) — копирование URL; может бросить
    // std::bad_alloc.
    req.responder_url = url;
    if (der_len > 0) {
        // std::vector<uint8_t>::assign(begin, end) — копирует байты DER
        // в собственный буфер, чтобы они не зависели от сообщения
        // (после отправки ответа ref на call будет снят); может бросить
        // std::bad_alloc.
        req.request_der.assign(static_cast<uint8_t const*>(der_ptr), static_cast<uint8_t const*>(der_ptr) + der_len);
    } else {}
    req.timeout_ms = timeout_ms;

    // sd_bus_message_ref(m):
    //   - Инкрементирует refcount на входящее сообщение и возвращает
    //     тот же указатель m. Нужно, чтобы держать сообщение живым ПОСЛЕ
    //     выхода из обработчика — пока воркер-поток не отправит ответ.
    //     Без ref'а sd-bus освободил бы m сразу после возврата из
    //     обработчика, и reply-сообщение (которое привязано к m) стало бы
    //     некорректным;
    //   - Возврат: sd_bus_message* (не может быть nullptr при валидном m).
    //   - Обязательство снять ref — в send_fetch_reply/send_internal_error_reply
    //     либо в catch-блоке лямбды ниже.
    sd_bus_message* call = sd_bus_message_ref(m);

    // sd_bus_message_get_bus(m):
    //   - Возвращает sd_bus*, к которому привязано сообщение m. Нужно,
    //     чтобы отправить ответ из воркер-потока без захвата this->bus
    //     (что потребовало бы синхронизации с stop());
    //   - Возврат: sd_bus* (указатель на соединение; владение не передаётся).
    sd_bus* bus = sd_bus_message_get_bus(m);

    // Кладём задачу в пул воркеров. Захватываем self/bus/call/req:
    //   - self — для доступа к router;
    //   - bus  — для отправки ответа;
    //   - call — чтобы ответить именно на этот вызов;
    //   - req  — перемещаем (std::move), чтобы не копировать DER лишний раз.
    // mutable нужен, т.к. лямбда изменяет захваченный req (передаёт по
    // ссылке в handle_ocsp, который может принимать по rvalue).
    self->enqueue(
        [self, bus, call, req = std::move(req)]() mutable {
            try {
                // Реальная работа: сеть + кэш, внутри RequestRouter.
                // Здесь возможны и "штатные" неуспехи (FetchStatus=Timeout/
                // NetworkError/InvalidResponse) — они приходят как обычный
                // resp, а не как C++-исключение.
                auto resp = self->router.handle_ocsp(req);
                // Сборка и отправка METHOD_RETURN — общий хвост для трёх Fetch*.
                send_fetch_reply(bus, call, resp);
            } catch (...) {
                // Неожиданный C++-сбой (например, std::bad_alloc) — отвечаем
                // D-Bus-ошибкой ERROR_INTERNAL_FAILURE вместо того, чтобы
                // дать исключению убить процесс через worker_loop.
                // std::current_exception() — захватывает текущее исключение
                // в std::exception_ptr; будет "переброшено" внутри
                // send_internal_error_reply для получения текста.
                send_internal_error_reply(bus, call, std::current_exception());
            }
        }
    );

    // Возврат 1 из обработчика означает для sd-bus: "метод принят к
    // обработке, ответ будет отправлен позже (асинхронно) самим
    // приложением через sd_bus_send". Это официально поддерживаемый
    // паттерн (см. шапку dbus_server.hpp).
    return 1;
}

// ROADMAP.md, раздел 2, пункт 14: FetchOcspBatch(a(sayu)) -> a(yayb).
// Читает массив структур {responder_url, request_der, timeout_ms} через
// sd_bus_message_enter_container/sd_bus_message_read по одному элементу
// за раз — sd-bus не даёт "прочитать весь массив структур одним вызовом"
// для неоднородных по типам структур (в отличие от 'ay', это не простой
// массив байт), только поэлементный обход контейнера.
int DbusServer::on_fetch_ocsp_batch(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    // Накопитель разобранных подзапросов.
    proto::FetchOcspBatchRequest batch_req;

    // sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sayu)"):
    //   - Открывает внешний контейнер — массив с сигнатурой "(sayu)"
    //     (каждый элемент — struct из string, ay, uint32). После успешного
    //     вызова все последующие sd_bus_message_read_* относятся к
    //     элементам этого массива;
    //   - SD_BUS_TYPE_ARRAY — константа 'a';
    //   - Возврат:
    //       >0 — вошли в контейнер, есть элементы;
    //        0 — массив пуст (валидный случай: a(...) с 0 элементов);
    //       <0 — ошибка (несовпадение типа и т.п.).
    int r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "(sayu)");
    if (r < 0) {
        return r;
    } else {}

    // sd-bus не умеет читать массив неоднородных структур целиком, поэтому
    // идём поэлементно: enter_container для каждого STRUCT.
    while (true) {
        // sd_bus_message_enter_container(m, SD_BUS_TYPE_STRUCT, "sayu"):
        //   - Входит в ОЧЕРЕДНУЮ struct текущего элемента массива;
        //   - Возврат:
        //       >0 — вошли в struct, она непустая;
        //        0 — элементов в массиве больше нет (естественный конец
        //            итерации; sd-bus сам "закрывает" массив за нас);
        //       <0 — ошибка.
        r = sd_bus_message_enter_container(m, SD_BUS_TYPE_STRUCT, "sayu");
        if (r < 0) {
            return r;
        } else {}
        if (r == 0) {
            // Элементы массива кончились — выходим из цикла.
            break;
        } else {}

        // Локальные переменные под один элемент структуры (s, ay, u).
        char const* url = nullptr;
        void const* der_ptr = nullptr;
        size_t der_len = 0;
        uint32_t timeout_ms = 0;

        // sd_bus_message_read(m, "s", &url) — читает строку из текущей
        // struct. Возврат: >=0 успех, <0 ошибка.
        r = sd_bus_message_read(m, "s", &url);
        if (r < 0) {
            return r;
        } else {}

        // sd_bus_message_read_array(m, 'y', &der_ptr, &der_len) — читает
        // ay из текущей struct. Данные живут внутри сообщения m.
        r = sd_bus_message_read_array(m, 'y', &der_ptr, &der_len);
        if (r < 0) {
            return r;
        } else {}

        // sd_bus_message_read(m, "u", &timeout_ms) — читает uint32 из
        // текущей struct.
        r = sd_bus_message_read(m, "u", &timeout_ms);
        if (r < 0) {
            return r;
        } else {}

        // Собираем один FetchOcspRequest и складываем в общий batch.
        proto::FetchOcspRequest req;
        req.responder_url = url;                 // копирование строки; bad_alloc возможен
        if (der_len > 0) {
            req.request_der.assign(
                static_cast<uint8_t const*>(der_ptr),
                static_cast<uint8_t const*>(der_ptr) + der_len); // bad_alloc возможен
        } else {}
        req.timeout_ms = timeout_ms;
        // std::vector::push_back — перемещаем req в batch.requests;
        // может бросить std::bad_alloc.
        batch_req.requests.push_back(std::move(req));

        // sd_bus_message_exit_container(m):
        //   - Закрывает ранее открытый через enter_container контейнер.
        //     Здесь — STRUCT текущего элемента;
        //   - Возврат: >=0 успех, <0 ошибка (например, если мы прочитали
        //     не все поля struct — sd-bus это проверяет).
        r = sd_bus_message_exit_container(m);  // закрывает STRUCT этого элемента
        if (r < 0) {
            return r;
        } else {}
    }

    // sd_bus_message_exit_container(m) — закрывает внешний ARRAY
    // (открытый в начале функции). Возврат: >=0 успех, <0 ошибка.
    r = sd_bus_message_exit_container(m);  // закрывает ARRAY
    if (r < 0) {
        return r;
    } else {}

    // sd_bus_message_ref(m) — удерживаем сообщение, чтобы ответить позже
    // из воркер-потока (см. пояснение в on_fetch_ocsp).
    sd_bus_message* call = sd_bus_message_ref(m);
    // sd_bus_message_get_bus(m) — соединение для отправки ответа.
    sd_bus* bus = sd_bus_message_get_bus(m);

    // Задача в пул: выполняем батч и собираем a(yayb) вручную.
    self->enqueue(
        [self, bus, call, batch_req = std::move(batch_req)]() mutable {
            try {
                // Реальная работа: сеть/кэш по каждому из подзапросов.
                auto batch_resp = self->router.handle_ocsp_batch(batch_req);

                // ---- Сборка ответа a(yayb) вручную ----
                sd_bus_message* reply = nullptr;

                // sd_bus_message_new_method_return(call, &reply) —
                // создаёт METHOD_RETURN, привязанный к call.
                // Возврат: >=0 успех, <0 ошибка.
                int rr = sd_bus_message_new_method_return(call, &reply);
                if (rr >= 0) {
                    // sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY,
                    // "(yayb)"):
                    //   - Открывает в reply контейнер-массив с сигнатурой
                    //     "(yayb)". Все последующие append'ы до
                    //     close_container будут добавлять элементы массива;
                    //   - Возврат: >=0 успех, <0 ошибка.
                    rr = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "(yayb)");
                } else {}
                if (rr >= 0) {
                    // Элемент за элементом: (y status, ay payload, b from_cache).
                    for (auto const& resp : batch_resp.responses) {
                        // sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT,
                        // "yayb"): открывает STRUCT одного элемента массива.
                        // Возврат: >=0 успех, <0 ошибка.
                        rr = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "yayb");
                        if (rr < 0) {
                            break;
                        } else {}
                        // sd_bus_message_append(reply, "y", val) — пишет
                        // status (byte) в текущую struct.
                        rr = sd_bus_message_append(reply, "y", static_cast<uint8_t>(resp.status));
                        if (rr >= 0) {
                            // sd_bus_message_append_array(reply, 'y', data, len) —
                            // пишет DER-байты в текущую struct.
                            void const* data = resp.payload_der.empty() ? nullptr : resp.payload_der.data();
                            rr = sd_bus_message_append_array(reply, 'y', data, resp.payload_der.size());
                        } else {}
                        if (rr >= 0) {
                            // sd_bus_message_append(reply, "b", val) —
                            // пишет from_cache в текущую struct.
                            rr = sd_bus_message_append(reply, "b", resp.from_cache ? 1 : 0);
                        } else {}
                        if (rr >= 0) {
                            // sd_bus_message_close_container(reply) —
                            // закрывает STRUCT текущего элемента.
                            // Возврат: >=0 успех, <0 ошибка.
                            rr = sd_bus_message_close_container(reply);  // закрывает этот STRUCT
                        } else {}
                        if (rr < 0) {
                            break;
                        } else {}
                    }
                } else {}
                if (rr >= 0) {
                    // sd_bus_message_close_container(reply) — закрывает
                    // внешний ARRAY (открытый sd_bus_message_open_container
                    // выше). Возврат: >=0 успех, <0 ошибка.
                    rr = sd_bus_message_close_container(reply);  // закрывает ARRAY
                } else {}
                if (rr >= 0) {
                    // sd_bus_send — отправляем ответ из воркер-потока
                    // (one-way, без ожидания; см. пояснение в
                    // send_fetch_reply).
                    sd_bus_send(bus, reply, nullptr);
                } else {}
                // sd_bus_message_unref(reply) — отпускаем локальный ref
                // на исходящее сообщение.
                if (reply != nullptr) {
                    sd_bus_message_unref(reply);
                } else {}
                // sd_bus_message_unref(call) — отпускаем ref на входящее
                // сообщение, взятый через sd_bus_message_ref(m).
                sd_bus_message_unref(call);
            } catch (...) {
                // Неожиданный C++-сбой — отвечаем ERROR_INTERNAL_FAILURE,
                // не роняем воркер/процесс.
                send_internal_error_reply(bus, call, std::current_exception());
            }
        }
    );
    return 1;
}

// ----------------------------------------------------------------------------
// DbusServer::on_fetch_crl — статический обработчик D-Bus-метода FetchCrl.
// ----------------------------------------------------------------------------
int DbusServer::on_fetch_crl(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    // Аргументы: s — distribution point URL, u — таймаут.
    char const* url = nullptr;
    uint32_t timeout_ms = 0;

    // sd_bus_message_read(m, "s", &url) — читает строку.
    int r = sd_bus_message_read(m, "s", &url);
    if (r < 0) {
        return r;
    } else {}

    // sd_bus_message_read(m, "u", &timeout_ms) — читает uint32.
    r = sd_bus_message_read(m, "u", &timeout_ms);
    if (r < 0) {
        return r;
    } else {}

    // Собираем proto::FetchCrlRequest.
    proto::FetchCrlRequest req;
    req.distribution_point_url = url; // копирование; bad_alloc возможен
    req.timeout_ms = timeout_ms;

    // sd_bus_message_ref(m) — держим сообщение до отправки ответа.
    sd_bus_message* call = sd_bus_message_ref(m);
    // sd_bus_message_get_bus(m) — соединение для отправки.
    sd_bus* bus = sd_bus_message_get_bus(m);

    // Задача в пул: реальная работа + ответ (успех или FetchStatus).
    self->enqueue(
        [self, bus, call, req = std::move(req)]() mutable {
            try {
                auto resp = self->router.handle_crl(req);
                send_fetch_reply(bus, call, resp);
            } catch (...) {
                send_internal_error_reply(bus, call, std::current_exception());
            }
        }
    );
    return 1;
}

// ----------------------------------------------------------------------------
// DbusServer::on_fetch_intermediate_cert — статический обработчик метода
// FetchIntermediateCert.
// ----------------------------------------------------------------------------
int DbusServer::on_fetch_intermediate_cert(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    // Аргументы: s — AIA URL, u — таймаут.
    char const* url = nullptr;
    uint32_t timeout_ms = 0;

    // sd_bus_message_read(m, "s", &url) — читает строку.
    int r = sd_bus_message_read(m, "s", &url);
    if (r < 0) {
        return r;
    } else {}

    // sd_bus_message_read(m, "u", &timeout_ms) — читает uint32.
    r = sd_bus_message_read(m, "u", &timeout_ms);
    if (r < 0) {
        return r;
    } else {}

    // Собираем proto::FetchIntermediateCertRequest.
    proto::FetchIntermediateCertRequest req;
    req.aia_url = url; // копирование; bad_alloc возможен
    req.timeout_ms = timeout_ms;

    // sd_bus_message_ref(m) — держим сообщение до отправки ответа.
    sd_bus_message* call = sd_bus_message_ref(m);
    // sd_bus_message_get_bus(m) — соединение для отправки.
    sd_bus* bus = sd_bus_message_get_bus(m);

    // Задача в пул: реальная работа + ответ.
    self->enqueue(
        [self, bus, call, req = std::move(req)]() mutable {
            try {
                auto resp = self->router.handle_intermediate_cert(req);
                send_fetch_reply(bus, call, resp);
            } catch (...) {
                send_internal_error_reply(bus, call, std::current_exception());
            }
        }
    );
    return 1;
}

// ----------------------------------------------------------------------------
// DbusServer::on_health_check — статический обработчик D-Bus-метода
// HealthCheck. Синхронный: выполняется прямо в bus-потоке, без воркера
// (не делает сети, только читает счётчики).
//
// ВАЖНО: в отличие от on_fetch_*, здесь НЕТ try/catch вокруг
// router.handle_health_check(). Если оно бросит — исключение уйдёт из
// C-колбэка в sd-bus (UB). Осознанное решение; если станет проблемой —
// обернуть аналогично send_internal_error_reply (см. комментарий в .hpp).
// ----------------------------------------------------------------------------
int DbusServer::on_health_check(sd_bus_message* m, void* userdata, sd_bus_error* /*ret_error*/) {
    auto* self = static_cast<DbusServer*>(userdata);

    // Синхронно читаем сводку: счётчики по типам запросов и уровню кэша.
    auto resp = self->router.handle_health_check();

    // Сборка METHOD_RETURN из b + 13*t.
    sd_bus_message* reply = nullptr;

    // sd_bus_message_new_method_return(m, &reply):
    //   - Создаёт METHOD_RETURN, привязанный к входящему m. Здесь call
    //     не нужен отдельно, потому что мы отвечаем сразу, из того же
    //     потока/кадра, где m ещё валиден;
    //   - Возврат: >=0 успех, <0 ошибка.
    int r = sd_bus_message_new_method_return(m, &reply);

    // sd_bus_message_append(reply, "b", healthy) — пишет b(bool healthy).
    if (r >= 0) {
        r = sd_bus_message_append(reply, "b", resp.healthy ? 1 : 0);
    } else {}

    // ---- Поля t (uint64) в том же порядке, что и в out_signature
    //      "bttttttttttttt" (см. VTABLE) ----

    // cache_entries — число записей в дисковом кэше.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.cache_entries);
    } else {}
    // cache_size_bytes — размер дискового кэша в байтах.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.cache_size_bytes);
    } else {}
    // memory_cache_entries — число записей в in-memory уровне кэша.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.memory_cache_entries);
    } else {}
    // memory_cache_size_bytes — размер in-memory кэша в байтах.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.memory_cache_size_bytes);
    } else {}
    // OCSP: requests / cache_hits / errors.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.ocsp.requests);
    } else {}
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.ocsp.cache_hits);
    } else {}
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.ocsp.errors);
    } else {}
    // CRL: requests / cache_hits / errors.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.crl.requests);
    } else {}
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.crl.cache_hits);
    } else {}
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.crl.errors);
    } else {}
    // AIA (промежуточные сертификаты): requests / cache_hits / errors.
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.intermediate_cert.requests);
    } else {}
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.intermediate_cert.cache_hits);
    } else {}
    if (r >= 0) {
        r = sd_bus_message_append(reply, "t", resp.intermediate_cert.errors);
    } else {}

    if (r >= 0) {
        // sd_bus_message_get_bus(m) — берём соединение прямо из m, чтобы
        // не тащить лишний параметр. Это тот же bus, что и в остальных
        // обработчиках; в отличие от них, здесь мы НЕ делаем
        // sd_bus_message_ref(m), потому что отправляем ответ сразу,
        // пока m ещё жив (обработчик не возвращает 1, а завершает
        // синхронно, но фактическую отправку делает sd_bus_send).
        //
        // sd_bus_send(bus, reply, nullptr) — отправляет METHOD_RETURN
        // в шину. Возврат присваиваем в r, чтобы попасть в общий
        // "if (reply != nullptr)" ниже, но по сути код возврата здесь
        // не важен (см. комментарий в send_fetch_reply).
        r = sd_bus_send(sd_bus_message_get_bus(m), reply, nullptr);
    } else {}

    // sd_bus_message_unref(reply) — отпускаем локальный ref на reply.
    if (reply != nullptr) {
        sd_bus_message_unref(reply);
    } else {}

    // Возврат 1 — стандартное "ответ отправлен" для синхронного
    // обработчика. Хотя фактически sd_bus_send уже вызван, семантика
    // возврата 1 та же, что и при асинхронном ответе: sd-bus не будет
    // ничего автоматически отправлять клиенту.
    return 1;
}

}  // namespace cert_helper::ipc