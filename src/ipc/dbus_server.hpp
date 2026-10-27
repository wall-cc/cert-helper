// dbus_server.hpp
//
// Серверная часть транспорта cert-helper поверх D-Bus (sd-bus, часть
// libsystemd).
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
// Права доступа контролируются D-Bus policy-файлом на системной шине — см.
// deploy/org.certhelper.CertHelper1.conf.

#pragma once

#include <systemd/sd-bus.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../request_router.hpp"
#include "dbus_interface.hpp"

namespace cert_helper::ipc {

/**
 * @brief D-Bus-транспорт сервера cert-helper поверх sd-bus.
 *
 * @details Разделяет обработку одного sd_bus-соединения (bus-поток) и
 *          фактическую работу по OCSP/CRL/AIA-запросам (пул воркеров).
 *          См. подробное обоснование архитектуры в шапке этого файла и в
 *          dbus_server.cpp.
 *
 * @note    Экземпляр не является копируемым/перемещаемым: содержит
 *          std::mutex, std::thread, sd_bus* — копирование/перемещение
 *          семантически бессмысленно и намеренно не поддержано.
 * @note    Время жизни: обычно создаётся в main демона, стартует через
 *          start(), живёт до stop()/деструктора. Методы start()/stop()
 *          не являются потокобезопасными относительно друг друга —
 *          вызывайте их из одного потока (обычно main).
 */
class DbusServer {
public:
    /**
     * @brief Параметры конфигурации сервера.
     * @details Передаётся по значению в конструктор и перемещается внутрь
     *          экземпляра; после старта не изменяется.
     */
    struct Config {
        /**
         * @brief Адрес шины D-Bus.
         * @details Пусто — подключиться к системной шине
         *          (sd_bus_open_system); непусто — подключиться к указанному
         *          адресу (используется в тестах: приватный dbus-daemon на
         *          своём сокете, см. tests/test_client_server_roundtrip.cpp).
         */
        std::string bus_address;

        /**
         * @brief Well-known имя, которое сервер запросит через
         *        sd_bus_request_name().
         * @details По умолчанию — SERVICE_NAME из dbus_interface.hpp.
         *          Вынесено в конфиг, чтобы в тестах можно было взять
         *          отдельное имя и не конфликтовать с "настоящим" демоном.
         */
        std::string well_known_name = SERVICE_NAME;

        /**
         * @brief Параметры эластичного пула воркеров (пункт 4 плана
         *        доработки).
         * @details Пул стартует с min потоками, при всплеске нагрузки
         *          временно расширяется до max, а "лишние" потоки
         *          самозавершаются после idle_timeout_ms простоя, но только
         *          пока их число выше min (см. worker_loop и
         *          maybe_spawn_worker в dbus_server.cpp).
         */
        struct  {
            int min = 2;                ///< Минимум постоянно живых воркеров (стартуют в start()).
            int max = 16;               ///< Потолок расширения пула; выше не растём.
            int idle_timeout_ms = 30000; ///< Простой (мс), после которого "лишний" воркер (сверх min) завершается.
        } worker_threads;
    };

    /**
     * @brief Конструктор: сохраняет конфиг и ссылку на роутер, но ещё не
     *        подключается к шине и не запускает потоки.
     * @param config  Конфигурация; перемещается внутрь экземпляра.
     * @param router  Ссылка на роутер запросов; должна пережить экземпляр
     *                DbusServer (обычно оба объекта живут в main демона).
     * @note  Ссылка на router не удерживается по времени жизни — за это
     *        отвечает вызывающий код.
     */
    DbusServer(Config config, RequestRouter& router);

    /**
     * @brief Деструктор: вызывает stop(), чтобы корректно завершить
     *        bus-поток и пул воркеров, если пользователь не сделал этого
     *        явно.
     * @note  Деструктор в C++11+ неявно `noexcept`; если stop() бросит
     *        исключение (например, std::thread::join — std::system_error),
     *        произойдёт std::terminate. Поэтому stop() должен завершаться
     *        без исключений в штатной эксплуатации.
     */
    ~DbusServer();

    /**
     * @brief Подключение к шине, регистрация объекта/имени, запуск потоков.
     * @return true — успех; false — любая ошибка подключения/регистрации
     *         на шине (с записью диагностики в log).
     * @note  Метод идемпотентно-небезопасен: повторный вызов после
     *        успешного start() без stop() приведёт к неопределённому
     *        поведению (повторная регистрация того же vtable и т.п.).
     * @throws Может выбросить std::system_error при неудачном создании
     *         std::thread, а также любое исключение из log::error.
     */
    bool start();

    /**
     * @brief Остановка: джойнит bus-поток, гасит воркеров, освобождает
     *        sd_bus/sd_bus_slot.
     * @details Идемпотентен: повторный вызов после успешного stop()
     *          — no-op (проверка через exchange(false)).
     * @note  Ожидает завершения всех уже запущенных воркеров (join) —
     *        поэтому не возвращается мгновенно, если воркеры заняты
     *        длинным HTTP-запросом.
     * @throws Может выбросить std::system_error из std::thread::join
     *         и любое исключение из log::error.
     */
    void stop();

    /**
     * @brief Блокирующее ожидание внешней остановки демона (running==false).
     * @details Реализовано как polling с шагом 200 мс; подходит для main
     *          демона, который после start() просто ждёт сигнала от
     *          systemd/SIGTERM и затем вызывает stop(). Реальная остановка
     *          выполняется не здесь, а внешним кодом (stop()).
     * @note  Помечен `noexcept`: тело метода — только
     *        `std::atomic_bool::load()` и `std::this_thread::sleep_for()`,
     *        оба `noexcept`; исключений бросать не может.
     */
    void wait_until_stopped() noexcept;

    /**
     * @brief Текущее число живых воркеров (только для тестов/диагностики).
     * @details Отражает эластичное масштабирование пула (пункт 4 плана
     *          доработки); меняется воркерами при старте/самозавершении.
     * @return Значение std::atomic<int> active_workers.
     * @note  Помечен `noexcept`: тело — только `std::atomic<int>::load()`.
     */
    int worker_count() const noexcept {
        return active_workers.load();
    }

    /**
     * @brief Статический обработчик D-Bus-метода FetchOcsp.
     * @details Вызывается sd-bus в bus-потоке; разбирает аргументы,
     *          оборачивает proto::FetchOcspRequest и ставит задачу в пул
     *          воркеров, возвращая 1 (ответ будет отправлен асинхронно).
     *          См. подробный разбор в одноимённой реализации в .cpp.
     * @return 1 (ответ отложен) или отрицательный код ошибки sd-bus при
     *         разборе аргументов.
     */
    static int on_fetch_ocsp(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

    /**
     * @brief Статический обработчик D-Bus-метода FetchOcspBatch.
     * @details Аналогичен on_fetch_ocsp, но читает массив структур
     *          "(sayu)" поэлементно через enter/exit_container — см. .cpp.
     */
    static int on_fetch_ocsp_batch(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

    /**
     * @brief Статический обработчик D-Bus-метода FetchCrl.
     */
    static int on_fetch_crl(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

    /**
     * @brief Статический обработчик D-Bus-метода FetchIntermediateCert.
     */
    static int on_fetch_intermediate_cert(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

    /**
     * @brief Статический обработчик D-Bus-метода HealthCheck.
     * @details Выполняется синхронно в bus-потоке (не через пул воркеров):
     *          не делает сети и не блокируется надолго — только читает
     *          атомарные счётчики и размеры кэша.
     * @warning В отличие от on_fetch_*, метод НЕ оборачивает вызов
     *          router.handle_health_check() в try/catch (осознанно: сбой
     *          health-check не должен маскироваться fetch-ошибкой). Если
     *          handle_health_check() бросит исключение — оно уйдёт наружу
     *          в sd-bus (UB для C-колбэка). Если это станет проблемой —
     *          обернуть аналогично send_internal_error_reply().
     */
    static int on_health_check(sd_bus_message* m, void* userdata, sd_bus_error* ret_error);

private:
    /**
     * @brief Элемент очереди пула воркеров.
     * @details Намеренно тонкая обёртка над std::function<void()>:
     *          конкретный payload (лямбда с захватом req, call, bus)
     *          формируется в on_fetch_* и не знает о структуре очереди.
     */
    struct PendingJob {
        std::function<void()> run; ///< Работа; вызывается воркером без аргументов.
    };

    /**
     * @brief Цикл bus-потока: sd_bus_process() + короткий sd_bus_wait().
     * @details При фатальной ошибке sd-bus выставляет running=false, и
     *          цикл завершается; оживить соединение пытается systemd/
     *          эксплуатация через Restart=on-failure (см. комментарий в .cpp).
     * @throws log::error потенциально может бросить; в штатной работе
     *         исключений не ожидается, но noexcept НЕ ставим.
     */
    void bus_loop();

    /**
     * @brief Цикл одного воркера: ждёт задачи в очереди, выполняет,
     *        самозавершается по idle-таймауту (если выше min).
     * @details Пункт 4 плана доработки: эластичный пул. Все исключения
     *          из job.run() перехватываются (иначе std::terminate всего
     *          процесса), см. подробный комментарий в .cpp.
     */
    void worker_loop();

    /**
     * @brief Постановка задачи в очередь + попытка расширить пул.
     * @param job Готовый функтор; перемещается в очередь.
     * @throws Может выбросить std::bad_alloc (push_back) или
     *         std::system_error (создание потока в maybe_spawn_worker).
     */
    void enqueue(std::function<void()> job);

    /**
     * @brief Эвристика эластичного расширения пула (пункт 4).
     * @details Вызывается из enqueue() ПОСЛЕ освобождения queue_mutex;
     *          берёт свой lock внутри. Если в очереди уже >1 задачи —
     *          считаем, что свободных воркеров нет, и добавляем ещё одного
     *          (но не выше config.max_worker_threads). См. комментарий
     *          в .cpp про упрощения этой эвристики.
     */
    void maybe_spawn_worker();  // вызывается из enqueue() под queue_mutex

    Config config;        ///< Конфигурация, перемещённая из конструктора.
    RequestRouter& router; ///< Ссылка на роутер (не владеем; должен пережить нас).

    sd_bus* bus = nullptr;      ///< Соединение sd-bus (nullptr до start()).
    sd_bus_slot* slot = nullptr; ///< Слот зарегистрированного vtable (для unref в stop()).

    std::atomic_bool running = false; ///< Флаг "демон работает"; выставляется/сбрасывается извне и из bus_loop.
    std::thread bus_thread;           ///< Поток, крутящий bus_loop().
    std::atomic_int active_workers = 0; ///< Кол-во живых воркеров (для worker_count и логики self-terminate).
    std::vector<std::thread> workers;  ///< Все запущенные воркеры (join'ятся в stop()).
    std::mutex queue_mutex;            ///< Защищает jobs и stopping.
    std::condition_variable queue_cv;  ///< Сигнализирует воркерам о новой задаче/остановке.
    std::deque<PendingJob> jobs;       ///< Очередь задач FIFO.
    bool stopping = false;             ///< Флаг "пора завершаться" для воркеров (под queue_mutex).
};

}  // namespace cert_helper::ipc