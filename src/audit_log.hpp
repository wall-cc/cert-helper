// audit_log.hpp
//
// Аудит-лог решений о фетче (ROADMAP.md, раздел 4, пункт 23). Для
// регуляторных сред: отдельный append-only построчный журнал "что
// докачивали, откуда, с каким результатом, когда". Это НЕ метрики
// (агрегаты в HealthCheck) и НЕ диагностический лог (logging.hpp, для
// людей и отладки, с уровнями и ротацией по усмотрению оператора) — а
// журнал событий, по которому можно восстановить, каждый ли запрос к
// внешним серверам был выполнен/отклонён и почему.
//
// Формат — JSON Lines (одна запись = одна строка = один JSON-объект,
// UTF-8), в файле, заданном --audit-log-file. Пусто (по умолчанию) —
// аудит выключен, и это ничего не стоит. Пример:
//
//   {"ts":"2026-01-02T03:04:05.678Z","seq":42,"event":"fetch","type":"ocsp",
//    "url":"http://ocsp.example/","serial":"0A1B2C","decision":"network_fetch",
//    "result":"ok","bytes":1830,"duration_ms":57,"http_status":200}
//
// Поля события "fetch":
//   type        ocsp | crl | aia
//   url         responder / CRL distribution point / AIA URL (недоверенные
//               данные из сертификата — экранируются как любая JSON-строка)
//   serial      только ocsp: серийный номер проверяемого сертификата (hex) —
//               URL responder'а сам по себе не говорит, ЧТО именно проверяли
//   decision    как запрос был обслужен:
//                 cache_hit       — ответ из кэша, сеть не трогали
//                 network_fetch   — запрос ушёл во внешнюю сеть
//                 shared_inflight — точно такой же запрос уже выполнялся в
//                                   этот момент (singleflight), взят его результат
//                 blocked         — демон САМ отказался выполнять запрос, см. reason
//   result      ok | timeout | network_error | invalid_response
//   reason      только при blocked: invalid_url | https_disabled |
//               https_unavailable | port_denied | address_denied |
//               circuit_open | ldap_disabled | policy_denied
//               (address_denied/policy_denied — потенциальная SSRF-попытка
//               через URL из сертификата)
//   bytes       размер отданного payload (0 при ошибке)
//   duration_ms сколько запрос занял в демоне (для cache_hit — ~0)
//   http_status HTTP-код ответа сервера, если он был получен
//   batch_size  только ocsp: сколько сертификатов ушло одним объединённым
//               OCSP-запросом (см. FetchOcspBatch), если больше одного
//
// Служебные события: "daemon_start" / "daemon_stop" — границы работы
// процесса (seq начинается с 1 после каждого старта, эти события делают
// такой сброс однозначным).
//
// ГАРАНТИИ И СОЗНАТЕЛЬНЫЕ ОГРАНИЧЕНИЯ:
//   * Append-only на уровне процесса: файл открыт с O_APPEND, демон ничего
//     не перезаписывает и не усекает. Защита от изменения ДРУГИМИ (chattr +a,
//     отдельная файловая система, пересылка в удалённый syslog/SIEM) — задача
//     эксплуатации; см. README.md.
//   * Сквозной номер seq назначается ДО записи: если запись не удалась
//     (диск полон), в файле останется пропуск в нумерации — потеря
//     обнаруживается, а не замалчивается. Поэтому seq не переиспользуется.
//   * Отказ записи НЕ останавливает обработку запросов (доступность
//     TLS-инспекции важнее): ошибка логируется один раз при переходе в
//     состояние отказа (и один раз при восстановлении), а счётчик
//     write_failures() растёт. Если оператору нужна политика "нет аудита —
//     нет сервиса" — это отдельное решение; сейчас проверяется только что
//     файл удалось ОТКРЫТЬ при старте (демон не стартует, если нет).
//   * Ротация: перед каждой записью сверяется (dev, inode) открытого файла
//     с тем, что сейчас лежит по пути. Переименовали/удалили файл (обычный
//     logrotate в режиме create) — демон сам откроет новый, SIGHUP не нужен.
//     copytruncate тоже безопасен (O_APPEND).
//   * --audit-log-fsync: fsync после каждого события. Дороже, но событие
//     переживает крах ОС/питания; по умолчанию выключено.
//   * Фетчи прогрева кэша (--warmup-file) идут через тот же роутер и попадают
//     в журнал так же, как запросы клиентов — отдельной пометки "кто
//     запросил" нет (идентификация D-Bus-клиента — возможное расширение).
//   * Файл создаётся с правами 0640 и открывается с O_NOFOLLOW (не следует
//     по symlink'у в последнем компоненте пути).

#pragma once

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/cert_helper/protocol.hpp"
#include "logging.hpp"

namespace cert_helper::audit {

enum class RequestType : uint8_t { Ocsp, Crl, Aia };
enum class Decision : uint8_t { CacheHit, NetworkFetch, SharedInflight, Blocked };

inline const char* request_type_name(RequestType t) {
    switch (t) {
        case RequestType::Ocsp: return "ocsp";
        case RequestType::Crl: return "crl";
        case RequestType::Aia: return "aia";
    }
    return "";
}

inline const char* decision_name(Decision d) {
    switch (d) {
        case Decision::CacheHit: return "cache_hit";
        case Decision::NetworkFetch: return "network_fetch";
        case Decision::SharedInflight: return "shared_inflight";
        case Decision::Blocked: return "blocked";
    }
    return "";
}

inline const char* status_name(protocol::FetchStatus s) {
    switch (s) {
        case protocol::FetchStatus::Ok: return "ok";
        case protocol::FetchStatus::Timeout: return "timeout";
        case protocol::FetchStatus::NetworkError: return "network_error";
        case protocol::FetchStatus::InvalidResponse: return "invalid_response";
    }
    return "network_error";
}

struct FetchEvent {
    RequestType type = RequestType::Ocsp;
    std::string url;
    Decision decision = Decision::NetworkFetch;
    std::string result;
    std::string reason;       // только для Blocked
    std::string serial;       // только для ocsp
    uint64_t bytes = 0;
    uint64_t duration_ms = 0;
    int http_status = 0;      // 0 — не было HTTP-ответа / неприменимо
    uint32_t batch_size = 0;  // > 1 — часть объединённого OCSP-запроса
};

inline std::vector<log::Field> to_fields(const FetchEvent& e) {
    std::vector<log::Field> f;
    f.push_back(log::field("type", request_type_name(e.type)));
    f.push_back(log::field("url", e.url));
    if (!e.serial.empty()) f.push_back(log::field("serial", e.serial));
    f.push_back(log::field("decision", decision_name(e.decision)));
    f.push_back(log::field("result", e.result));
    if (!e.reason.empty()) f.push_back(log::field("reason", e.reason));
    f.push_back(log::field("bytes", e.bytes));
    f.push_back(log::field("duration_ms", e.duration_ms));
    if (e.http_status > 0) f.push_back(log::field("http_status", e.http_status));
    if (e.batch_size > 1) f.push_back(log::field("batch_size", e.batch_size));
    return f;
}

// Приёмник аудит-событий. Реализация ОБЯЗАНА быть потокобезопасной
// (роутер вызывает её из нескольких воркер-потоков) и не должна бросать
// исключения в вызывающий код.
class IAuditSink {
public:
    virtual ~IAuditSink() = default;
    virtual void record(std::string_view event, const std::vector<log::Field>& fields) = 0;
};

// Одна строка журнала без завершающего '\n'. Чистая функция — тестируется
// отдельно от файлового ввода-вывода. Ключи полей ts/seq/event зарезервированы:
// совпавший ключ получает суффикс '_', чтобы не подменить служебное поле.
inline std::string format_audit_line(int64_t unix_ms, uint64_t seq, std::string_view event,
                                     const std::vector<log::Field>& fields) {
    std::string out = "{\"ts\":";
    log::detail::append_json_escaped(out, log::format_timestamp(unix_ms));
    out += ",\"seq\":";
    out += std::to_string(seq);
    out += ",\"event\":";
    log::detail::append_json_escaped(out, event);
    for (const auto& f : fields) {
        std::string key = f.key;
        if (key == "ts" || key == "seq" || key == "event") key.push_back('_');
        out.push_back(',');
        log::detail::append_json_escaped(out, key);
        out.push_back(':');
        if (f.kind == log::Field::Kind::String) {
            log::detail::append_json_escaped(out, f.value);
        } else {
            out += f.value; // Number/Bool — уже валидный JSON-литерал
        }
    }
    out.push_back('}');
    return out;
}

class FileAuditLog : public IAuditSink {
public:
    struct Options {
        std::string path;
        bool fsync_each_event = false;
    };

    explicit FileAuditLog(Options options) : options_(std::move(options)) {}
    ~FileAuditLog() override {
        std::lock_guard<std::mutex> lock(mutex_);
        close_locked();
    }
    FileAuditLog(const FileAuditLog&) = delete;
    FileAuditLog& operator=(const FileAuditLog&) = delete;

    // Открывает (при необходимости создаёт) файл. Вызывается при старте
    // демона: если не получилось — демон не должен стартовать молча без
    // аудита, который оператор явно потребовал.
    bool open(std::string* error = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (open_locked()) return true;
        if (error != nullptr) *error = last_error_;
        return false;
    }

    void record(std::string_view event, const std::vector<log::Field>& fields) override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const uint64_t seq = ++seq_; // до записи — см. "ГАРАНТИИ" в шапке файла
            std::string line = format_audit_line(log::now_unix_ms(), seq, event, fields);
            line.push_back('\n');
            // Прошлая запись оборвалась посреди строки и закрыть её не
            // удалось — начинаем с перевода строки, иначе эта (хорошая)
            // запись слиплась бы с огрызком в одну нечитаемую строку.
            if (dirty_tail_) line.insert(line.begin(), '\n');

            bool ok = ensure_current_locked() && write_all_locked(line);
            if (ok && options_.fsync_each_event && ::fsync(fd_) != 0) {
                last_error_ = std::strerror(errno);
                ok = false;
            }

            if (ok) {
                dirty_tail_ = false;
                if (failing_) {
                    failing_ = false;
                    log::info("audit", "audit log writes recovered", {log::field("path", options_.path)});
                }
            } else {
                failures_.fetch_add(1, std::memory_order_relaxed);
                if (!failing_) {
                    failing_ = true;
                    log::error("audit",
                               "audit log write failed — events are lost until it recovers "
                               "(gap in seq will show how many)",
                               {log::field("path", options_.path), log::field("error", last_error_)});
                }
            }
        } catch (...) {
            failures_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Сколько событий не удалось записать с момента старта.
    uint64_t write_failures() const { return failures_.load(std::memory_order_relaxed); }

private:
    bool open_locked() {
        int fd = ::open(options_.path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
        if (fd < 0) {
            last_error_ = std::strerror(errno);
            return false;
        }
        struct stat st{};
        if (::fstat(fd, &st) != 0) {
            last_error_ = std::strerror(errno);
            ::close(fd);
            return false;
        }
        if (!S_ISREG(st.st_mode)) {
            last_error_ = "not a regular file";
            ::close(fd);
            return false;
        }
        fd_ = fd;
        dev_ = st.st_dev;
        ino_ = st.st_ino;
        return true;
    }

    void close_locked() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    // Если файл по пути уже не тот (переименован/удалён/заменён ротацией) —
    // переоткрываем; иначе продолжали бы писать в ротированный файл.
    bool ensure_current_locked() {
        if (fd_ >= 0) {
            struct stat st{};
            if (::stat(options_.path.c_str(), &st) == 0 && st.st_dev == dev_ && st.st_ino == ino_) {
                return true;
            }
            close_locked();
        }
        return open_locked();
    }

    bool write_all_locked(const std::string& data) {
        size_t written = 0;
        while (written < data.size()) {
            ssize_t n = ::write(fd_, data.data() + written, data.size() - written);
            if (n < 0) {
                if (errno == EINTR) continue;
                last_error_ = std::strerror(errno);
                if (written > 0) {
                    // Оборванная посреди строки запись: пытаемся закрыть
                    // огрызок переводом строки. Не вышло (типично: то же
                    // самое "диск полон") — помним об этом (dirty_tail_),
                    // и СЛЕДУЮЩАЯ успешная запись начнёт с '\n'.
                    dirty_tail_ = (::write(fd_, "\n", 1) != 1);
                }
                return false;
            }
            written += static_cast<size_t>(n);
        }
        return true;
    }

    const Options options_;
    std::mutex mutex_;
    int fd_ = -1;
    dev_t dev_ = 0;
    ino_t ino_ = 0;
    uint64_t seq_ = 0;
    bool failing_ = false;
    bool dirty_tail_ = false; // в конце файла остался незакрытый обрывок строки
    std::string last_error_;
    std::atomic<uint64_t> failures_{0};
};

} // namespace cert_helper::audit
