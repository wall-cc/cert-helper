// logging.hpp
//
// Структурированное логирование демона (ROADMAP.md, раздел 4, пункт 22).
// Заменяет разрозненные fprintf(stderr, "cert-helper: ...") единым
// интерфейсом с уровнями и именованными полями.
//
// Три формата вывода (--log-format):
//   text     — `[2026-01-02T03:04:05.678Z] [warn] [http] сообщение key=value ...`
//              (по умолчанию: под systemd stderr и так попадает в journald,
//              а для ручного запуска это самый читаемый вариант);
//   json     — один JSON-объект на строку (JSON Lines) для ELK/Loki/Vector:
//              {"ts":"...","level":"warn","component":"http","msg":"...","port":8080}
//   journald — нативные структурированные поля через sd_journal_sendv()
//              (тот же libsystemd, что уже используется под sd-bus):
//              MESSAGE, PRIORITY, SYSLOG_IDENTIFIER, CH_COMPONENT и по
//              одному полю CH_<КЛЮЧ> на каждое поле записи, так что
//              работает `journalctl CH_COMPONENT=http CH_PORT=8080`.
//              Если журнал недоступен (контейнер без journald и т.п.) —
//              запись не теряется, а уходит текстом в stderr. Доступность
//              проверяется по наличию сокета журнала перед КАЖДОЙ записью, а
//              не по коду возврата sd_journal_sendv(): при отсутствии сокета
//              (ENOENT) libsystemd намеренно возвращает успех и молча
//              выбрасывает запись, так что по коду возврата потерю не увидеть.
//
// БЕЗОПАСНОСТЬ (log injection): значительная часть того, что мы логируем
// (URL из AIA/OCSP/CDP, имена хостов), приходит из сертификатов, то есть
// от недоверенной стороны. Поэтому во ВСЕХ форматах управляющие символы
// (включая \n и \r) экранируются, а некорректный UTF-8 не пропускается
// как есть: в text — \xNN, в json — U+FFFD. Так один сертификат не может
// вставить в лог поддельную строку или сломать разбор JSON.
//
// Потокобезопасность: каждая запись форматируется в одну строку и
// выводится одним вызовом под мьютексом — строки разных потоков не
// перемешиваются. Проверка уровня — атомарная, без блокировки.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <sys/uio.h>
#include <systemd/sd-journal.h>

namespace cert_helper::log {

enum class Level : uint8_t { Debug = 0, Info = 1, Warn = 2, Error = 3 };
enum class Format : uint8_t { Text, Json, Journald };

// Одно именованное поле записи. kind определяет, как значение выводится
// в JSON (строка в кавычках / число / true|false); в text и journald
// значение всегда выводится как текст.
struct Field {
    enum class Kind : uint8_t { String, Number, Bool };
    std::string key;
    std::string value;
    Kind kind = Kind::String;
};

inline Field field(std::string key, std::string value) {
    return Field{std::move(key), std::move(value), Field::Kind::String};
}
inline Field field(std::string key, const char* value) {
    return Field{std::move(key), value != nullptr ? value : "", Field::Kind::String};
}
inline Field field(std::string key, bool value) {
    return Field{std::move(key), value ? "true" : "false", Field::Kind::Bool};
}
template <typename T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
Field field(std::string key, T value) {
    return Field{std::move(key), std::to_string(value), Field::Kind::Number};
}

struct Record {
    int64_t unix_ms = 0;
    Level level = Level::Info;
    std::string component;
    std::string message;
    std::vector<Field> fields;
};

inline const char* level_name(Level level) {
    switch (level) {
        case Level::Debug: return "debug";
        case Level::Info: return "info";
        case Level::Warn: return "warn";
        case Level::Error: return "error";
    }
    return "info";
}

inline std::optional<Level> parse_level(std::string_view s) {
    std::string lower;
    for (char c : s) lower.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
    if (lower == "debug") return Level::Debug;
    if (lower == "info") return Level::Info;
    if (lower == "warn" || lower == "warning") return Level::Warn;
    if (lower == "error") return Level::Error;
    return std::nullopt;
}

inline std::optional<Format> parse_format(std::string_view s) {
    std::string lower;
    for (char c : s) lower.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
    if (lower == "text") return Format::Text;
    if (lower == "json") return Format::Json;
    if (lower == "journald") return Format::Journald;
    return std::nullopt;
}

namespace detail {

// Длина корректной UTF-8 последовательности, начинающейся в s[i] (1..4),
// либо 0, если там некорректные байты. Отвергает "overlong"-формы,
// суррогаты (U+D800..U+DFFF) и значения выше U+10FFFF — то есть ровно то,
// что строгие JSON-парсеры и journald тоже не считают допустимым.
inline size_t valid_utf8_len(std::string_view s, size_t i) {
    const auto b0 = static_cast<unsigned char>(s[i]);
    if (b0 < 0x80) return 1;
    auto cont = [&](size_t k) {
        return i + k < s.size() && (static_cast<unsigned char>(s[i + k]) & 0xC0) == 0x80;
    };
    if (b0 >= 0xC2 && b0 <= 0xDF) return cont(1) ? 2 : 0;
    if (b0 >= 0xE0 && b0 <= 0xEF) {
        if (!cont(1) || !cont(2)) return 0;
        const auto b1 = static_cast<unsigned char>(s[i + 1]);
        if (b0 == 0xE0 && b1 < 0xA0) return 0; // overlong
        if (b0 == 0xED && b1 > 0x9F) return 0; // суррогаты
        return 3;
    }
    if (b0 >= 0xF0 && b0 <= 0xF4) {
        if (!cont(1) || !cont(2) || !cont(3)) return 0;
        const auto b1 = static_cast<unsigned char>(s[i + 1]);
        if (b0 == 0xF0 && b1 < 0x90) return 0; // overlong
        if (b0 == 0xF4 && b1 > 0x8F) return 0; // > U+10FFFF
        return 4;
    }
    return 0;
}

inline void append_hex_byte(std::string& out, const char* prefix, unsigned char b) {
    static const char* kHex = "0123456789abcdef";
    out += prefix;
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
}

// Экранирование для text-формата и journald: печатный ASCII и корректный
// UTF-8 проходят как есть; \n \r \t, кавычка и обратный слэш — как в C;
// прочие управляющие и некорректные байты — \xNN. Кавычку и слэш
// экранируем только когда значение выводится в кавычках (quote=true).
inline void append_text_escaped(std::string& out, std::string_view s, bool quote) {
    for (size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            switch (c) {
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                case '"':
                    if (quote) out += "\\\""; else out.push_back('"');
                    break;
                case '\\':
                    if (quote) out += "\\\\"; else out.push_back('\\');
                    break;
                default:
                    if (c < 0x20 || c == 0x7F) append_hex_byte(out, "\\x", c);
                    else out.push_back(static_cast<char>(c));
            }
            ++i;
            continue;
        }
        const size_t len = valid_utf8_len(s, i);
        if (len == 0) {
            append_hex_byte(out, "\\x", c);
            ++i;
        } else {
            out.append(s.substr(i, len));
            i += len;
        }
    }
}

inline void append_json_escaped(std::string& out, std::string_view s) {
    out.push_back('"');
    for (size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20 || c == 0x7F) {
                        static const char* kHex = "0123456789abcdef";
                        out += "\\u00";
                        out.push_back(kHex[c >> 4]);
                        out.push_back(kHex[c & 0x0F]);
                    } else {
                        out.push_back(static_cast<char>(c));
                    }
            }
            ++i;
            continue;
        }
        const size_t len = valid_utf8_len(s, i);
        if (len == 0) {
            out += "\\ufffd"; // U+FFFD REPLACEMENT CHARACTER
            ++i;
        } else {
            out.append(s.substr(i, len));
            i += len;
        }
    }
    out.push_back('"');
}

// Значение в text-формате берётся в кавычки, если оно пустое или
// содержит пробел, '=', кавычку, слэш либо что-то нестандартное — иначе
// `key=value` нельзя было бы однозначно разобрать (logfmt-подобное правило).
inline bool text_value_needs_quotes(std::string_view v) {
    if (v.empty()) return true;
    for (char ch : v) {
        const auto c = static_cast<unsigned char>(ch);
        if (c <= 0x20 || c == '"' || c == '=' || c == '\\' || c >= 0x7F) return true;
    }
    return false;
}

inline bool is_reserved_json_key(std::string_view k) {
    return k == "ts" || k == "level" || k == "component" || k == "msg";
}

} // namespace detail

inline std::string format_timestamp(int64_t unix_ms) {
    if (unix_ms < 0) unix_ms = 0;
    const std::time_t secs = static_cast<std::time_t>(unix_ms / 1000);
    const int ms = static_cast<int>(unix_ms % 1000);
    struct tm tm_utc{};
    gmtime_r(&secs, &tm_utc);
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm_utc.tm_year + 1900,
                  tm_utc.tm_mon + 1, tm_utc.tm_mday, tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec, ms);
    return buf;
}

inline int64_t now_unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// `[ts] [level] [component] message key=value key2="value with spaces"`
// Без завершающего перевода строки.
inline std::string format_text(const Record& r) {
    std::string out;
    out += '[';
    out += format_timestamp(r.unix_ms);
    out += "] [";
    out += level_name(r.level);
    out += "] [";
    detail::append_text_escaped(out, r.component, /*quote=*/false);
    out += "] ";
    detail::append_text_escaped(out, r.message, /*quote=*/false);
    for (const auto& f : r.fields) {
        out += ' ';
        detail::append_text_escaped(out, f.key, /*quote=*/false);
        out += '=';
        if (detail::text_value_needs_quotes(f.value)) {
            out += '"';
            detail::append_text_escaped(out, f.value, /*quote=*/true);
            out += '"';
        } else {
            out += f.value;
        }
    }
    return out;
}

// Один JSON-объект без завершающего перевода строки. Если ключ поля
// совпадает со служебным (ts/level/component/msg) — к нему добавляется
// подчёркивание, чтобы поле не перезаписало служебное.
inline std::string format_json(const Record& r) {
    std::string out = "{\"ts\":";
    detail::append_json_escaped(out, format_timestamp(r.unix_ms));
    out += ",\"level\":";
    detail::append_json_escaped(out, level_name(r.level));
    out += ",\"component\":";
    detail::append_json_escaped(out, r.component);
    out += ",\"msg\":";
    detail::append_json_escaped(out, r.message);
    for (const auto& f : r.fields) {
        std::string key = f.key;
        if (detail::is_reserved_json_key(key)) key.push_back('_');
        out.push_back(',');
        detail::append_json_escaped(out, key);
        out.push_back(':');
        switch (f.kind) {
            case Field::Kind::Number:
            case Field::Kind::Bool:
                out += f.value; // значение получено из to_string()/true|false — уже валидный JSON-литерал
                break;
            case Field::Kind::String:
                detail::append_json_escaped(out, f.value);
                break;
        }
    }
    out.push_back('}');
    return out;
}

// Имя поля journald: только [A-Z0-9_], не начинается с '_' (такие имена
// зарезервированы за системой). Все наши поля получают префикс CH_ — это
// заодно исключает коллизии со стандартными полями (MESSAGE, PRIORITY...).
inline std::string journald_field_name(std::string_view key) {
    std::string out = "CH_";
    for (char ch : key) {
        if (ch >= 'a' && ch <= 'z') out.push_back(static_cast<char>(ch - 'a' + 'A'));
        else if ((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') out.push_back(ch);
        else out.push_back('_');
    }
    return out;
}

inline int journald_priority(Level level) {
    switch (level) {
        case Level::Debug: return 7; // LOG_DEBUG
        case Level::Info: return 6;  // LOG_INFO
        case Level::Warn: return 4;  // LOG_WARNING
        case Level::Error: return 3; // LOG_ERR
    }
    return 6;
}

// Список "KEY=value" для sd_journal_sendv(). Значения проходят то же
// экранирование, что и в text-формате (без кавычек), чтобы управляющие
// символы из недоверенных данных не попадали в журнал как есть.
inline std::vector<std::string> format_journald_fields(const Record& r) {
    std::vector<std::string> out;
    std::string msg = "MESSAGE=";
    detail::append_text_escaped(msg, r.message, /*quote=*/false);
    out.push_back(std::move(msg));
    out.push_back("PRIORITY=" + std::to_string(journald_priority(r.level)));
    out.push_back("SYSLOG_IDENTIFIER=cert-helper");
    std::string comp = "CH_COMPONENT=";
    detail::append_text_escaped(comp, r.component, /*quote=*/false);
    out.push_back(std::move(comp));
    for (const auto& f : r.fields) {
        std::string line = journald_field_name(f.key);
        line.push_back('=');
        detail::append_text_escaped(line, f.value, /*quote=*/false);
        out.push_back(std::move(line));
    }
    return out;
}

// Есть ли по этому пути сокет systemd-journald. Проверка ДО отправки —
// см. пояснение в шапке файла про молчаливый успех sd_journal_sendv().
inline bool journald_socket_present(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
}

inline bool journald_send(const std::vector<std::string>& fields) {
    std::vector<struct iovec> iov;
    iov.reserve(fields.size());
    for (const auto& f : fields) {
        struct iovec v;
        v.iov_base = const_cast<char*>(f.data());
        v.iov_len = f.size();
        iov.push_back(v);
    }
    return sd_journal_sendv(iov.data(), static_cast<int>(iov.size())) >= 0;
}

class Logger {
public:
    // Приёмник готовых строк (без '\n'). Нужен тестам и встраиванию;
    // по умолчанию (пустой) — stderr.
    using LineWriter = std::function<void(const std::string& line)>;

    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void set_level(Level level) { level_.store(level, std::memory_order_relaxed); }
    Level level() const { return level_.load(std::memory_order_relaxed); }
    void set_format(Format format) { format_.store(format, std::memory_order_relaxed); }
    Format format() const { return format_.load(std::memory_order_relaxed); }

    void set_line_writer(LineWriter writer) {
        std::lock_guard<std::mutex> lock(mutex_);
        writer_ = std::move(writer);
    }

    // Путь к сокету journald; меняется только в тестах (детерминированная
    // проверка отката на stderr независимо от того, есть ли journald на
    // машине, где гоняют тесты).
    void set_journal_socket_path(std::string path) {
        std::lock_guard<std::mutex> lock(mutex_);
        journal_socket_path_ = std::move(path);
    }

    // Возврат к состоянию по умолчанию: info, text, stderr.
    void reset() {
        set_level(Level::Info);
        set_format(Format::Text);
        set_line_writer(nullptr);
        set_journal_socket_path("/run/systemd/journal/socket");
    }

    bool enabled(Level level) const {
        return static_cast<uint8_t>(level) >= static_cast<uint8_t>(this->level());
    }

    void write(Level level, std::string_view component, std::string message,
               std::vector<Field> fields = {}) {
        if (!enabled(level)) return;

        Record r;
        r.unix_ms = now_unix_ms();
        r.level = level;
        r.component = std::string(component);
        r.message = std::move(message);
        r.fields = std::move(fields);

        const Format fmt = format();
        if (fmt == Format::Journald && journald_available()) {
            if (journald_send(format_journald_fields(r))) return;
            // Отправка не удалась — не теряем запись, пишем текстом.
        }
        const std::string line = (fmt == Format::Json) ? format_json(r) : format_text(r);
        emit_line(line);
    }

private:
    Logger() = default;

    bool journald_available() {
        std::string path;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            path = journal_socket_path_;
        }
        return journald_socket_present(path);
    }

    void emit_line(const std::string& line) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (writer_) {
            writer_(line);
            return;
        }
        std::string with_newline = line;
        with_newline.push_back('\n');
        std::fwrite(with_newline.data(), 1, with_newline.size(), stderr);
    }

    std::atomic<Level> level_{Level::Info};
    std::atomic<Format> format_{Format::Text};
    std::mutex mutex_;
    LineWriter writer_;
    std::string journal_socket_path_ = "/run/systemd/journal/socket";
};

inline void debug(std::string_view component, std::string message, std::vector<Field> fields = {}) {
    Logger::instance().write(Level::Debug, component, std::move(message), std::move(fields));
}
inline void info(std::string_view component, std::string message, std::vector<Field> fields = {}) {
    Logger::instance().write(Level::Info, component, std::move(message), std::move(fields));
}
inline void warn(std::string_view component, std::string message, std::vector<Field> fields = {}) {
    Logger::instance().write(Level::Warn, component, std::move(message), std::move(fields));
}
inline void error(std::string_view component, std::string message, std::vector<Field> fields = {}) {
    Logger::instance().write(Level::Error, component, std::move(message), std::move(fields));
}

} // namespace cert_helper::log
