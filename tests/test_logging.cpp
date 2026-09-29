// test_logging.cpp — тесты структурированного логирования (ROADMAP.md,
// раздел 4, пункт 22). Форматирование проверяется на чистых функциях с
// фиксированной меткой времени (детерминированно); поведение Logger
// (фильтрация по уровню, потокобезопасность) — через подменяемый приёмник
// строк вместо реального stderr.

#include <string>
#include <thread>
#include <vector>

#include "../src/logging.hpp"
#include "test_util.hpp"

using namespace cert_helper::log;

namespace {

// 2026-01-02T03:04:05.678Z
constexpr int64_t kFixedMs = 1767323045678LL;

Record make_record(Level level, const std::string& component, const std::string& msg,
                   std::vector<Field> fields = {}) {
    Record r;
    r.unix_ms = kFixedMs;
    r.level = level;
    r.component = component;
    r.message = msg;
    r.fields = std::move(fields);
    return r;
}

bool has_raw_control_chars(const std::string& s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7F) return true;
    }
    return false;
}

// RAII: перехватывает вывод синглтона Logger и гарантированно возвращает
// его в состояние по умолчанию — тесты не должны влиять друг на друга.
struct LogCapture {
    std::vector<std::string> lines;
    LogCapture() {
        Logger::instance().reset();
        Logger::instance().set_line_writer([this](const std::string& line) { lines.push_back(line); });
    }
    ~LogCapture() { Logger::instance().reset(); }
};

void test_timestamp_format() {
    TEST_CHECK_EQ(format_timestamp(kFixedMs), std::string("2026-01-02T03:04:05.678Z"));
    TEST_CHECK_EQ(format_timestamp(0), std::string("1970-01-01T00:00:00.000Z"));
    TEST_CHECK_EQ(format_timestamp(-5), std::string("1970-01-01T00:00:00.000Z")); // отрицательное не ломается
}

void test_text_format_matches_roadmap_layout() {
    auto r = make_record(Level::Warn, "http", "policy denied port",
                         {field("port", 8080), field("url", "http://x.example/a")});
    TEST_CHECK_EQ(format_text(r),
                  std::string("[2026-01-02T03:04:05.678Z] [warn] [http] policy denied port "
                              "port=8080 url=http://x.example/a"));
}

void test_text_quotes_values_that_need_it() {
    auto r = make_record(Level::Info, "c", "m",
                         {field("a", "has space"), field("b", ""), field("c", "x=y"), field("d", "plain")});
    TEST_CHECK_EQ(format_text(r),
                  std::string("[2026-01-02T03:04:05.678Z] [info] [c] m "
                              "a=\"has space\" b=\"\" c=\"x=y\" d=plain"));
}

// КРИТИЧНО ДЛЯ БЕЗОПАСНОСТИ: URL из сертификата с переводом строки не должен
// породить в логе вторую, поддельную запись.
void test_text_format_prevents_log_injection() {
    const std::string evil_url = "http://evil/\n[2026-01-02T03:04:05.678Z] [error] [daemon] fake entry";
    auto r = make_record(Level::Warn, "http", "policy denied port", {field("url", evil_url)});
    std::string line = format_text(r);
    TEST_CHECK(line.find('\n') == std::string::npos);
    TEST_CHECK(line.find('\r') == std::string::npos);
    TEST_CHECK(!has_raw_control_chars(line));
    TEST_CHECK(line.find("\\n") != std::string::npos); // виден как экранированная последовательность

    // То же самое для сообщения и компонента, а не только полей.
    auto r2 = make_record(Level::Error, "a\nb", "line1\nline2\r\n");
    TEST_CHECK(!has_raw_control_chars(format_text(r2)));
}

void test_text_format_escapes_control_and_invalid_utf8() {
    std::string tricky = std::string("esc\x1b[31m") + "bad\xff\xfe" + "nul" + '\0' + "end";
    auto r = make_record(Level::Info, "c", "m", {field("v", tricky)});
    std::string line = format_text(r);
    TEST_CHECK(!has_raw_control_chars(line));
    TEST_CHECK(line.find("\\x1b") != std::string::npos);
    TEST_CHECK(line.find("\\xff") != std::string::npos);
    TEST_CHECK(line.find("\\x00") != std::string::npos);
}

void test_text_format_keeps_valid_utf8() {
    auto r = make_record(Level::Info, "warmup", "завершён", {field("файл", "путь/к/файлу")});
    std::string line = format_text(r);
    TEST_CHECK(line.find("завершён") != std::string::npos);
    // Не-ASCII значение берётся в кавычки (консервативное правило), но остаётся читаемым.
    TEST_CHECK(line.find("\"путь/к/файлу\"") != std::string::npos);
}

void test_json_format_exact() {
    auto r = make_record(Level::Warn, "http", "policy denied port",
                         {field("port", 8080), field("url", "http://x.example/a"), field("ok", false)});
    TEST_CHECK_EQ(format_json(r),
                  std::string("{\"ts\":\"2026-01-02T03:04:05.678Z\",\"level\":\"warn\","
                              "\"component\":\"http\",\"msg\":\"policy denied port\","
                              "\"port\":8080,\"url\":\"http://x.example/a\",\"ok\":false}"));
}

void test_json_escaping_is_strict() {
    std::string tricky = std::string("q\"uote back\\slash nl\n tab\t ctl\x01 del\x7f") + " bad\xc3\x28" +
                         " ok\xd0\xb0"; // \xc3\x28 — некорректный UTF-8; \xd0\xb0 — корректная "а"
    auto r = make_record(Level::Info, "c", "m", {field("v", tricky)});
    std::string j = format_json(r);
    TEST_CHECK(!has_raw_control_chars(j));
    TEST_CHECK(j.find("q\\\"uote") != std::string::npos);
    TEST_CHECK(j.find("back\\\\slash") != std::string::npos);
    TEST_CHECK(j.find("nl\\n") != std::string::npos);
    TEST_CHECK(j.find("tab\\t") != std::string::npos);
    TEST_CHECK(j.find("ctl\\u0001") != std::string::npos);
    TEST_CHECK(j.find("del\\u007f") != std::string::npos);
    TEST_CHECK(j.find("\\ufffd") != std::string::npos); // некорректный UTF-8 заменён
    TEST_CHECK(j.find("\xd0\xb0") != std::string::npos); // корректный — сохранён
    // Некорректный байт 0xc3 не должен просочиться как есть.
    TEST_CHECK(j.find("bad\xc3\x28") == std::string::npos);
}

// Overlong-формы, суррогаты и значения > U+10FFFF — тоже некорректный UTF-8.
void test_json_rejects_overlong_surrogate_and_out_of_range_utf8() {
    const char* bad_sequences[] = {
        "\xc0\x80",         // overlong NUL
        "\xe0\x80\x80",     // overlong
        "\xed\xa0\x80",     // суррогат U+D800
        "\xf4\x90\x80\x80", // U+110000
        "\xf8\x88\x80\x80\x80", // 5-байтовая форма
    };
    for (const char* seq : bad_sequences) {
        auto r = make_record(Level::Info, "c", "m", {field("v", std::string("x") + seq + "y")});
        std::string j = format_json(r);
        TEST_CHECK(j.find("\\ufffd") != std::string::npos);
        TEST_CHECK(j.find(seq) == std::string::npos);
    }
}

void test_json_reserved_keys_do_not_override_builtin_fields() {
    auto r = make_record(Level::Info, "real", "real msg",
                         {field("msg", "hijack"), field("level", "hijack"), field("ts", "hijack"),
                          field("component", "hijack")});
    std::string j = format_json(r);
    TEST_CHECK(j.find("\"msg\":\"real msg\"") != std::string::npos);
    TEST_CHECK(j.find("\"level\":\"info\"") != std::string::npos);
    TEST_CHECK(j.find("\"component\":\"real\"") != std::string::npos);
    TEST_CHECK(j.find("\"msg_\":\"hijack\"") != std::string::npos);
}

void test_field_overloads_pick_expected_kinds() {
    TEST_CHECK(field("k", 5).kind == Field::Kind::Number);
    TEST_CHECK(field("k", uint16_t{8080}).kind == Field::Kind::Number);
    TEST_CHECK(field("k", int64_t{-3}).value == "-3");
    TEST_CHECK(field("k", true).kind == Field::Kind::Bool);
    TEST_CHECK(field("k", "text").kind == Field::Kind::String);
    TEST_CHECK(field("k", std::string("text")).kind == Field::Kind::String);
    TEST_CHECK(field("k", static_cast<const char*>(nullptr)).value.empty()); // nullptr не падает
}

void test_journald_fields() {
    auto r = make_record(Level::Warn, "http", "line1\nline2",
                         {field("port", 8080), field("bad key-name", "v"), field("url", "http://a/\nb")});
    auto f = format_journald_fields(r);

    auto contains = [&](const std::string& s) {
        for (const auto& x : f) if (x == s) return true;
        return false;
    };
    TEST_CHECK(contains("PRIORITY=4"));
    TEST_CHECK(contains("SYSLOG_IDENTIFIER=cert-helper"));
    TEST_CHECK(contains("CH_COMPONENT=http"));
    TEST_CHECK(contains("CH_PORT=8080"));
    TEST_CHECK(contains("CH_BAD_KEY_NAME=v")); // регистр и недопустимые символы нормализованы
    TEST_CHECK(contains("MESSAGE=line1\\nline2")); // перевод строки экранирован
    TEST_CHECK(contains("CH_URL=http://a/\\nb"));
    for (const auto& x : f) TEST_CHECK(!has_raw_control_chars(x));

    TEST_CHECK_EQ(journald_priority(Level::Debug), 7);
    TEST_CHECK_EQ(journald_priority(Level::Info), 6);
    TEST_CHECK_EQ(journald_priority(Level::Warn), 4);
    TEST_CHECK_EQ(journald_priority(Level::Error), 3);
    // Префикс CH_ исключает коллизию с системными полями.
    TEST_CHECK_EQ(journald_field_name("message"), std::string("CH_MESSAGE"));
}

void test_parse_level_and_format() {
    TEST_CHECK(parse_level("debug") == Level::Debug);
    TEST_CHECK(parse_level("INFO") == Level::Info);
    TEST_CHECK(parse_level("Warn") == Level::Warn);
    TEST_CHECK(parse_level("warning") == Level::Warn);
    TEST_CHECK(parse_level("error") == Level::Error);
    TEST_CHECK(!parse_level("verbose").has_value());
    TEST_CHECK(!parse_level("").has_value());

    TEST_CHECK(parse_format("text") == Format::Text);
    TEST_CHECK(parse_format("JSON") == Format::Json);
    TEST_CHECK(parse_format("journald") == Format::Journald);
    TEST_CHECK(!parse_format("xml").has_value());
}

void test_level_filtering() {
    LogCapture cap;
    Logger::instance().set_level(Level::Warn);
    debug("t", "d");
    info("t", "i");
    warn("t", "w");
    error("t", "e");
    TEST_CHECK_EQ(cap.lines.size(), size_t{2});
    TEST_CHECK(cap.lines[0].find("[warn]") != std::string::npos);
    TEST_CHECK(cap.lines[1].find("[error]") != std::string::npos);

    cap.lines.clear();
    Logger::instance().set_level(Level::Debug);
    debug("t", "d");
    TEST_CHECK_EQ(cap.lines.size(), size_t{1});
    TEST_CHECK(cap.lines[0].find("[debug]") != std::string::npos);
    TEST_CHECK(Logger::instance().enabled(Level::Debug));
}

void test_logger_uses_selected_format() {
    LogCapture cap;
    Logger::instance().set_format(Format::Json);
    info("daemon", "hello", {field("n", 1)});
    TEST_CHECK_EQ(cap.lines.size(), size_t{1});
    TEST_CHECK(cap.lines[0].front() == '{' && cap.lines[0].back() == '}');
    TEST_CHECK(cap.lines[0].find("\"msg\":\"hello\"") != std::string::npos);
    TEST_CHECK(cap.lines[0].find("\"n\":1") != std::string::npos);

    cap.lines.clear();
    Logger::instance().set_format(Format::Text);
    info("daemon", "hello");
    TEST_CHECK_EQ(cap.lines.size(), size_t{1});
    TEST_CHECK(cap.lines[0].front() == '[');
}

// Записи из разных потоков не должны перемешиваться внутри строки, и ни
// одна не должна потеряться. Приёмник намеренно пишет в НЕсинхронизированный
// вектор: его защищает мьютекс Logger — под TSan любое нарушение вылезет.
// РЕГРЕССИЯ: sd_journal_sendv() при отсутствии сокета journald возвращает
// УСПЕХ и молча выбрасывает запись, поэтому откат на stderr по коду возврата
// не работал — при --log-format journald без journald пропадало ВСЁ. Теперь
// доступность проверяется по сокету; путь подменяем, чтобы тест не зависел
// от того, есть ли journald на машине.
void test_journald_format_falls_back_to_text_when_journal_socket_missing() {
    LogCapture cap;
    Logger::instance().set_format(Format::Journald);
    Logger::instance().set_journal_socket_path("/nonexistent/dir/journal/socket");
    error("daemon", "must not be lost", {field("k", 1)});
    TEST_CHECK_EQ(cap.lines.size(), size_t{1});
    if (cap.lines.size() == 1) {
        TEST_CHECK(cap.lines[0].find("must not be lost") != std::string::npos);
        TEST_CHECK(cap.lines[0].front() == '['); // текстовый формат
    }
    TEST_CHECK(!journald_socket_present("/nonexistent/dir/journal/socket"));
    TEST_CHECK(!journald_socket_present("/tmp")); // существует, но это не сокет
}

void test_concurrent_logging_keeps_lines_intact() {
    LogCapture cap;
    constexpr int kThreads = 8;
    constexpr int kPerThread = 250;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t] {
            for (int i = 0; i < kPerThread; ++i) {
                info("stress", "message from worker", {field("thread", t), field("i", i)});
            }
        });
    }
    for (auto& th : threads) th.join();

    TEST_CHECK_EQ(cap.lines.size(), static_cast<size_t>(kThreads * kPerThread));
    std::vector<int> per_thread(kThreads, 0);
    bool all_well_formed = true;
    for (const auto& line : cap.lines) {
        // Каждая строка целая: одна открывающая метка времени и оба поля на месте.
        size_t thr = line.find(" thread=");
        size_t idx = line.find(" i=");
        bool ok = line.rfind("[20", 0) == 0 && thr != std::string::npos && idx != std::string::npos &&
                  line.find("[20", 1) == std::string::npos;
        if (!ok) {
            all_well_formed = false;
            continue;
        }
        int t = std::stoi(line.substr(thr + 8));
        if (t >= 0 && t < kThreads) ++per_thread[t];
    }
    TEST_CHECK(all_well_formed);
    for (int t = 0; t < kThreads; ++t) TEST_CHECK_EQ(per_thread[t], kPerThread);
}

} // namespace

int main() {
    RUN_TEST(test_timestamp_format);
    RUN_TEST(test_text_format_matches_roadmap_layout);
    RUN_TEST(test_text_quotes_values_that_need_it);
    RUN_TEST(test_text_format_prevents_log_injection);
    RUN_TEST(test_text_format_escapes_control_and_invalid_utf8);
    RUN_TEST(test_text_format_keeps_valid_utf8);
    RUN_TEST(test_json_format_exact);
    RUN_TEST(test_json_escaping_is_strict);
    RUN_TEST(test_json_rejects_overlong_surrogate_and_out_of_range_utf8);
    RUN_TEST(test_json_reserved_keys_do_not_override_builtin_fields);
    RUN_TEST(test_field_overloads_pick_expected_kinds);
    RUN_TEST(test_journald_fields);
    RUN_TEST(test_parse_level_and_format);
    RUN_TEST(test_level_filtering);
    RUN_TEST(test_logger_uses_selected_format);
    RUN_TEST(test_journald_format_falls_back_to_text_when_journal_socket_missing);
    RUN_TEST(test_concurrent_logging_keeps_lines_intact);
    TEST_MAIN_EXIT();
}
