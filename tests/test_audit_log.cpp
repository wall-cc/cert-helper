// test_audit_log.cpp — тесты аудит-лога решений о фетче (ROADMAP.md,
// раздел 4, пункт 23).
//
// Две части:
//   1. FileAuditLog как файловый журнал: формат строки, append-only,
//      нумерация seq, ротация, права, symlink, конкурентность, сбой записи.
//   2. RequestRouter → IAuditSink: какие события и с какими полями
//      порождает роутер (cache_hit / network_fetch / shared_inflight /
//      blocked + reason, серийный номер OCSP, батчи). Роутер тестируется
//      с фейковым HTTP-фетчером и in-memory кэшем — без сети и D-Bus.

#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/audit_log.hpp"
#include "../src/request_router.hpp"
#include "test_util.hpp"

namespace fs = std::filesystem;
namespace audit = cert_helper::audit;
namespace lg = cert_helper::log;
namespace proto = cert_helper::protocol;
namespace http = cert_helper::http;
namespace cache = cert_helper::cache;

namespace {

// ---------------------------------------------------------------------------
// Вспомогательное
// ---------------------------------------------------------------------------

struct TempDir {
    std::string path;
    TempDir() {
        char tmpl[] = "/tmp/cert_helper_audit_test_XXXXXX";
        char* p = ::mkdtemp(tmpl);
        path = p != nullptr ? p : "";
    }
    ~TempDir() {
        if (!path.empty()) fs::remove_all(path);
    }
    std::string file(const std::string& name) const { return path + "/" + name; }
};

std::vector<std::string> read_lines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) lines.push_back(line);
    return lines;
}

// Достаёт значение поля из СТРОКИ НАШЕГО ЖЕ формата (плоский объект, без
// вложенности). Строковые значения возвращаются как есть, в экранированном
// виде — этого достаточно для проверок; полноценный JSON-парсер тут не нужен.
std::string jget(const std::string& line, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    size_t p = line.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    if (p < line.size() && line[p] == '"') {
        ++p;
        std::string out;
        while (p < line.size() && line[p] != '"') {
            if (line[p] == '\\' && p + 1 < line.size()) {
                out += line[p];
                out += line[p + 1];
                p += 2;
            } else {
                out += line[p++];
            }
        }
        return out;
    }
    size_t e = line.find_first_of(",}", p);
    return line.substr(p, e - p);
}

bool jhas(const std::string& line, const std::string& key) {
    return line.find("\"" + key + "\":") != std::string::npos;
}

// Перехват вывода диагностического логгера (для проверки сообщений об
// ошибках аудита) с гарантированным возвратом в исходное состояние.
struct LogCapture {
    std::vector<std::string> lines;
    LogCapture() {
        lg::Logger::instance().reset();
        lg::Logger::instance().set_line_writer([this](const std::string& l) { lines.push_back(l); });
    }
    ~LogCapture() { lg::Logger::instance().reset(); }
    int count_containing(const std::string& needle) const {
        int n = 0;
        for (const auto& l : lines) if (l.find(needle) != std::string::npos) ++n;
        return n;
    }
};

// ---------------------------------------------------------------------------
// Часть 1: FileAuditLog
// ---------------------------------------------------------------------------

constexpr int64_t kFixedMs = 1767323045678LL; // 2026-01-02T03:04:05.678Z

void test_format_audit_line_exact() {
    std::string line = audit::format_audit_line(
        kFixedMs, 42, "fetch",
        {lg::field("type", "crl"), lg::field("bytes", uint64_t{1830}), lg::field("ok", true)});
    TEST_CHECK_EQ(line, std::string("{\"ts\":\"2026-01-02T03:04:05.678Z\",\"seq\":42,\"event\":\"fetch\","
                                    "\"type\":\"crl\",\"bytes\":1830,\"ok\":true}"));
}

// URL из сертификата с кавычками/переводами строк не должен ни сломать
// JSON, ни породить вторую строку журнала.
void test_format_audit_line_escapes_untrusted_values() {
    std::string line = audit::format_audit_line(
        kFixedMs, 1, "fetch",
        {lg::field("url", "http://e/\"},{\"seq\":999,\"event\":\"fake\n{\"x\":1"), lg::field("bad", "a\xffz")});
    TEST_CHECK(line.find('\n') == std::string::npos);
    TEST_CHECK(line.find("\\ufffd") != std::string::npos);
    // Внедрённый фрагмент остался внутри строкового значения (кавычки экранированы).
    TEST_CHECK(line.find("\\\"},{\\\"seq\\\":999") != std::string::npos);
    TEST_CHECK_EQ(jget(line, "seq"), std::string("1")); // настоящий seq не подменён
}

void test_format_audit_line_reserved_keys_are_renamed() {
    std::string line = audit::format_audit_line(
        kFixedMs, 7, "fetch",
        {lg::field("seq", "hijack"), lg::field("ts", "hijack"), lg::field("event", "hijack")});
    TEST_CHECK_EQ(jget(line, "seq"), std::string("7"));
    TEST_CHECK_EQ(jget(line, "event"), std::string("fetch"));
    TEST_CHECK_EQ(jget(line, "seq_"), std::string("hijack"));
    TEST_CHECK_EQ(jget(line, "event_"), std::string("hijack"));
    TEST_CHECK_EQ(jget(line, "ts_"), std::string("hijack"));
}

void test_file_log_writes_jsonl_with_sequential_seq() {
    TempDir dir;
    audit::FileAuditLog audit_log({dir.file("audit.log"), false});
    std::string err;
    TEST_CHECK(audit_log.open(&err));

    audit_log.record("daemon_start", {lg::field("pid", 123)});
    audit_log.record("fetch", {lg::field("type", "aia")});
    audit_log.record("daemon_stop", {});

    auto lines = read_lines(dir.file("audit.log"));
    TEST_CHECK_EQ(lines.size(), size_t{3});
    if (lines.size() == 3) {
        TEST_CHECK_EQ(jget(lines[0], "seq"), std::string("1"));
        TEST_CHECK_EQ(jget(lines[1], "seq"), std::string("2"));
        TEST_CHECK_EQ(jget(lines[2], "seq"), std::string("3"));
        TEST_CHECK_EQ(jget(lines[0], "event"), std::string("daemon_start"));
        TEST_CHECK_EQ(jget(lines[0], "pid"), std::string("123"));
        TEST_CHECK_EQ(jget(lines[1], "type"), std::string("aia"));
        TEST_CHECK_EQ(jget(lines[2], "event"), std::string("daemon_stop"));
        for (const auto& l : lines) {
            TEST_CHECK(l.front() == '{' && l.back() == '}');
            TEST_CHECK_EQ(jget(l, "ts").size(), size_t{24}); // 2026-01-02T03:04:05.678Z
        }
    }
    TEST_CHECK_EQ(audit_log.write_failures(), uint64_t{0});
}

// Append-only: новый экземпляр (рестарт демона) дописывает в конец, а не
// затирает журнал; seq при этом начинается с 1 — границу запуска задаёт daemon_start.
void test_file_log_appends_across_restarts_and_never_truncates() {
    TempDir dir;
    const std::string path = dir.file("audit.log");
    {
        audit::FileAuditLog first({path, false});
        TEST_CHECK(first.open());
        first.record("a", {});
        first.record("b", {});
    }
    {
        audit::FileAuditLog second({path, false});
        TEST_CHECK(second.open());
        second.record("c", {});
    }
    auto lines = read_lines(path);
    TEST_CHECK_EQ(lines.size(), size_t{3});
    if (lines.size() == 3) {
        TEST_CHECK_EQ(jget(lines[0], "event"), std::string("a"));
        TEST_CHECK_EQ(jget(lines[1], "event"), std::string("b"));
        TEST_CHECK_EQ(jget(lines[2], "event"), std::string("c"));
        TEST_CHECK_EQ(jget(lines[2], "seq"), std::string("1"));
    }
}

void test_file_log_open_failures_are_reported() {
    TempDir dir;
    {
        audit::FileAuditLog bad({dir.path + "/no/such/dir/audit.log", false});
        std::string err;
        TEST_CHECK(!bad.open(&err));
        TEST_CHECK(!err.empty());
    }
    {
        // Путь — каталог, а не файл.
        audit::FileAuditLog bad({dir.path, false});
        std::string err;
        TEST_CHECK(!bad.open(&err));
        TEST_CHECK(!err.empty());
    }
    {
        // O_NOFOLLOW: не идём по symlink'у (иначе тот, кто может создать
        // ссылку в каталоге журнала, перенаправил бы запись куда угодно).
        const std::string target = dir.file("target.log");
        { std::ofstream(target) << "precious\n"; }
        fs::create_symlink(target, dir.file("link.log"));
        audit::FileAuditLog via_link({dir.file("link.log"), false});
        std::string err;
        TEST_CHECK(!via_link.open(&err));
        TEST_CHECK(!err.empty());
        TEST_CHECK_EQ(read_lines(target).size(), size_t{1}); // цель не тронута
    }
}

void test_file_log_is_created_with_restrictive_mode() {
    TempDir dir;
    mode_t old_umask = ::umask(0); // чтобы проверить именно запрошенный режим
    {
        audit::FileAuditLog audit_log({dir.file("audit.log"), false});
        TEST_CHECK(audit_log.open());
    }
    ::umask(old_umask);
    struct stat st{};
    TEST_CHECK_EQ(::stat(dir.file("audit.log").c_str(), &st), 0);
    TEST_CHECK_EQ(static_cast<int>(st.st_mode & 0777), 0640); // не world-readable
}

// Ротация logrotate'ом (rename + create) без SIGHUP: демон сам замечает
// смену inode и пишет в НОВЫЙ файл, а не продолжает дописывать в ротированный.
void test_file_log_follows_rotation_by_rename() {
    TempDir dir;
    const std::string path = dir.file("audit.log");
    audit::FileAuditLog audit_log({path, false});
    TEST_CHECK(audit_log.open());

    audit_log.record("before_rotation", {});
    fs::rename(path, path + ".1");
    audit_log.record("after_rotation", {});

    auto rotated = read_lines(path + ".1");
    auto fresh = read_lines(path);
    TEST_CHECK_EQ(rotated.size(), size_t{1});
    TEST_CHECK_EQ(fresh.size(), size_t{1});
    if (rotated.size() == 1 && fresh.size() == 1) {
        TEST_CHECK_EQ(jget(rotated[0], "event"), std::string("before_rotation"));
        TEST_CHECK_EQ(jget(fresh[0], "event"), std::string("after_rotation"));
        TEST_CHECK_EQ(jget(fresh[0], "seq"), std::string("2")); // нумерация сквозная через ротацию
    }
    TEST_CHECK_EQ(audit_log.write_failures(), uint64_t{0});
}

void test_file_log_recreates_deleted_file() {
    TempDir dir;
    const std::string path = dir.file("audit.log");
    audit::FileAuditLog audit_log({path, false});
    TEST_CHECK(audit_log.open());
    audit_log.record("one", {});
    fs::remove(path);
    audit_log.record("two", {});

    auto lines = read_lines(path);
    TEST_CHECK_EQ(lines.size(), size_t{1});
    if (lines.size() == 1) TEST_CHECK_EQ(jget(lines[0], "event"), std::string("two"));
}

void test_file_log_fsync_mode_writes_normally() {
    TempDir dir;
    audit::FileAuditLog audit_log({dir.file("audit.log"), /*fsync_each_event=*/true});
    TEST_CHECK(audit_log.open());
    audit_log.record("durable", {lg::field("n", 1)});
    auto lines = read_lines(dir.file("audit.log"));
    TEST_CHECK_EQ(lines.size(), size_t{1});
    TEST_CHECK_EQ(audit_log.write_failures(), uint64_t{0});
}

// Много потоков: ни одной потерянной/склеенной строки, seq — ровно 1..N без
// пропусков и повторов, и порядок в файле совпадает с порядком seq (запись
// и назначение номера происходят под одним мьютексом).
void test_file_log_concurrent_records_are_intact_and_ordered() {
    TempDir dir;
    audit::FileAuditLog audit_log({dir.file("audit.log"), false});
    TEST_CHECK(audit_log.open());

    constexpr int kThreads = 8;
    constexpr int kPerThread = 100;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&audit_log, t] {
            for (int i = 0; i < kPerThread; ++i) {
                audit_log.record("fetch", {lg::field("thread", t), lg::field("i", i),
                                           lg::field("url", "http://ca.example.test/x.crl")});
            }
        });
    }
    for (auto& th : threads) th.join();

    auto lines = read_lines(dir.file("audit.log"));
    TEST_CHECK_EQ(lines.size(), static_cast<size_t>(kThreads * kPerThread));
    bool well_formed = true;
    bool ordered = true;
    long prev = 0;
    std::map<int, int> per_thread;
    for (const auto& l : lines) {
        if (l.rfind("{\"ts\":\"", 0) != 0 || l.back() != '}') well_formed = false;
        long seq = std::stol(jget(l, "seq"));
        if (seq != prev + 1) ordered = false;
        prev = seq;
        ++per_thread[std::stoi(jget(l, "thread"))];
    }
    TEST_CHECK(well_formed);
    TEST_CHECK(ordered);
    for (int t = 0; t < kThreads; ++t) TEST_CHECK_EQ(per_thread[t], kPerThread);
    TEST_CHECK_EQ(audit_log.write_failures(), uint64_t{0});
}

// Отказ записи: не роняет вызывающего, считается в write_failures(), ошибка
// логируется РОВНО ОДИН раз при переходе в состояние отказа (а не на каждое
// событие — иначе лог забился бы), плюс один раз о восстановлении; в seq
// остаётся видимый пропуск; после восстановления запись не склеивается с
// оборванным огрызком. Отказ имитируем через RLIMIT_FSIZE (write() -> EFBIG):
// детерминированно и без прав root.
void test_file_log_write_failure_is_counted_reported_once_and_recovers() {
    TempDir dir;
    const std::string path = dir.file("audit.log");
    LogCapture cap;

    audit::FileAuditLog audit_log({path, false});
    TEST_CHECK(audit_log.open());
    audit_log.record("ok_before", {});
    const auto size_before = fs::file_size(path);

    struct rlimit old_limit{};
    ::getrlimit(RLIMIT_FSIZE, &old_limit);
    auto old_handler = std::signal(SIGXFSZ, SIG_IGN); // иначе процесс убьёт сигнал, а не write() вернёт EFBIG
    std::fflush(stdout);
    std::fflush(stderr);

    struct rlimit tight = old_limit;
    tight.rlim_cur = size_before + 20; // меньше одной строки: первая запись оборвётся посередине
    ::setrlimit(RLIMIT_FSIZE, &tight);
    audit_log.record("lost_1", {lg::field("url", "http://ca.example.test/a")});
    audit_log.record("lost_2", {lg::field("url", "http://ca.example.test/b")});
    audit_log.record("lost_3", {lg::field("url", "http://ca.example.test/c")});
    ::setrlimit(RLIMIT_FSIZE, &old_limit); // "диск освободился"

    audit_log.record("ok_after", {});
    std::signal(SIGXFSZ, old_handler);

    TEST_CHECK_EQ(audit_log.write_failures(), uint64_t{3});
    TEST_CHECK_EQ(cap.count_containing("audit log write failed"), 1);   // не на каждое событие
    TEST_CHECK_EQ(cap.count_containing("audit log writes recovered"), 1);

    auto lines = read_lines(path);
    bool found_before = false, found_after = false;
    for (const auto& l : lines) {
        if (jget(l, "event") == "ok_before") found_before = true;
        if (jget(l, "event") == "ok_after") {
            found_after = true;
            // Пропуск в нумерации: 1 (ok_before), 2..4 потеряны, 5 — ok_after.
            TEST_CHECK_EQ(jget(l, "seq"), std::string("5"));
            TEST_CHECK(l.rfind("{\"ts\":\"", 0) == 0); // строка целая, не склеена с огрызком
        }
    }
    TEST_CHECK(found_before);
    TEST_CHECK(found_after);
}

// ---------------------------------------------------------------------------
// Часть 2: роутер -> аудит-события
// ---------------------------------------------------------------------------

class MemoryCache : public cache::ICacheStore {
public:
    std::optional<cache::CacheEntry> get(cache::EntryKind kind, const std::string& key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(std::to_string(static_cast<int>(kind)) + "|" + key);
        if (it == entries_.end()) return std::nullopt;
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        if (it->second.valid_until <= now) return std::nullopt;
        return it->second;
    }
    void put(cache::EntryKind kind, const std::string& key, const cache::CacheEntry& entry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_[std::to_string(static_cast<int>(kind)) + "|" + key] = entry;
    }
    cache::CacheStats stats() override { return {}; }

private:
    std::mutex mutex_;
    std::map<std::string, cache::CacheEntry> entries_;
};

class FakeHttpFetcher : public http::IHttpFetcher {
public:
    std::function<http::HttpResult(const std::string& url)> on_fetch;
    std::atomic<int> calls{0};

    http::HttpResult fetch(http::Method, const std::string& url, const std::vector<uint8_t>&,
                           const std::string&, uint32_t, size_t) override {
        ++calls;
        return on_fetch(url);
    }
};

class FakeLdapFetcher : public cert_helper::ldap::ILdapFetcher {
public:
    cert_helper::ldap::LdapResult result;
    cert_helper::ldap::LdapResult fetch(const std::string&, const std::string&, uint32_t, size_t) override {
        return result;
    }
};

struct Captured {
    std::string event;
    std::vector<lg::Field> fields;

    bool has(const std::string& key) const {
        for (const auto& f : fields) if (f.key == key) return true;
        return false;
    }
    std::string get(const std::string& key) const {
        for (const auto& f : fields) if (f.key == key) return f.value;
        return "";
    }
};

class MemorySink : public audit::IAuditSink {
public:
    void record(std::string_view event, const std::vector<lg::Field>& fields) override {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(Captured{std::string(event), fields});
    }
    std::vector<Captured> events() {
        std::lock_guard<std::mutex> lock(mutex_);
        return events_;
    }
    int count_decision(const std::string& decision) {
        int n = 0;
        for (const auto& e : events()) if (e.get("decision") == decision) ++n;
        return n;
    }

private:
    std::mutex mutex_;
    std::vector<Captured> events_;
};

class ThrowingSink : public audit::IAuditSink {
public:
    void record(std::string_view, const std::vector<lg::Field>&) override {
        throw std::runtime_error("audit backend exploded");
    }
};

http::HttpResult ok_result(std::vector<uint8_t> body, int status = 200) {
    http::HttpResult r;
    r.ok = true;
    r.status_code = status;
    r.body = std::move(body);
    return r;
}

http::HttpResult failed_result(http::FailureReason reason = http::FailureReason::None) {
    http::HttpResult r;
    r.ok = false;
    r.failure_reason = reason;
    return r;
}

cert_helper::RequestRouter::Config fast_config() {
    cert_helper::RequestRouter::Config c;
    c.max_retries = 0; // без backoff — тесты не должны спать
    c.circuit_breaker_failure_threshold = 1000;
    return c;
}

// Сеть -> кэш: первый запрос network_fetch с http_status и размером, второй — cache_hit.
void test_router_audits_network_fetch_then_cache_hit() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    const auto cert = test_util::generate_self_signed_cert_der("aia-audit", -1, 365);
    http.on_fetch = [&](const std::string&) { return ok_result(cert); };
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    proto::FetchIntermediateCertRequest req;
    req.aia_url = "http://ca.example.test/issuer.cer";
    TEST_CHECK(router.handle_intermediate_cert(req).status == proto::FetchStatus::Ok);
    TEST_CHECK(router.handle_intermediate_cert(req).from_cache);

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{2});
    if (events.size() == 2) {
        const auto& first = events[0];
        TEST_CHECK_EQ(first.event, std::string("fetch"));
        TEST_CHECK_EQ(first.get("type"), std::string("aia"));
        TEST_CHECK_EQ(first.get("url"), req.aia_url);
        TEST_CHECK_EQ(first.get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(first.get("result"), std::string("ok"));
        TEST_CHECK_EQ(first.get("bytes"), std::to_string(cert.size()));
        TEST_CHECK_EQ(first.get("http_status"), std::string("200"));
        TEST_CHECK(!first.has("reason"));
        TEST_CHECK(!first.has("serial")); // serial — только для ocsp
        TEST_CHECK(!first.has("batch_size"));

        const auto& second = events[1];
        TEST_CHECK_EQ(second.get("decision"), std::string("cache_hit"));
        TEST_CHECK_EQ(second.get("result"), std::string("ok"));
        TEST_CHECK_EQ(second.get("bytes"), std::to_string(cert.size()));
        TEST_CHECK(!second.has("http_status")); // сети не было
    }
    TEST_CHECK_EQ(http.calls.load(), 1);
}

void test_router_audits_ordinary_network_failures_without_blocked_reason() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    http.on_fetch = [](const std::string&) { return failed_result(); };
    proto::FetchCrlRequest req;
    req.distribution_point_url = "http://crl.example.test/a.crl";
    TEST_CHECK(router.handle_crl(req).status == proto::FetchStatus::NetworkError);

    http.on_fetch = [](const std::string&) {
        http::HttpResult r;
        r.timed_out = true;
        return r;
    };
    req.distribution_point_url = "http://crl.example.test/b.crl";
    TEST_CHECK(router.handle_crl(req).status == proto::FetchStatus::Timeout);

    http.on_fetch = [](const std::string&) { return ok_result({1, 2, 3}, 200); }; // не сертификат
    proto::FetchIntermediateCertRequest aia;
    aia.aia_url = "http://ca.example.test/garbage.cer";
    TEST_CHECK(router.handle_intermediate_cert(aia).status == proto::FetchStatus::InvalidResponse);

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{3});
    if (events.size() == 3) {
        // Сбой сети — это network_fetch с ошибкой, а НЕ blocked (демон не отказывался).
        TEST_CHECK_EQ(events[0].get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(events[0].get("result"), std::string("network_error"));
        TEST_CHECK(!events[0].has("reason"));
        TEST_CHECK_EQ(events[0].get("bytes"), std::string("0"));

        TEST_CHECK_EQ(events[1].get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(events[1].get("result"), std::string("timeout"));

        TEST_CHECK_EQ(events[2].get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(events[2].get("result"), std::string("invalid_response"));
        TEST_CHECK_EQ(events[2].get("http_status"), std::string("200")); // сервер ответил, но разобрать нельзя
    }
}

// Каждая причина отказа самого демона отражается в аудите как blocked + reason.
void test_router_audits_blocked_reasons_from_http_layer() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    struct Case { http::FailureReason reason; const char* expected; };
    const Case cases[] = {
        {http::FailureReason::InvalidUrl, "invalid_url"},
        {http::FailureReason::HttpsDisabled, "https_disabled"},
        {http::FailureReason::HttpsUnavailable, "https_unavailable"},
        {http::FailureReason::PortDenied, "port_denied"},
        {http::FailureReason::AddressDenied, "address_denied"},
    };
    int i = 0;
    for (const auto& c : cases) {
        http.on_fetch = [&](const std::string&) { return failed_result(c.reason); };
        proto::FetchCrlRequest req;
        req.distribution_point_url = "http://host" + std::to_string(i++) + ".example.test/x.crl";
        auto resp = router.handle_crl(req);
        TEST_CHECK(resp.status == proto::FetchStatus::NetworkError);
    }

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{5});
    for (size_t k = 0; k < events.size() && k < 5; ++k) {
        TEST_CHECK_EQ(events[k].get("decision"), std::string("blocked"));
        TEST_CHECK_EQ(events[k].get("reason"), std::string(cases[k].expected));
        TEST_CHECK_EQ(events[k].get("result"), std::string("network_error"));
    }
}

void test_router_audits_circuit_open_as_blocked() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    auto cfg = fast_config();
    cfg.circuit_breaker_failure_threshold = 2;
    cfg.circuit_breaker_cooldown_seconds = 60;
    cert_helper::RequestRouter router(cache, http, cfg, nullptr, &sink);
    http.on_fetch = [](const std::string&) { return failed_result(); };

    for (const char* path : {"/1.crl", "/2.crl", "/3.crl"}) {
        proto::FetchCrlRequest req;
        req.distribution_point_url = std::string("http://flaky.example.test") + path;
        router.handle_crl(req);
    }
    TEST_CHECK_EQ(http.calls.load(), 2); // третий запрос до сети не дошёл

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{3});
    if (events.size() == 3) {
        TEST_CHECK_EQ(events[0].get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(events[1].get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(events[2].get("decision"), std::string("blocked"));
        TEST_CHECK_EQ(events[2].get("reason"), std::string("circuit_open"));
    }
}

void test_router_audits_ldap_disabled_and_ldap_policy_denial() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    proto::FetchCrlRequest req;
    req.distribution_point_url = "ldap://dir.example.test/cn=CA?certificateRevocationList";

    {
        cert_helper::RequestRouter router(cache, http, fast_config(), /*ldap=*/nullptr, &sink);
        router.handle_crl(req);
    }
    {
        FakeLdapFetcher ldap;
        ldap.result.ok = false;
        ldap.result.policy_denied = true;
        cert_helper::RequestRouter router(cache, http, fast_config(), &ldap, &sink);
        router.handle_crl(req);
    }
    {
        FakeLdapFetcher ldap; // обычный сбой сети — не blocked
        ldap.result.ok = false;
        cert_helper::RequestRouter router(cache, http, fast_config(), &ldap, &sink);
        router.handle_crl(req);
    }

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{3});
    if (events.size() == 3) {
        TEST_CHECK_EQ(events[0].get("decision"), std::string("blocked"));
        TEST_CHECK_EQ(events[0].get("reason"), std::string("ldap_disabled"));
        TEST_CHECK_EQ(events[1].get("decision"), std::string("blocked"));
        TEST_CHECK_EQ(events[1].get("reason"), std::string("policy_denied"));
        TEST_CHECK_EQ(events[2].get("decision"), std::string("network_fetch"));
        TEST_CHECK(!events[2].has("reason"));
    }
    TEST_CHECK_EQ(http.calls.load(), 0); // ldap:// не ходит через HTTP-фетчер
}

// N одновременных одинаковых запросов: сеть дёргается один раз, одно
// событие network_fetch (лидер), остальные — shared_inflight. Аудит
// отражает КАЖДЫЙ запрос клиента, а не только реальные сетевые походы.
void test_router_audits_singleflight_followers_as_shared_inflight() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    http.on_fetch = [](const std::string&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300)); // запас против шедулинга в CI
        return ok_result({9, 8, 7, 6, 5});
    };
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    constexpr int kThreads = 4;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&router] {
            proto::FetchCrlRequest req;
            req.distribution_point_url = "http://crl.example.test/herd.crl";
            router.handle_crl(req);
        });
    }
    for (auto& th : threads) th.join();

    TEST_CHECK_EQ(http.calls.load(), 1);
    TEST_CHECK_EQ(sink.events().size(), static_cast<size_t>(kThreads));
    TEST_CHECK_EQ(sink.count_decision("network_fetch"), 1);
    TEST_CHECK(sink.count_decision("shared_inflight") >= 1);
    // Остаток (если поток запоздал настолько, что застал уже заполненный кэш) — cache_hit.
    TEST_CHECK_EQ(sink.count_decision("network_fetch") + sink.count_decision("shared_inflight") +
                      sink.count_decision("cache_hit"),
                  kThreads);
    for (const auto& e : sink.events()) {
        if (e.get("decision") == "shared_inflight") TEST_CHECK(!e.has("http_status"));
    }
}

void test_router_audits_ocsp_with_certificate_serial() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    auto fx = test_util::generate_ocsp_batch_fixtures(6, 8);
    http.on_fetch = [&](const std::string&) { return ok_result(fx.combined_response); };
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    proto::FetchOcspRequest a;
    a.responder_url = "http://ocsp.example.test/";
    a.request_der = fx.request_a;
    proto::FetchOcspRequest b = a;
    b.request_der = fx.request_b;
    TEST_CHECK(router.handle_ocsp(a).status == proto::FetchStatus::Ok);
    TEST_CHECK(router.handle_ocsp(b).status == proto::FetchStatus::Ok);

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{2});
    if (events.size() == 2) {
        TEST_CHECK_EQ(events[0].get("type"), std::string("ocsp"));
        TEST_CHECK_EQ(events[0].get("url"), a.responder_url);
        // Фикстуры: leaf A имеет serial 100 (0x64), leaf B — 101 (0x65).
        TEST_CHECK_EQ(events[0].get("serial"), std::string("64"));
        TEST_CHECK_EQ(events[1].get("serial"), std::string("65"));
        TEST_CHECK_EQ(events[0].get("decision"), std::string("network_fetch"));
    }
}

// Батч: один HTTP round-trip на группу, но по событию НА КАЖДЫЙ сертификат,
// с общим batch_size; повторный батч — cache_hit-события без batch_size.
void test_router_audits_ocsp_batch_per_certificate() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    auto fx = test_util::generate_ocsp_batch_fixtures(6, 8);
    http.on_fetch = [&](const std::string&) { return ok_result(fx.combined_response); };
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    proto::FetchOcspBatchRequest batch;
    proto::FetchOcspRequest a;
    a.responder_url = "http://ocsp.example.test/";
    a.request_der = fx.request_a;
    proto::FetchOcspRequest b = a;
    b.request_der = fx.request_b;
    batch.requests = {a, b};

    auto first = router.handle_ocsp_batch(batch);
    TEST_CHECK_EQ(first.responses.size(), size_t{2});
    TEST_CHECK_EQ(http.calls.load(), 1); // один объединённый запрос

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{2});
    if (events.size() == 2) {
        TEST_CHECK_EQ(events[0].get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(events[1].get("decision"), std::string("network_fetch"));
        TEST_CHECK_EQ(events[0].get("batch_size"), std::string("2"));
        TEST_CHECK_EQ(events[1].get("batch_size"), std::string("2"));
        TEST_CHECK_EQ(events[0].get("serial"), std::string("64"));
        TEST_CHECK_EQ(events[1].get("serial"), std::string("65"));
        TEST_CHECK_EQ(events[0].get("http_status"), std::string("200"));
    }

    router.handle_ocsp_batch(batch); // всё уже в кэше
    TEST_CHECK_EQ(http.calls.load(), 1);
    auto all = sink.events();
    TEST_CHECK_EQ(all.size(), size_t{4});
    if (all.size() == 4) {
        TEST_CHECK_EQ(all[2].get("decision"), std::string("cache_hit"));
        TEST_CHECK_EQ(all[3].get("decision"), std::string("cache_hit"));
        TEST_CHECK(!all[2].has("batch_size"));
        TEST_CHECK_EQ(all[2].get("serial"), std::string("64"));
    }
}

void test_router_audits_failed_ocsp_batch_for_every_member() {
    MemoryCache cache;
    FakeHttpFetcher http;
    MemorySink sink;
    auto fx = test_util::generate_ocsp_batch_fixtures(6, 8);
    http.on_fetch = [](const std::string&) { return failed_result(http::FailureReason::AddressDenied); };
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    proto::FetchOcspBatchRequest batch;
    proto::FetchOcspRequest a;
    a.responder_url = "http://ocsp.example.test/";
    a.request_der = fx.request_a;
    proto::FetchOcspRequest b = a;
    b.request_der = fx.request_b;
    batch.requests = {a, b};
    router.handle_ocsp_batch(batch);

    auto events = sink.events();
    TEST_CHECK_EQ(events.size(), size_t{2});
    for (const auto& e : events) {
        TEST_CHECK_EQ(e.get("decision"), std::string("blocked"));
        TEST_CHECK_EQ(e.get("reason"), std::string("address_denied"));
        TEST_CHECK_EQ(e.get("batch_size"), std::string("2"));
    }
}

// Отказ самого аудита (исключение из приёмника) не должен ломать обработку запроса.
void test_router_survives_throwing_audit_sink() {
    MemoryCache cache;
    FakeHttpFetcher http;
    ThrowingSink sink;
    http.on_fetch = [](const std::string&) { return ok_result({1, 2, 3, 4}); };
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &sink);

    proto::FetchCrlRequest req;
    req.distribution_point_url = "http://crl.example.test/x.crl";
    auto resp = router.handle_crl(req);
    TEST_CHECK(resp.status == proto::FetchStatus::Ok);
    TEST_CHECK_EQ(resp.payload_der.size(), size_t{4});
}

// Без приёмника роутер работает как раньше (аудит выключен по умолчанию).
void test_router_without_audit_sink_behaves_as_before() {
    MemoryCache cache;
    FakeHttpFetcher http;
    http.on_fetch = [](const std::string&) { return ok_result({1, 2, 3}); };
    cert_helper::RequestRouter router(cache, http, fast_config());
    proto::FetchCrlRequest req;
    req.distribution_point_url = "http://crl.example.test/x.crl";
    TEST_CHECK(router.handle_crl(req).status == proto::FetchStatus::Ok);
    TEST_CHECK(router.handle_crl(req).from_cache);
}

// Событие целиком проходит через реальный файловый журнал: URL с
// управляющими символами (враждебный сертификат) не ломает построчность.
void test_end_to_end_router_to_file_with_hostile_url() {
    TempDir dir;
    audit::FileAuditLog audit_log({dir.file("audit.log"), false});
    TEST_CHECK(audit_log.open());

    MemoryCache cache;
    FakeHttpFetcher http;
    http.on_fetch = [](const std::string&) { return failed_result(http::FailureReason::InvalidUrl); };
    cert_helper::RequestRouter router(cache, http, fast_config(), nullptr, &audit_log);

    proto::FetchCrlRequest req;
    req.distribution_point_url = "http://evil.example.test/\n{\"seq\":1,\"event\":\"fake\"}\r\n";
    router.handle_crl(req);

    auto lines = read_lines(dir.file("audit.log"));
    TEST_CHECK_EQ(lines.size(), size_t{1}); // ровно одна строка, поддельных нет
    if (lines.size() == 1) {
        TEST_CHECK_EQ(jget(lines[0], "event"), std::string("fetch"));
        TEST_CHECK_EQ(jget(lines[0], "decision"), std::string("blocked"));
        TEST_CHECK_EQ(jget(lines[0], "reason"), std::string("invalid_url"));
        TEST_CHECK(jhas(lines[0], "duration_ms"));
    }
}

} // namespace

int main() {
    RUN_TEST(test_format_audit_line_exact);
    RUN_TEST(test_format_audit_line_escapes_untrusted_values);
    RUN_TEST(test_format_audit_line_reserved_keys_are_renamed);
    RUN_TEST(test_file_log_writes_jsonl_with_sequential_seq);
    RUN_TEST(test_file_log_appends_across_restarts_and_never_truncates);
    RUN_TEST(test_file_log_open_failures_are_reported);
    RUN_TEST(test_file_log_is_created_with_restrictive_mode);
    RUN_TEST(test_file_log_follows_rotation_by_rename);
    RUN_TEST(test_file_log_recreates_deleted_file);
    RUN_TEST(test_file_log_fsync_mode_writes_normally);
    RUN_TEST(test_file_log_concurrent_records_are_intact_and_ordered);
    RUN_TEST(test_file_log_write_failure_is_counted_reported_once_and_recovers);
    RUN_TEST(test_router_audits_network_fetch_then_cache_hit);
    RUN_TEST(test_router_audits_ordinary_network_failures_without_blocked_reason);
    RUN_TEST(test_router_audits_blocked_reasons_from_http_layer);
    RUN_TEST(test_router_audits_circuit_open_as_blocked);
    RUN_TEST(test_router_audits_ldap_disabled_and_ldap_policy_denial);
    RUN_TEST(test_router_audits_singleflight_followers_as_shared_inflight);
    RUN_TEST(test_router_audits_ocsp_with_certificate_serial);
    RUN_TEST(test_router_audits_ocsp_batch_per_certificate);
    RUN_TEST(test_router_audits_failed_ocsp_batch_for_every_member);
    RUN_TEST(test_router_survives_throwing_audit_sink);
    RUN_TEST(test_router_without_audit_sink_behaves_as_before);
    RUN_TEST(test_end_to_end_router_to_file_with_hostile_url);
    TEST_MAIN_EXIT();
}
