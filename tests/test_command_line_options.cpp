// test_command_line_options.cpp
//
// Тесты CommandLineOptions/DaemonSettings (src/command_line_options.*):
// значения по умолчанию, переопределение флагов, ошибки использования,
// нормализация пула воркеров, справка.

#include <string>
#include <vector>

#include "../src/command_line_options.hpp"
#include "test_util.hpp"

using cert_helper::CommandLineOptions;
using cert_helper::DaemonSettings;
namespace {

using Status = CommandLineOptions::ParseStatus;

// Запускает разбор на списке аргументов (без argv[0] — он добавляется
// здесь же, как в настоящем main()).
Status run_parse(CommandLineOptions& options,
                 std::vector<std::string> const& args) {
    std::vector<std::string> storage;
    storage.push_back("cert-helper");
    storage.insert(storage.end(), args.begin(), args.end());
    std::vector<char const*> argv;
    for (auto const& arg : storage) {
        argv.push_back(arg.c_str());
    }
    return options.parse(static_cast<int>(argv.size()), argv.data());
}

bool contains(std::string const& haystack, std::string const& needle) {
    return haystack.find(needle) != std::string::npos;
}

void test_defaults() {
    CommandLineOptions options;
    TEST_CHECK(run_parse(options, {}) == Status::OK);
    DaemonSettings const& s = options.settings();
    TEST_CHECK_EQ(s.cache_dir, std::string("/var/lib/cert-helper/cache"));
    TEST_CHECK_EQ(s.max_cache_entries, static_cast<uint64_t>(100000));
    TEST_CHECK_EQ(s.max_cache_bytes, static_cast<uint64_t>(512) * 1024 * 1024);
    TEST_CHECK_EQ(s.min_worker_threads, 2);
    TEST_CHECK_EQ(s.max_worker_threads, 16);
    TEST_CHECK_EQ(s.worker_idle_timeout_ms, 30000);
    TEST_CHECK(!s.allow_private_destinations);
    TEST_CHECK(!s.allow_https);
    TEST_CHECK(!s.allow_ldap);
    TEST_CHECK(s.allowed_ports == std::vector<uint16_t>{80});
    TEST_CHECK(s.allow_cidrs.empty());
    TEST_CHECK(s.deny_cidrs.empty());
    TEST_CHECK(s.log_level == cert_helper::log::Level::INFO);
    TEST_CHECK(s.log_format == cert_helper::log::Format::TEXT);
    TEST_CHECK(s.audit_log_file.empty());
    TEST_CHECK(!s.audit_log_fsync);
    TEST_CHECK(s.bus_address.empty());
    TEST_CHECK_EQ(s.bus_name, std::string("org.certhelper.CertHelper1"));
}

void test_overrides() {
    CommandLineOptions options;
    Status status = run_parse(options, {"--cache-dir",
                                        "/tmp/x",
                                        "--min-worker-threads",
                                        "3",
                                        "--max-worker-threads",
                                        "5",
                                        "--allow-cidr",
                                        "10.0.0.0/8",
                                        "--allow-cidr",
                                        "192.168.0.0/16",
                                        "--deny-cidr",
                                        "203.0.113.0/24",
                                        "--allowed-ports",
                                        "80",
                                        "443",
                                        "--allow-https",
                                        "--allow-ldap",
                                        "--allow-private-destinations",
                                        "--log-level",
                                        "debug",
                                        "--log-format",
                                        "json",
                                        "--audit-log-file",
                                        "/tmp/a.log",
                                        "--audit-log-fsync",
                                        "--max-retries",
                                        "7"});
    TEST_CHECK(status == Status::OK);
    DaemonSettings const& s = options.settings();
    TEST_CHECK_EQ(s.cache_dir, std::string("/tmp/x"));
    TEST_CHECK_EQ(s.min_worker_threads, 3);
    TEST_CHECK_EQ(s.max_worker_threads, 5);
    TEST_CHECK((s.allow_cidrs ==
                std::vector<std::string>{"10.0.0.0/8", "192.168.0.0/16"}));
    TEST_CHECK((s.deny_cidrs == std::vector<std::string>{"203.0.113.0/24"}));
    TEST_CHECK((s.allowed_ports == std::vector<uint16_t>{80, 443}));
    TEST_CHECK(s.allow_https);
    TEST_CHECK(s.allow_ldap);
    TEST_CHECK(s.allow_private_destinations);
    TEST_CHECK(s.log_level == cert_helper::log::Level::DEBUG);
    TEST_CHECK(s.log_format == cert_helper::log::Format::JSON);
    TEST_CHECK_EQ(s.audit_log_file, std::string("/tmp/a.log"));
    TEST_CHECK(s.audit_log_fsync);
    TEST_CHECK_EQ(s.max_retries, static_cast<uint32_t>(7));
}

void test_help_requested() {
    for (std::string flag : {"--help", "-h"}) {
        CommandLineOptions options;
        TEST_CHECK(run_parse(options, {flag}) == Status::HELP_REQUESTED);
        TEST_CHECK(options.error_message().empty());
    }
    CommandLineOptions options;
    std::string help = options.help_text();
    // Каждый флаг обязан быть описан в справке.
    for (char const* name : {"--bus-address",
                             "--bus-name",
                             "--cache-dir",
                             "--max-cache-entries",
                             "--max-cache-bytes",
                             "--mem-cache-max-entries",
                             "--mem-cache-max-bytes",
                             "--aia-ttl-seconds",
                             "--max-ocsp-ttl-seconds",
                             "--max-crl-ttl-seconds",
                             "--max-ocsp-response-bytes",
                             "--max-aia-response-bytes",
                             "--max-crl-response-bytes",
                             "--max-retries",
                             "--retry-base-delay-ms",
                             "--circuit-breaker-failure-threshold",
                             "--circuit-breaker-cooldown-seconds",
                             "--circuit-breaker-max-tracked-hosts",
                             "--min-worker-threads",
                             "--max-worker-threads",
                             "--worker-idle-timeout-ms",
                             "--allow-private-destinations",
                             "--allow-cidr",
                             "--deny-cidr",
                             "--allowed-ports",
                             "--allow-https",
                             "--https-ca-bundle",
                             "--allow-ldap",
                             "--dns-cache-ttl-seconds",
                             "--warmup-file",
                             "--log-level",
                             "--log-format",
                             "--audit-log-file",
                             "--audit-log-fsync"}) {
        TEST_CHECK(contains(help, name));
    }
}

void test_unknown_option_is_invalid_usage() {
    CommandLineOptions options;
    TEST_CHECK(run_parse(options, {"--worker-threads", "4"}) ==
               Status::INVALID_USAGE);
    std::string const& message = options.error_message();
    TEST_CHECK(message.rfind("cert-helper: ", 0) == 0);
    TEST_CHECK(contains(message, "unrecognised option '--worker-threads'"));
    // При синтаксической ошибке следом идёт справка.
    TEST_CHECK(contains(message, "--cache-dir"));
}

void test_bad_value_type_is_invalid_usage() {
    CommandLineOptions options;
    TEST_CHECK(run_parse(options, {"--max-retries", "many"}) ==
               Status::INVALID_USAGE);
    TEST_CHECK(!options.error_message().empty());
}

void test_bad_log_level_message() {
    CommandLineOptions options;
    TEST_CHECK(run_parse(options, {"--log-level", "verbose"}) ==
               Status::INVALID_USAGE);
    TEST_CHECK_EQ(options.error_message(),
                  std::string("cert-helper: --log-level: неизвестный уровень "
                              "\"verbose\" (ожидается "
                              "debug|info|warn|error)\n"));
}

void test_bad_log_format_message() {
    CommandLineOptions options;
    TEST_CHECK(run_parse(options, {"--log-format", "xml"}) ==
               Status::INVALID_USAGE);
    TEST_CHECK_EQ(options.error_message(),
                  std::string("cert-helper: --log-format: неизвестный формат "
                              "\"xml\" (ожидается text|json|journald)\n"));
}

void test_worker_pool_is_normalized() {
    {
        CommandLineOptions options;
        TEST_CHECK(run_parse(options, {"--min-worker-threads", "0"}) ==
                   Status::OK);
        TEST_CHECK_EQ(options.settings().min_worker_threads, 1);
    }
    {
        // max < min поднимается до min.
        CommandLineOptions options;
        TEST_CHECK(run_parse(options, {"--min-worker-threads", "5",
                                       "--max-worker-threads", "2"}) ==
                   Status::OK);
        TEST_CHECK_EQ(options.settings().min_worker_threads, 5);
        TEST_CHECK_EQ(options.settings().max_worker_threads, 5);
    }
    {
        CommandLineOptions options;
        TEST_CHECK(run_parse(options, {"--min-worker-threads", "-3"}) ==
                   Status::OK);
        TEST_CHECK_EQ(options.settings().min_worker_threads, 1);
    }
}

void test_error_message_is_empty_after_successful_reparse() {
    CommandLineOptions options;
    TEST_CHECK(run_parse(options, {"--log-level", "bogus"}) ==
               Status::INVALID_USAGE);
    TEST_CHECK(!options.error_message().empty());
    TEST_CHECK(run_parse(options, {}) == Status::OK);
    TEST_CHECK(options.error_message().empty());
}

}  // namespace

int main() {
    RUN_TEST(test_defaults);
    RUN_TEST(test_overrides);
    RUN_TEST(test_help_requested);
    RUN_TEST(test_unknown_option_is_invalid_usage);
    RUN_TEST(test_bad_value_type_is_invalid_usage);
    RUN_TEST(test_bad_log_level_message);
    RUN_TEST(test_bad_log_format_message);
    RUN_TEST(test_worker_pool_is_normalized);
    RUN_TEST(test_error_message_is_empty_after_successful_reparse);
    TEST_MAIN_EXIT();
}
