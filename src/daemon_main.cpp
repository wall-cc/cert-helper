// daemon_main.cpp
//
// Точка входа демона cert-helper. Читает конфигурацию из аргументов
// командной строки (описание флагов и их разбор вынесены в класс
// CommandLineOptions — см. command_line_options.hpp), поднимает
// кэш (диск + опциональный in-memory слой), HTTP-фетчер (с сетевой
// политикой destination'ов), роутер и D-Bus сервер (эластичный пул
// воркеров), обрабатывает SIGINT/SIGTERM для штатной остановки (важно
// для systemd — раздел 8 исходного ТЗ).
//
// Транспорт — D-Bus (см. src/ipc/dbus_interface.hpp): по умолчанию демон
// подключается к системной шине (system bus) и запрашивает well-known
// имя org.certhelper.CertHelper1. Права доступа клиентов регулируются
// D-Bus policy-файлом (deploy/org.certhelper.CertHelper1.conf), а не
// правами на файл сокета, как было в UDS-версии.
//
// Пункты 1–5 из анализа демона докачки сертификатов в Squid (см.
// README.md за подробным обоснованием каждого):
//   1. HTTP Cache-Control/Expires от AIA/CRL/OCSP-сервера уважаются
//      автоматически внутри RequestRouter — конфигурировать здесь нечего.
//   2. Двухуровневый кэш (диск + память) — флаги --mem-cache-*.
//   3. Политика destination'ов для исходящего трафика cert-helper
//      (SSRF-защита) — флаги --allow-private-destinations/--allow-cidr/
//      --deny-cidr/--allowed-ports. Поддержка https:// (ROADMAP.md,
//      раздел 1, пункт 7, выключена по умолчанию) — флаги --allow-https/
//      --https-ca-bundle. Поддержка ldap:// для CRL (ROADMAP.md, раздел
//      1, пункт 9, тоже выключена по умолчанию) — флаг --allow-ldap.
//   4. Эластичный пул воркеров — флаги --min-worker-threads/
//      --max-worker-threads/--worker-idle-timeout-ms.
//   5. Разбивка HealthCheck по типу запроса — включена всегда, без флагов.
//
// Наблюдаемость и эксплуатация (ROADMAP.md, раздел 4):
//   п.22 — структурированное логирование (src/logging.hpp): флаги
//          --log-level/--log-format. Сообщения об ошибках разбора
//          аргументов и вывод --help намеренно идут напрямую в
//          stderr/stdout, минуя логгер: это интерфейс командной строки,
//          а не журнал работы демона, и они возникают до его настройки.
//   п.23 — аудит-лог решений о фетче (src/audit_log.hpp): флаги
//          --audit-log-file/--audit-log-fsync, по умолчанию выключен.

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "audit_log.hpp"
#include "cache/cache_store.hpp"
#include "cache/two_tier_cache.hpp"
#include "cache_warmup.hpp"
#include "command_line_options.hpp"
#include "http_client.hpp"
#include "ipc/dbus_server.hpp"
#include "ldap_client.hpp"
#include "logging.hpp"
#include "net_policy.hpp"
#include "request_router.hpp"

namespace {

std::atomic<bool>* g_running_flag = nullptr;

void handle_signal(int) {
    if (g_running_flag != nullptr) {
        g_running_flag->store(false);
    }
}

}  // namespace

int main(int argc, char** argv) {
    cert_helper::CommandLineOptions options;
    using ParseStatus = cert_helper::CommandLineOptions::ParseStatus;
    switch (options.parse(argc, argv)) {
        case ParseStatus::OK:
            break;
        case ParseStatus::HELP_REQUESTED:
            std::cout << options.help_text() << "\n";
            return 0;
        case ParseStatus::INVALID_USAGE:
            std::cerr << options.error_message();
            return 2;
    }
    cert_helper::DaemonSettings const& settings = options.settings();

    // Логгер настраиваем первым делом — всё, что ниже, уже пишет через него.
    cert_helper::log::Logger::instance().set_level(settings.log_level);
    cert_helper::log::Logger::instance().set_format(settings.log_format);
    namespace log = cert_helper::log;

    // --- Кэш: диск (источник истины) + опциональный memory-слой (пункт 2) ---
    cert_helper::cache::FileCacheStore::Limits disk_limits;
    disk_limits.max_entries = settings.max_cache_entries;
    disk_limits.max_size_bytes = settings.max_cache_bytes;
    cert_helper::cache::FileCacheStore disk_cache(settings.cache_dir,
                                                  disk_limits);

    cert_helper::cache::MemoryLruCache::Limits mem_limits;
    mem_limits.max_entries = settings.mem_cache_max_entries;
    mem_limits.max_size_bytes = settings.mem_cache_max_bytes;
    cert_helper::cache::TwoTierCacheStore cache(disk_cache, mem_limits);

    // --- Сетевая политика для исходящих fetch-запросов (пункт 3) ---
    cert_helper::net::NetworkPolicy::Config net_policy_config;
    net_policy_config.block_private_by_default =
        !settings.allow_private_destinations;
    net_policy_config.allow_cidrs = settings.allow_cidrs;
    net_policy_config.extra_deny_cidrs = settings.deny_cidrs;
    net_policy_config.allowed_ports = settings.allowed_ports;
    cert_helper::net::NetworkPolicy net_policy(net_policy_config);

    cert_helper::http::SimpleHttpFetcher http(net_policy, settings.allow_https,
                                              settings.https_ca_bundle,
                                              settings.dns_cache_ttl_seconds);

    // ROADMAP.md, раздел 1, пункт 9: LDAP-фетчер создаётся, только если
    // явно включён --allow-ldap — та же логика "не тратить время на
    // инициализацию неиспользуемой возможности", что и для https:// в
    // SimpleHttpFetcher (см. http_client.hpp). unique_ptr вместо
    // std::optional<SimpleLdapFetcher> — RequestRouter хранит указатель
    // (nullable), а не владеет объектом; unique_ptr здесь только
    // управляет временем жизни в main().
    std::unique_ptr<cert_helper::ldap::SimpleLdapFetcher> ldap_fetcher;
    if (settings.allow_ldap) {
        ldap_fetcher = std::make_unique<cert_helper::ldap::SimpleLdapFetcher>(
            net_policy, settings.dns_cache_ttl_seconds);
    }

    cert_helper::RequestRouter::Config router_config;
    router_config.aia_ttl_seconds = settings.aia_ttl_seconds;
    router_config.max_ocsp_ttl_seconds = settings.max_ocsp_ttl_seconds;
    router_config.max_crl_ttl_seconds = settings.max_crl_ttl_seconds;
    router_config.max_ocsp_response_bytes = settings.max_ocsp_response_bytes;
    router_config.max_aia_response_bytes = settings.max_aia_response_bytes;
    router_config.max_crl_response_bytes = settings.max_crl_response_bytes;
    router_config.max_retries = settings.max_retries;
    router_config.retry_base_delay_ms = settings.retry_base_delay_ms;
    router_config.circuit_breaker_failure_threshold =
        settings.circuit_breaker_failure_threshold;
    router_config.circuit_breaker_cooldown_seconds =
        settings.circuit_breaker_cooldown_seconds;
    router_config.circuit_breaker_max_tracked_hosts =
        settings.circuit_breaker_max_tracked_hosts;

    // ROADMAP.md, раздел 4, пункт 23: аудит-лог создаётся, только если явно
    // задан --audit-log-file. Файл открываем ЗДЕСЬ, до старта D-Bus
    // сервера: если оператор потребовал аудит, а писать его некуда, —
    // демон не должен молча начать работать без него (fail closed при
    // старте; последующие сбои записи запросы не блокируют — см.
    // "ГАРАНТИИ" в audit_log.hpp).
    std::unique_ptr<cert_helper::audit::FileAuditLog> audit_log;
    if (!settings.audit_log_file.empty()) {
        cert_helper::audit::FileAuditLog::Options audit_options;
        audit_options.path = settings.audit_log_file;
        audit_options.fsync_each_event = settings.audit_log_fsync;
        audit_log =
            std::make_unique<cert_helper::audit::FileAuditLog>(audit_options);
        std::string audit_error;
        if (!audit_log->open(&audit_error)) {
            log::error("daemon",
                       "cannot open audit log — refusing to start without "
                       "requested audit",
                       {log::field("path", settings.audit_log_file),
                        log::field("error", audit_error)});
            return 1;
        }
    }

    cert_helper::RequestRouter router(cache, http, router_config,
                                      ldap_fetcher.get(), audit_log.get());

    // --- D-Bus сервер: эластичный пул воркеров (пункт 4) ---
    cert_helper::ipc::DbusServer::Config server_config;
    server_config.bus_address = settings.bus_address;
    server_config.well_known_name = settings.bus_name;
    server_config.min_worker_threads = settings.min_worker_threads;
    server_config.max_worker_threads = settings.max_worker_threads;
    server_config.worker_idle_timeout_ms = settings.worker_idle_timeout_ms;
    cert_helper::ipc::DbusServer server(server_config, router);

    // daemon_start пишем ДО server.start(): воркеры начинают обслуживать
    // запросы сразу после старта, и первым событием в журнале должна быть
    // граница запуска, а не чей-то фетч.
    if (audit_log) {
        audit_log->record("daemon_start",
                          {log::field("pid", static_cast<int64_t>(::getpid())),
                           log::field("bus_name", settings.bus_name)});
    }

    if (!server.start()) {
        log::error("daemon", "failed to start D-Bus service",
                   {log::field("bus_name", settings.bus_name)});
        if (audit_log) {
            audit_log->record("daemon_stop",
                              {log::field("reason", "start_failed")});
        }
        return 1;
    }

    log::info("daemon", "registered on D-Bus",
              {log::field("bus_name", settings.bus_name),
               log::field("bus", settings.bus_address.empty()
                                     ? std::string("system bus")
                                     : settings.bus_address),
               log::field("min_workers", settings.min_worker_threads),
               log::field("max_workers", settings.max_worker_threads),
               log::field("cache_dir", settings.cache_dir),
               log::field("mem_cache", settings.mem_cache_max_entries == 0
                                           ? "disabled"
                                           : "enabled"),
               log::field("audit_log", settings.audit_log_file.empty()
                                           ? std::string("disabled")
                                           : settings.audit_log_file)});

    // ROADMAP.md, раздел 2, пункт 15 (P3): прогрев кэша — запускается ПОСЛЕ
    // старта D-Bus сервера, в фоновом потоке, чтобы не задерживать
    // готовность демона отвечать на обычные запросы (см. подробное
    // обоснование в cache_warmup.hpp). Пустой warmup_file (по умолчанию)
    // означает "прогрев выключен" — ничего не меняется относительно
    // поведения без этого пункта вовсе.
    std::thread warmup_thread;
    if (!settings.warmup_file.empty()) {
        warmup_thread =
            std::thread([&router, warmup_file = settings.warmup_file] {
                cert_helper::warmup::run(warmup_file, router);
            });
    }

    std::atomic<bool> running{true};
    g_running_flag = &running;
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGPIPE, SIG_IGN);

    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    log::info("daemon", "shutting down");
    if (warmup_thread.joinable()) {
        warmup_thread.join();
    }
    server.stop();
    // После server.stop(): воркеры уже остановлены, так что daemon_stop —
    // гарантированно последнее событие этого запуска.
    if (audit_log) {
        audit_log->record("daemon_stop", {log::field("reason", "signal")});
    }
    return 0;
}
