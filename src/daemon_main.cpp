// daemon_main.cpp
//
// Точка входа демона cert-helper. Читает конфигурацию из аргументов
// командной строки (через boost::program_options — см. ниже), поднимает
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

#include <boost/program_options.hpp>

#include "cache/cache_store.hpp"
#include "cache/two_tier_cache.hpp"
#include "cache_warmup.hpp"
#include "http_client.hpp"
#include "ipc/dbus_server.hpp"
#include "ldap_client.hpp"
#include "net_policy.hpp"
#include "request_router.hpp"

namespace po = boost::program_options;

namespace {

// boost::program_options переносит строки в --help по количеству БАЙТ,
// не по числу символов — на кириллице (многобайтовый UTF-8) это может
// разрезать текст посередине символа и испортить вывод. Явно задаём
// заведомо большую длину строки, чтобы перенос практически никогда не
// срабатывал (описания у нас короче ~200 байт).
constexpr unsigned kHelpLineLength = 4096;

std::atomic<bool>* g_running_flag = nullptr;

void handle_signal(int) {
    if (g_running_flag != nullptr) {
        g_running_flag->store(false);
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string bus_address; // пусто = системная шина
    std::string bus_name;
    std::string cache_dir;
    uint64_t max_cache_entries = 0;
    uint64_t max_cache_bytes = 0;
    uint64_t mem_cache_max_entries = 0;
    uint64_t mem_cache_max_bytes = 0;
    uint32_t aia_ttl_seconds = 0;
    uint32_t max_ocsp_ttl_seconds = 0;
    uint32_t max_crl_ttl_seconds = 0;
    uint32_t max_ocsp_response_bytes = 0;
    uint32_t max_aia_response_bytes = 0;
    uint32_t max_crl_response_bytes = 0;
    uint32_t max_retries = 0;
    uint32_t retry_base_delay_ms = 0;
    uint32_t circuit_breaker_failure_threshold = 0;
    uint32_t circuit_breaker_cooldown_seconds = 0;
    uint32_t circuit_breaker_max_tracked_hosts = 0;
    int min_worker_threads = 0;
    int max_worker_threads = 0;
    int worker_idle_timeout_ms = 0;
    bool allow_private_destinations = false;
    std::vector<std::string> allow_cidrs;
    std::vector<std::string> deny_cidrs;
    std::vector<uint16_t> allowed_ports;
    bool allow_https = false;
    std::string https_ca_bundle;
    bool allow_ldap = false;
    uint32_t dns_cache_ttl_seconds = 0;
    std::string warmup_file;

    po::options_description dbus_opts("D-Bus", kHelpLineLength);
    dbus_opts.add_options()
        ("bus-address", po::value<std::string>(&bus_address)->default_value(""),
         "адрес D-Bus для подключения (пусто = системная шина; непустой адрес "
         "используется в тестах для приватного dbus-daemon)")
        ("bus-name", po::value<std::string>(&bus_name)->default_value(cert_helper::ipc::kServiceName),
         "well-known имя, запрашиваемое на шине");

    po::options_description cache_opts("Кэш (диск + опциональный memory-слой, пункт 2)", kHelpLineLength);
    cache_opts.add_options()
        ("cache-dir", po::value<std::string>(&cache_dir)->default_value("/var/lib/cert-helper/cache"),
         "директория персистентного (файлового) кэша")
        ("max-cache-entries", po::value<uint64_t>(&max_cache_entries)->default_value(100000),
         "лимит числа записей на диске")
        ("max-cache-bytes", po::value<uint64_t>(&max_cache_bytes)->default_value(512ull * 1024 * 1024),
         "лимит суммарного размера на диске, в байтах")
        ("mem-cache-max-entries", po::value<uint64_t>(&mem_cache_max_entries)->default_value(20000),
         "лимит записей в memory-слое (0 отключает эффект memory-слоя)")
        ("mem-cache-max-bytes", po::value<uint64_t>(&mem_cache_max_bytes)->default_value(64ull * 1024 * 1024),
         "лимит байт в memory-слое")
        ("aia-ttl-seconds", po::value<uint32_t>(&aia_ttl_seconds)->default_value(7 * 24 * 3600),
         "базовый TTL кэша для докачанных промежуточных сертификатов (секунды)")
        ("max-ocsp-ttl-seconds", po::value<uint32_t>(&max_ocsp_ttl_seconds)->default_value(24 * 3600),
         "верхняя граница TTL OCSP-кэша (секунды) — клампит nextUpdate "
         "независимо от того, что заявил responder (ROADMAP.md п.2)")
        ("max-crl-ttl-seconds", po::value<uint32_t>(&max_crl_ttl_seconds)->default_value(7 * 24 * 3600),
         "верхняя граница TTL CRL-кэша (секунды) — клампит nextUpdate "
         "независимо от того, что заявил CA (ROADMAP.md п.2)")
        ("max-ocsp-response-bytes", po::value<uint32_t>(&max_ocsp_response_bytes)->default_value(256 * 1024),
         "лимит размера тела OCSP-ответа в байтах (ROADMAP.md п.4)")
        ("max-aia-response-bytes", po::value<uint32_t>(&max_aia_response_bytes)->default_value(256 * 1024),
         "лимит размера тела ответа AIA (докачанный сертификат) в байтах (ROADMAP.md п.4)")
        ("max-crl-response-bytes", po::value<uint32_t>(&max_crl_response_bytes)->default_value(16 * 1024 * 1024),
         "лимит размера тела CRL-ответа в байтах (ROADMAP.md п.4)")
        ("max-retries", po::value<uint32_t>(&max_retries)->default_value(2),
         "число ПОВТОРНЫХ попыток при транзиентной сетевой ошибке "
         "OCSP/CRL/AIA-fetch (не считая исходной попытки; не применяется "
         "к ldap:// и не применяется к успешным HTTP-ответам с кодом "
         "ошибки — только к сбоям транспорта). ROADMAP.md п.10")
        ("retry-base-delay-ms", po::value<uint32_t>(&retry_base_delay_ms)->default_value(100),
         "базовая задержка (мс) экспоненциального backoff с джиттером "
         "между повторными попытками (ROADMAP.md п.10)")
        ("circuit-breaker-failure-threshold",
         po::value<uint32_t>(&circuit_breaker_failure_threshold)->default_value(5),
         "число подряд неудачных ЗАПРОСОВ (после исчерпания retry на "
         "каждый) к одному хосту, после которого breaker открывается и "
         "начинает отказывать немедленно (ROADMAP.md п.11)")
        ("circuit-breaker-cooldown-seconds",
         po::value<uint32_t>(&circuit_breaker_cooldown_seconds)->default_value(30),
         "время (секунды) в открытом состоянии breaker'а, прежде чем "
         "пропустить пробный запрос (ROADMAP.md п.11)")
        ("circuit-breaker-max-tracked-hosts",
         po::value<uint32_t>(&circuit_breaker_max_tracked_hosts)->default_value(10000),
         "предел числа одновременно отслеживаемых хостов для circuit "
         "breaker — защита от неограниченного роста памяти, т.к. хосты "
         "приходят из потенциально недобросовестных сертификатов "
         "(ROADMAP.md п.11)");

    po::options_description worker_opts("Пул воркеров (пункт 4)", kHelpLineLength);
    worker_opts.add_options()
        ("min-worker-threads", po::value<int>(&min_worker_threads)->default_value(2),
         "минимальное число воркеров, всегда в строю")
        ("max-worker-threads", po::value<int>(&max_worker_threads)->default_value(16),
         "максимальное число воркеров под нагрузкой")
        ("worker-idle-timeout-ms", po::value<int>(&worker_idle_timeout_ms)->default_value(30000),
         "простой дольше этого — воркер завершается, если это не опустит "
         "пул ниже минимума");

    po::options_description net_opts("Сетевая политика для исходящих запросов (пункт 3, SSRF-защита)", kHelpLineLength);
    net_opts.add_options()
        ("allow-private-destinations", po::bool_switch(&allow_private_destinations),
         "отключить блокировку loopback/link-local/private/CGNAT/multicast "
         "диапазонов по умолчанию")
        ("allow-cidr", po::value<std::vector<std::string>>(&allow_cidrs)->composing(),
         "разрешить конкретный CIDR-диапазон явно, в обход deny-списка "
         "(можно указывать несколько раз)")
        ("deny-cidr", po::value<std::vector<std::string>>(&deny_cidrs)->composing(),
         "запретить дополнительный CIDR-диапазон сверх дефолтного "
         "(можно указывать несколько раз)")
        ("allowed-ports",
         po::value<std::vector<uint16_t>>(&allowed_ports)->multitoken()->default_value({80}, "80"),
         "список разрешённых портов назначения, через пробел "
         "(например: --allowed-ports 80 8080; при --allow-https не забудьте "
         "добавить 443)")
        ("allow-https", po::bool_switch(&allow_https),
         "разрешить https:// в AIA/OCSP/CDP URL (по умолчанию выключено — "
         "см. ROADMAP.md п.7 и комментарий в http_client.hpp; не забудьте "
         "также добавить 443 в --allowed-ports)")
        ("https-ca-bundle", po::value<std::string>(&https_ca_bundle)->default_value(""),
         "путь к файлу/директории с доверенными CA для https:// (пусто = "
         "системный набор корневых сертификатов); действует, только если "
         "--allow-https")
        ("allow-ldap", po::bool_switch(&allow_ldap),
         "разрешить ldap:// в CRL distribution point URL (по умолчанию "
         "выключено — см. ROADMAP.md п.9 и комментарий в ldap_client.hpp; "
         "поддерживается только anonymous bind, без TLS, без пустого host "
         "в URL)")
        ("dns-cache-ttl-seconds", po::value<uint32_t>(&dns_cache_ttl_seconds)->default_value(60),
         "TTL (секунды) локального кэша DNS-резолвинга имён из "
         "AIA/OCSP/CDP URL — короткий фиксированный TTL, т.к. getaddrinfo() "
         "не отдаёт реальный TTL DNS-записи (ROADMAP.md п.13). Адрес "
         "всё равно проверяется политикой при КАЖДОМ использовании "
         "закэшированной записи, не только при первом резолве.")
        ("warmup-file", po::value<std::string>(&warmup_file)->default_value(""),
         "путь к файлу прогрева кэша (пусто = прогрев выключен) — "
         "построчный список crl:<url>/aia:<url>/"
         "ocsp:<responder_url>:<cert_path>:<issuer_path>, выполняется в "
         "фоновом потоке сразу после старта D-Bus сервера, не блокируя "
         "готовность демона (ROADMAP.md п.15, см. cache_warmup.hpp)");

    po::options_description visible("cert-helper — вспомогательный демон докачки/проверки сертификатов", kHelpLineLength);
    visible.add_options()("help,h", "показать эту справку");
    visible.add(dbus_opts).add(cache_opts).add(worker_opts).add(net_opts);

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, visible), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "cert-helper: " << e.what() << "\n\n" << visible << "\n";
        return 2;
    }

    if (vm.count("help")) {
        std::cout << visible << "\n";
        return 0;
    }

    if (min_worker_threads < 1) min_worker_threads = 1;
    if (max_worker_threads < min_worker_threads) max_worker_threads = min_worker_threads;

    // --- Кэш: диск (источник истины) + опциональный memory-слой (пункт 2) ---
    cert_helper::cache::FileCacheStore::Limits disk_limits;
    disk_limits.max_entries = max_cache_entries;
    disk_limits.max_size_bytes = max_cache_bytes;
    cert_helper::cache::FileCacheStore disk_cache(cache_dir, disk_limits);

    cert_helper::cache::MemoryLruCache::Limits mem_limits;
    mem_limits.max_entries = mem_cache_max_entries;
    mem_limits.max_size_bytes = mem_cache_max_bytes;
    cert_helper::cache::TwoTierCacheStore cache(disk_cache, mem_limits);

    // --- Сетевая политика для исходящих fetch-запросов (пункт 3) ---
    cert_helper::net::NetworkPolicy::Config net_policy_config;
    net_policy_config.block_private_by_default = !allow_private_destinations;
    net_policy_config.allow_cidrs = allow_cidrs;
    net_policy_config.extra_deny_cidrs = deny_cidrs;
    net_policy_config.allowed_ports = allowed_ports;
    cert_helper::net::NetworkPolicy net_policy(net_policy_config);

    cert_helper::http::SimpleHttpFetcher http(net_policy, allow_https, https_ca_bundle,
                                                dns_cache_ttl_seconds);

    // ROADMAP.md, раздел 1, пункт 9: LDAP-фетчер создаётся, только если
    // явно включён --allow-ldap — та же логика "не тратить время на
    // инициализацию неиспользуемой возможности", что и для https:// в
    // SimpleHttpFetcher (см. http_client.hpp). unique_ptr вместо
    // std::optional<SimpleLdapFetcher> — RequestRouter хранит указатель
    // (nullable), а не владеет объектом; unique_ptr здесь только
    // управляет временем жизни в daemon_main().
    std::unique_ptr<cert_helper::ldap::SimpleLdapFetcher> ldap_fetcher;
    if (allow_ldap) {
        ldap_fetcher =
            std::make_unique<cert_helper::ldap::SimpleLdapFetcher>(net_policy, dns_cache_ttl_seconds);
    }

    cert_helper::RequestRouter::Config router_config;
    router_config.aia_ttl_seconds = aia_ttl_seconds;
    router_config.max_ocsp_ttl_seconds = max_ocsp_ttl_seconds;
    router_config.max_crl_ttl_seconds = max_crl_ttl_seconds;
    router_config.max_ocsp_response_bytes = max_ocsp_response_bytes;
    router_config.max_aia_response_bytes = max_aia_response_bytes;
    router_config.max_crl_response_bytes = max_crl_response_bytes;
    router_config.max_retries = max_retries;
    router_config.retry_base_delay_ms = retry_base_delay_ms;
    router_config.circuit_breaker_failure_threshold = circuit_breaker_failure_threshold;
    router_config.circuit_breaker_cooldown_seconds = circuit_breaker_cooldown_seconds;
    router_config.circuit_breaker_max_tracked_hosts = circuit_breaker_max_tracked_hosts;
    cert_helper::RequestRouter router(cache, http, router_config, ldap_fetcher.get());

    // --- D-Bus сервер: эластичный пул воркеров (пункт 4) ---
    cert_helper::ipc::DbusServer::Config server_config;
    server_config.bus_address = bus_address;
    server_config.well_known_name = bus_name;
    server_config.min_worker_threads = min_worker_threads;
    server_config.max_worker_threads = max_worker_threads;
    server_config.worker_idle_timeout_ms = worker_idle_timeout_ms;
    cert_helper::ipc::DbusServer server(server_config, router);

    if (!server.start()) {
        std::fprintf(stderr, "cert-helper: failed to start D-Bus service (name=%s)\n",
                      bus_name.c_str());
        return 1;
    }

    std::fprintf(stderr,
                  "cert-helper: registered as %s on %s (workers=%d..%d, cache=%s, "
                  "mem-cache=%s)\n",
                  bus_name.c_str(), bus_address.empty() ? "system bus" : bus_address.c_str(),
                  min_worker_threads, max_worker_threads, cache_dir.c_str(),
                  mem_cache_max_entries == 0 ? "disabled" : "enabled");

    // ROADMAP.md, раздел 2, пункт 15 (P3): прогрев кэша — запускается ПОСЛЕ
    // старта D-Bus сервера, в фоновом потоке, чтобы не задерживать
    // готовность демона отвечать на обычные запросы (см. подробное
    // обоснование в cache_warmup.hpp). Пустой warmup_file (по умолчанию)
    // означает "прогрев выключен" — ничего не меняется относительно
    // поведения без этого пункта вовсе.
    std::thread warmup_thread;
    if (!warmup_file.empty()) {
        warmup_thread = std::thread([&router, warmup_file] {
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

    std::fprintf(stderr, "cert-helper: shutting down\n");
    if (warmup_thread.joinable()) warmup_thread.join();
    server.stop();
    return 0;
}
