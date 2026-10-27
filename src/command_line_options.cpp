// command_line_options.cpp
//
// Реализация CommandLineOptions. Тексты справки и значения по умолчанию
// перенесены из daemon_main.cpp без изменений: вывод --help и поведение
// при ошибках остались побайтно прежними.

#include "command_line_options.hpp"

#include <sstream>

namespace cert_helper {

namespace po = boost::program_options;

namespace {

// boost::program_options переносит строки в --help по количеству БАЙТ,
// не по числу символов — на кириллице (многобайтовый UTF-8) это может
// разрезать текст посередине символа и испортить вывод. Явно задаём
// заведомо большую длину строки, чтобы перенос практически никогда не
// срабатывал (описания у нас короче ~200 байт).
constexpr unsigned HELP_LINE_LENGTH = 4096;

// Значение по умолчанию берётся из текущего значения *target, то есть из
// инициализатора поля в DaemonSettings: оно записано в одном месте.
template <typename T>
void add_value(po::options_description* group, char const* name, T* target,
               char const* help) {
    group->add_options()(name, po::value<T>(target)->default_value(*target),
                         help);
}

void add_flag(po::options_description* group, char const* name, bool* target,
              char const* help) {
    group->add_options()(name, po::bool_switch(target), help);
}

// Флаг, который можно указывать несколько раз; значения накапливаются.
void add_repeatable(po::options_description* group, char const* name,
                    std::vector<std::string>* target, char const* help) {
    group->add_options()(
        name, po::value<std::vector<std::string>>(target)->composing(), help);
}

void add_port_list(po::options_description* group, char const* name,
                   std::vector<uint16_t>* target, char const* help) {
    // boost не умеет сам напечатать значение по умолчанию для вектора,
    // поэтому текст для справки собираем явно: «80» или «80 8080».
    std::ostringstream default_text;
    for (size_t i = 0; i < target->size(); ++i) {
        if (i > 0) {
            default_text << ' ';
        }
        default_text << (*target)[i];
    }
    group->add_options()(
        name,
        po::value<std::vector<uint16_t>>(target)->multitoken()->default_value(
            *target, default_text.str()),
        help);
}

po::options_description describe_dbus_options(DaemonSettings* settings) {
    po::options_description group("D-Bus", HELP_LINE_LENGTH);
    add_value(&group, "bus-address", &settings->bus_address,
              "адрес D-Bus для подключения (пусто = системная шина; непустой "
              "адрес используется в тестах для приватного dbus-daemon)");
    add_value(&group, "bus-name", &settings->bus_name,
              "well-known имя, запрашиваемое на шине");
    return group;
}

po::options_description describe_cache_options(DaemonSettings* settings) {
    po::options_description group(
        "Кэш (диск + опциональный memory-слой, пункт 2)", HELP_LINE_LENGTH);
    add_value(&group, "cache-dir", &settings->cache_dir,
              "директория персистентного (файлового) кэша");
    add_value(&group, "max-cache-entries", &settings->max_cache_entries,
              "лимит числа записей на диске");
    add_value(&group, "max-cache-bytes", &settings->max_cache_bytes,
              "лимит суммарного размера на диске, в байтах");
    add_value(&group, "mem-cache-max-entries", &settings->mem_cache_max_entries,
              "лимит записей в memory-слое (0 отключает эффект memory-слоя)");
    add_value(&group, "mem-cache-max-bytes", &settings->mem_cache_max_bytes,
              "лимит байт в memory-слое");
    add_value(&group, "aia-ttl-seconds", &settings->aia_ttl_seconds,
              "базовый TTL кэша для докачанных промежуточных сертификатов "
              "(секунды)");
    add_value(&group, "max-ocsp-ttl-seconds", &settings->max_ocsp_ttl_seconds,
              "верхняя граница TTL OCSP-кэша (секунды) — клампит nextUpdate "
              "независимо от того, что заявил responder (ROADMAP.md п.2)");
    add_value(&group, "max-crl-ttl-seconds", &settings->max_crl_ttl_seconds,
              "верхняя граница TTL CRL-кэша (секунды) — клампит nextUpdate "
              "независимо от того, что заявил CA (ROADMAP.md п.2)");
    add_value(&group, "max-ocsp-response-bytes",
              &settings->max_ocsp_response_bytes,
              "лимит размера тела OCSP-ответа в байтах (ROADMAP.md п.4)");
    add_value(&group, "max-aia-response-bytes",
              &settings->max_aia_response_bytes,
              "лимит размера тела ответа AIA (докачанный сертификат) в байтах "
              "(ROADMAP.md п.4)");
    add_value(&group, "max-crl-response-bytes",
              &settings->max_crl_response_bytes,
              "лимит размера тела CRL-ответа в байтах (ROADMAP.md п.4)");
    add_value(&group, "max-retries", &settings->max_retries,
              "число ПОВТОРНЫХ попыток при транзиентной сетевой ошибке "
              "OCSP/CRL/AIA-fetch (не считая исходной попытки; не применяется "
              "к ldap:// и не применяется к успешным HTTP-ответам с кодом "
              "ошибки — только к сбоям транспорта). ROADMAP.md п.10");
    add_value(&group, "retry-base-delay-ms", &settings->retry_base_delay_ms,
              "базовая задержка (мс) экспоненциального backoff с джиттером "
              "между повторными попытками (ROADMAP.md п.10)");
    add_value(&group, "circuit-breaker-failure-threshold",
              &settings->circuit_breaker_failure_threshold,
              "число подряд неудачных ЗАПРОСОВ (после исчерпания retry на "
              "каждый) к одному хосту, после которого breaker открывается и "
              "начинает отказывать немедленно (ROADMAP.md п.11)");
    add_value(&group, "circuit-breaker-cooldown-seconds",
              &settings->circuit_breaker_cooldown_seconds,
              "время (секунды) в открытом состоянии breaker'а, прежде чем "
              "пропустить пробный запрос (ROADMAP.md п.11)");
    add_value(&group, "circuit-breaker-max-tracked-hosts",
              &settings->circuit_breaker_max_tracked_hosts,
              "предел числа одновременно отслеживаемых хостов для circuit "
              "breaker — защита от неограниченного роста памяти, т.к. хосты "
              "приходят из потенциально недобросовестных сертификатов "
              "(ROADMAP.md п.11)");
    return group;
}

po::options_description describe_worker_options(DaemonSettings* settings) {
    po::options_description group("Пул воркеров (пункт 4)", HELP_LINE_LENGTH);
    add_value(&group, "min-worker-threads", &settings->min_worker_threads,
              "минимальное число воркеров, всегда в строю");
    add_value(&group, "max-worker-threads", &settings->max_worker_threads,
              "максимальное число воркеров под нагрузкой");
    add_value(&group, "worker-idle-timeout-ms",
              &settings->worker_idle_timeout_ms,
              "простой дольше этого — воркер завершается, если это не опустит "
              "пул ниже минимума");
    return group;
}

po::options_description describe_network_options(DaemonSettings* settings) {
    po::options_description group(
        "Сетевая политика для исходящих запросов (пункт 3, SSRF-защита)",
        HELP_LINE_LENGTH);
    add_flag(&group, "allow-private-destinations",
             &settings->allow_private_destinations,
             "отключить блокировку loopback/link-local/private/CGNAT/multicast "
             "диапазонов по умолчанию");
    add_repeatable(&group, "allow-cidr", &settings->allow_cidrs,
                   "разрешить конкретный CIDR-диапазон явно, в обход "
                   "deny-списка (можно указывать несколько раз)");
    add_repeatable(&group, "deny-cidr", &settings->deny_cidrs,
                   "запретить дополнительный CIDR-диапазон сверх дефолтного "
                   "(можно указывать несколько раз)");
    add_port_list(&group, "allowed-ports", &settings->allowed_ports,
                  "список разрешённых портов назначения, через пробел "
                  "(например: --allowed-ports 80 8080; при --allow-https не "
                  "забудьте добавить 443)");
    add_flag(&group, "allow-https", &settings->allow_https,
             "разрешить https:// в AIA/OCSP/CDP URL (по умолчанию выключено — "
             "см. ROADMAP.md п.7 и комментарий в http_client.hpp; не забудьте "
             "также добавить 443 в --allowed-ports)");
    add_value(&group, "https-ca-bundle", &settings->https_ca_bundle,
              "путь к файлу/директории с доверенными CA для https:// (пусто = "
              "системный набор корневых сертификатов); действует, только если "
              "--allow-https");
    add_flag(&group, "allow-ldap", &settings->allow_ldap,
             "разрешить ldap:// в CRL distribution point URL (по умолчанию "
             "выключено — см. ROADMAP.md п.9 и комментарий в ldap_client.hpp; "
             "поддерживается только anonymous bind, без TLS, без пустого host "
             "в URL)");
    add_value(&group, "dns-cache-ttl-seconds", &settings->dns_cache_ttl_seconds,
              "TTL (секунды) локального кэша DNS-резолвинга имён из "
              "AIA/OCSP/CDP URL — короткий фиксированный TTL, т.к. "
              "getaddrinfo() не отдаёт реальный TTL DNS-записи (ROADMAP.md "
              "п.13). Адрес всё равно проверяется политикой при КАЖДОМ "
              "использовании закэшированной записи, не только при первом "
              "резолве.");
    add_value(&group, "warmup-file", &settings->warmup_file,
              "путь к файлу прогрева кэша (пусто = прогрев выключен) — "
              "построчный список crl:<url>/aia:<url>/"
              "ocsp:<responder_url>:<cert_path>:<issuer_path>, выполняется в "
              "фоновом потоке сразу после старта D-Bus сервера, не блокируя "
              "готовность демона (ROADMAP.md п.15, см. cache_warmup.hpp)");
    return group;
}

po::options_description describe_logging_options(DaemonSettings* settings) {
    po::options_description group("Логирование (ROADMAP.md п.22)",
                                  HELP_LINE_LENGTH);
    add_value(&group, "log-level", &settings->log_level_name,
              "минимальный уровень записей диагностического лога: "
              "debug|info|warn|error");
    add_value(&group, "log-format", &settings->log_format_name,
              "формат диагностического лога: text ([время] [уровень] "
              "[компонент] сообщение key=value), json (JSON Lines) или "
              "journald (структурированные поля CH_* через sd_journal_send; "
              "если журнал недоступен — текстом в stderr)");
    return group;
}

po::options_description describe_audit_options(DaemonSettings* settings) {
    po::options_description group("Аудит-лог решений о фетче (ROADMAP.md п.23)",
                                  HELP_LINE_LENGTH);
    add_value(&group, "audit-log-file", &settings->audit_log_file,
              "путь к append-only журналу (JSON Lines): что докачивали, "
              "откуда, с каким результатом, когда (пусто = аудит выключен). "
              "Если файл не удаётся открыть при старте — демон не "
              "запускается. Формат и гарантии — см. audit_log.hpp");
    add_flag(&group, "audit-log-fsync", &settings->audit_log_fsync,
             "fsync после каждого события аудита (событие переживает крах "
             "ОС/питания; медленнее). Действует, только если задан "
             "--audit-log-file");
    return group;
}

}  // namespace

CommandLineOptions::CommandLineOptions()
    : option_description(
          "cert-helper — вспомогательный демон докачки/проверки сертификатов",
          HELP_LINE_LENGTH) {
    option_description.add_options()("help,h", "показать эту справку");
    option_description.add(describe_dbus_options(&parsed_settings))
        .add(describe_cache_options(&parsed_settings))
        .add(describe_worker_options(&parsed_settings))
        .add(describe_network_options(&parsed_settings))
        .add(describe_logging_options(&parsed_settings))
        .add(describe_audit_options(&parsed_settings));
}

CommandLineOptions::ParseStatus CommandLineOptions::parse(
    int argc, char const* const* argv) {
    error_text.clear();

    po::variables_map variables;
    try {
        po::store(po::parse_command_line(argc, argv, option_description),
                  variables);
        po::notify(variables);
    } catch (po::error const& error) {
        error_text = std::string("cert-helper: ") + error.what() + "\n\n" +
                     help_text() + "\n";
        return ParseStatus::INVALID_USAGE;
    }

    if (variables.count("help") > 0) {
        return ParseStatus::HELP_REQUESTED;
    }
    if (!validate_and_normalize()) {
        return ParseStatus::INVALID_USAGE;
    }
    return ParseStatus::OK;
}

DaemonSettings const& CommandLineOptions::settings() const {
    return parsed_settings;
}

std::string const& CommandLineOptions::error_message() const {
    return error_text;
}

std::string CommandLineOptions::help_text() const {
    std::ostringstream text;
    text << option_description;
    return text.str();
}

bool CommandLineOptions::validate_and_normalize() {
    // Неверное значение — ошибка использования (как и любой другой неверный
    // аргумент), поэтому сообщаем о ней и выходим с кодом 2, а не молча берём
    // значение по умолчанию.
    auto const level = log::parse_level(parsed_settings.log_level_name);
    if (!level) {
        error_text = "cert-helper: --log-level: неизвестный уровень \"" +
                     parsed_settings.log_level_name +
                     "\" (ожидается debug|info|warn|error)\n";
        return false;
    }
    auto const format = log::parse_format(parsed_settings.log_format_name);
    if (!format) {
        error_text = "cert-helper: --log-format: неизвестный формат \"" +
                     parsed_settings.log_format_name +
                     "\" (ожидается text|json|journald)\n";
        return false;
    }
    parsed_settings.log_level = *level;
    parsed_settings.log_format = *format;

    if (parsed_settings.min_worker_threads < 1) {
        parsed_settings.min_worker_threads = 1;
    }
    if (parsed_settings.max_worker_threads <
        parsed_settings.min_worker_threads) {
        parsed_settings.max_worker_threads = parsed_settings.min_worker_threads;
    }
    return true;
}

}  // namespace cert_helper
