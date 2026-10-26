// command_line_options.hpp
//
// Описание параметров командной строки демона cert-helper и их разбор.
//
// Раньше всё это жило прямо в main() (daemon_main.cpp): ~40 локальных
// переменных, описания флагов и значения по умолчанию вперемешку с
// запуском демона. Теперь:
//   - DaemonSettings — «паспорт» конфигурации: плоская структура с
//     значениями по умолчанию. Единственное место, где эти значения
//     записаны: описание флагов берёт default_value() прямо отсюда.
//   - CommandLineOptions — описание флагов (boost::program_options),
//     разбор argv и проверка значений. Не пишет в stdout/stderr и не
//     завершает процесс: решение, что напечатать и с каким кодом выйти,
//     остаётся за вызывающим кодом (см. daemon_main.cpp).

#pragma once

#include <boost/program_options.hpp>
#include <cstdint>
#include <string>
#include <vector>

#include "ipc/dbus_interface.hpp"
#include "logging.hpp"

namespace cert_helper {

// Все параметры демона после разбора командной строки.
struct DaemonSettings {
    // --- D-Bus ---
    std::string bus_address;  // Пусто = системная шина.
    std::string bus_name = ipc::SERVICE_NAME;

    // --- Кэш (диск + опциональный memory-слой) ---
    std::string cache_dir = "/var/lib/cert-helper/cache";
    uint64_t max_cache_entries = 100000;
    uint64_t max_cache_bytes = 512ULL * 1024 * 1024;
    uint64_t mem_cache_max_entries = 20000;
    uint64_t mem_cache_max_bytes = 64ULL * 1024 * 1024;
    uint32_t aia_ttl_seconds = 7 * 24 * 3600;
    uint32_t max_ocsp_ttl_seconds = 24 * 3600;
    uint32_t max_crl_ttl_seconds = 7 * 24 * 3600;
    uint32_t max_ocsp_response_bytes = 256 * 1024;
    uint32_t max_aia_response_bytes = 256 * 1024;
    uint32_t max_crl_response_bytes = 16 * 1024 * 1024;
    uint32_t max_retries = 2;
    uint32_t retry_base_delay_ms = 100;
    uint32_t circuit_breaker_failure_threshold = 5;
    uint32_t circuit_breaker_cooldown_seconds = 30;
    uint32_t circuit_breaker_max_tracked_hosts = 10000;

    // --- Пул воркеров ---
    // После parse() гарантированно: min >= 1 и max >= min.
    int min_worker_threads = 2;
    int max_worker_threads = 16;
    int worker_idle_timeout_ms = 30000;

    // --- Сетевая политика исходящих запросов (SSRF-защита) ---
    bool allow_private_destinations = false;
    std::vector<std::string> allow_cidrs;
    std::vector<std::string> deny_cidrs;
    std::vector<uint16_t> allowed_ports = {80};
    bool allow_https = false;
    std::string https_ca_bundle;  // Пусто = системный набор корневых CA.
    bool allow_ldap = false;
    uint32_t dns_cache_ttl_seconds = 60;
    std::string warmup_file;  // Пусто = прогрев выключен.

    // --- Логирование ---
    // Имена, как их ввёл пользователь, и значения, разобранные из них
    // (разобранные корректны только после успешного parse()).
    std::string log_level_name = "info";
    std::string log_format_name = "text";
    log::Level log_level = log::Level::INFO;
    log::Format log_format = log::Format::TEXT;

    // --- Аудит-лог ---
    std::string audit_log_file;  // Пусто = аудит выключен.
    bool audit_log_fsync = false;
};

class CommandLineOptions {
public:
    enum class ParseStatus {
        OK,  // Параметры разобраны и проверены, можно запускаться.
        HELP_REQUESTED,  // Был --help: напечатать help_text(), выйти с кодом 0.
        INVALID_USAGE,  // Ошибка: напечатать error_message(), выйти с кодом 2.
    };

    CommandLineOptions();

    // Описания флагов хранят указатели на поля parsed_settings, поэтому
    // копирование и перемещение объекта запрещены.
    CommandLineOptions(CommandLineOptions const&) = delete;
    CommandLineOptions& operator=(CommandLineOptions const&) = delete;

    // Разбирает argv (argv[0] — имя программы, как в main()).
    ParseStatus parse(int argc, char const* const* argv);

    // Результат разбора. Осмысленен только при ParseStatus::OK.
    DaemonSettings const& settings() const;

    // Полный текст для stderr при INVALID_USAGE (включая справку, если
    // ошибка — в синтаксисе командной строки). Пуст при других статусах.
    std::string const& error_message() const;

    // Справка по всем флагам (то, что печатает --help).
    std::string help_text() const;

private:
    // Проверки и нормализация значений, которые boost разобрать не может.
    // Возвращает false и заполняет error_text при неверном значении.
    bool validate_and_normalize();

    boost::program_options::options_description option_description;
    DaemonSettings parsed_settings;
    std::string error_text;
};

}  // namespace cert_helper
