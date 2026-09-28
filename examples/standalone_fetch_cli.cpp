// standalone_fetch_cli.cpp
//
// cert-helper-cli — небольшая утилита командной строки для ручной
// диагностики уже запущенного демона: health-check и одиночные fetch-
// запросы без необходимости поднимать NGFW/tls-mitm целиком.
//
// Аргументы разбираются через boost::program_options: команда (health /
// fetch-crl / fetch-intermediate) — позиционный аргумент, остальное —
// именованные опции.
//
// Примеры:
//   cert-helper-cli health
//   cert-helper-cli fetch-crl --url http://crl.example.com/ca.crl --out /tmp/ca.crl
//   cert-helper-cli fetch-intermediate
//       --url http://ca.example.com/intermediate.cer --out /tmp/intermediate.der
//   cert-helper-cli --bus-address "unix:path=/tmp/test.sock" health   # для тестового приватного bus'а

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

#include "../include/cert_helper/client.hpp"

namespace po = boost::program_options;

namespace {

// См. комментарий в daemon_main.cpp: boost::program_options переносит
// строки в --help по байтам, что ломает многобайтовый UTF-8 (кириллицу).
// Задаём большую длину строки, чтобы перенос не срабатывал.
constexpr unsigned kHelpLineLength = 4096;

bool write_output(const std::string& out_path, const std::vector<uint8_t>& data) {
    if (out_path.empty()) {
        std::fwrite(data.data(), 1, data.size(), stdout);
        return true;
    }
    std::ofstream out(out_path, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return true;
}

} // namespace

int main(int argc, char** argv) {
    std::string bus_address; // пусто = системная шина
    std::string command;
    std::string url;
    std::string out_path;
    uint32_t timeout_ms = 0;

    // "command" — позиционный аргумент (health | fetch-crl | fetch-intermediate),
    // держим его в отдельном "скрытом" options_description, чтобы он не
    // засорял вывод --help как флаг "--command".
    po::options_description visible("cert-helper-cli — диагностика запущенного демона cert-helper",
                                     kHelpLineLength);
    visible.add_options()
        ("help,h", "показать эту справку")
        ("bus-address", po::value<std::string>(&bus_address)->default_value(""),
         "адрес D-Bus (пусто = системная шина)")
        ("url", po::value<std::string>(&url)->default_value(""),
         "URL для fetch-crl / fetch-intermediate")
        ("out", po::value<std::string>(&out_path)->default_value(""),
         "куда записать результат (по умолчанию — stdout)")
        ("timeout-ms", po::value<uint32_t>(&timeout_ms)->default_value(5000),
         "таймаут запроса в миллисекундах");

    po::options_description hidden;
    hidden.add_options()("command", po::value<std::string>(&command), "команда");

    po::options_description all;
    all.add(visible).add(hidden);

    po::positional_options_description positional;
    positional.add("command", 1);

    auto print_usage = [&]() {
        std::cerr << "Usage: " << argv[0] << " [options] <command>\n"
                   << "Commands:\n"
                   << "  health                                   проверить доступность демона\n"
                   << "  fetch-crl --url URL [--out FILE]          скачать CRL (через кэш демона)\n"
                   << "  fetch-intermediate --url URL [--out FILE] докачать промежуточный сертификат (AIA)\n\n"
                   << visible << "\n";
    };

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv).options(all).positional(positional).run(), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "cert-helper-cli: " << e.what() << "\n\n";
        print_usage();
        return 2;
    }

    if (vm.count("help")) {
        print_usage();
        return 0;
    }

    if (command.empty()) {
        print_usage();
        return 2;
    }

    cert_helper::Client client(bus_address);

    if (command == "health") {
        auto status = client.health_check(timeout_ms);
        if (!status.reachable) {
            std::fprintf(stderr, "cert-helper: unreachable on %s\n",
                          bus_address.empty() ? "system bus" : bus_address.c_str());
            return 1;
        }
        std::printf("healthy=%s\n", status.healthy ? "true" : "false");
        std::printf("disk cache:   entries=%llu size_bytes=%llu\n",
                     static_cast<unsigned long long>(status.cache_entries),
                     static_cast<unsigned long long>(status.cache_size_bytes));
        std::printf("memory cache: entries=%llu size_bytes=%llu\n",
                     static_cast<unsigned long long>(status.memory_cache_entries),
                     static_cast<unsigned long long>(status.memory_cache_size_bytes));
        std::printf("ocsp:  requests=%llu cache_hits=%llu errors=%llu\n",
                     static_cast<unsigned long long>(status.ocsp.requests),
                     static_cast<unsigned long long>(status.ocsp.cache_hits),
                     static_cast<unsigned long long>(status.ocsp.errors));
        std::printf("crl:   requests=%llu cache_hits=%llu errors=%llu\n",
                     static_cast<unsigned long long>(status.crl.requests),
                     static_cast<unsigned long long>(status.crl.cache_hits),
                     static_cast<unsigned long long>(status.crl.errors));
        std::printf("aia:   requests=%llu cache_hits=%llu errors=%llu\n",
                     static_cast<unsigned long long>(status.intermediate_cert.requests),
                     static_cast<unsigned long long>(status.intermediate_cert.cache_hits),
                     static_cast<unsigned long long>(status.intermediate_cert.errors));
        return status.healthy ? 0 : 1;
    }

    if (command == "fetch-crl") {
        if (url.empty()) {
            std::fprintf(stderr, "fetch-crl requires --url\n");
            return 2;
        }
        auto data = client.fetch_crl(url, timeout_ms);
        if (data.empty()) {
            std::fprintf(stderr, "fetch-crl: failed (timeout, network error, or empty response)\n");
            return 1;
        }
        return write_output(out_path, data) ? 0 : 1;
    }

    if (command == "fetch-intermediate") {
        if (url.empty()) {
            std::fprintf(stderr, "fetch-intermediate requires --url\n");
            return 2;
        }
        auto data = client.fetch_intermediate_cert(url, timeout_ms);
        if (data.empty()) {
            std::fprintf(stderr, "fetch-intermediate: failed (timeout, network error, or invalid cert)\n");
            return 1;
        }
        return write_output(out_path, data) ? 0 : 1;
    }

    std::fprintf(stderr, "unknown command: %s\n", command.c_str());
    print_usage();
    return 2;
}
