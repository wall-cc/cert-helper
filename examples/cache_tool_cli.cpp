// cache_tool_cli.cpp
//
// ROADMAP.md, раздел 2, пункт 16 (P3): отдельный, самостоятельный CLI-
// инструмент для экспорта/импорта кэша между хостами (см.
// cache_export.hpp за подробным обоснованием формата и подхода).
//
// СОЗНАТЕЛЬНО отдельный бинарник, а не подкоманда cert-helper-cli:
// cert-helper-cli — это D-Bus клиент, говорящий с ЗАПУЩЕННЫМ демоном;
// экспорт/импорт кэша — это файловая операция на каталоге кэша
// НАПРЯМУЮ, не требующая ни демона, ни D-Bus вообще (и по этой же
// причине не линкуется с sd-bus/OpenSSL — они этому инструменту не
// нужны).

#include <cstdio>
#include <sstream>
#include <string>

#include <boost/program_options.hpp>

#include "../src/cache_export.hpp"

namespace po = boost::program_options;

int main(int argc, char** argv) {
    po::options_description desc(
        "cert-helper-cache-tool — экспорт/импорт кэша cert-helper между хостами\n"
        "(ROADMAP.md, раздел 2, пункт 16)\n\n"
        "Использование:\n"
        "  cert-helper-cache-tool export --cache-dir <dir> --file <path>\n"
        "  cert-helper-cache-tool import --cache-dir <dir> --file <path>\n\n"
        "Опции");
    std::string command;
    std::string cache_dir;
    std::string file;
    desc.add_options()("help,h", "показать эту справку")(
        "command", po::value<std::string>(&command), "export|import")(
        "cache-dir", po::value<std::string>(&cache_dir), "каталог кэша cert-helper (--cache-dir демона)")(
        "file", po::value<std::string>(&file), "путь к портируемому файлу кэша");

    po::positional_options_description pos;
    pos.add("command", 1);

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pos).run(), vm);
        po::notify(vm);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "cert-helper-cache-tool: ошибка разбора аргументов: %s\n", e.what());
        std::fprintf(stderr, "%s\n", [&] { std::ostringstream os; os << desc; return os.str(); }().c_str());
        return 2;
    }

    if (vm.count("help") || command.empty()) {
        std::ostringstream os;
        os << desc;
        std::fprintf(stdout, "%s\n", os.str().c_str());
        return command.empty() ? 2 : 0;
    }

    if (cache_dir.empty() || file.empty()) {
        std::fprintf(stderr, "cert-helper-cache-tool: нужны --cache-dir и --file\n");
        return 2;
    }

    if (command == "export") {
        auto stats = cert_helper::cache_export::run_export(cache_dir, file);
        if (!stats) {
            std::fprintf(stderr, "cert-helper-cache-tool: не удалось открыть %s на запись\n", file.c_str());
            return 1;
        }
        std::fprintf(stdout,
                      "экспортировано=%llu пропущено_просроченных=%llu пропущено_битых=%llu\n",
                      static_cast<unsigned long long>(stats->exported),
                      static_cast<unsigned long long>(stats->skipped_expired),
                      static_cast<unsigned long long>(stats->skipped_malformed));
        return 0;
    }
    if (command == "import") {
        auto stats = cert_helper::cache_export::run_import(cache_dir, file);
        if (!stats) {
            std::fprintf(stderr,
                          "cert-helper-cache-tool: не удалось прочитать %s (нет файла или не тот формат)\n",
                          file.c_str());
            return 1;
        }
        std::fprintf(stdout, "импортировано=%llu пропущено_просроченных=%llu пропущено_битых=%llu\n",
                      static_cast<unsigned long long>(stats->imported),
                      static_cast<unsigned long long>(stats->skipped_expired),
                      static_cast<unsigned long long>(stats->skipped_malformed));
        return 0;
    }

    std::fprintf(stderr, "cert-helper-cache-tool: неизвестная команда \"%s\" (ожидается export|import)\n",
                  command.c_str());
    return 2;
}
