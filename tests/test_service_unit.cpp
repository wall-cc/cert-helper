// test_service_unit.cpp
//
// ПУНКТ 7 ПЛАНА ДОРАБОТКИ (P1): deploy/cert-helper.service вызывал
// демон с флагом --worker-threads, которого в CLI не существует
// (есть --min-worker-threads/--max-worker-threads): с таким unit-файлом
// демон завершался с кодом 2 ("unrecognised option") и не запускался
// под systemd вообще — а проверить это было нечем, пока описание флагов
// жило внутри main().
//
// Этот тест берёт строку ExecStart= из реального unit-файла и прогоняет
// её аргументы через настоящий CommandLineOptions: расхождение между
// unit-файлом и CLI теперь ловится на этапе сборки, а не при первом
// запуске на сервере.
//
// Путь к unit-файлу задаётся через CERT_HELPER_SOURCE_DIR (compile
// definition из CMake), а не относительным путём от текущей директории:
// относительные пути к фикстурам — причина того, что тесты
// test_aia_extraction/test_crl_delta_extraction/test_https_support
// падают при сборке вне дерева исходников.

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "../src/command_line_options.hpp"
#include "test_util.hpp"

using cert_helper::CommandLineOptions;

#ifndef CERT_HELPER_SOURCE_DIR
#error "CERT_HELPER_SOURCE_DIR must be defined by the build system"
#endif

namespace {

std::string read_file(std::string const& path) {
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// Достаёт аргументы из ExecStart= (с учётом переносов строк через "\"),
// без пути к самому бинарнику. Пустой результат + found=false, если
// ExecStart= не найден.
std::vector<std::string> exec_start_arguments(std::string const& unit,
                                              bool* found) {
    *found = false;
    std::istringstream lines(unit);
    std::string line;
    std::string joined;
    bool in_exec_start = false;
    while (std::getline(lines, line)) {
        if (!in_exec_start) {
            if (line.rfind("ExecStart=", 0) != 0) {
                continue;
            }
            in_exec_start = true;
            line = line.substr(std::string("ExecStart=").size());
        }
        bool continued = !line.empty() && line.back() == '\\';
        if (continued) {
            line.pop_back();
        }
        joined += line + " ";
        if (!continued) {
            break;
        }
    }
    if (!in_exec_start) {
        return {};
    }
    *found = true;

    std::vector<std::string> tokens;
    std::istringstream words(joined);
    std::string word;
    while (words >> word) {
        tokens.push_back(word);
    }
    if (!tokens.empty()) {
        tokens.erase(tokens.begin());  // путь к бинарнику
    }
    return tokens;
}

void test_unit_exec_start_is_accepted_by_the_real_cli_parser() {
    std::string const unit_path =
        std::string(CERT_HELPER_SOURCE_DIR) + "/deploy/cert-helper.service";
    std::string const unit = read_file(unit_path);
    TEST_CHECK(!unit.empty());

    bool found = false;
    std::vector<std::string> args = exec_start_arguments(unit, &found);
    TEST_CHECK(found);
    TEST_CHECK(!args.empty());

    std::vector<std::string> storage{"cert-helper"};
    storage.insert(storage.end(), args.begin(), args.end());
    std::vector<char const*> argv;
    for (auto const& arg : storage) {
        argv.push_back(arg.c_str());
    }

    CommandLineOptions options;
    auto status = options.parse(static_cast<int>(argv.size()), argv.data());
    if (status != CommandLineOptions::ParseStatus::OK) {
        // Для диагностики: что именно не принял разбор.
        std::cerr << options.error_message().substr(0, 300) << "\n";
    }
    TEST_CHECK(status == CommandLineOptions::ParseStatus::OK);
}

// Страховка от того, что сам разбор ExecStart= в этом тесте сломается и
// тихо перестанет что-либо проверять.
void test_exec_start_parser_helper_works() {
    bool found = false;
    auto args = exec_start_arguments(
        "[Service]\nExecStart=/bin/x \\\n    --a 1 \\\n    --b\n\nUser=u\n",
        &found);
    TEST_CHECK(found);
    TEST_CHECK((args == std::vector<std::string>{"--a", "1", "--b"}));

    bool found_missing = true;
    auto none = exec_start_arguments("[Service]\nUser=u\n", &found_missing);
    TEST_CHECK(!found_missing);
    TEST_CHECK(none.empty());
}

}  // namespace

int main() {
    RUN_TEST(test_exec_start_parser_helper_works);
    RUN_TEST(test_unit_exec_start_is_accepted_by_the_real_cli_parser);
    TEST_MAIN_EXIT();
}
