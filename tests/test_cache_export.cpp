// test_cache_export.cpp — тесты экспорта/импорта кэша между хостами
// (ROADMAP.md, раздел 2, пункт 16). См. подробное обоснование формата и
// подхода в комментарии в начале src/cache_export.hpp.

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include <unistd.h>

#include "../src/cache/cache_store.hpp"
#include "../src/cache_export.hpp"
#include "test_util.hpp"

namespace fs = std::filesystem;
using namespace cert_helper;

namespace {

fs::path make_temp_dir(const std::string& suffix) {
    auto dir = fs::temp_directory_path() / ("cert_helper_export_test_" + suffix + "_" +
                                             std::to_string(::getpid()));
    fs::create_directories(dir);
    return dir;
}

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Пишет "сырой" файл записи кэша напрямую (в обход FileCacheStore::put(),
// который проактивно вычищает уже просроченные записи при каждой
// записи — см. cache_store.hpp::evict_if_needed()) — имитирует запись,
// которая БЫЛА валидна на момент записи, но с тех пор протухла и лежит
// на диске нетронутой, пока put() не вызывался повторно. Именно этот
// сценарий (не "запись, просроченная с самого начала") и проверяет
// логику "пропустить просроченное" в run_export()/run_import().
void write_raw_entry(const fs::path& cache_dir, const std::string& filename, int64_t fetched_at,
                      int64_t valid_until, const std::vector<uint8_t>& payload) {
    std::ofstream out(cache_dir / filename, std::ios::binary);
    auto write_le = [&](uint64_t v, int bytes) {
        for (int i = 0; i < bytes; ++i) {
            char b = static_cast<char>((v >> (8 * i)) & 0xFF);
            out.write(&b, 1);
        }
    };
    write_le(static_cast<uint64_t>(fetched_at), 8);
    write_le(static_cast<uint64_t>(valid_until), 8);
    if (!payload.empty()) {
        out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    }
}

// ROADMAP.md, раздел 2, пункт 16: экспорт валидных записей + импорт на
// "другой хост" (другой каталог) должен дать ПОБАЙТОВО ИДЕНТИЧНЫЙ
// результат — и, что важнее, результат, который настоящий
// FileCacheStore::get() на целевом каталоге находит по ТЕМ ЖЕ (kind,
// key), что и на исходном.
void test_export_import_round_trip_preserves_entries_and_is_readable_by_filecachestore() {
    auto src_dir = make_temp_dir("roundtrip_src");
    auto dst_dir = make_temp_dir("roundtrip_dst");
    auto export_file = (make_temp_dir("roundtrip_export") / "export.chcache").string();

    {
        cache::FileCacheStore src_cache(src_dir, cache::FileCacheStore::Limits{});
        int64_t now = now_seconds();
        src_cache.put(cache::EntryKind::Crl, "http://crl.example.test/a.crl",
                       {{1, 2, 3}, now, now + 3600});
        src_cache.put(cache::EntryKind::Ocsp, "http://ocsp.example.test/x|certid-fingerprint",
                       {{4, 5, 6, 7}, now, now + 300});
    }

    auto export_stats = cache_export::run_export(src_dir.string(), export_file);
    TEST_CHECK(export_stats.has_value());
    if (export_stats) {
        TEST_CHECK_EQ(export_stats->exported, uint64_t{2});
        TEST_CHECK_EQ(export_stats->skipped_expired, uint64_t{0});
    }

    auto import_stats = cache_export::run_import(dst_dir.string(), export_file);
    TEST_CHECK(import_stats.has_value());
    if (import_stats) {
        TEST_CHECK_EQ(import_stats->imported, uint64_t{2});
        TEST_CHECK_EQ(import_stats->skipped_expired, uint64_t{0});
    }

    // Настоящий FileCacheStore на "целевом хосте" должен находить обе
    // записи по тем же (kind, key), что и на исходном — файлы кэша
    // хостонезависимы по конструкции (имя = sha256(kind|key)).
    cache::FileCacheStore dst_cache(dst_dir, cache::FileCacheStore::Limits{});
    auto crl = dst_cache.get(cache::EntryKind::Crl, "http://crl.example.test/a.crl");
    auto ocsp = dst_cache.get(cache::EntryKind::Ocsp, "http://ocsp.example.test/x|certid-fingerprint");
    TEST_CHECK(crl.has_value());
    TEST_CHECK(ocsp.has_value());
    if (crl) TEST_CHECK(crl->payload == std::vector<uint8_t>({1, 2, 3}));
    if (ocsp) TEST_CHECK(ocsp->payload == std::vector<uint8_t>({4, 5, 6, 7}));

    std::error_code ec;
    fs::remove_all(src_dir, ec);
    fs::remove_all(dst_dir, ec);
}

// Запись, уже просроченная НА МОМЕНТ ЭКСПОРТА (валидна была раньше, но
// put() с тех пор не вызывался — см. write_raw_entry() выше), не должна
// попасть в портируемый файл вовсе.
void test_export_skips_already_expired_entries() {
    auto src_dir = make_temp_dir("expskip_src");
    auto export_file = (make_temp_dir("expskip_export") / "export.chcache").string();

    int64_t now = now_seconds();
    write_raw_entry(src_dir, std::string(64, 'a') + ".bin", now - 200, now - 100, {9, 9, 9});

    auto stats = cache_export::run_export(src_dir.string(), export_file);
    TEST_CHECK(stats.has_value());
    if (stats) {
        TEST_CHECK_EQ(stats->exported, uint64_t{0});
        TEST_CHECK_EQ(stats->skipped_expired, uint64_t{1});
    }

    std::error_code ec;
    fs::remove_all(src_dir, ec);
}

// Запись была ещё валидна на момент экспорта, но успела протухнуть к
// моменту импорта (например, файл переносился между хостами достаточно
// долго) — импорт не должен класть её в целевой кэш.
void test_import_skips_entries_that_expired_since_export() {
    auto dst_dir = make_temp_dir("impexpired_dst");
    auto export_file = (make_temp_dir("impexpired_export") / "export.chcache").string();

    // Собираем портируемый файл ВРУЧНУЮ с уже просроченным valid_until —
    // имитирует "успела протухнуть за время между export и import", не
    // прогоняя реальный export (который бы её и сам отфильтровал).
    {
        std::ofstream out(export_file, std::ios::binary);
        auto write_le = [&](uint64_t v, int bytes) {
            for (int i = 0; i < bytes; ++i) {
                char b = static_cast<char>((v >> (8 * i)) & 0xFF);
                out.write(&b, 1);
            }
        };
        out.write("CHCACHE1", 8);
        write_le(1, 4); // 1 запись
        std::string name = std::string(64, 'b') + ".bin";
        write_le(name.size(), 2);
        out.write(name.data(), static_cast<std::streamsize>(name.size()));
        int64_t now = now_seconds();
        write_le(static_cast<uint64_t>(now - 500), 8); // fetched_at
        write_le(static_cast<uint64_t>(now - 100), 8); // valid_until — уже в прошлом
        std::vector<uint8_t> payload = {1, 2, 3};
        write_le(payload.size(), 4);
        out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
    }

    auto stats = cache_export::run_import(dst_dir.string(), export_file);
    TEST_CHECK(stats.has_value());
    if (stats) {
        TEST_CHECK_EQ(stats->imported, uint64_t{0});
        TEST_CHECK_EQ(stats->skipped_expired, uint64_t{1});
    }
    TEST_CHECK(!fs::exists(dst_dir / (std::string(64, 'b') + ".bin")));

    std::error_code ec;
    fs::remove_all(dst_dir, ec);
}

// Файл не в нашем формате (неверная магическая строка) должен быть
// отклонён целиком, а не привести к попытке "угадать" структуру.
void test_import_rejects_file_with_wrong_magic() {
    auto dst_dir = make_temp_dir("wrongmagic_dst");
    auto bad_file = (make_temp_dir("wrongmagic_file") / "not_a_cache_export.bin").string();
    {
        std::ofstream out(bad_file, std::ios::binary);
        out << "this is not a cert-helper cache export file at all";
    }

    auto stats = cache_export::run_import(dst_dir.string(), bad_file);
    TEST_CHECK(!stats.has_value());

    std::error_code ec;
    fs::remove_all(dst_dir, ec);
}

// Экспорт из пустого/несуществующего каталога кэша не должен падать —
// просто ноль экспортированных записей.
void test_export_empty_cache_dir_produces_zero_entries() {
    auto src_dir = make_temp_dir("empty_src");
    auto export_file = (make_temp_dir("empty_export") / "export.chcache").string();

    auto stats = cache_export::run_export(src_dir.string(), export_file);
    TEST_CHECK(stats.has_value());
    if (stats) TEST_CHECK_EQ(stats->exported, uint64_t{0});

    std::error_code ec;
    fs::remove_all(src_dir, ec);
}

} // namespace

int main() {
    RUN_TEST(test_export_import_round_trip_preserves_entries_and_is_readable_by_filecachestore);
    RUN_TEST(test_export_skips_already_expired_entries);
    RUN_TEST(test_import_skips_entries_that_expired_since_export);
    RUN_TEST(test_import_rejects_file_with_wrong_magic);
    RUN_TEST(test_export_empty_cache_dir_produces_zero_entries);
    TEST_MAIN_EXIT();
}
