// test_cache.cpp — юнит-тесты кэша: TTL-протухание, LRU-вытеснение по
// лимитам числа записей и суммарного размера, персистентность между
// "перезапусками" (новый FileCacheStore над той же директорией).

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <thread>
#include <unistd.h>

#include "../src/cache/cache_store.hpp"
#include "test_util.hpp"

using namespace cert_helper::cache;
namespace fs = std::filesystem;

namespace {

fs::path make_temp_dir(const std::string& suffix) {
    fs::path dir = fs::temp_directory_path() / ("cert_helper_test_" + suffix + "_" +
                                                 std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void test_put_and_get_roundtrip() {
    auto dir = make_temp_dir("roundtrip");
    FileCacheStore::Limits limits;
    FileCacheStore store(dir, limits);

    CacheEntry entry;
    entry.payload = {1, 2, 3, 4};
    entry.fetched_at = now_seconds();
    entry.valid_until = now_seconds() + 3600;
    store.put(EntryKind::Crl, "https://example.com/crl.der", entry);

    auto got = store.get(EntryKind::Crl, "https://example.com/crl.der");
    TEST_CHECK(got.has_value());
    TEST_CHECK(got->payload == entry.payload);

    fs::remove_all(dir);
}

void test_missing_key_returns_nullopt() {
    auto dir = make_temp_dir("missing");
    FileCacheStore::Limits limits;
    FileCacheStore store(dir, limits);
    auto got = store.get(EntryKind::Ocsp, "no-such-key");
    TEST_CHECK(!got.has_value());
    fs::remove_all(dir);
}

void test_expired_entry_not_returned() {
    auto dir = make_temp_dir("ttl");
    FileCacheStore::Limits limits;
    FileCacheStore store(dir, limits);

    CacheEntry entry;
    entry.payload = {9, 9, 9};
    entry.fetched_at = now_seconds() - 10;
    entry.valid_until = now_seconds() - 1; // уже просрочено
    store.put(EntryKind::Ocsp, "key-ttl", entry);

    auto got = store.get(EntryKind::Ocsp, "key-ttl");
    TEST_CHECK(!got.has_value());
    fs::remove_all(dir);
}

void test_different_kinds_do_not_collide() {
    auto dir = make_temp_dir("kinds");
    FileCacheStore::Limits limits;
    FileCacheStore store(dir, limits);

    CacheEntry a;
    a.payload = {1};
    a.valid_until = now_seconds() + 3600;
    CacheEntry b;
    b.payload = {2};
    b.valid_until = now_seconds() + 3600;

    // Один и тот же ключ (URL), разный EntryKind — не должны затирать друг
    // друга (в реальности маловероятно, что один URL — и OCSP responder, и
    // CRL distribution point, но протокол это не запрещает).
    store.put(EntryKind::Ocsp, "same-url", a);
    store.put(EntryKind::Crl, "same-url", b);

    auto got_a = store.get(EntryKind::Ocsp, "same-url");
    auto got_b = store.get(EntryKind::Crl, "same-url");
    TEST_CHECK(got_a.has_value() && got_a->payload == a.payload);
    TEST_CHECK(got_b.has_value() && got_b->payload == b.payload);
    fs::remove_all(dir);
}

void test_lru_eviction_by_entry_count() {
    auto dir = make_temp_dir("lru_count");
    FileCacheStore::Limits limits;
    limits.max_entries = 3;
    limits.max_size_bytes = 1024 * 1024;
    FileCacheStore store(dir, limits);

    for (int i = 0; i < 3; ++i) {
        CacheEntry e;
        e.payload = {static_cast<uint8_t>(i)};
        e.valid_until = now_seconds() + 3600;
        store.put(EntryKind::Crl, "key" + std::to_string(i), e);
    }
    // Трогаем key0, чтобы он стал "недавно использованным" и не подлежал
    // вытеснению вместо key1.
    (void)store.get(EntryKind::Crl, "key0");

    CacheEntry e3;
    e3.payload = {99};
    e3.valid_until = now_seconds() + 3600;
    store.put(EntryKind::Crl, "key3", e3); // должно вытеснить наименее недавно использованный (key1)

    auto stats = store.stats();
    TEST_CHECK(stats.entries <= 3);

    auto got0 = store.get(EntryKind::Crl, "key0");
    auto got3 = store.get(EntryKind::Crl, "key3");
    TEST_CHECK(got0.has_value()); // недавно использованный — должен выжить
    TEST_CHECK(got3.has_value()); // только что записанный — должен выжить

    fs::remove_all(dir);
}

void test_lru_eviction_by_size() {
    auto dir = make_temp_dir("lru_size");
    FileCacheStore::Limits limits;
    limits.max_entries = 1000;
    limits.max_size_bytes = 30; // очень маленький лимит по байтам
    FileCacheStore store(dir, limits);

    for (int i = 0; i < 5; ++i) {
        CacheEntry e;
        e.payload = std::vector<uint8_t>(10, static_cast<uint8_t>(i)); // 10 байт каждая
        e.valid_until = now_seconds() + 3600;
        store.put(EntryKind::IntermediateCert, "cert" + std::to_string(i), e);
    }

    auto stats = store.stats();
    TEST_CHECK(stats.size_bytes <= 30);
    fs::remove_all(dir);
}

void test_persistence_across_restart() {
    auto dir = make_temp_dir("persist");
    {
        FileCacheStore::Limits limits;
        FileCacheStore store(dir, limits);
        CacheEntry e;
        e.payload = {7, 7, 7};
        e.valid_until = now_seconds() + 3600;
        store.put(EntryKind::IntermediateCert, "persisted-key", e);
    } // store уничтожен — имитация рестарта процесса

    {
        FileCacheStore::Limits limits;
        FileCacheStore store2(dir, limits); // "новый процесс", та же директория
        auto got = store2.get(EntryKind::IntermediateCert, "persisted-key");
        TEST_CHECK(got.has_value());
        TEST_CHECK(got->payload == std::vector<uint8_t>({7, 7, 7}));
    }

    fs::remove_all(dir);
}

} // namespace

int main() {
    RUN_TEST(test_put_and_get_roundtrip);
    RUN_TEST(test_missing_key_returns_nullopt);
    RUN_TEST(test_expired_entry_not_returned);
    RUN_TEST(test_different_kinds_do_not_collide);
    RUN_TEST(test_lru_eviction_by_entry_count);
    RUN_TEST(test_lru_eviction_by_size);
    RUN_TEST(test_persistence_across_restart);
    TEST_MAIN_EXIT();
}
