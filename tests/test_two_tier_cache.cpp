// test_two_tier_cache.cpp — юнит-тесты TwoTierCacheStore (пункт 2 из
// анализа Squid: memory-слой поверх персистентного диска).

#include <chrono>
#include <filesystem>
#include <unistd.h>

#include "../src/cache/cache_store.hpp"
#include "../src/cache/two_tier_cache.hpp"
#include "test_util.hpp"

using namespace cert_helper::cache;
namespace fs = std::filesystem;

namespace {

fs::path make_temp_dir(const std::string& suffix) {
    fs::path dir = fs::temp_directory_path() / ("cert_helper_2tier_test_" + suffix + "_" +
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

// Обёртка вокруг FileCacheStore, считающая число реальных обращений к
// диску (get/put) — используется, чтобы доказать, что повторное чтение
// горячего ключа обслуживается из памяти, не бьёт в диск повторно.
class CountingCacheStore : public ICacheStore {
public:
    explicit CountingCacheStore(ICacheStore& inner) : inner(inner) {}

    std::optional<CacheEntry> get(EntryKind kind, const std::string& key) override {
        ++get_calls;
        return inner.get(kind, key);
    }
    void put(EntryKind kind, const std::string& key, const CacheEntry& entry) override {
        ++put_calls;
        inner.put(kind, key, entry);
    }
    CacheStats stats() override { return inner.stats(); }

    int get_calls = 0;
    int put_calls = 0;

private:
    ICacheStore& inner;
};

void test_memory_hit_avoids_disk_read() {
    auto dir = make_temp_dir("mem_hit");
    FileCacheStore disk(dir, FileCacheStore::Limits{});
    CountingCacheStore counting(disk);
    TwoTierCacheStore two_tier(counting, MemoryLruCache::Limits{});

    CacheEntry entry;
    entry.payload = {1, 2, 3};
    entry.valid_until = now_seconds() + 3600;
    two_tier.put(EntryKind::Ocsp, "hot-key", entry);
    TEST_CHECK_EQ(counting.put_calls, 1); // write-through: один put дошёл до диска

    // Первое чтение после put() тоже должно быть memory-хитом (put() уже
    // прогрел память) — значит get_calls на диск не должен вырасти.
    auto hit1 = two_tier.get(EntryKind::Ocsp, "hot-key");
    auto hit2 = two_tier.get(EntryKind::Ocsp, "hot-key");
    TEST_CHECK(hit1.has_value() && hit1->payload == entry.payload);
    TEST_CHECK(hit2.has_value() && hit2->payload == entry.payload);
    TEST_CHECK_EQ(counting.get_calls, 0); // оба чтения обслужены из памяти

    fs::remove_all(dir);
}

void test_disk_hit_promotes_to_memory() {
    auto dir = make_temp_dir("promote");
    FileCacheStore disk(dir, FileCacheStore::Limits{});

    // Кладём напрямую в диск, в обход memory-слоя — имитация "холодного
    // старта" TwoTierCacheStore над уже существующим диск-кэшем (например,
    // после рестарта процесса, когда память пуста, а диск ещё хранит
    // валидные записи с предыдущего запуска).
    CacheEntry entry;
    entry.payload = {9, 9, 9};
    entry.valid_until = now_seconds() + 3600;
    disk.put(EntryKind::Crl, "cold-key", entry);

    CountingCacheStore counting(disk);
    TwoTierCacheStore two_tier(counting, MemoryLruCache::Limits{});

    auto first = two_tier.get(EntryKind::Crl, "cold-key");
    TEST_CHECK(first.has_value());
    TEST_CHECK_EQ(counting.get_calls, 1); // промах памяти -> один поход на диск

    auto second = two_tier.get(EntryKind::Crl, "cold-key");
    TEST_CHECK(second.has_value());
    TEST_CHECK_EQ(counting.get_calls, 1); // второй раз — уже из памяти, диск не тронут

    fs::remove_all(dir);
}

void test_different_kinds_do_not_collide_in_memory_layer() {
    auto dir = make_temp_dir("kinds");
    FileCacheStore disk(dir, FileCacheStore::Limits{});
    TwoTierCacheStore two_tier(disk, MemoryLruCache::Limits{});

    CacheEntry a;
    a.payload = {1};
    a.valid_until = now_seconds() + 3600;
    CacheEntry b;
    b.payload = {2};
    b.valid_until = now_seconds() + 3600;

    two_tier.put(EntryKind::Ocsp, "same-url", a);
    two_tier.put(EntryKind::Crl, "same-url", b);

    auto got_a = two_tier.get(EntryKind::Ocsp, "same-url");
    auto got_b = two_tier.get(EntryKind::Crl, "same-url");
    TEST_CHECK(got_a.has_value() && got_a->payload == a.payload);
    TEST_CHECK(got_b.has_value() && got_b->payload == b.payload);

    fs::remove_all(dir);
}

void test_memory_lru_respects_entry_limit() {
    MemoryLruCache::Limits limits;
    limits.max_entries = 2;
    limits.max_size_bytes = 1024 * 1024;
    MemoryLruCache cache(limits);

    CacheEntry e0, e1, e2;
    e0.payload = {0};
    e0.valid_until = now_seconds() + 3600;
    e1.payload = {1};
    e1.valid_until = now_seconds() + 3600;
    e2.payload = {2};
    e2.valid_until = now_seconds() + 3600;

    cache.put("k0", e0);
    cache.put("k1", e1);
    (void)cache.get("k0"); // k0 становится most-recently-used
    cache.put("k2", e2);   // должно вытеснить k1 (least-recently-used), не k0

    TEST_CHECK(cache.get("k0").has_value());
    TEST_CHECK(!cache.get("k1").has_value());
    TEST_CHECK(cache.get("k2").has_value());
    TEST_CHECK_EQ(cache.size(), uint64_t{2});
}

void test_memory_lru_respects_ttl() {
    MemoryLruCache cache(MemoryLruCache::Limits{});
    CacheEntry expired;
    expired.payload = {1, 2};
    expired.valid_until = now_seconds() - 1; // уже просрочено
    cache.put("expired-key", expired);

    TEST_CHECK(!cache.get("expired-key").has_value());
}

void test_stats_report_both_tiers() {
    auto dir = make_temp_dir("stats");
    FileCacheStore disk(dir, FileCacheStore::Limits{});
    TwoTierCacheStore two_tier(disk, MemoryLruCache::Limits{});

    CacheEntry entry;
    entry.payload = {1, 2, 3, 4, 5};
    entry.valid_until = now_seconds() + 3600;
    two_tier.put(EntryKind::IntermediateCert, "stats-key", entry);

    auto stats = two_tier.stats();
    TEST_CHECK_EQ(stats.entries, uint64_t{1});          // диск (источник истины)
    TEST_CHECK_EQ(stats.memory_entries, uint64_t{1});   // memory-слой тоже прогрет
    TEST_CHECK(stats.memory_size_bytes >= 5);

    fs::remove_all(dir);
}

} // namespace

int main() {
    RUN_TEST(test_memory_hit_avoids_disk_read);
    RUN_TEST(test_disk_hit_promotes_to_memory);
    RUN_TEST(test_different_kinds_do_not_collide_in_memory_layer);
    RUN_TEST(test_memory_lru_respects_entry_limit);
    RUN_TEST(test_memory_lru_respects_ttl);
    RUN_TEST(test_stats_report_both_tiers);
    TEST_MAIN_EXIT();
}
