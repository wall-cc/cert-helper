// two_tier_cache.hpp
//
// ПУНКТ 2 ИЗ АНАЛИЗА SQUID: двухуровневый кэш — быстрый in-memory слой
// поверх персистентного диска.
//
// Squid отдельно настраивает размер memory-кэша сертификатов
// (dynamic_cert_mem_cache_size) и размер disk-хранилища (security_file_certgen
// -M) — у нас же изначально был только файловый кэш (FileCacheStore),
// и каждое обращение, даже к "горячему" ключу (популярный OCSP-responder,
// который спрашивают параллельно много одновременных TLS handshake),
// шло через диск. TwoTierCacheStore добавляет перед диском небольшой
// in-memory LRU-слой: то же самое разделение "быстрая горячая часть в
// памяти + большая персистентная часть на диске", просто в терминах
// нашей архитектуры (ICacheStore-декоратор, а не два отдельных
// конфиг-параметра одного демона, как в Squid).
//
// Семантика:
//   - get(): сначала смотрим в память; при промахе — идём в
//     персистентный бэкенд и, если там нашлось, прогреваем память этим
//     значением (populate-on-read).
//   - put(): пишем В ОБА слоя сразу (write-through) — так что запись,
//     read-after-write в этом же процессе, никогда не промахивается ни на
//     одном из уровней, а персистентный бэкенд остаётся источником
//     истины, переживающим рестарт демона (память — нет, это ожидаемо
//     для in-memory слоя).
//   - TTL/протухание проверяется независимо на каждом уровне — если
//     запись протухла в памяти, но ещё жива на диске (не должно
//     случаться при одинаковом valid_until, но существует как
//     подстраховка от рассинхрона логики), promotion на чтение всё
//     равно работает корректно, т.к. память просто перезатирается свежим
//     диск-хитом.

#pragma once

#include <chrono>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "cache_store.hpp"

namespace cert_helper::cache {

// Простой in-memory LRU с TTL и лимитами по числу записей/суммарному
// размеру — по духу то же самое, что и FileCacheStore::evict_if_needed,
// но без диска, поэтому можно позволить себе прямой intrusive-список
// вместо периодической полной пересортировки.
class MemoryLruCache {
public:
    struct Limits {
        uint64_t max_entries = 20000;
        uint64_t max_size_bytes = 64ull * 1024 * 1024; // 64 МиБ — заметно меньше диска по умолчанию
    };

    explicit MemoryLruCache(Limits limits) : limits(limits) {}

    std::optional<CacheEntry> get(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = index.find(key);
        if (it == index.end()) return std::nullopt;

        if (it->second->entry.valid_until != 0 && now_seconds() >= it->second->entry.valid_until) {
            total_bytes -= it->second->entry.payload.size();
            list.erase(it->second);
            index.erase(it);
            return std::nullopt;
        }

        list.splice(list.begin(), list, it->second); // переносим в начало (most-recently-used)
        return it->second->entry;
    }

    void put(const std::string& key, const CacheEntry& entry) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = index.find(key);
        if (it != index.end()) {
            total_bytes -= it->second->entry.payload.size();
            list.erase(it->second);
            index.erase(it);
        }

        list.push_front(Node{key, entry});
        index[key] = list.begin();
        total_bytes += entry.payload.size();

        evict_if_needed();
    }

    uint64_t size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return index.size();
    }

    uint64_t size_bytes() const {
        std::lock_guard<std::mutex> lock(mutex);
        return total_bytes;
    }

private:
    struct Node {
        std::string key;
        CacheEntry entry;
    };

    static int64_t now_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    void evict_if_needed() {
        while ((index.size() > limits.max_entries || total_bytes > limits.max_size_bytes) &&
               !list.empty()) {
            auto& back = list.back();
            total_bytes -= back.entry.payload.size();
            index.erase(back.key);
            list.pop_back();
        }
    }

    Limits limits;
    mutable std::mutex mutex;
    std::list<Node> list; // front = most recently used, back = least recently used
    std::unordered_map<std::string, std::list<Node>::iterator> index;
    uint64_t total_bytes = 0;
};

// Декоратор ICacheStore: memory-слой перед произвольным персистентным
// бэкендом (обычно — FileCacheStore, но подойдёт любая реализация
// ICacheStore благодаря тому, что оба слоя работают через один и тот же
// интерфейс).
class TwoTierCacheStore : public ICacheStore {
public:
    TwoTierCacheStore(ICacheStore& persistent_backend, MemoryLruCache::Limits memory_limits)
        : backend(persistent_backend), memory(memory_limits) {}

    std::optional<CacheEntry> get(EntryKind kind, const std::string& key) override {
        std::string composite = make_key(kind, key);

        if (auto hit = memory.get(composite)) {
            return hit;
        }

        auto disk_hit = backend.get(kind, key);
        if (disk_hit) {
            memory.put(composite, *disk_hit); // прогреваем память на чтении
        }
        return disk_hit;
    }

    void put(EntryKind kind, const std::string& key, const CacheEntry& entry) override {
        // Персистентный бэкенд — источник истины, пишем в него первым;
        // если он почему-то не смог сохранить (например, файловая
        // система недоступна для записи — FileCacheStore в этом случае
        // молча деградирует, см. её комментарии), память всё равно
        // получит значение и хотя бы в рамках текущего процесса кэш
        // продолжит работать.
        backend.put(kind, key, entry);
        memory.put(make_key(kind, key), entry);
    }

    CacheStats stats() override {
        CacheStats stats = backend.stats(); // entries/size_bytes — из персистентного слоя (источник истины)
        stats.memory_entries = memory.size();
        stats.memory_size_bytes = memory.size_bytes();
        return stats;
    }

private:
    static std::string make_key(EntryKind kind, const std::string& key) {
        return std::to_string(static_cast<int>(kind)) + "|" + key;
    }

    ICacheStore& backend;
    MemoryLruCache memory;
};

} // namespace cert_helper::cache
