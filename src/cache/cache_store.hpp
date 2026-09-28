// cache_store.hpp
//
// РЕШЕНИЕ ПО ОТКРЫТОМУ ВОПРОСУ №2 ТЗ (бэкенд кэша):
// выбран файловый бэкенд (директория с файлами) вместо SQLite.
//
// Обоснование: доступ к кэшу в этой версии демона идёт из одного процесса,
// сериализованный через мьютекс внутри процесса (см. модель конкурентности
// ниже — пул потоков внутри ОДНОГО процесса демона, не несколько процессов,
// пишущих в один кэш). Единственный источник конкурентного доступа —
// потоки самого демона, а не внешние процессы, поэтому транзакционность
// SQLite не даёт здесь принципиального выигрыша, а лишняя зависимость
// (libsqlite3) не оправдана. Атомарность на диске достигается паттерном
// "написать во временный файл + rename()" (rename атомарен на одной ФС),
// внутрипроцессная согласованность — мьютексом. Если в будущем демон
// станет многопроцессным (несколько независимых инстансов на один кэш) —
// это явный сигнал мигрировать на SQLite; интерфейс ICacheStore ниже
// спроектирован так, чтобы такая замена не потребовала правок вызывающего
// кода (request_router).
//
// Формат записи на диске: JSON-подобный компактный текстовый заголовок
// не используется намеренно (лишний парсинг) — вместо этого простой
// бинарный формат файла записи:
//   [8 байт: fetched_at, unix seconds, LE]
//   [8 байт: valid_until, unix seconds, LE]
//   [payload_der bytes: остаток файла]
// Имя файла = hex(SHA-256(cache_key)) — где cache_key = "<тип запроса>|<URL>"
// (тип запроса включён в ключ, чтобы OCSP/CRL/AIA-запросы на один и тот же
// URL, если такое вдруг случится, не путались друг с другом).

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/sha.h>

namespace cert_helper::cache {

namespace fs = std::filesystem;

enum class EntryKind : uint8_t {
    Ocsp = 0,
    Crl = 1,
    IntermediateCert = 2,
};

struct CacheEntry {
    std::vector<uint8_t> payload;
    int64_t fetched_at = 0;
    int64_t valid_until = 0;
};

struct CacheStats {
    uint64_t entries = 0;
    uint64_t size_bytes = 0;
    // Заполняются только когда перед этим бэкендом стоит слой
    // in-memory кэша (см. two_tier_cache.hpp, пункт 2 из анализа Squid:
    // отдельный быстрый memory-слой поверх персистентного диска, по
    // аналогии с dynamic_cert_mem_cache_size). FileCacheStore сам по себе
    // (без обёртки) оставляет их нулями — у него нет памяти "поверх себя".
    uint64_t memory_entries = 0;
    uint64_t memory_size_bytes = 0;
};

// Абстракция кэша — намеренно вынесена за интерфейс (см. открытый вопрос №6
// ТЗ: не строить плагинную архитектуру заранее, но не завязывать остальной
// код демона на конкретную реализацию), чтобы будущая замена на SQLite или
// иной бэкенд не потребовала правок request_router.
class ICacheStore {
public:
    virtual ~ICacheStore() = default;
    virtual std::optional<CacheEntry> get(EntryKind kind, const std::string& key) = 0;
    virtual void put(EntryKind kind, const std::string& key, const CacheEntry& entry) = 0;
    virtual CacheStats stats() = 0;
};

// Файловый кэш с TTL и LRU-вытеснением по суммарному размеру/числу записей.
// Потокобезопасен (внутренний мьютекс) — рассчитан на использование из
// пула потоков демона.
class FileCacheStore : public ICacheStore {
public:
    struct Limits {
        uint64_t max_entries = 100000;
        uint64_t max_size_bytes = 512ull * 1024 * 1024; // 512 МиБ по умолчанию
    };

    FileCacheStore(fs::path root_dir, Limits limits)
        : root(std::move(root_dir)), limits(limits) {
        fs::create_directories(root);
        load_index();
    }

    std::optional<CacheEntry> get(EntryKind kind, const std::string& key) override {
        std::lock_guard<std::mutex> lock(mutex);
        std::string filename = make_filename(kind, key);
        auto it = index.find(filename);
        if (it == index.end()) return std::nullopt;

        int64_t now = now_seconds();
        if (it->second.valid_until != 0 && now >= it->second.valid_until) {
            // Просрочено — удаляем лениво (при следующем обращении), не
            // держим место под мёртвую запись.
            remove_file(filename);
            index.erase(it);
            return std::nullopt;
        }

        auto entry = read_entry_file(filename);
        if (!entry) {
            // Индекс рассинхронизировался с диском (например, файл удалили
            // вручную) — самовосстанавливаемся.
            index.erase(it);
            return std::nullopt;
        }
        touch_lru(filename);
        return entry;
    }

    void put(EntryKind kind, const std::string& key, const CacheEntry& entry) override {
        std::lock_guard<std::mutex> lock(mutex);
        std::string filename = make_filename(kind, key);
        write_entry_file(filename, entry);

        IndexRecord rec;
        rec.size_bytes = entry.payload.size();
        rec.valid_until = entry.valid_until;
        rec.lru_seq = next_lru_seq++;
        index[filename] = rec;

        evict_if_needed();
    }

    CacheStats stats() override {
        std::lock_guard<std::mutex> lock(mutex);
        CacheStats s;
        s.entries = index.size();
        for (const auto& [name, rec] : index) {
            s.size_bytes += rec.size_bytes;
        }
        return s;
    }

private:
    struct IndexRecord {
        uint64_t size_bytes = 0;
        int64_t valid_until = 0;
        uint64_t lru_seq = 0; // больше = использовано позже
    };

    static int64_t now_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    static std::string sha256_hex(const std::string& s) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);
        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(SHA256_DIGEST_LENGTH * 2);
        for (unsigned char b : digest) {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 0xF]);
        }
        return out;
    }

    std::string make_filename(EntryKind kind, const std::string& key) {
        std::string composite = std::to_string(static_cast<int>(kind)) + "|" + key;
        return sha256_hex(composite) + ".bin";
    }

    fs::path path_for(const std::string& filename) const { return root / filename; }

    void write_entry_file(const std::string& filename, const CacheEntry& entry) {
        fs::path final_path = path_for(filename);
        fs::path tmp_path = root / (filename + ".tmp");

        {
            std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
            if (!out) return; // директория недоступна для записи — молча деградируем до "без кэша"
            write_le64(out, static_cast<uint64_t>(entry.fetched_at));
            write_le64(out, static_cast<uint64_t>(entry.valid_until));
            if (!entry.payload.empty()) {
                out.write(reinterpret_cast<const char*>(entry.payload.data()),
                           static_cast<std::streamsize>(entry.payload.size()));
            }
        }
        // rename() атомарен на одной файловой системе — так мы никогда не
        // оставляем частично записанный файл под финальным именем, даже
        // если демон упадёт посреди записи.
        std::error_code ec;
        fs::rename(tmp_path, final_path, ec);
    }

    std::optional<CacheEntry> read_entry_file(const std::string& filename) {
        std::ifstream in(path_for(filename), std::ios::binary);
        if (!in) return std::nullopt;
        CacheEntry entry;
        uint64_t fetched_at = 0, valid_until = 0;
        if (!read_le64(in, fetched_at)) return std::nullopt;
        if (!read_le64(in, valid_until)) return std::nullopt;
        entry.fetched_at = static_cast<int64_t>(fetched_at);
        entry.valid_until = static_cast<int64_t>(valid_until);
        entry.payload.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        return entry;
    }

    static void write_le64(std::ofstream& out, uint64_t v) {
        char buf[8];
        for (int i = 0; i < 8; ++i) buf[i] = static_cast<char>((v >> (8 * i)) & 0xFF);
        out.write(buf, 8);
    }

    static bool read_le64(std::ifstream& in, uint64_t& v) {
        char buf[8];
        in.read(buf, 8);
        if (in.gcount() != 8) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(static_cast<unsigned char>(buf[i])) << (8 * i);
        return true;
    }

    void remove_file(const std::string& filename) {
        std::error_code ec;
        fs::remove(path_for(filename), ec);
    }

    void touch_lru(const std::string& filename) {
        auto it = index.find(filename);
        if (it != index.end()) it->second.lru_seq = next_lru_seq++;
    }

    // Восстанавливает индекс по содержимому директории при старте демона —
    // так кэш переживает рестарт (требование раздела 5 ТЗ "персистентность
    // кэша"). valid_until/size читаются из самих файлов; порядок LRU при
    // рестарте не сохраняется (не критично — после рестарта он просто
    // выстроится заново по фактическому использованию).
    void load_index() {
        std::error_code ec;
        for (const auto& de : fs::directory_iterator(root, ec)) {
            if (!de.is_regular_file()) continue;
            std::string name = de.path().filename().string();
            if (name.size() < 5 || name.substr(name.size() - 4) != ".bin") continue;
            auto entry = read_entry_file(name);
            if (!entry) continue;
            IndexRecord rec;
            rec.size_bytes = entry->payload.size();
            rec.valid_until = entry->valid_until;
            rec.lru_seq = next_lru_seq++;
            index[name] = rec;
        }
    }

    void evict_if_needed() {
        auto total_size = [this] {
            uint64_t sum = 0;
            for (auto& [name, rec] : index) sum += rec.size_bytes;
            return sum;
        };

        // Сначала выкидываем явно просроченные записи — дёшево и часто
        // достаточно, чтобы вообще не трогать LRU-порядок.
        int64_t now = now_seconds();
        for (auto it = index.begin(); it != index.end();) {
            if (it->second.valid_until != 0 && now >= it->second.valid_until) {
                remove_file(it->first);
                it = index.erase(it);
            } else {
                ++it;
            }
        }

        if (index.size() <= limits.max_entries && total_size() <= limits.max_size_bytes) {
            return;
        }

        // LRU-вытеснение: сортируем по lru_seq по возрастанию (самое
        // старое использование — первое) и выкидываем, пока не впишемся
        // в лимиты. CRL могут быть тяжёлыми (до нескольких МБ) — поэтому
        // ограничение и по числу записей, и по суммарному размеру.
        std::vector<std::pair<std::string, IndexRecord>> entries(index.begin(), index.end());
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
            return a.second.lru_seq < b.second.lru_seq;
        });

        uint64_t size = total_size();
        size_t i = 0;
        while ((index.size() > limits.max_entries || size > limits.max_size_bytes) &&
               i < entries.size()) {
            const auto& [name, rec] = entries[i++];
            remove_file(name);
            size -= rec.size_bytes;
            index.erase(name);
        }
    }

    fs::path root;
    Limits limits;
    std::mutex mutex;
    std::unordered_map<std::string, IndexRecord> index;
    uint64_t next_lru_seq = 1;
};

} // namespace cert_helper::cache
