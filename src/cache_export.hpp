// cache_export.hpp
//
// ROADMAP.md, раздел 2, пункт 16 (P3): экспорт/импорт кэша между хостами
// — для миграции/клонирования инсталляции (например, при горизонтальном
// масштабировании NGFW), чтобы не "прогревать" каждый новый узел с нуля.
//
// КЛЮЧЕВОЕ НАБЛЮДЕНИЕ, УПРОСТИВШЕЕ ЭТУ ЗАДАЧУ: файлы `FileCacheStore` на
// диске (см. cache_store.hpp) УЖЕ хостонезависимы сами по себе — имя
// файла это `sha256(kind|cache_key)` (чистая функция от типа запроса и
// URL/CertID, не зависит от хоста, на котором вычислена), а содержимое —
// это просто (fetched_at, valid_until, payload) без каких-либо
// host-specific полей. Формально `cp -r`/`rsync` каталога кэша между
// хостами уже сработал бы сам по себе, без единой строчки нового кода —
// `FileCacheStore::load_index()` при следующем старте демона на
// целевом хосте подхватит любые `*.bin` файлы, откуда бы они ни взялись.
//
// Тем не менее просто скопировать директорию — не то же самое, что
// providing safe, ergonomic export/import: нужно (а) не тащить уже
// просроченные записи (бессмысленный балласт), (б) дать администратору
// единый переносимый файл вместо "не забудь скопировать именно эту
// директорию целиком, ничего лишнего не прихватив", (в) дать понятную
// сводку (сколько экспортировано/импортировано/пропущено). Отсюда —
// собственный простой портируемый формат-контейнер (не архив общего
// назначения вроде tar/zip — не тянем новую зависимость вроде libarchive
// ради одного узкого случая использования) поверх УЖЕ существующего
// on-disk формата отдельной записи.
//
// ФОРМАТ ПОРТИРУЕМОГО ФАЙЛА (всё целочисленное — little-endian):
//   [8 байт: магическая строка "CHCACHE1"]
//   [4 байта: число записей N]
//   N раз:
//     [2 байта: длина имени файла L]
//     [L байт: имя файла — как на диске, "<64 hex>.bin"]
//     [8 байт: fetched_at, unix seconds]
//     [8 байт: valid_until, unix seconds]
//     [4 байта: длина payload]
//     [payload байт]
//
// ВАЖНО: этот инструмент работает НАПРЯМУЮ с файлами каталога кэша, в
// обход интерфейса ICacheStore/FileCacheStore — сознательное решение, а
// не обход абстракции по недосмотру: экспорт/импорт оперирует именами
// файлов (уже являющимися хешами) и сырыми записями, а не
// (kind, cache_key) парами, которые ICacheStore ожидает на вход/выход —
// у нас и не может быть исходных cache_key, только их хеши. Добавление
// такой возможности в сам ICacheStore ради узкого сценария CLI-утилиты
// раздуло бы интерфейс, которым RequestRouter не пользуется.
//
// СНИМОК, А НЕ ТРАНЗАКЦИЯ: если демон продолжает работать во время
// экспорта, возможна гонка с записью новых файлов кэша — экспорт в
// худшем случае не подхватит запись, дописанную ПОСЛЕ начала обхода
// каталога (не крашится и не портит данные: запись отдельного файла в
// FileCacheStore атомарна через "временный файл + rename()"). Для
// строго консистентного снимка следует останавливать демон перед
// экспортом, но это не обязательно для корректности — просто снимок
// может быть на мгновение отстающим от актуального состояния.

#pragma once

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace cert_helper::cache_export {

namespace fs = std::filesystem;

namespace detail {

constexpr char kMagic[8] = {'C', 'H', 'C', 'A', 'C', 'H', 'E', '1'};

inline void write_le(std::ofstream& out, uint64_t v, int bytes) {
    for (int i = 0; i < bytes; ++i) {
        char b = static_cast<char>((v >> (8 * i)) & 0xFF);
        out.write(&b, 1);
    }
}

inline bool read_le(std::ifstream& in, uint64_t& v, int bytes) {
    v = 0;
    for (int i = 0; i < bytes; ++i) {
        char b = 0;
        in.read(&b, 1);
        if (in.gcount() != 1) return false;
        v |= static_cast<uint64_t>(static_cast<unsigned char>(b)) << (8 * i);
    }
    return true;
}

inline int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Тот же layout, что FileCacheStore пишет на диск (см. cache_store.hpp) —
// намеренно продублирован здесь как самостоятельные функции, а не
// переиспользован из FileCacheStore напрямую: это приватные детали
// реализации того класса, а экспорт/импорт по дизайну работает НИЖЕ
// уровня ICacheStore (см. комментарий в начале файла).
struct RawEntry {
    int64_t fetched_at = 0;
    int64_t valid_until = 0;
    std::vector<uint8_t> payload;
};

inline std::optional<RawEntry> read_raw_entry_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    uint64_t fetched_at = 0, valid_until = 0;
    if (!read_le(in, fetched_at, 8)) return std::nullopt;
    if (!read_le(in, valid_until, 8)) return std::nullopt;
    RawEntry entry;
    entry.fetched_at = static_cast<int64_t>(fetched_at);
    entry.valid_until = static_cast<int64_t>(valid_until);
    entry.payload.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return entry;
}

inline bool write_raw_entry_file(const fs::path& final_path, const RawEntry& entry) {
    fs::path tmp_path = final_path;
    tmp_path += ".import_tmp";
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        write_le(out, static_cast<uint64_t>(entry.fetched_at), 8);
        write_le(out, static_cast<uint64_t>(entry.valid_until), 8);
        if (!entry.payload.empty()) {
            out.write(reinterpret_cast<const char*>(entry.payload.data()),
                       static_cast<std::streamsize>(entry.payload.size()));
        }
    }
    // rename() атомарен на одной ФС — та же гарантия, что и у самого
    // FileCacheStore (см. cache_store.hpp), чтобы конкурентно работающий
    // демон никогда не увидел частично записанный файл под финальным
    // именем.
    std::error_code ec;
    fs::rename(tmp_path, final_path, ec);
    return !ec;
}

} // namespace detail

struct ExportStats {
    uint64_t exported = 0;
    uint64_t skipped_expired = 0;
    uint64_t skipped_malformed = 0;
};

// Экспортирует все ещё действительные (valid_until в будущем, либо 0 —
// "без срока") записи из cache_dir в один портируемый файл output_path.
// Возвращает nullopt, если output_path не удалось открыть на запись —
// в остальном (отдельные битые/просроченные файлы кэша) — best-effort,
// не прерывает весь экспорт.
inline std::optional<ExportStats> run_export(const std::string& cache_dir, const std::string& output_path) {
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) return std::nullopt;

    ExportStats stats;
    std::vector<std::pair<std::string, detail::RawEntry>> entries;

    std::error_code ec;
    int64_t now = detail::now_seconds();
    for (const auto& de : fs::directory_iterator(cache_dir, ec)) {
        if (!de.is_regular_file()) continue;
        std::string name = de.path().filename().string();
        if (name.size() < 5 || name.substr(name.size() - 4) != ".bin") continue;

        auto entry = detail::read_raw_entry_file(de.path());
        if (!entry) {
            ++stats.skipped_malformed;
            continue;
        }
        if (entry->valid_until != 0 && now >= entry->valid_until) {
            ++stats.skipped_expired; // не тащим заведомо мёртвый балласт на другой хост
            continue;
        }
        entries.emplace_back(name, std::move(*entry));
    }

    out.write(detail::kMagic, sizeof(detail::kMagic));
    detail::write_le(out, entries.size(), 4);
    for (const auto& [name, entry] : entries) {
        detail::write_le(out, name.size(), 2);
        out.write(name.data(), static_cast<std::streamsize>(name.size()));
        detail::write_le(out, static_cast<uint64_t>(entry.fetched_at), 8);
        detail::write_le(out, static_cast<uint64_t>(entry.valid_until), 8);
        detail::write_le(out, entry.payload.size(), 4);
        if (!entry.payload.empty()) {
            out.write(reinterpret_cast<const char*>(entry.payload.data()),
                       static_cast<std::streamsize>(entry.payload.size()));
        }
        ++stats.exported;
    }
    return stats;
}

struct ImportStats {
    uint64_t imported = 0;
    uint64_t skipped_expired = 0;
    uint64_t skipped_malformed = 0;
};

// Импортирует записи из портируемого файла input_path в cache_dir —
// демон (если запущен на целевом хосте) подхватит их при следующем
// старте через FileCacheStore::load_index(); если демон уже запущен и
// продолжает работать во время импорта, свежедобавленные файлы
// подхватятся при следующем ПРОМАХЕ кэша по этому же ключу (текущий
// FileCacheStore не перечитывает индекс на лету для файлов, добавленных
// в обход его собственного put()) — это ограничение текущей реализации
// FileCacheStore, не самого экспорта/импорта; на практике импорт
// делается перед стартом/рестартом демона на новом хосте, что этого
// ограничения не касается.
inline std::optional<ImportStats> run_import(const std::string& cache_dir, const std::string& input_path) {
    std::ifstream in(input_path, std::ios::binary);
    if (!in) return std::nullopt;

    char magic[8];
    in.read(magic, sizeof(magic));
    if (in.gcount() != sizeof(magic) || std::memcmp(magic, detail::kMagic, sizeof(magic)) != 0) {
        return std::nullopt; // не наш формат — не пытаемся угадать/чинить
    }

    uint64_t count = 0;
    if (!detail::read_le(in, count, 4)) return std::nullopt;

    fs::create_directories(cache_dir);
    ImportStats stats;
    int64_t now = detail::now_seconds();

    for (uint64_t i = 0; i < count; ++i) {
        uint64_t name_len = 0;
        if (!detail::read_le(in, name_len, 2)) { ++stats.skipped_malformed; break; }
        std::string name(name_len, '\0');
        in.read(name.data(), static_cast<std::streamsize>(name_len));
        if (static_cast<uint64_t>(in.gcount()) != name_len) { ++stats.skipped_malformed; break; }

        uint64_t fetched_at = 0, valid_until = 0, payload_len = 0;
        if (!detail::read_le(in, fetched_at, 8) || !detail::read_le(in, valid_until, 8) ||
            !detail::read_le(in, payload_len, 4)) {
            ++stats.skipped_malformed;
            break;
        }
        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0) {
            in.read(reinterpret_cast<char*>(payload.data()), static_cast<std::streamsize>(payload_len));
            if (static_cast<uint64_t>(in.gcount()) != payload_len) { ++stats.skipped_malformed; break; }
        }

        int64_t valid_until_signed = static_cast<int64_t>(valid_until);
        if (valid_until_signed != 0 && now >= valid_until_signed) {
            // Между export'ом (на исходном хосте) и import'ом (здесь)
            // прошло достаточно времени, что запись успела протухнуть —
            // не кладём в кэш заведомо мёртвую запись, даже если она
            // была ещё жива на момент экспорта.
            ++stats.skipped_expired;
            continue;
        }

        detail::RawEntry entry;
        entry.fetched_at = static_cast<int64_t>(fetched_at);
        entry.valid_until = valid_until_signed;
        entry.payload = std::move(payload);

        if (detail::write_raw_entry_file(fs::path(cache_dir) / name, entry)) {
            ++stats.imported;
        } else {
            ++stats.skipped_malformed;
        }
    }
    return stats;
}

} // namespace cert_helper::cache_export
