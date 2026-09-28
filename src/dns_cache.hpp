// dns_cache.hpp
//
// ROADMAP.md, раздел 2, пункт 13 (P2): короткий локальный кэш DNS-
// резолвинга имён из AIA/OCSP/CDP URL — снижает задержку и нагрузку на
// резолвер при частых повторных запросах к одному и тому же хосту.
//
// ВАЖНОЕ ОГРАНИЧЕНИЕ И ЕГО ОБОСНОВАНИЕ: `getaddrinfo()` (используемый
// здесь, как и раньше) не отдаёт TTL самой DNS-записи — эта информация
// доступна только через разбор сырого DNS-ответа (RR TTL field), что
// потребовало бы писать собственный DNS-клиент поверх UDP/TCP с разбором
// wire-формата — сопоставимый по объёму работы с LDAP-клиентом из пункта
// 9, и неоправданный для этого пункта. Вместо этого используется
// ФИКСИРОВАННЫЙ, консервативно короткий, настраиваемый TTL кэша
// (по умолчанию 60 секунд) — именно второй из двух вариантов,
// явно допущенных формулировкой пункта 13 ("нужен либо короткий TTL,
// либо повторная проверка адреса при использовании кэша").
//
// БЕЗОПАСНОСТЬ (тоже прямо оговорена в пункте 13): кэширование IP-адресов
// само по себе не должно позволять обойти NetworkPolicy — если бы адрес
// проверялся ТОЛЬКО в момент первого резолва, а не при каждом
// использовании закэшированной записи, кэш DNS стал бы удобной лазейкой
// (например, для DNS rebinding: имя сначала резолвится в публичный IP,
// проходит проверку и попадает в кэш, но обращение к серверу могло бы
// использовать другой, уже не проверенный IP из того же кэша при
// повторном использовании). DnsCache возвращает СПИСОК IP-адресов и
// оставляет ответственность за policy-проверку КАЖДОГО адреса КАЖДЫЙ РАЗ
// на вызывающем коде (см. http_client.hpp/ldap_client.hpp::
// connect_with_timeout()) — сам класс адреса не фильтрует и не помнит,
// проходили ли они policy-проверку раньше.

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace cert_helper::net {

// IP-адрес без порта — порт добавляется отдельно вызывающим кодом при
// построении sockaddr для конкретной попытки соединения (один и тот же
// резолв хоста может использоваться для разных портов: например, OCSP
// responder на 80 и CDP на 8080 одного и того же хоста).
struct ResolvedAddress {
    int family = AF_INET; // AF_INET или AF_INET6
    std::array<uint8_t, 16> bytes{}; // 4 байта для AF_INET, 16 для AF_INET6
};

// Собирает sockaddr_storage для данного ResolvedAddress + порта — общий
// хелпер, чтобы http_client.hpp/ldap_client.hpp не дублировали разбор
// AF_INET/AF_INET6 каждый у себя.
inline void make_sockaddr(const ResolvedAddress& addr, uint16_t port, struct sockaddr_storage& out,
                           socklen_t& out_len) {
    std::memset(&out, 0, sizeof(out));
    if (addr.family == AF_INET6) {
        auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&out);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        std::memcpy(&sin6->sin6_addr, addr.bytes.data(), 16);
        out_len = sizeof(struct sockaddr_in6);
    } else {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&out);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        std::memcpy(&sin->sin_addr, addr.bytes.data(), 4);
        out_len = sizeof(struct sockaddr_in);
    }
}

class DnsCache {
public:
    // Внедряемая функция резолвинга — по умолчанию настоящий getaddrinfo()
    // (default_resolver ниже), но тесты могут подставить свою для
    // детерминированной проверки самой логики кэша (попадание/промах,
    // истечение TTL) без зависимости от реальной DNS/сети — тот же
    // interface-based подход к тестируемости, что и у IHttpFetcher/
    // ICacheStore/ILdapFetcher в остальном проекте.
    using ResolverFn = std::function<std::vector<ResolvedAddress>(const std::string&)>;

    explicit DnsCache(uint32_t ttl_seconds = 60, ResolverFn resolver = default_resolver)
        : ttl_seconds_(ttl_seconds), resolver_(std::move(resolver)) {}

    // Возвращает список IP-адресов для host: из кэша, если запись ещё не
    // устарела, иначе выполняет резолвинг через resolver_ и (при успехе)
    // кэширует результат на ttl_seconds_. Пустой результат (ошибка DNS) НЕ
    // кэшируется — следующий вызов сразу попробует резолвить заново, а
    // не будет ждать TTL после сбоя (транзиентный сбой резолвера не
    // должен блокировать все последующие попытки на целый TTL).
    std::vector<ResolvedAddress> resolve(const std::string& host) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = cache_.find(host);
            if (it != cache_.end() && std::chrono::steady_clock::now() < it->second.expires_at) {
                return it->second.addresses;
            }
        }

        auto resolved = resolver_(host);
        if (!resolved.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_[host] = CacheEntry{resolved, std::chrono::steady_clock::now() +
                                                     std::chrono::seconds(ttl_seconds_)};
        }
        return resolved;
    }

    static std::vector<ResolvedAddress> default_resolver(const std::string& host) {
        std::vector<ResolvedAddress> out;
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) {
            return out;
        }
        for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
            ResolvedAddress addr;
            if (rp->ai_family == AF_INET) {
                addr.family = AF_INET;
                auto* sin = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
                std::memcpy(addr.bytes.data(), &sin->sin_addr, 4);
            } else if (rp->ai_family == AF_INET6) {
                addr.family = AF_INET6;
                auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
                std::memcpy(addr.bytes.data(), &sin6->sin6_addr, 16);
            } else {
                continue; // ни IPv4, ни IPv6 — пропускаем (не наш случай на практике)
            }
            out.push_back(addr);
        }
        freeaddrinfo(res);
        return out;
    }

private:
    struct CacheEntry {
        std::vector<ResolvedAddress> addresses;
        std::chrono::steady_clock::time_point expires_at;
    };

    uint32_t ttl_seconds_;
    ResolverFn resolver_;
    std::mutex mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
};

} // namespace cert_helper::net
