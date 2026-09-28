// net_policy.hpp
//
// ПУНКТ 3 ИЗ АНАЛИЗА SQUID: явно помечаемый и фильтруемый класс
// "сертификатного" трафика.
//
// В Squid AIA-докачка помечается отдельным transaction_initiator
// "certificate-fetching", и под него можно написать свой ACL
// (`acl intermediate_fetching transaction_initiator certificate-fetching`)
// — то есть админ может явно ограничить, куда именно разрешено ходить
// именно этому типу трафика, а не только обычному пользовательскому.
//
// Это одновременно устраняет SSRF-риск, отмеченный ранее: URL-ы, по
// которым демон ходит в сеть (AIA caIssuers, OCSP responder, CRL
// distribution point), берутся из полей сертификата, присланного
// upstream-сервером — то есть из данных, которые контролирует другая
// сторона TLS-соединения, потенциально ДО завершения полной проверки
// доверия к цепочке. Без ограничений ничто не мешает вредоносному
// серверу указать в AIA URL адрес внутреннего сервиса за NGFW
// (169.254.169.254 — cloud metadata, 127.0.0.1, RFC1918-диапазоны и т.п.)
// — демон послушно сходит по этому адресу с довольно привилегированной
// сетевой позиции.
//
// NetworkPolicy — это тот самый "ACL для certificate-fetching трафика":
//   - allowed_ports: whitelist портов (по умолчанию только 80 — см.
//     http_client.hpp, демон умеет только http://).
//   - deny-список CIDR (по умолчанию — loopback/link-local/private/CGNAT/
//     multicast/reserved и т.п., как и положено для SSRF-защиты).
//   - allow-список CIDR: явные исключения из deny-списка — например,
//     если у организации внутренний CA/OCSP-responder специально живёт
//     в приватном диапазоне, и админ сознательно этого хочет, а не забыл
//     про default-deny.
//
// Проверка происходит ПОСЛЕ разрешения DNS-имени в конкретный IP (см.
// вызов в http_client.hpp): фильтруется именно то, к чему демон реально
// собирается подключиться — так что политика не обходится DNS rebinding
// (URL с "безобидным" именем хоста, который резолвится в приватный IP).

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace cert_helper::net {

// CIDR-диапазон, представленный уже как разобранные байты сети + длина
// префикса — чтобы не парсить строку на каждой проверке адреса.
struct CidrRange {
    int family = AF_INET; // AF_INET или AF_INET6
    std::array<uint8_t, 16> bytes{}; // сетевой адрес, в сетевом порядке байт
    int prefix_len = 32;

    static std::optional<CidrRange> parse(const std::string& cidr) {
        size_t slash = cidr.find('/');
        std::string addr_part = (slash == std::string::npos) ? cidr : cidr.substr(0, slash);

        CidrRange range;
        if (addr_part.find(':') != std::string::npos) {
            range.family = AF_INET6;
            range.prefix_len = 128;
            if (inet_pton(AF_INET6, addr_part.c_str(), range.bytes.data()) != 1) return std::nullopt;
        } else {
            range.family = AF_INET;
            range.prefix_len = 32;
            uint32_t v4 = 0;
            if (inet_pton(AF_INET, addr_part.c_str(), &v4) != 1) return std::nullopt;
            std::memcpy(range.bytes.data(), &v4, 4);
        }

        if (slash != std::string::npos) {
            try {
                range.prefix_len = std::stoi(cidr.substr(slash + 1));
            } catch (...) {
                return std::nullopt;
            }
        }
        int max_prefix = (range.family == AF_INET) ? 32 : 128;
        if (range.prefix_len < 0 || range.prefix_len > max_prefix) return std::nullopt;
        return range;
    }

    bool contains(int family, const uint8_t* addr_bytes) const {
        if (family != this->family) return false;
        int full_bytes = prefix_len / 8;
        int rem_bits = prefix_len % 8;
        if (std::memcmp(addr_bytes, bytes.data(), static_cast<size_t>(full_bytes)) != 0) return false;
        if (rem_bits == 0) return true;
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rem_bits));
        return (addr_bytes[full_bytes] & mask) == (bytes[static_cast<size_t>(full_bytes)] & mask);
    }
};

class NetworkPolicy {
public:
    struct Config {
        // Если false — деny-проверка вообще не выполняется (полностью
        // открытая политика). По умолчанию true — safe-by-default,
        // администратор должен осознанно ослабить, а не наоборот.
        bool block_private_by_default = true;
        std::vector<std::string> extra_deny_cidrs;
        std::vector<std::string> allow_cidrs; // явное исключение из deny (проверяется первым)
        std::vector<uint16_t> allowed_ports{80};
    };

    explicit NetworkPolicy(Config config) {
        allowed_ports = config.allowed_ports;

        if (config.block_private_by_default) {
            for (const auto& cidr : default_deny_cidrs()) {
                if (auto parsed = CidrRange::parse(cidr)) deny_ranges.push_back(*parsed);
            }
        }
        for (const auto& cidr : config.extra_deny_cidrs) {
            if (auto parsed = CidrRange::parse(cidr)) deny_ranges.push_back(*parsed);
        }
        for (const auto& cidr : config.allow_cidrs) {
            if (auto parsed = CidrRange::parse(cidr)) allow_ranges.push_back(*parsed);
        }
    }

    bool is_port_allowed(uint16_t port) const {
        if (allowed_ports.empty()) return true; // пустой список = не ограничиваем порты
        for (uint16_t p : allowed_ports) {
            if (p == port) return true;
        }
        return false;
    }

    // addr — sockaddr_in* или sockaddr_in6*, как их отдаёт getaddrinfo().
    bool is_address_allowed(const struct sockaddr* addr) const {
        int family;
        const uint8_t* bytes;
        uint8_t v4_bytes[4];

        if (addr->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const struct sockaddr_in*>(addr);
            std::memcpy(v4_bytes, &sin->sin_addr, 4);
            family = AF_INET;
            bytes = v4_bytes;
        } else if (addr->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(addr);
            family = AF_INET6;
            bytes = sin6->sin6_addr.s6_addr;
        } else {
            return false; // неизвестное семейство — по умолчанию запрещаем
        }

        // Явный allow — приоритетнее любого deny (осознанное исключение
        // администратора, например для внутреннего CA-сервера).
        for (const auto& range : allow_ranges) {
            if (range.contains(family, bytes)) return true;
        }
        for (const auto& range : deny_ranges) {
            if (range.contains(family, bytes)) return false;
        }
        return true;
    }

private:
    // Диапазоны, которые по умолчанию небезопасно разрешать для
    // "сертификатного" трафика, инициируемого содержимым сертификата
    // третьей стороны: loopback, link-local, RFC1918 private, CGNAT,
    // документационные/тестовые сети, multicast, "этот хост".
    static const std::vector<std::string>& default_deny_cidrs() {
        static const std::vector<std::string> kDefaults = {
            // IPv4
            "0.0.0.0/8",       // "этот хост"
            "10.0.0.0/8",      // RFC1918 private
            "100.64.0.0/10",   // CGNAT (RFC 6598)
            "127.0.0.0/8",     // loopback
            "169.254.0.0/16",  // link-local (в т.ч. cloud metadata endpoint 169.254.169.254)
            "172.16.0.0/12",   // RFC1918 private
            "192.0.0.0/24",    // IETF protocol assignments
            "192.0.2.0/24",    // TEST-NET-1
            "192.168.0.0/16",  // RFC1918 private
            "198.18.0.0/15",   // benchmarking
            "198.51.100.0/24", // TEST-NET-2
            "203.0.113.0/24",  // TEST-NET-3
            "224.0.0.0/4",     // multicast
            "240.0.0.0/4",     // reserved
            // IPv6
            "::1/128",         // loopback
            "fe80::/10",       // link-local
            "fc00::/7",        // unique local (аналог RFC1918 для v6)
            "ff00::/8",        // multicast
            "::/128",          // unspecified
            "64:ff9b::/96",    // NAT64 well-known prefix (может маппиться на приватные v4)
        };
        return kDefaults;
    }

    std::vector<CidrRange> deny_ranges;
    std::vector<CidrRange> allow_ranges;
    std::vector<uint16_t> allowed_ports;
};

} // namespace cert_helper::net
