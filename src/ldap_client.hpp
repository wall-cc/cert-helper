// ldap_client.hpp
//
// ROADMAP.md, раздел 1, пункт 9 (P3, "делать только при реальной
// потребности" — реализовано по явному запросу, без дожидания реального
// кейса): поддержка `ldap://` URL в CRL distribution points.
//
// Некоторые корпоративные и государственные PKI (типичный пример —
// Active Directory Certificate Services) публикуют CRL через LDAP, а не
// HTTP: DN конкретного объекта-контейнера CRL плюс имя атрибута
// (`certificateRevocationList;binary`), а не URL для GET.
//
// Реализован минимальный LDAPv3-клиент (RFC 4511) поверх сырых сокетов —
// в системе нет `libldap`, а тянуть новую системную зависимость ради
// редкого случая (сам пункт ROADMAP называет его "делать только при
// реальной потребности") — отдельное решение, которое здесь сознательно
// не принято: вместо этого написан свой минимальный BER-кодек и
// протокольный клиент, тем же интерфейсным подходом, что и
// `IHttpFetcher`/`SimpleHttpFetcher` (см. http_client.hpp).
//
// ЯВНЫЕ ОГРАНИЧЕНИЯ (сознательные, не забытые края):
//   - Поддерживается только anonymous simple bind (пустые name/password).
//     CRL — публичная информация, LDAP-серверы, публикующие CDP, как
//     правило разрешают анонимное чтение контейнера CRL. SASL и
//     аутентифицированный simple bind не реализованы.
//   - Поддерживается только `ldap://` (без TLS). `ldaps://` и STARTTLS
//     не реализованы — по той же логике, что и обычный `https://`
//     (ROADMAP.md п.7): TLS-стек внутри демона — сознательно
//     редкая необходимость, добавляется отдельно и только когда
//     понадобится именно LDAP-over-TLS.
//   - LDAP URL с ПУСТЫМ host (`ldap:///...`) не поддерживается: RFC 4516
//     формально это разрешает (клиент должен сам знать, к какому серверу
//     обращаться — например, через DNS-based service discovery домена
//     Active Directory), но у cert-helper нет и не будет domain-awareness
//     для такого discovery. Это НАСТОЯЩЕЕ ограничение, а не техническая
//     деталь: значительная часть реальных AD-публикуемых CDP LDAP URL
//     используют именно пустой host, рассчитывая на клиента, знающего
//     свой домен. Если это понадобится — придётся либо принимать
//     сконфигурированный administrator'ом дефолтный LDAP-сервер, либо
//     интегрироваться с системным resolver'ом Kerberos/AD.
//   - Разбор LDAP Filter (RFC 4515) поддерживает только `(attr=*)`
//     (presence) и `(attr=value)` (equality), включая их через `&`/`|`;
//     substring-фильтры с wildcard ВНУТРИ значения (`(cn=foo*bar)`),
//     `>=`/`<=`/`~=` и extensible match — не поддерживаются. Отсутствие
//     фильтра в URL (обычный случай для CDP: только DN + имя атрибута)
//     трактуется как `(objectClass=*)`, ровно как того требует RFC 4516.
//   - BER-декодер ожидает definite-length кодирование (indefinite-length
//     формально допустим классическим BER, но не встречается в
//     реальных LDAP-серверах и не поддерживается).
//   - Как и `https://` (ROADMAP.md п.7), выключено по умолчанию — флаг
//     `--allow-ldap` демона: разбор BER от недоверенного сервера — новая,
//     неаудированная поверхность атаки, и без реального кейса включать
//     её по умолчанию неоправданно.

#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns_cache.hpp"
#include "net_policy.hpp"

namespace cert_helper::ldap {

// --- Минимальный BER-кодек (только то подмножество X.690, которое нужно
// для LDAPv3: definite-length TLV, universal/application/context тэги
// младше 31 — многобайтные номера тэгов LDAP не использует). ---
namespace ber {

inline std::vector<uint8_t> encode_length(size_t len) {
    std::vector<uint8_t> out;
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
        return out;
    }
    std::vector<uint8_t> bytes;
    size_t tmp = len;
    while (tmp > 0) {
        bytes.insert(bytes.begin(), static_cast<uint8_t>(tmp & 0xFF));
        tmp >>= 8;
    }
    out.push_back(static_cast<uint8_t>(0x80 | bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
    return out;
}

inline std::vector<uint8_t> encode_tlv(uint8_t tag, const std::vector<uint8_t>& content) {
    std::vector<uint8_t> out;
    out.push_back(tag);
    auto len = encode_length(content.size());
    out.insert(out.end(), len.begin(), len.end());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

inline std::vector<uint8_t> encode_tlv(uint8_t tag, const std::string& content) {
    return encode_tlv(tag, std::vector<uint8_t>(content.begin(), content.end()));
}

constexpr uint8_t kTagBoolean = 0x01;
constexpr uint8_t kTagInteger = 0x02;
constexpr uint8_t kTagOctetString = 0x04;
constexpr uint8_t kTagEnumerated = 0x0A;
constexpr uint8_t kTagSequence = 0x30;
constexpr uint8_t kTagSet = 0x31;

inline std::vector<uint8_t> encode_integer(int64_t value) {
    std::vector<uint8_t> bytes;
    uint64_t u = static_cast<uint64_t>(value);
    do {
        bytes.insert(bytes.begin(), static_cast<uint8_t>(u & 0xFF));
        u >>= 8;
    } while (u != 0);
    if (value >= 0 && (bytes[0] & 0x80) != 0) {
        bytes.insert(bytes.begin(), 0x00);
    }
    return encode_tlv(kTagInteger, bytes);
}

inline std::vector<uint8_t> encode_enumerated(int value) {
    auto tlv = encode_integer(value);
    tlv[0] = kTagEnumerated;
    return tlv;
}

inline std::vector<uint8_t> encode_octet_string(const std::string& s) { return encode_tlv(kTagOctetString, s); }

inline std::vector<uint8_t> encode_boolean(bool b) {
    return encode_tlv(kTagBoolean, std::vector<uint8_t>{static_cast<uint8_t>(b ? 0xFF : 0x00)});
}

inline std::vector<uint8_t> encode_sequence(const std::vector<uint8_t>& content) {
    return encode_tlv(kTagSequence, content);
}

inline std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

struct Tlv {
    uint8_t tag = 0;
    std::vector<uint8_t> content;
};

inline std::optional<Tlv> try_read_tlv(const std::vector<uint8_t>& data, size_t pos, size_t& out_consumed,
                                        bool& out_malformed) {
    out_malformed = false;
    if (pos >= data.size()) return std::nullopt;

    uint8_t tag = data[pos];
    size_t p = pos + 1;
    if (p >= data.size()) return std::nullopt;

    uint8_t first_len_byte = data[p];
    size_t len = 0;
    size_t len_field_size = 1;
    if ((first_len_byte & 0x80) == 0) {
        len = first_len_byte;
    } else {
        size_t num_len_bytes = first_len_byte & 0x7F;
        if (num_len_bytes == 0) {
            out_malformed = true;
            return std::nullopt;
        }
        if (num_len_bytes > sizeof(size_t)) {
            out_malformed = true;
            return std::nullopt;
        }
        if (p + 1 + num_len_bytes > data.size()) return std::nullopt;
        len = 0;
        for (size_t i = 0; i < num_len_bytes; ++i) {
            len = (len << 8) | data[p + 1 + i];
        }
        len_field_size = 1 + num_len_bytes;
    }

    size_t header_size = 1 + len_field_size;
    if (pos + header_size + len < pos + header_size) {
        out_malformed = true;
        return std::nullopt;
    }
    if (data.size() < pos + header_size + len) return std::nullopt;

    Tlv tlv;
    tlv.tag = tag;
    tlv.content.assign(data.begin() + pos + header_size, data.begin() + pos + header_size + len);
    out_consumed = header_size + len;
    return tlv;
}

inline std::vector<Tlv> parse_children(const std::vector<uint8_t>& content) {
    std::vector<Tlv> out;
    size_t pos = 0;
    while (pos < content.size()) {
        size_t consumed = 0;
        bool malformed = false;
        auto tlv = try_read_tlv(content, pos, consumed, malformed);
        if (!tlv || malformed) break;
        out.push_back(*tlv);
        pos += consumed;
    }
    return out;
}

inline int64_t decode_integer(const std::vector<uint8_t>& content) {
    int64_t value = 0;
    for (uint8_t b : content) value = (value << 8) | b;
    return value;
}

inline std::string decode_octet_string(const std::vector<uint8_t>& content) {
    return std::string(content.begin(), content.end());
}

} // namespace ber

struct ParsedLdapUrl {
    std::string host;
    uint16_t port = 389;
    std::string dn;
    std::vector<std::string> attributes;
    std::string filter = "(objectClass=*)";
};

namespace detail {

inline std::string percent_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            std::string hex = s.substr(i + 1, 2);
            out.push_back(static_cast<char>(std::stoi(hex, nullptr, 16)));
            i += 2;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

inline std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    if (s.empty()) return out;
    size_t start = 0;
    while (true) {
        size_t pos = s.find(delim, start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

} // namespace detail

inline std::optional<ParsedLdapUrl> parse_ldap_url(const std::string& url) {
    const std::string prefix = "ldap://";
    if (url.compare(0, prefix.size(), prefix) != 0) return std::nullopt;
    std::string rest = url.substr(prefix.size());

    size_t slash = rest.find('/');
    std::string authority = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    std::string tail = (slash == std::string::npos) ? "" : rest.substr(slash + 1);

    ParsedLdapUrl out;
    if (authority.empty()) {
        return std::nullopt; // пустой host — см. ограничения в начале файла
    }
    size_t colon = authority.find(':');
    if (colon == std::string::npos) {
        out.host = authority;
        out.port = 389;
    } else {
        out.host = authority.substr(0, colon);
        try {
            out.port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1)));
        } catch (...) {
            return std::nullopt;
        }
    }
    if (out.host.empty()) return std::nullopt;

    auto parts = detail::split(tail, '?');
    if (!parts.empty()) out.dn = detail::percent_decode(parts[0]);
    if (parts.size() >= 2 && !parts[1].empty()) {
        for (auto& a : detail::split(parts[1], ',')) {
            out.attributes.push_back(detail::percent_decode(a));
        }
    }
    // parts[2] (scope) сознательно игнорируется: мы всегда делаем
    // baseObject-поиск — единственный осмысленный scope для "докачать
    // конкретный CRL-объект по известному DN".
    if (parts.size() >= 4 && !parts[3].empty()) {
        out.filter = detail::percent_decode(parts[3]);
    }
    return out;
}

namespace filter {

inline std::optional<std::vector<uint8_t>> encode(const std::string& s, size_t& pos);

inline std::optional<std::vector<uint8_t>> encode_list(const std::string& s, size_t& pos) {
    std::vector<uint8_t> out;
    bool any = false;
    while (pos < s.size() && s[pos] == '(') {
        auto child = encode(s, pos);
        if (!child) return std::nullopt;
        out.insert(out.end(), child->begin(), child->end());
        any = true;
    }
    if (!any) return std::nullopt;
    return out;
}

inline std::optional<std::vector<uint8_t>> encode(const std::string& s, size_t& pos) {
    if (pos >= s.size() || s[pos] != '(') return std::nullopt;
    ++pos;
    if (pos >= s.size()) return std::nullopt;

    char c = s[pos];
    if (c == '&' || c == '|') {
        ++pos;
        auto list = encode_list(s, pos);
        if (!list) return std::nullopt;
        if (pos >= s.size() || s[pos] != ')') return std::nullopt;
        ++pos;
        uint8_t tag = 0x80 | 0x20 | (c == '&' ? 0x00 : 0x01);
        return ber::encode_tlv(tag, *list);
    }
    if (c == '!') {
        ++pos;
        auto child = encode(s, pos);
        if (!child) return std::nullopt;
        if (pos >= s.size() || s[pos] != ')') return std::nullopt;
        ++pos;
        uint8_t tag = 0x80 | 0x20 | 0x02;
        return ber::encode_tlv(tag, *child);
    }

    size_t close = s.find(')', pos);
    if (close == std::string::npos) return std::nullopt;
    std::string clause = s.substr(pos, close - pos);
    pos = close + 1;

    size_t eq = clause.find('=');
    if (eq == std::string::npos) return std::nullopt;
    if (eq > 0 && (clause[eq - 1] == '>' || clause[eq - 1] == '<' || clause[eq - 1] == '~')) {
        return std::nullopt;
    }
    std::string attr = clause.substr(0, eq);
    std::string value = clause.substr(eq + 1);
    if (attr.empty()) return std::nullopt;

    if (value == "*") {
        uint8_t tag = 0x80 | 0x07;
        return ber::encode_tlv(tag, attr);
    }
    if (value.find('*') != std::string::npos) return std::nullopt;

    uint8_t tag = 0x80 | 0x20 | 0x03;
    auto inner = ber::concat({ber::encode_octet_string(attr), ber::encode_octet_string(value)});
    return ber::encode_tlv(tag, inner);
}

inline std::optional<std::vector<uint8_t>> encode_top_level(const std::string& s) {
    size_t pos = 0;
    auto result = encode(s, pos);
    if (!result) return std::nullopt;
    if (pos != s.size()) return std::nullopt;
    return result;
}

} // namespace filter

struct LdapResult {
    bool ok = false;
    std::vector<uint8_t> value;
};

class ILdapFetcher {
public:
    virtual ~ILdapFetcher() = default;
    virtual LdapResult fetch(const std::string& url, const std::string& attribute_name, uint32_t timeout_ms,
                              size_t max_response_bytes) = 0;
};

namespace detail {

inline std::string strip_attr_options_lower(std::string s) {
    size_t semi = s.find(';');
    if (semi != std::string::npos) s = s.substr(0, semi);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

inline bool attrs_match(const std::string& a, const std::string& b) {
    return strip_attr_options_lower(a) == strip_attr_options_lower(b);
}

} // namespace detail

class SimpleLdapFetcher : public ILdapFetcher {
public:
    explicit SimpleLdapFetcher(net::NetworkPolicy policy, uint32_t dns_cache_ttl_seconds = 60)
        : policy_(std::move(policy)), dns_cache_(dns_cache_ttl_seconds) {}

    LdapResult fetch(const std::string& url, const std::string& attribute_name, uint32_t timeout_ms,
                      size_t max_response_bytes) override {
        LdapResult result;

        auto parsed = parse_ldap_url(url);
        if (!parsed) return result;

        auto filter_ber = filter::encode_top_level(parsed->filter);
        if (!filter_ber) {
            std::fprintf(stderr,
                          "cert-helper: не поддерживаемая конструкция LDAP-фильтра в %s "
                          "(см. ограничения в ldap_client.hpp)\n",
                          url.c_str());
            return result;
        }

        if (!policy_.is_port_allowed(parsed->port)) {
            std::fprintf(stderr, "cert-helper: policy denied port %u for %s\n", parsed->port, url.c_str());
            return result;
        }

        int fd = connect_with_timeout(parsed->host, parsed->port, timeout_ms, policy_);
        if (fd < 0) return result;
        set_socket_timeout(fd, timeout_ms);

        bool ok = do_bind(fd, timeout_ms, max_response_bytes) &&
                  do_search(fd, *parsed, *filter_ber, attribute_name, timeout_ms, max_response_bytes, result);

        send_unbind(fd);
        ::close(fd);

        result.ok = ok && !result.value.empty();
        return result;
    }

private:
    net::NetworkPolicy policy_;
    // ROADMAP.md, раздел 2, пункт 13: см. подробное обоснование в
    // dns_cache.hpp и в http_client.hpp (SimpleHttpFetcher::dns_cache_) —
    // отдельный экземпляр, не разделяется с SimpleHttpFetcher.
    net::DnsCache dns_cache_;

    // Больше не static — нужен доступ к dns_cache_ как члену экземпляра.
    // policy.is_address_allowed() по-прежнему вызывается для КАЖДОГО
    // адреса при КАЖДОМ вызове, вне зависимости от того, пришёл ли он из
    // кэша — см. dns_cache.hpp про то, почему это критично для безопасности.
    int connect_with_timeout(const std::string& host, uint16_t port, uint32_t timeout_ms,
                              const net::NetworkPolicy& policy) {
        auto addresses = dns_cache_.resolve(host);
        if (addresses.empty()) return -1;

        int fd = -1;
        bool saw_policy_denial = false;
        for (const auto& addr : addresses) {
            struct sockaddr_storage ss;
            socklen_t ss_len = 0;
            net::make_sockaddr(addr, port, ss, ss_len);
            if (!policy.is_address_allowed(reinterpret_cast<struct sockaddr*>(&ss))) {
                saw_policy_denial = true;
                continue;
            }
            fd = ::socket(addr.family, SOCK_STREAM, 0);
            if (fd < 0) continue;
            set_socket_timeout(fd, timeout_ms);
            if (::connect(fd, reinterpret_cast<struct sockaddr*>(&ss), ss_len) == 0) break;
            ::close(fd);
            fd = -1;
        }
        if (fd < 0 && saw_policy_denial) {
            std::fprintf(stderr,
                          "cert-helper: policy denied all resolved addresses for LDAP host %s "
                          "(possible SSRF attempt via certificate-supplied URL)\n",
                          host.c_str());
        }
        return fd;
    }

    static void set_socket_timeout(int fd, uint32_t timeout_ms) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    static bool send_all(int fd, const std::vector<uint8_t>& data) {
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t w = ::send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
            if (w < 0) return false;
            sent += static_cast<size_t>(w);
        }
        return true;
    }

    static std::optional<std::vector<uint8_t>> recv_one_message(int fd, std::vector<uint8_t>& buffer,
                                                                  size_t& total_received,
                                                                  size_t max_response_bytes) {
        while (true) {
            size_t consumed = 0;
            bool malformed = false;
            auto tlv = ber::try_read_tlv(buffer, 0, consumed, malformed);
            if (malformed) return std::nullopt;
            if (tlv) {
                std::vector<uint8_t> message(buffer.begin(), buffer.begin() + consumed);
                buffer.erase(buffer.begin(), buffer.begin() + consumed);
                return message;
            }

            char chunk[4096];
            ssize_t r = ::recv(fd, chunk, sizeof(chunk), 0);
            if (r <= 0) return std::nullopt;
            total_received += static_cast<size_t>(r);
            if (total_received > max_response_bytes) return std::nullopt;
            buffer.insert(buffer.end(), chunk, chunk + r);
        }
    }

    static bool parse_ldap_message(const std::vector<uint8_t>& raw, int64_t& out_message_id,
                                    uint8_t& out_op_tag, std::vector<uint8_t>& out_op_content) {
        size_t consumed = 0;
        bool malformed = false;
        auto top = ber::try_read_tlv(raw, 0, consumed, malformed);
        if (!top || malformed || top->tag != ber::kTagSequence) return false;
        auto children = ber::parse_children(top->content);
        if (children.size() < 2) return false;
        if (children[0].tag != ber::kTagInteger) return false;
        out_message_id = ber::decode_integer(children[0].content);
        out_op_tag = children[1].tag;
        out_op_content = children[1].content;
        return true;
    }

    static bool parse_ldap_result_code(const std::vector<uint8_t>& op_content, int64_t& out_result_code) {
        auto children = ber::parse_children(op_content);
        if (children.empty() || children[0].tag != ber::kTagEnumerated) return false;
        out_result_code = ber::decode_integer(children[0].content);
        return true;
    }

    bool do_bind(int fd, uint32_t /*timeout_ms*/, size_t max_response_bytes) {
        auto bind_body = ber::concat({
            ber::encode_integer(3),
            ber::encode_octet_string(""),
            ber::encode_tlv(0x80, std::string()),
        });
        constexpr uint8_t kTagBindRequest = 0x60;
        auto protocol_op = ber::encode_tlv(kTagBindRequest, bind_body);
        auto message = ber::encode_sequence(ber::concat({ber::encode_integer(1), protocol_op}));
        if (!send_all(fd, message)) return false;

        std::vector<uint8_t> buffer;
        size_t total_received = 0;
        auto raw = recv_one_message(fd, buffer, total_received, max_response_bytes);
        if (!raw) return false;

        int64_t message_id = 0;
        uint8_t op_tag = 0;
        std::vector<uint8_t> op_content;
        if (!parse_ldap_message(*raw, message_id, op_tag, op_content)) return false;
        constexpr uint8_t kTagBindResponse = 0x61;
        if (op_tag != kTagBindResponse || message_id != 1) return false;

        int64_t result_code = -1;
        if (!parse_ldap_result_code(op_content, result_code)) return false;
        return result_code == 0;
    }

    bool do_search(int fd, const ParsedLdapUrl& parsed, const std::vector<uint8_t>& filter_ber,
                    const std::string& attribute_name, uint32_t timeout_ms, size_t max_response_bytes,
                    LdapResult& out_result) {
        std::vector<uint8_t> attrs_seq_content;
        for (const auto& a : parsed.attributes) {
            auto attr = ber::encode_octet_string(a);
            attrs_seq_content.insert(attrs_seq_content.end(), attr.begin(), attr.end());
        }
        if (parsed.attributes.empty()) {
            auto attr = ber::encode_octet_string(attribute_name);
            attrs_seq_content.insert(attrs_seq_content.end(), attr.begin(), attr.end());
        }

        auto search_body = ber::concat({
            ber::encode_octet_string(parsed.dn),
            ber::encode_enumerated(0),
            ber::encode_enumerated(0),
            ber::encode_integer(0),
            ber::encode_integer(static_cast<int64_t>(timeout_ms / 1000 + 1)),
            ber::encode_boolean(false),
            filter_ber,
            ber::encode_sequence(attrs_seq_content),
        });
        constexpr uint8_t kTagSearchRequest = 0x63;
        auto protocol_op = ber::encode_tlv(kTagSearchRequest, search_body);
        auto message = ber::encode_sequence(ber::concat({ber::encode_integer(2), protocol_op}));
        if (!send_all(fd, message)) return false;

        constexpr uint8_t kTagSearchResultEntry = 0x64;
        constexpr uint8_t kTagSearchResultDone = 0x65;
        constexpr uint8_t kTagSearchResultReference = 0x73;

        std::vector<uint8_t> buffer;
        size_t total_received = 0;
        bool found_value = false;

        while (true) {
            auto raw = recv_one_message(fd, buffer, total_received, max_response_bytes);
            if (!raw) return false;

            int64_t message_id = 0;
            uint8_t op_tag = 0;
            std::vector<uint8_t> op_content;
            if (!parse_ldap_message(*raw, message_id, op_tag, op_content)) return false;
            if (message_id != 2) continue;

            if (op_tag == kTagSearchResultReference) continue;
            if (op_tag == kTagSearchResultEntry) {
                if (!found_value) {
                    auto value = extract_attribute_value(op_content, attribute_name);
                    if (value) {
                        out_result.value = std::move(*value);
                        found_value = true;
                    }
                }
                continue;
            }
            if (op_tag == kTagSearchResultDone) {
                int64_t result_code = -1;
                if (!parse_ldap_result_code(op_content, result_code)) return false;
                return result_code == 0;
            }
            return false;
        }
    }

    static std::optional<std::vector<uint8_t>> extract_attribute_value(const std::vector<uint8_t>& entry_content,
                                                                          const std::string& attribute_name) {
        auto top_children = ber::parse_children(entry_content);
        if (top_children.size() < 2) return std::nullopt;
        auto attributes = ber::parse_children(top_children[1].content);
        for (const auto& attr_tlv : attributes) {
            auto attr_fields = ber::parse_children(attr_tlv.content);
            if (attr_fields.size() < 2) continue;
            std::string type_name = ber::decode_octet_string(attr_fields[0].content);
            if (!detail::attrs_match(type_name, attribute_name)) continue;
            auto values = ber::parse_children(attr_fields[1].content);
            if (values.empty()) continue;
            return values[0].content;
        }
        return std::nullopt;
    }

    void send_unbind(int fd) {
        constexpr uint8_t kTagUnbindRequest = 0x42;
        auto protocol_op = ber::encode_tlv(kTagUnbindRequest, std::vector<uint8_t>{});
        auto message = ber::encode_sequence(ber::concat({ber::encode_integer(3), protocol_op}));
        send_all(fd, message);
    }
};

} // namespace cert_helper::ldap
