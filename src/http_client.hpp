// http_client.hpp
//
// РЕШЕНИЕ ПО ОТКРЫТОМУ ВОПРОСУ №3 ТЗ (HTTP-клиент):
// выбран собственный минимальный HTTP/1.1-клиент поверх BSD-сокетов, а не
// libcurl.
//
// Обоснование: как отмечено в самом ТЗ, URL в AIA/OCSP/CDP-расширениях по
// конвенции (RFC 5280 §4.2.2.1, RFC 6960) почти всегда используют http://,
// не https:// — сами сертификаты являются механизмом обеспечения
// целостности данных, получаемых по этим URL (OCSP-ответ подписан
// respondent'ом, CRL подписан CA, AIA-сертификат проверяется как часть
// цепочки), так что TLS-транспорт для их скачивания не добавляет
// защиты, которой не было бы уже на уровне X.509/OCSP/CRL-подписей.
// GET (для CRL/AIA) и POST (для OCSP) без сложной аутентификации — это
// весь необходимый набор функциональности.
//
// ПОДДЕРЖКА https:// (ROADMAP.md, раздел 1, пункт 7):
// нестандартный, но не запрещённый RFC случай — некоторые CA/responder'ы
// всё же публикуют AIA/OCSP/CDP по https://. Поддержка добавлена, но
// СОЗНАТЕЛЬНО выключена по умолчанию (флаг --allow-https демона,
// SimpleHttpFetcher::allow_https): TLS-стек внутри демона — тот же класс
// поверхности атаки, от которого мы изолируемся, обрабатывая недоверенные
// внешние ответы, и по обоснованию выше почти всегда не нужен. Если
// администратор явно включил поддержку, демон делает НАСТОЯЩУЮ проверку
// сертификата сервера (системный доверенный набор корневых сертификатов
// по умолчанию, либо явно заданный CA bundle через --https-ca-bundle) и
// проверку имени хоста (SNI + X509_VERIFY_PARAM_set1_host) — никогда не
// отключает верификацию тихой деградацией, даже ради "лишь бы
// заработало": ответ без валидного TLS-сертификата сервера трактуется
// как NetworkError, как и любая другая сетевая ошибка.
//
// ЯВНОЕ ОГРАНИЧЕНИЕ: без явного --allow-https демон по-прежнему
// возвращает NetworkError на https:// URL, а не пытается сделать
// TLS-запрос. Это соответствует принципу "не усложнять до появления
// реальной потребности" (открытый вопрос №6) и явно документированное
// ограничение, а не забытый край.
//
// HTTP KEEP-ALIVE / ПУЛ СОЕДИНЕНИЙ (ROADMAP.md, раздел 2, пункт 12):
// SimpleHttpFetcher переиспользует TCP/TLS-соединения к одному и тому же
// host:port между вызовами fetch() — типичный сценарий "несколько
// крупных публичных CA обслуживают большую часть трафика" означает
// частые повторные запросы к одному хосту, и новое TCP+TLS-соединение на
// КАЖДЫЙ запрос — заметные и задержка, и нагрузка на CA. Реализовано
// полностью прозрачно для IHttpFetcher/RequestRouter — интерфейс не
// изменился, пул живёт внутри SimpleHttpFetcher.
//   Ключевая техническая сложность: раньше framing ответа определялся
//   чтением ДО ЗАКРЫТИЯ соединения сервером ("мы всегда шлём Connection:
//   close"), что несовместимо с keep-alive по определению. Теперь запрос
//   шлёт "Connection: keep-alive", а конец тела ответа определяется по
//   Content-Length или инкрементальному разбору Transfer-Encoding:
//   chunked (см. recv_and_parse_response()/try_decode_chunked_
//   incremental() ниже) — соединение закрывается сервером лишь тогда,
//   когда framing вообще неоднозначен (ни Content-Length, ни chunked) —
//   это единственный оставшийся случай чтения до EOF.
//   Протухшие соединения: сервер может закрыть простаивающее соединение
//   по своему idle-таймауту в любой момент между тем, как мы вернули его
//   в пул, и следующим использованием — это ожидаемый, а не ошибочный
//   race для connection-пулов. При неудаче на переиспользованном
//   соединении (send не прошёл, либо recv оборвался НЕ по таймауту)
//   fetch() прозрачно и БЕЗ backoff открывает новое соединение и
//   повторяет запрос ровно один раз — это не то же самое, что
//   retry_with_backoff() в request_router.hpp (тот борется с сетевыми
//   ошибками между демоном и сервером; это — с локальной особенностью
//   пула, которая с точки зрения "сеть работает или нет" вообще не
//   является сбоем).
//   Лимиты пула (kMaxIdleConnectionsPerHost/kMaxTotalIdleConnections) —
//   фиксированные константы, не вынесены в CLI-флаги: это внутренний
//   параметр производительности, а не что-то, что реально требует тюнинга
//   в проде (в отличие от security-relevant лимитов вроде
//   max_response_bytes/max_retries).
//
// Интерфейс IHttpFetcher вынесен отдельно (как и ICacheStore), чтобы
// тесты могли подставить фиктивную реализацию без реальной сети, и чтобы
// возможная будущая замена (libcurl) не требовала правок request_router.

#pragma once

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "dns_cache.hpp"
#include "net_policy.hpp"

namespace cert_helper::http {

enum class Method { Get, Post };

// ПУНКТ 1 ИЗ АНАЛИЗА SQUID: уважать HTTP Cache-Control/Expires от самого
// AIA/CRL/OCSP-сервера.
//
// В Squid докачанные intermediate-сертификаты трактуются как обычный
// HTTP-ответ и подчиняются обычным правилам HTTP-кэширования — если
// сервер явно говорит "не кэшируй" или "кэшируй максимум N секунд", это
// уважается, а не полностью игнорируется в пользу одного
// администраторского TTL. RequestRouter комбинирует эти подсказки со
// своими собственными пределами (min(...), см. request_router.hpp) —
// сервер может только УКОРОТИТЬ наш TTL, никогда не удлинить его сверх
// того, что мы и так сочли безопасным (nextUpdate/aia_ttl_seconds).
struct CacheHints {
    bool no_store = false;         // Cache-Control: no-store — не кэшировать вовсе
    bool no_cache = false;         // Cache-Control: no-cache — трактуем консервативно как no-store
                                    // (у демона нет condition GET/revalidation, поэтому
                                    // "нельзя отдавать без ревалидации" эквивалентно
                                    // "нельзя отдавать из кэша вообще" в нашей модели)
    std::optional<int64_t> max_age_seconds; // Cache-Control: max-age=N
    std::optional<int64_t> expires_unix;    // Expires: <HTTP-date>, разобранный в unix time
};

struct HttpResult {
    bool ok = false;
    int status_code = 0;
    std::vector<uint8_t> body;
    bool timed_out = false;
    CacheHints cache_hints;
};

class IHttpFetcher {
public:
    virtual ~IHttpFetcher() = default;
    // ROADMAP.md, раздел 1, пункт 4 (P1): max_response_bytes передаётся
    // явно на каждый вызов (не константа внутри фетчера), т.к. разумный
    // предел размера ответа принципиально разный для разных типов
    // запросов — вызывающий код (RequestRouter) решает по типу запроса
    // (OCSP/AIA/CRL), не сам HTTP-клиент. Обязательный параметр, а не
    // значение по умолчанию — так вызывающая сторона не может случайно
    // забыть подумать о пределе для нового типа запроса.
    virtual HttpResult fetch(Method method, const std::string& url,
                              const std::vector<uint8_t>& post_body,
                              const std::string& post_content_type,
                              uint32_t timeout_ms,
                              size_t max_response_bytes) = 0;
};

// Разобранный http(s):// URL.
struct ParsedUrl {
    std::string host;
    uint16_t port = 80;
    std::string path; // включая query, без хоста
    bool is_https = false;
};

inline std::optional<ParsedUrl> parse_http_url(const std::string& url) {
    const std::string http_prefix = "http://";
    const std::string https_prefix = "https://";

    bool is_https = false;
    std::string rest;
    if (url.compare(0, http_prefix.size(), http_prefix) == 0) {
        rest = url.substr(http_prefix.size());
        is_https = false;
    } else if (url.compare(0, https_prefix.size(), https_prefix) == 0) {
        rest = url.substr(https_prefix.size());
        is_https = true;
    } else {
        return std::nullopt; // ни http://, ни https:// — не поддерживаем
    }
    if (rest.empty()) return std::nullopt;

    size_t slash = rest.find('/');
    std::string authority = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    std::string path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    if (path.empty()) path = "/";

    ParsedUrl out;
    out.is_https = is_https;
    size_t colon = authority.find(':');
    if (colon == std::string::npos) {
        out.host = authority;
        out.port = is_https ? 443 : 80;
    } else {
        out.host = authority.substr(0, colon);
        try {
            out.port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1)));
        } catch (...) {
            return std::nullopt;
        }
    }
    if (out.host.empty()) return std::nullopt;
    out.path = path;
    return out;
}

// Минимальный HTTP/1.1-клиент: одно соединение на запрос (без keep-alive —
// запросы к CA/OCSP-респондерам единичные и не оправдывают сложность пула
// соединений в первой версии), с таймаутом на подключение и на чтение.
class SimpleHttpFetcher : public IHttpFetcher {
public:
    explicit SimpleHttpFetcher(net::NetworkPolicy policy, bool allow_https = false,
                                std::string https_ca_bundle_path = "", uint32_t dns_cache_ttl_seconds = 60)
        : policy(std::move(policy)), allow_https_(allow_https), dns_cache_(dns_cache_ttl_seconds) {
        // ROADMAP.md, раздел 1, пункт 7 (P2): SSL_CTX создаётся один раз в
        // конструкторе (не на каждый запрос) — создание контекста и
        // загрузка доверенного набора корневых сертификатов не бесплатны,
        // а сам SSL_CTX безопасно использовать из нескольких потоков
        // одновременно для создания новых SSL* (мы его больше не
        // модифицируем после этой точки). Создаём его, только если https
        // явно разрешён — иначе не тратим время на инициализацию TLS
        // вообще, раз он и так не будет использован.
        if (allow_https_) {
            https_ctx_.reset(create_https_ctx(https_ca_bundle_path));
            if (!https_ctx_) {
                std::fprintf(stderr,
                              "cert-helper: warning: could not initialize TLS trust store for "
                              "https:// support (%s) — все https:// запросы будут завершаться "
                              "NetworkError\n",
                              https_ca_bundle_path.empty() ? "системный набор корневых "
                                                              "сертификатов не найден"
                                                            : ("bundle: " + https_ca_bundle_path).c_str());
            }
        }
    }

    HttpResult fetch(Method method, const std::string& url,
                      const std::vector<uint8_t>& post_body,
                      const std::string& post_content_type,
                      uint32_t timeout_ms,
                      size_t max_response_bytes) override {
        HttpResult result;

        auto parsed = parse_http_url(url);
        if (!parsed) {
            return result; // ok=false — вызывающий код трактует как NetworkError/InvalidResponse
        }

        if (parsed->is_https && !allow_https_) {
            // ROADMAP.md, раздел 1, пункт 7: https:// выключен по
            // умолчанию — см. комментарий в начале файла. Проверяем ДО
            // connect_with_timeout(), чтобы демон даже не пытался
            // устанавливать соединение (не тратил время/файловые
            // дескрипторы на URL, который всё равно будет отклонён).
            std::fprintf(stderr,
                          "cert-helper: https:// отключён по умолчанию, запрос к %s отклонён "
                          "(см. --allow-https)\n",
                          url.c_str());
            return result;
        }
        if (parsed->is_https && !https_ctx_) {
            // allow_https=true, но SSL_CTX не удалось создать (см.
            // конструктор) — не деградируем до незашифрованного/
            // неверифицированного запроса, просто отказываем.
            return result;
        }

        if (!policy.is_port_allowed(parsed->port)) {
            std::fprintf(stderr, "cert-helper: policy denied port %u for %s\n", parsed->port,
                          url.c_str());
            return result;
        }

        std::string pool_key = make_pool_key(*parsed);
        std::string request = build_request(method, *parsed, post_body, post_content_type);

        // ROADMAP.md, раздел 2, пункт 12 (P1): пробуем переиспользовать
        // простаивающее соединение из пула для этого host:port — см.
        // подробный комментарий в начале файла про то, почему это не
        // требует изменений в IHttpFetcher/RequestRouter (прозрачно
        // внутри SimpleHttpFetcher).
        if (auto pooled = checkout_pooled_connection(pool_key)) {
            Transport transport{pooled->fd, pooled->ssl};
            set_socket_timeout(pooled->fd, timeout_ms); // таймаут мог отличаться от прошлого использования

            bool timed_out = false;
            bool should_close = true;
            std::optional<HttpResult> reused_result;
            if (send_all(transport, request)) {
                reused_result = recv_and_parse_response(transport, max_response_bytes, timed_out, should_close);
            }

            if (reused_result) {
                if (!should_close) {
                    return_pooled_connection(pool_key, std::move(pooled));
                }
                // Если should_close — pooled уничтожится ниже при выходе
                // из блока (RAII в PooledConnection закрывает fd/SSL).
                return *reused_result;
            }
            if (timed_out) {
                // Настоящий таймаут на переиспользованном соединении —
                // это НЕ типичный признак "сервер тихо закрыл простаивавшее
                // соединение" (тот случай ловится ниже через send/recv
                // failure без таймаута), а самостоятельная сетевая
                // проблема — не пытаемся прозрачно переоткрывать, отдаём
                // как есть (RequestRouter трактует как обычный NetworkError,
                // retry_with_backoff уже решает, ретраить ли).
                HttpResult timeout_result;
                timeout_result.timed_out = true;
                return timeout_result;
            }
            // send не удался, либо приём оборвался НЕ по таймауту (EOF
            // сразу/ошибка сокета) — типичный race для connection-пулов:
            // сервер закрыл соединение по idle-таймауту как раз между тем,
            // как мы его извлекли из пула, и тем, как успели им
            // воспользоваться. Это ожидаемо и не квалифицируется как
            // "сетевая ошибка" уровня retry_with_backoff в RequestRouter —
            // здесь же, прозрачно и без backoff, открываем свежее
            // соединение и повторяем ровно один раз (см. ниже). pooled
            // (сломанное соединение) уничтожается сейчас при выходе из
            // этого блока.
        }

        return fetch_over_new_connection(*parsed, pool_key, request, timeout_ms, max_response_bytes);
    }

private:
    HttpResult fetch_over_new_connection(const ParsedUrl& parsed, const std::string& pool_key,
                                          const std::string& request, uint32_t timeout_ms,
                                          size_t max_response_bytes) {
        HttpResult result;

        int fd = connect_with_timeout(parsed.host, parsed.port, timeout_ms, policy);
        if (fd < 0) {
            return result;
        }
        set_socket_timeout(fd, timeout_ms);

        // Оборачиваем сокет в TLS, если это https:// — Transport ниже
        // прозрачно перенаправляет send/recv либо на SSL_write/SSL_read,
        // либо на голые send(2)/recv(2), так что весь остальной код
        // (сборка запроса, чтение ответа, парсинг) не знает и не должен
        // знать, был ли использован TLS.
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl_guard(nullptr, SSL_free);
        Transport transport{fd, nullptr};
        if (parsed.is_https) {
            SSL* ssl = SSL_new(https_ctx_.get());
            if (ssl == nullptr) {
                ::close(fd);
                return result;
            }
            ssl_guard.reset(ssl);
            SSL_set_fd(ssl, fd);
            // SNI — многие TLS-серверы отдают неверный/дефолтный
            // сертификат без этого расширения. Для IP-литерала в SNI
            // смысла нет (SNI — это имя хоста), но и вреда тоже: серверы
            // либо игнорируют его для IP, либо (RFC 6066 формально не
            // разрешает IP в SNI) просто не находят соответствия и отдают
            // сертификат по умолчанию — не наш случай (единственный
            // виртуальный хост), поэтому не усложняем отдельной веткой.
            SSL_set_tlsext_host_name(ssl, parsed.host.c_str());

            // Проверка имени/адреса хоста в сертификате сервера (RFC
            // 6125) — без этого SSL_VERIFY_PEER проверяет только цепочку
            // доверия, но не то, что сертификат вообще выписан НА ЭТОТ
            // хост. IP-литерал (типичный случай в тестах и иногда в
            // AIA/OCSP/CDP URL) должен сверяться с iPAddress SAN через
            // set1_ip_asc — set1_host сверяет только dNSName/CN и не
            // видит iPAddress-записи вообще, так что для IP-литерала он
            // молча не даёт никакой защиты (не ошибка, а просто "0
            // совпадений", что OpenSSL трактует как непройденную
            // проверку — то есть строже, чем надо, а не слабее; но раз мы
            // всё равно умеем отличить этот случай, делаем это правильно).
            X509_VERIFY_PARAM* vpm = SSL_get0_param(ssl);
            if (X509_VERIFY_PARAM_set1_ip_asc(vpm, parsed.host.c_str()) != 1) {
                X509_VERIFY_PARAM_set1_host(vpm, parsed.host.c_str(), parsed.host.size());
            }
            SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);

            if (SSL_connect(ssl) != 1) {
                // Хендшейк или проверка сертификата не прошли — трактуем
                // как обычную сетевую ошибку (NetworkError выше по
                // стеку), не как что-то, требующее отдельной обработки:
                // с точки зрения вызывающего кода "сервер недоступен" и
                // "сервер представил недоверенный сертификат" одинаково
                // означают "AIA/OCSP/CRL сейчас недокачать".
                ::close(fd);
                return result;
            }
            transport.ssl = ssl;
        }

        bool send_ok = send_all(transport, request);
        if (!send_ok) {
            if (transport.ssl) SSL_shutdown(transport.ssl);
            ::close(fd);
            return result;
        }

        bool timed_out = false;
        bool should_close = true;
        auto parsed_result = recv_and_parse_response(transport, max_response_bytes, timed_out, should_close);

        if (!parsed_result) {
            if (transport.ssl) SSL_shutdown(transport.ssl);
            ::close(fd);
            result.timed_out = timed_out;
            return result;
        }

        if (should_close) {
            if (transport.ssl) SSL_shutdown(transport.ssl);
            ::close(fd);
        } else {
            auto conn = std::make_unique<PooledConnection>();
            conn->fd = fd;
            conn->ssl = ssl_guard.release(); // nullptr для http:// — release() на nullptr безопасен
            return_pooled_connection(pool_key, std::move(conn));
        }
        return *parsed_result;
    }


    // Тонкая абстракция поверх "голого" fd и (опционально) TLS-сессии на
    // нём — позволяет send_all()/recv_all() ниже оставаться одним и тем
    // же кодом независимо от того, http:// это соединение или https://.
    // ssl == nullptr означает "обычный TCP", как и раньше.
    struct Transport {
        int fd;
        SSL* ssl;
    };

    static ssize_t transport_send(Transport& t, const void* data, size_t len) {
        if (t.ssl != nullptr) return SSL_write(t.ssl, data, static_cast<int>(len));
        return ::send(t.fd, data, len, MSG_NOSIGNAL);
    }

    // Возвращает >0 — прочитано N байт; 0 — чистое закрытие соединения
    // (EOF); <0 — ошибка/таймаут (out_timed_out выставляется отдельно).
    static ssize_t transport_recv(Transport& t, void* buf, size_t len, bool& out_timed_out) {
        if (t.ssl != nullptr) {
            int r = SSL_read(t.ssl, buf, static_cast<int>(len));
            if (r > 0) return r;
            int err = SSL_get_error(t.ssl, r);
            if (err == SSL_ERROR_ZERO_RETURN) return 0; // TLS close_notify — чистое закрытие
            if (err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                out_timed_out = true;
                return -1;
            }
            return -1; // любая другая ошибка TLS-уровня
        }
        ssize_t r = ::recv(t.fd, buf, len, 0);
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            out_timed_out = true;
        }
        return r;
    }

    // ROADMAP.md, раздел 1, пункт 7 (P2): создаёт TLS-контекст для
    // https://. verify_mode всегда SSL_VERIFY_PEER — сюда НЕЛЬЗЯ
    // добавлять режим без проверки сертификата, каким бы соблазнительным
    // это ни казалось для "просто заставить заработать": единственная
    // причина вообще поддерживать https — не потерять целостность
    // данных, а неверифицированный TLS её не даёт вообще, только
    // видимость защиты. Если ca_bundle_path пуст — используется системный
    // доверенный набор (SSL_CTX_set_default_verify_paths); если задан —
    // используется явно указанный файл/директория (например, для тестов
    // или для окружений с приватным corporate CA), СТРОГО ВМЕСТО
    // системного набора, а не в дополнение к нему (иначе один
    // единственный скомпрометированный публичный CA в системном наборе
    // свёл бы на нет весь смысл указания приватного CA явно).
    static SSL_CTX* create_https_ctx(const std::string& ca_bundle_path) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == nullptr) return nullptr;

        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

        bool trust_store_ok;
        if (ca_bundle_path.empty()) {
            trust_store_ok = (SSL_CTX_set_default_verify_paths(ctx) == 1);
        } else {
            trust_store_ok = (SSL_CTX_load_verify_locations(ctx, ca_bundle_path.c_str(), nullptr) == 1);
        }
        if (!trust_store_ok) {
            SSL_CTX_free(ctx);
            return nullptr;
        }
        return ctx;
    }

    // ROADMAP.md, раздел 2, пункт 13 (P2): резолвинг теперь идёт через
    // dns_cache_ вместо прямого getaddrinfo() на каждый вызов — см.
    // dns_cache.hpp. Больше не static (нужен доступ к dns_cache_ как
    // члену экземпляра), policy по-прежнему передаётся параметром для
    // единообразия с остальными приватными хелперами.
    // КРИТИЧНО ДЛЯ БЕЗОПАСНОСТИ: policy.is_address_allowed() вызывается
    // здесь для КАЖДОГО адреса при КАЖДОМ вызове, независимо от того,
    // пришёл ли адрес из кэша или свежего резолва — кэширование DNS не
    // должно давать способ обойти policy (см. подробное обоснование в
    // dns_cache.hpp).
    int connect_with_timeout(const std::string& host, uint16_t port, uint32_t timeout_ms,
                              const net::NetworkPolicy& policy) {
        auto addresses = dns_cache_.resolve(host);
        if (addresses.empty()) {
            return -1;
        }

        int fd = -1;
        bool saw_policy_denial = false;
        for (const auto& addr : addresses) {
            struct sockaddr_storage ss;
            socklen_t ss_len = 0;
            net::make_sockaddr(addr, port, ss, ss_len);

            // Проверяем политику ПОСЛЕ резолва DNS-имени в конкретный IP —
            // фильтруем именно то, к чему реально собираемся подключиться,
            // так что политику нельзя обойти DNS rebinding (имя хоста,
            // которое выглядит безобидно, но резолвится в приватный IP).
            if (!policy.is_address_allowed(reinterpret_cast<struct sockaddr*>(&ss))) {
                saw_policy_denial = true;
                continue;
            }

            fd = ::socket(addr.family, SOCK_STREAM, 0);
            if (fd < 0) continue;

            set_socket_timeout(fd, timeout_ms);
            if (::connect(fd, reinterpret_cast<struct sockaddr*>(&ss), ss_len) == 0) {
                break;
            }
            ::close(fd);
            fd = -1;
        }

        if (fd < 0 && saw_policy_denial) {
            std::fprintf(stderr,
                          "cert-helper: policy denied all resolved addresses for host %s "
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

    static std::string build_request(Method method, const ParsedUrl& url,
                                      const std::vector<uint8_t>& post_body,
                                      const std::string& post_content_type) {
        std::string req;
        req += (method == Method::Get ? "GET " : "POST ");
        req += url.path;
        req += " HTTP/1.1\r\n";
        req += "Host: " + url.host + "\r\n";
        req += "User-Agent: cert-helper/1.0\r\n";
        req += "Connection: keep-alive\r\n"; // ROADMAP.md, раздел 2, пункт 12
        if (method == Method::Post) {
            req += "Content-Type: " + post_content_type + "\r\n";
            req += "Content-Length: " + std::to_string(post_body.size()) + "\r\n";
        }
        req += "Accept: */*\r\n\r\n";
        if (method == Method::Post) {
            req.append(reinterpret_cast<const char*>(post_body.data()), post_body.size());
        }
        return req;
    }

    static bool send_all(Transport& transport, const std::string& data) {
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t w = transport_send(transport, data.data() + sent, data.size() - sent);
            if (w < 0) return false;
            sent += static_cast<size_t>(w);
        }
        return true;
    }

    // Транспортно-независимая инкрементальная проверка "дочитан ли уже
    // chunked body целиком" (ROADMAP.md, раздел 2, пункт 12 — нужна для
    // keep-alive: framing должен определяться БЕЗ чтения до EOF, иначе
    // соединение нельзя переиспользовать). Идёт по chunk'ам строго по их
    // заявленным размерам, никогда не ищет байтовые паттерны внутри
    // непрозрачных данных чанка — иначе бинарные данные CRL/OCSP-ответа,
    // случайно содержащие подстроку вроде "0\r\n\r\n", могли бы дать
    // ложное срабатывание "конец найден" (реальный риск корректности при
    // наивном substring-поиске терминатора в уже накопленном буфере).
    struct ChunkedParseResult {
        bool complete = false;
        bool malformed = false;
        std::vector<uint8_t> decoded;
    };

    static ChunkedParseResult try_decode_chunked_incremental(const std::string& body) {
        ChunkedParseResult result;
        size_t pos = 0;
        while (true) {
            size_t line_end = body.find("\r\n", pos);
            if (line_end == std::string::npos) return result; // строка размера ещё не дочитана целиком

            std::string size_line = body.substr(pos, line_end - pos);
            size_t semi = size_line.find(';'); // chunk-extensions отбрасываем
            if (semi != std::string::npos) size_line = size_line.substr(0, semi);

            size_t chunk_size;
            try {
                chunk_size = std::stoul(size_line, nullptr, 16);
            } catch (...) {
                result.malformed = true;
                return result;
            }

            size_t data_start = line_end + 2;
            if (chunk_size == 0) {
                // Терминирующий chunk: сразу за ним либо CRLF (без
                // trailer-заголовков), либо trailer-заголовки + CRLF.
                if (data_start + 2 > body.size()) return result;
                if (body.compare(data_start, 2, "\r\n") == 0) {
                    result.complete = true;
                    return result;
                }
                size_t trailers_end = body.find("\r\n\r\n", data_start);
                if (trailers_end == std::string::npos) return result; // trailers ещё не дочитаны целиком
                result.complete = true;
                return result;
            }

            if (data_start + chunk_size + 2 > body.size()) return result; // данные chunk'а ещё не все пришли
            result.decoded.insert(result.decoded.end(), body.begin() + static_cast<long>(data_start),
                                   body.begin() + static_cast<long>(data_start + chunk_size));
            if (body.compare(data_start + chunk_size, 2, "\r\n") != 0) {
                result.malformed = true;
                return result;
            }
            pos = data_start + chunk_size + 2;
        }
    }

    static bool header_value_contains_ci(const std::string& header_block, const std::string& name,
                                          const std::string& needle_lower) {
        auto value = find_header(header_block, name);
        if (!value) return false;
        std::string lower = *value;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                        [](unsigned char c) { return std::tolower(c); });
        return lower.find(needle_lower) != std::string::npos;
    }

    // Читает и разбирает ОДИН полный HTTP-ответ с транспорта, определяя
    // конец тела по framing-заголовкам (Content-Length/Transfer-Encoding:
    // chunked), а НЕ по закрытию соединения — это ключевое отличие от
    // старой (до ROADMAP.md, раздел 2, пункта 12) реализации: без этого
    // соединение нельзя было бы переиспользовать (keep-alive), т.к.
    // "читать до EOF" по определению требует, чтобы сервер закрыл
    // соединение. Возвращает nullopt при любой ошибке чтения/парсинга
    // (timed_out различает таймаут от прочих ошибок). should_close
    // выставляется в true (консервативный дефолт), если соединение
    // ПОСЛЕ этого ответа переиспользовать нельзя — либо framing
    // неоднозначен (нет ни Content-Length, ни chunked — тогда пришлось
    // читать до EOF, соединение сервер и так уже закрыл), либо сервер
    // явно попросил "Connection: close", либо это HTTP/1.0 без
    // "Connection: keep-alive" (для HTTP/1.0 keep-alive не дефолтен).
    static std::optional<HttpResult> recv_and_parse_response(Transport& transport,
                                                               size_t max_response_bytes, bool& timed_out,
                                                               bool& should_close) {
        should_close = true;

        std::string buffer;
        size_t header_end = std::string::npos;
        while (header_end == std::string::npos) {
            char chunk[8192];
            ssize_t r = transport_recv(transport, chunk, sizeof(chunk), timed_out);
            if (r <= 0) return std::nullopt; // EOF/ошибка раньше, чем дочитали заголовки целиком
            buffer.append(chunk, static_cast<size_t>(r));
            if (buffer.size() > max_response_bytes) return std::nullopt;
            header_end = buffer.find("\r\n\r\n");
        }
        std::string header_block = buffer.substr(0, header_end);
        std::string body_so_far = buffer.substr(header_end + 4);

        size_t first_line_end = header_block.find("\r\n");
        std::string status_line =
            (first_line_end == std::string::npos) ? header_block : header_block.substr(0, first_line_end);
        size_t sp1 = status_line.find(' ');
        if (sp1 == std::string::npos) return std::nullopt;
        size_t sp2 = status_line.find(' ', sp1 + 1);
        std::string code_str = (sp2 == std::string::npos) ? status_line.substr(sp1 + 1)
                                                            : status_line.substr(sp1 + 1, sp2 - sp1 - 1);
        int code = 0;
        try {
            code = std::stoi(code_str);
        } catch (...) {
            return std::nullopt;
        }

        bool http_1_0 = status_line.compare(0, 8, "HTTP/1.0") == 0;
        bool connection_close = header_value_contains_ci(header_block, "Connection", "close");
        bool connection_keep_alive = header_value_contains_ci(header_block, "Connection", "keep-alive");
        bool may_reuse = !connection_close && !(http_1_0 && !connection_keep_alive);
        bool chunked = header_value_contains_ci(header_block, "Transfer-Encoding", "chunked");
        auto content_length_header = find_header(header_block, "Content-Length");

        HttpResult result;
        result.ok = true;
        result.status_code = code;
        result.cache_hints = parse_cache_hints(header_block);

        if (content_length_header) {
            size_t want;
            try {
                want = static_cast<size_t>(std::stoull(*content_length_header));
            } catch (...) {
                return std::nullopt;
            }
            while (body_so_far.size() < want) {
                char chunk[8192];
                ssize_t r = transport_recv(transport, chunk, sizeof(chunk), timed_out);
                if (r <= 0) return std::nullopt;
                body_so_far.append(chunk, static_cast<size_t>(r));
                if (header_block.size() + body_so_far.size() > max_response_bytes) return std::nullopt;
            }
            // Лишние байты сверх заявленного Content-Length — аномалия
            // (или сервер что-то допипелайнил, чего мы не поддерживаем):
            // используем только заявленную часть и не переиспользуем
            // соединение (should_close остаётся true).
            result.body.assign(body_so_far.begin(), body_so_far.begin() + static_cast<long>(want));
            if (body_so_far.size() == want && may_reuse) should_close = false;
            return result;
        }

        if (chunked) {
            while (true) {
                auto attempt = try_decode_chunked_incremental(body_so_far);
                if (attempt.malformed) return std::nullopt;
                if (attempt.complete) {
                    result.body = std::move(attempt.decoded);
                    if (may_reuse) should_close = false;
                    return result;
                }
                char chunk[8192];
                ssize_t r = transport_recv(transport, chunk, sizeof(chunk), timed_out);
                if (r <= 0) return std::nullopt;
                body_so_far.append(chunk, static_cast<size_t>(r));
                if (header_block.size() + body_so_far.size() > max_response_bytes) return std::nullopt;
            }
        }

        // Ни Content-Length, ни chunked — framing неоднозначен для
        // HTTP/1.1 keep-alive; единственный надёжный способ понять конец
        // тела в этом случае — читать до закрытия соединения сервером
        // (ровно то поведение, что было ДО пункта 12 всегда). should_close
        // остаётся true — этот ответ в любом случае means сервер сам
        // закрыл соединение, реального выбора переиспользовать или нет
        // здесь и не стоит.
        while (true) {
            char chunk[8192];
            ssize_t r = transport_recv(transport, chunk, sizeof(chunk), timed_out);
            if (r == 0) break; // EOF — тело получено целиком
            if (r < 0) return std::nullopt;
            body_so_far.append(chunk, static_cast<size_t>(r));
            if (header_block.size() + body_so_far.size() > max_response_bytes) return std::nullopt;
        }
        result.body.assign(body_so_far.begin(), body_so_far.end());
        return result;
    }

    // Регистронезависимый поиск значения заголовка "Name: value" внутри
    // блока заголовков (строки разделены \r\n). Возвращает значение без
    // окружающих пробелов, либо nullopt, если заголовок не встретился.
    static std::optional<std::string> find_header(const std::string& header_block,
                                                     const std::string& name) {
        size_t pos = 0;
        while (pos < header_block.size()) {
            size_t line_end = header_block.find("\r\n", pos);
            if (line_end == std::string::npos) line_end = header_block.size();
            std::string line = header_block.substr(pos, line_end - pos);

            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = line.substr(0, colon);
                if (key.size() == name.size() &&
                    std::equal(key.begin(), key.end(), name.begin(), [](char a, char b) {
                        return std::tolower(static_cast<unsigned char>(a)) ==
                               std::tolower(static_cast<unsigned char>(b));
                    })) {
                    std::string value = line.substr(colon + 1);
                    size_t start = value.find_first_not_of(" \t");
                    size_t end = value.find_last_not_of(" \t");
                    if (start == std::string::npos) return std::string();
                    return value.substr(start, end - start + 1);
                }
            }
            pos = line_end + 2;
        }
        return std::nullopt;
    }

    // Парсит Cache-Control (no-store/no-cache/max-age=N) и Expires
    // (IMF-fixdate, стандартный формат HTTP-date по RFC 7231 §7.1.1.1 —
    // единственный формат, который реально массово используется CA/OCSP
    // серверами; два устаревших формата из того же RFC умышленно не
    // поддерживаются ради простоты — при неудаче парсинга Expires просто
    // игнорируется, не являясь фатальной ошибкой).
    static CacheHints parse_cache_hints(const std::string& header_block) {
        CacheHints hints;

        if (auto cache_control = find_header(header_block, "Cache-Control")) {
            std::string value = *cache_control;
            std::string lower = value;
            for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            if (lower.find("no-store") != std::string::npos) hints.no_store = true;
            if (lower.find("no-cache") != std::string::npos) hints.no_cache = true;

            size_t max_age_pos = lower.find("max-age");
            if (max_age_pos != std::string::npos) {
                size_t eq = lower.find('=', max_age_pos);
                if (eq != std::string::npos) {
                    size_t num_start = eq + 1;
                    size_t num_end = num_start;
                    while (num_end < lower.size() &&
                           (std::isdigit(static_cast<unsigned char>(lower[num_end])) ||
                            lower[num_end] == '-')) {
                        ++num_end;
                    }
                    try {
                        int64_t max_age = std::stoll(lower.substr(num_start, num_end - num_start));
                        if (max_age >= 0) hints.max_age_seconds = max_age;
                        else hints.no_store = true; // отрицательный max-age трактуем как "не кэшировать"
                    } catch (...) {
                        // не разобрали число — просто не выставляем max_age_seconds
                    }
                }
            }
        }

        if (auto expires = find_header(header_block, "Expires")) {
            struct tm tm_val{};
            // IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
            if (strptime(expires->c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm_val) != nullptr) {
                time_t t = timegm(&tm_val);
                if (t != static_cast<time_t>(-1)) hints.expires_unix = static_cast<int64_t>(t);
            }
        }

        return hints;
    }

    static std::vector<uint8_t> decode_chunked(const std::string& body) {
        return try_decode_chunked_incremental(body).decoded;
    }

    // --- ROADMAP.md, раздел 2, пункт 12 (P1): пул простаивающих
    // keep-alive-соединений. Владеет fd и (если https) SSL* через RAII —
    // деструктор закрывает оба, так что "уронить" PooledConnection
    // (например, при отказе вернуть его в пул из-за превышения лимита)
    // безопасно закрывает соединение автоматически. ---
    struct PooledConnection {
        int fd = -1;
        SSL* ssl = nullptr;

        ~PooledConnection() {
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            if (fd >= 0) ::close(fd);
        }
    };

    // Небольшие фиксированные лимиты, не вынесенные в конфигурацию —
    // сознательное решение: это внутренний параметр производительности,
    // а не что-то, что реально нужно тюнить в проде (в отличие от
    // security-relevant лимитов вроде max_response_bytes/max_retries,
    // которые вынесены в CLI-флаги). При необходимости несложно сделать
    // конфигурируемым позже — YAGNI на данный момент.
    static constexpr size_t kMaxIdleConnectionsPerHost = 4;
    static constexpr size_t kMaxTotalIdleConnections = 64;

    static std::string make_pool_key(const ParsedUrl& parsed) {
        return (parsed.is_https ? std::string("https://") : std::string("http://")) + parsed.host + ":" +
               std::to_string(parsed.port);
    }

    std::unique_ptr<PooledConnection> checkout_pooled_connection(const std::string& key) {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        auto it = idle_pool_.find(key);
        if (it == idle_pool_.end() || it->second.empty()) return nullptr;
        auto conn = std::move(it->second.back());
        it->second.pop_back();
        return conn;
    }

    void return_pooled_connection(const std::string& key, std::unique_ptr<PooledConnection> conn) {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        auto& vec = idle_pool_[key];
        if (vec.size() >= kMaxIdleConnectionsPerHost) return; // conn уничтожится при выходе — закроет соединение

        size_t total = 0;
        for (const auto& kv : idle_pool_) total += kv.second.size();
        if (total >= kMaxTotalIdleConnections) return; // аналогично — просто закрываем лишнее

        vec.push_back(std::move(conn));
    }

    net::NetworkPolicy policy;
    bool allow_https_ = false;
    // ROADMAP.md, раздел 1, пункт 7: nullptr, пока allow_https_ == false
    // (не тратим время на инициализацию TLS, который всё равно не будет
    // использован) — см. конструктор.
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> https_ctx_{nullptr, SSL_CTX_free};

    // ROADMAP.md, раздел 2, пункт 12: пул простаивающих соединений,
    // ключ — make_pool_key() (host:port, отдельно для http/https).
    // pool_mutex_ защищает только саму map операций (checkout/return),
    // не время использования соединения — тот же принцип, что и у
    // остальных map-based структур в этом проекте (singleflight/circuit
    // breaker в request_router.hpp).
    std::mutex pool_mutex_;
    std::unordered_map<std::string, std::vector<std::unique_ptr<PooledConnection>>> idle_pool_;

    // ROADMAP.md, раздел 2, пункт 13: короткий локальный DNS-кэш — см.
    // dns_cache.hpp. Отдельный экземпляр на каждый SimpleHttpFetcher
    // (обычно один на процесс демона) — не разделяется с
    // SimpleLdapFetcher (у него свой), т.к. в реальном использовании
    // HTTP- и LDAP-хосты, как правило, разные, и делить кэш между ними
    // не даёт заметной выгоды при дополнительной сложности.
    net::DnsCache dns_cache_;
};

} // namespace cert_helper::http
