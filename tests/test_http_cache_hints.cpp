// test_http_cache_hints.cpp — юнит-тесты разбора Cache-Control/Expires из
// реального HTTP-ответа (пункт 1 из анализа Squid: уважать HTTP-кэш
// подсказки AIA/CRL/OCSP-сервера).
//
// Поднимает собственный минимальный "сервер" на 127.0.0.1 (сырые сокеты,
// без внешних зависимостей вроде python) прямо в тесте: слушает один
// заранее заданный ответ, отдаёт его единственному подключившемуся
// клиенту (SimpleHttpFetcher) и закрывается. NetworkPolicy теста явно
// разрешает loopback и конкретный порт — в проде такой трафик заблокирован
// по умолчанию (см. test_net_policy.cpp), здесь мы намеренно ослабляем
// политику, чтобы протестировать сам HTTP-клиент в изоляции от неё.

#include <chrono>
#include <cstring>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/http_client.hpp"
#include "../src/net_policy.hpp"
#include "test_util.hpp"

using namespace cert_helper::http;
using namespace cert_helper::net;

namespace {

// Слушает один заранее заданный HTTP-ответ на 127.0.0.1:<ephemeral>,
// отдаёт порт вызывающему сразу (до accept()), обслуживает РОВНО одно
// соединение в отдельном потоке, затем закрывается.
class OneShotHttpServer {
public:
    explicit OneShotHttpServer(std::string response_text) : response(std::move(response_text)) {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // пусть ОС выберет свободный порт
        bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

        socklen_t addr_len = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), &addr_len);
        listening_port = ntohs(addr.sin_port);

        listen(listen_fd, 1);

        server_thread = std::thread([this] {
            // select() с таймаутом вместо блокирующего accept() — в
            // тесте на блокировку политикой (test_default_policy_blocks_
            // loopback_even_for_this_fetcher) клиент СОЗНАТЕЛЬНО никогда
            // не подключится (фетчер отклонён политикой до connect()), и
            // блокирующий accept() без таймаута повесил бы join() в
            // деструкторе навсегда.
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_fd, &read_fds);
            struct timeval tv{};
            tv.tv_sec = 1;
            int sel = select(listen_fd + 1, &read_fds, nullptr, nullptr, &tv);
            if (sel <= 0) return; // таймаут — никто не подключился, это ожидаемо в некоторых тестах

            int client_fd = accept(listen_fd, nullptr, nullptr);
            if (client_fd < 0) return;
            // Не парсим запрос — тесту важен только ответ; просто вычитываем
            // что пришло (достаточно для корректного TCP-обмена) и отвечаем.
            char buf[4096];
            recv(client_fd, buf, sizeof(buf), 0);
            send(client_fd, response.data(), response.size(), MSG_NOSIGNAL);
            ::close(client_fd);
        });
    }

    ~OneShotHttpServer() {
        if (server_thread.joinable()) server_thread.join();
        ::close(listen_fd);
    }

    uint16_t port() const { return listening_port; }

private:
    std::string response;
    int listen_fd = -1;
    uint16_t listening_port = 0;
    std::thread server_thread;
};

NetworkPolicy make_permissive_policy(uint16_t port) {
    NetworkPolicy::Config cfg;
    cfg.block_private_by_default = false; // разрешаем loopback только для этого теста
    cfg.allowed_ports = {port};
    return NetworkPolicy(cfg);
}

void test_max_age_is_parsed() {
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/pkix-crl\r\n"
        "Cache-Control: max-age=120\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "HELLO");

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(result.body == std::vector<uint8_t>({'H', 'E', 'L', 'L', 'O'}));
    TEST_CHECK(result.cache_hints.max_age_seconds.has_value());
    TEST_CHECK_EQ(*result.cache_hints.max_age_seconds, int64_t{120});
    TEST_CHECK(!result.cache_hints.no_store);
    TEST_CHECK(!result.cache_hints.no_cache);
}

void test_no_store_is_parsed() {
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(result.cache_hints.no_store);
}

void test_no_cache_is_parsed() {
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Cache-Control: no-cache\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(result.cache_hints.no_cache);
}

void test_expires_header_is_parsed() {
    // Фиксированная дата, известная как контрольный пример IMF-fixdate из
    // RFC 7231 §7.1.1.1 — проверяем, что она разбирается в точно то же
    // unix-время, не завязываясь на "текущее время" запуска теста.
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Expires: Sun, 06 Nov 1994 08:49:37 GMT\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(result.cache_hints.expires_unix.has_value());
    TEST_CHECK_EQ(*result.cache_hints.expires_unix, int64_t{784111777});
}

void test_no_cache_headers_leaves_hints_empty() {
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(!result.cache_hints.no_store);
    TEST_CHECK(!result.cache_hints.no_cache);
    TEST_CHECK(!result.cache_hints.max_age_seconds.has_value());
    TEST_CHECK(!result.cache_hints.expires_unix.has_value());
}

void test_default_policy_blocks_loopback_even_for_this_fetcher() {    // Регрессия на пункт 3: без явного ослабления политики (как во всех
    // остальных тестах этого файла через make_permissive_policy())
    // SimpleHttpFetcher не должен суметь достучаться до loopback вовсе —
    // проверяем именно адресную блокировку (не порт), поэтому явно
    // разрешаем порт сервера, оставляя блокировку приватных диапазонов
    // включённой (значение по умолчанию).
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    NetworkPolicy::Config cfg; // block_private_by_default остаётся true (default)
    cfg.allowed_ports = {server.port()};
    NetworkPolicy policy(cfg);
    SimpleHttpFetcher fetcher(policy);
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 500, 1024 * 1024);

    TEST_CHECK(!result.ok);
}

// ROADMAP.md, раздел 2, пункт 13 (P2): DNS-кэш не должен становиться
// лазейкой в обход NetworkPolicy — адрес обязан проверяться политикой
// ПРИ КАЖДОМ использовании закэшированной записи, а не только при первом
// резолве (см. подробное обоснование в dns_cache.hpp). Проверяем это
// поведенчески: второй fetch() к тому же самому хосту (после того, как
// DNS уже закэширован первым вызовом) должен быть отклонён политикой
// точно так же, как и первый — если бы кэш "запоминал", что хост уже был
// проверен, и пропускал повторную проверку, второй вызов прошёл бы.
void test_dns_cache_does_not_bypass_policy_on_repeated_use() {
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    NetworkPolicy::Config cfg; // block_private_by_default остаётся true (default)
    cfg.allowed_ports = {server.port()};
    NetworkPolicy policy(cfg);
    SimpleHttpFetcher fetcher(policy);
    std::string url = "http://localhost:" + std::to_string(server.port()) + "/x";

    auto result1 = fetcher.fetch(Method::Get, url, {}, "", 500, 1024 * 1024);
    TEST_CHECK(!result1.ok); // первый вызов — DNS ещё не закэширован, но политика уже блокирует

    // "localhost" теперь в DNS-кэше (резолвится в 127.0.0.1) — если бы
    // кэш давал возможность обойти политику, второй вызов прошёл бы.
    auto result2 = fetcher.fetch(Method::Get, url, {}, "", 500, 1024 * 1024);
    TEST_CHECK(!result2.ok);
}

// ROADMAP.md, раздел 1, пункт 4 (P1): лимиты размера ответа по типу
// запроса — здесь тестируем сам механизм enforcement в SimpleHttpFetcher
// (per-request-type пределы, которые вычисляет RequestRouter, покрыты
// tests/test_client_server_roundtrip.cpp::test_response_size_limits_
// differ_per_request_type через StubHttpFetcher). max_response_bytes
// теперь обязательный параметр fetch(), а не общая константа 32 МиБ
// внутри клиента.
void test_response_exceeding_max_bytes_is_rejected() {
    std::string body(2000, 'X');
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2000\r\n"
        "\r\n" +
        body);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, /*max_response_bytes=*/500);

    TEST_CHECK(!result.ok);
}

void test_response_within_max_bytes_is_accepted() {
    std::string body(400, 'Y');
    OneShotHttpServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 400\r\n"
        "\r\n" +
        body);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, /*max_response_bytes=*/500);

    TEST_CHECK(result.ok);
    TEST_CHECK_EQ(result.body.size(), size_t{400});
}

} // namespace

int main() {
    RUN_TEST(test_max_age_is_parsed);
    RUN_TEST(test_no_store_is_parsed);
    RUN_TEST(test_no_cache_is_parsed);
    RUN_TEST(test_expires_header_is_parsed);
    RUN_TEST(test_no_cache_headers_leaves_hints_empty);
    RUN_TEST(test_default_policy_blocks_loopback_even_for_this_fetcher);
    RUN_TEST(test_dns_cache_does_not_bypass_policy_on_repeated_use);
    RUN_TEST(test_response_exceeding_max_bytes_is_rejected);
    RUN_TEST(test_response_within_max_bytes_is_accepted);
    TEST_MAIN_EXIT();
}
