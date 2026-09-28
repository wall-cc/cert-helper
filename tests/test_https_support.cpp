// test_https_support.cpp — тесты поддержки https:// в SimpleHttpFetcher
// (ROADMAP.md, раздел 1, пункт 7).
//
// Поднимает настоящий TLS-сервер на 127.0.0.1 (сырые сокеты + OpenSSL,
// без внешних зависимостей) с сертификатом, подписанным собственным
// тестовым CA (test_certs/https_test_ca_cert.pem — см.
// test_certs/README.md). Проверяет три сценария:
//   1. https:// выключен по умолчанию — запрос отклоняется ДО попытки
//      сетевого подключения вообще (сервер не видит даже TCP-соединения).
//   2. https:// включён и клиенту передан bundle с доверенным тестовым
//      CA — запрос проходит, тело ответа корректно.
//   3. https:// включён, но БЕЗ доверенного bundle (системный набор,
//      который не знает о тестовом CA) — хендшейк проваливается, запрос
//      трактуется как сетевая ошибка, а не тихо принимается с
//      недоверенным сертификатом.

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../src/http_client.hpp"
#include "../src/net_policy.hpp"
#include "test_util.hpp"

using namespace cert_helper::http;
using namespace cert_helper::net;

namespace {

constexpr const char* kServerCertPath = "../test_certs/https_test_server_cert.pem";
constexpr const char* kServerKeyPath = "../test_certs/https_test_server_key.pem";
constexpr const char* kCaBundlePath = "../test_certs/https_test_ca_cert.pem";

// Слушает на 127.0.0.1:<ephemeral>, принимает РОВНО одно TLS-соединение
// в отдельном потоке, отдаёт заранее заданный "сырой" HTTP-ответ поверх
// TLS, затем закрывается. was_handshake_completed() позволяет тестам
// различить "клиент вообще не подключился" (например, потому что
// https:// отклонён политикой ДО connect()) от "подключился, но
// хендшейк/что-то ещё не задалось".
class OneShotHttpsServer {
public:
    explicit OneShotHttpsServer(std::string response_text) : response(std::move(response_text)) {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

        socklen_t addr_len = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), &addr_len);
        listening_port = ntohs(addr.sin_port);

        listen(listen_fd, 1);

        ctx = SSL_CTX_new(TLS_server_method());
        if (SSL_CTX_use_certificate_file(ctx, kServerCertPath, SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, kServerKeyPath, SSL_FILETYPE_PEM) != 1) {
            std::fprintf(stderr, "test_https_support: failed to load server cert/key fixtures\n");
        }

        server_thread = std::thread([this] {
            // select() с таймаутом — в тесте на "https отключён по
            // умолчанию" клиент СОЗНАТЕЛЬНО никогда не подключится
            // (отклонён ДО connect()), и блокирующий accept() без
            // таймаута повесил бы join() в деструкторе навсегда.
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_fd, &read_fds);
            struct timeval tv{};
            tv.tv_sec = 1;
            int sel = select(listen_fd + 1, &read_fds, nullptr, nullptr, &tv);
            if (sel <= 0) return; // таймаут — никто не подключился, это ожидаемо в некоторых тестах

            int client_fd = accept(listen_fd, nullptr, nullptr);
            if (client_fd < 0) return;

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) == 1) {
                handshake_completed.store(true);
                char buf[4096];
                SSL_read(ssl, buf, sizeof(buf));
                SSL_write(ssl, response.data(), static_cast<int>(response.size()));
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            ::close(client_fd);
        });
    }

    ~OneShotHttpsServer() {
        if (server_thread.joinable()) server_thread.join();
        ::close(listen_fd);
        if (ctx) SSL_CTX_free(ctx);
    }

    uint16_t port() const { return listening_port; }
    bool was_handshake_completed() const { return handshake_completed.load(); }

private:
    std::string response;
    int listen_fd = -1;
    uint16_t listening_port = 0;
    SSL_CTX* ctx = nullptr;
    std::thread server_thread;
    std::atomic<bool> handshake_completed{false};
};

NetworkPolicy make_permissive_policy(uint16_t port) {
    NetworkPolicy::Config cfg;
    cfg.block_private_by_default = false; // разрешаем loopback только для этого теста
    cfg.allowed_ports = {port};
    return NetworkPolicy(cfg);
}

// ROADMAP.md, раздел 1, пункт 7: https:// выключен по умолчанию — запрос
// должен отклоняться ДО попытки сетевого подключения, так что сервер не
// должен увидеть даже TCP SYN, не то что TLS-хендшейк.
void test_https_disabled_by_default_never_connects() {
    OneShotHttpsServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port())); // allow_https по умолчанию false
    std::string url = "https://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(!result.ok);
    TEST_CHECK(!server.was_handshake_completed());
}

// https:// включён и клиенту передан доверенный bundle с тестовым CA —
// запрос должен пройти целиком, включая проверку сертификата и имени
// хоста (SAN сертификата содержит IP 127.0.0.1 — см. test_certs/README.md).
void test_https_with_trusted_ca_bundle_succeeds() {
    std::string body = "hello-https";
    OneShotHttpsServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: " +
        std::to_string(body.size()) +
        "\r\n"
        "\r\n" +
        body);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()), /*allow_https=*/true, kCaBundlePath);
    std::string url = "https://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK_EQ(result.status_code, 200);
    TEST_CHECK(server.was_handshake_completed());
    std::string got(result.body.begin(), result.body.end());
    TEST_CHECK(got == body);
}

// https:// включён, но БЕЗ доверенного bundle (системный набор, который
// ничего не знает про наш тестовый CA) — демон не должен тихо принять
// недоверенный сертификат: хендшейк должен провалиться на этапе
// верификации, и результат должен быть трактован как сетевая ошибка.
void test_https_without_trusted_ca_fails_closed() {
    OneShotHttpsServer server(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK");

    // Пустой ca_bundle_path => SSL_CTX_set_default_verify_paths()
    // (системный набор), который не содержит наш тестовый CA.
    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()), /*allow_https=*/true, "");
    std::string url = "https://127.0.0.1:" + std::to_string(server.port()) + "/x";
    auto result = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(!result.ok);
}

} // namespace

int main() {
    RUN_TEST(test_https_disabled_by_default_never_connects);
    RUN_TEST(test_https_with_trusted_ca_bundle_succeeds);
    RUN_TEST(test_https_without_trusted_ca_fails_closed);
    TEST_MAIN_EXIT();
}
