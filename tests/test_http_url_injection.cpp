// test_http_url_injection.cpp
//
// ПУНКТ 2.2 ПЛАНА ДОРАБОТКИ (P0): CRLF/control-символы в URL из
// сертификата приводят к request smuggling.
//
// build_request() собирает сырую строку HTTP-запроса конкатенацией
// url.path и url.host БЕЗ экранирования. URL, который разбирает
// parse_http_url(), приходит из AIA/CRL distribution point/OCSP
// responder полей сертификата — от третьей стороны, которой мы не
// доверяем. До фикса URL вида
//   "http://host/ok HTTP/1.1\r\nX-Injected: yes\r\n\r\nGET /smuggled"
// порождал ДВА HTTP-запроса в одном TCP-соединении (воспроизведено
// вручную: сервер реально получил второй, "контрабандный" запрос с
// собственной строкой запроса и заголовками).
//
// Фикс — parse_http_url() отклоняет host/path, содержащие любой байт с
// кодом < 0x20 или 0x7F (DEL). Эти тесты проверяют и сам парсер
// изолированно (не долетает ли мусор до ParsedUrl вообще), и то, что
// SimpleHttpFetcher::fetch() с таким URL не делает НИ ОДНОГО сетевого
// обращения — url.ok=false с FailureReason::INVALID_URL ДО
// connect()/DNS, а не "подключились, но что-то не так".

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

#include "../src/http_client.hpp"
#include "../src/net_policy.hpp"
#include "test_util.hpp"

using namespace cert_helper::http;
using namespace cert_helper::net;

namespace {

// --- Часть 1: parse_http_url() изолированно ---

void test_raw_crlf_in_path_is_rejected() {
    auto r = parse_http_url(
        "http://ca.example/ok HTTP/1.1\r\nX-Injected: yes\r\n\r\nGET "
        "/smuggled");
    TEST_CHECK(!r.has_value());
}

void test_raw_crlf_in_host_is_rejected() {
    auto r = parse_http_url("http://ca.example\r\nX-Injected: yes\r\n\r\n/x");
    TEST_CHECK(!r.has_value());
}

// Вариант БЕЗ двоеточия во внедрённых данных — важен отдельно: строка
// выше с "X-Injected:" до фикса СЛУЧАЙНО тоже давала nullopt (не из-за
// защиты от CRLF, а потому что ':' внутри внедрённого текста ловился
// как разделитель host:port, а std::stoi на "yes..." бросал исключение
// по несвязанной причине). Эта версия без двоеточия показывает, что
// защищает именно has_control_byte(), а не случайное стечение
// обстоятельств: без фикса host реально содержит сырые "\r\n".
void test_raw_crlf_in_host_is_rejected_even_without_colon_in_payload() {
    auto r = parse_http_url("http://ca.example\r\nEVIL\r\n\r\n/x");
    TEST_CHECK(!r.has_value());
}

void test_bare_cr_without_lf_is_rejected() {
    auto r = parse_http_url("http://ca.example/a\rb");
    TEST_CHECK(!r.has_value());
}

void test_null_byte_is_rejected() {
    std::string url = "http://ca.example/a";
    url.push_back('\0');
    url += "b";
    auto r = parse_http_url(url);
    TEST_CHECK(!r.has_value());
}

void test_del_byte_is_rejected() {
    std::string url = "http://ca.example/a";
    url.push_back('\x7f');
    auto r = parse_http_url(url);
    TEST_CHECK(!r.has_value());
}

void test_tab_is_rejected() {
    // Горизонтальная табуляция (0x09) тоже управляющий символ — formally
    // не \r и не \n, но по той же логике "< 0x20" мы отклоняем и её.
    auto r = parse_http_url("http://ca.example/a\tb");
    TEST_CHECK(!r.has_value());
}

// percent-encoded CRLF ("%0D%0A") остаётся шестью печатными ASCII-
// символами — cert-helper path не декодирует, так что он уходит на
// сервер буквально как "%0D%0A", без собственного смысла для НАШЕЙ
// строки запроса. Это НЕ отклоняется (и не должно), в отличие от сырых
// байт выше — разница принципиальна и описана в комментарии у
// has_control_byte() в http_client.hpp.
void test_percent_encoded_crlf_is_not_treated_as_raw_control_byte() {
    auto r = parse_http_url("http://ca.example/a%0D%0Ab");
    TEST_CHECK(r.has_value());
    if (r) {
        TEST_CHECK_EQ(r->path, std::string("/a%0D%0Ab"));
    }
}

// Негативный контроль: обычные легитимные URL по-прежнему разбираются
// как раньше — фикс не должен задеть штатный путь.
void test_normal_url_still_parses() {
    auto r = parse_http_url("http://ca.example:8080/path?query=1");
    TEST_CHECK(r.has_value());
    if (r) {
        TEST_CHECK_EQ(r->host, std::string("ca.example"));
        TEST_CHECK_EQ(r->port, static_cast<uint16_t>(8080));
        TEST_CHECK_EQ(r->path, std::string("/path?query=1"));
        TEST_CHECK(!r->is_https);
    }
}

// --- Часть 2: end-to-end через SimpleHttpFetcher::fetch() ---

// Сервер, который следит, дошло ли до него вообще хоть одно TCP-
// соединение — для проверки "сеть не тронута" для заведомо отклоняемого
// URL.
class ConnectionObservingServer {
public:
    explicit ConnectionObservingServer() {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr));

        socklen_t addr_len = sizeof(addr);
        getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&addr),
                    &addr_len);
        listening_port = ntohs(addr.sin_port);

        listen(listen_fd, 1);

        server_thread = std::thread([this] {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_fd, &read_fds);
            struct timeval tv {};
            tv.tv_sec = 1;
            int sel = select(listen_fd + 1, &read_fds, nullptr, nullptr, &tv);
            if (sel <= 0) {
                return;  // таймаут — никто не подключился (ожидаемый
                         // исход для теста, который это и проверяет)
            }
            int client_fd = accept(listen_fd, nullptr, nullptr);
            if (client_fd < 0) {
                return;
            }
            connected.store(true);
            char buf[4096];
            recv(client_fd, buf, sizeof(buf), 0);
            std::string const resp =
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            send(client_fd, resp.data(), resp.size(), MSG_NOSIGNAL);
            ::close(client_fd);
        });
    }

    ~ConnectionObservingServer() {
        if (server_thread.joinable()) {
            server_thread.join();
        }
        ::close(listen_fd);
    }

    uint16_t port() const { return listening_port; }
    bool was_connected() const { return connected.load(); }

private:
    std::atomic<bool> connected{false};
    int listen_fd = -1;
    uint16_t listening_port = 0;
    std::thread server_thread;
};

NetworkPolicy make_permissive_policy(uint16_t port) {
    NetworkPolicy::Config cfg;
    cfg.block_private_by_default = false;
    cfg.allowed_ports = {port};
    return NetworkPolicy(cfg);
}

// Главный регрессионный тест: URL с CRLF-инъекцией не должен приводить
// НИ К КАКОМУ сетевому обращению — отказ обязан происходить ещё на
// этапе разбора URL, до DNS/connect().
void test_fetch_rejects_crlf_url_without_touching_network() {
    ConnectionObservingServer server;

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) +
                      "/ok HTTP/1.1\r\nX-Injected: yes\r\n\r\nGET /smuggled";

    auto result = fetcher.fetch(Method::GET, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(!result.ok);
    TEST_CHECK(result.failure_reason == FailureReason::INVALID_URL);
    TEST_CHECK(!server.was_connected());
}

// Негативный контроль: обычный URL на тот же сервер по-прежнему
// нормально отрабатывает (фикс не сломал штатный путь).
void test_fetch_normal_url_still_works() {
    ConnectionObservingServer server;

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/ok";

    auto result = fetcher.fetch(Method::GET, url, {}, "", 2000, 1024 * 1024);

    TEST_CHECK(result.ok);
    TEST_CHECK(server.was_connected());
    std::string body(result.body.begin(), result.body.end());
    TEST_CHECK_EQ(body, std::string("ok"));
}

}  // namespace

int main() {
    RUN_TEST(test_raw_crlf_in_path_is_rejected);
    RUN_TEST(test_raw_crlf_in_host_is_rejected);
    RUN_TEST(test_raw_crlf_in_host_is_rejected_even_without_colon_in_payload);
    RUN_TEST(test_bare_cr_without_lf_is_rejected);
    RUN_TEST(test_null_byte_is_rejected);
    RUN_TEST(test_del_byte_is_rejected);
    RUN_TEST(test_tab_is_rejected);
    RUN_TEST(test_percent_encoded_crlf_is_not_treated_as_raw_control_byte);
    RUN_TEST(test_normal_url_still_parses);
    RUN_TEST(test_fetch_rejects_crlf_url_without_touching_network);
    RUN_TEST(test_fetch_normal_url_still_works);
    TEST_MAIN_EXIT();
}
