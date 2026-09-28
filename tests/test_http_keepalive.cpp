// test_http_keepalive.cpp — тесты HTTP keep-alive / пула соединений
// (ROADMAP.md, раздел 2, пункт 12).
//
// Поднимает собственный минимальный "персистентный" HTTP-сервер на
// 127.0.0.1 (сырые сокеты, без внешних зависимостей): в отличие от
// OneShotHttpServer в test_http_cache_hints.cpp (ровно одно соединение,
// ровно один ответ), этот сервер способен принять НЕСКОЛЬКО соединений
// и на каждом обслужить несколько запросов подряд — что и нужно для
// проверки как самого переиспользования соединения (несколько запросов
// на одном accept()), так и прозрачного восстановления после того, как
// сервер закрыл простаивавшее соединение (два accept() вместо одного).

#include <atomic>
#include <chrono>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

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

// Обслуживает несколько TCP-соединений подряд (до max_connections), на
// каждом отдаёт из responses по одному ответу на запрос, ПОКА они не
// кончатся для этого соединения — после чего закрывает его (сервер
// каждый раз ограничивает себя ровно `responses.size()` ответами на
// соединение, что естественным образом моделирует и "сервер закрыл
// простаивавшее соединение", если клиент попробует использовать его для
// ещё одного запроса).
class PersistentHttpServer {
public:
    explicit PersistentHttpServer(std::vector<std::string> responses, int max_connections = 4)
        : responses_(std::move(responses)), max_connections_(max_connections) {
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

        listen(listen_fd, 4);

        server_thread = std::thread([this] { run(); });
    }

    ~PersistentHttpServer() {
        stop_.store(true);
        if (server_thread.joinable()) server_thread.join();
        ::close(listen_fd);
    }

    uint16_t port() const { return listening_port; }
    int accept_count() const { return accept_count_.load(); }

private:
    void run() {
        for (int i = 0; i < max_connections_ && !stop_.load(); ++i) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_fd, &read_fds);
            struct timeval tv{};
            tv.tv_sec = 2;
            int sel = select(listen_fd + 1, &read_fds, nullptr, nullptr, &tv);
            if (sel <= 0) return; // таймаут — больше подключений не ожидается

            int fd = accept(listen_fd, nullptr, nullptr);
            if (fd < 0) continue;
            accept_count_.fetch_add(1);
            handle_connection(fd);
        }
    }

    void handle_connection(int fd) {
        for (const auto& resp : responses_) {
            if (!read_one_request(fd)) break; // клиент закрыл соединение раньше, чем прислал запрос
            ::send(fd, resp.data(), resp.size(), 0);
        }
        ::close(fd); // после исчерпания responses_ на этом соединении — закрываем
    }

    static bool read_one_request(int fd) {
        std::string buffer;
        char chunk[4096];
        while (buffer.find("\r\n\r\n") == std::string::npos) {
            ssize_t r = ::recv(fd, chunk, sizeof(chunk), 0);
            if (r <= 0) return false;
            buffer.append(chunk, static_cast<size_t>(r));
        }
        return true; // GET-запросы без тела — заголовков достаточно
    }

    std::vector<std::string> responses_;
    int max_connections_;
    int listen_fd = -1;
    uint16_t listening_port = 0;
    std::thread server_thread;
    std::atomic<bool> stop_{false};
    std::atomic<int> accept_count_{0};
};

NetworkPolicy make_permissive_policy(uint16_t port) {
    NetworkPolicy::Config cfg;
    cfg.block_private_by_default = false;
    cfg.allowed_ports = {port};
    return NetworkPolicy(cfg);
}

std::string content_length_response(const std::string& body, bool explicit_close = false) {
    return "HTTP/1.1 200 OK\r\n"
           "Content-Length: " +
           std::to_string(body.size()) + "\r\n" + (explicit_close ? "Connection: close\r\n" : "") +
           "\r\n" + body;
}

std::string chunked_response(const std::string& body) {
    // Разбиваем на два чанка произвольного размера — чтобы упражнять сам
    // разбор chunked, а не только вырожденный случай "один чанк на всё".
    size_t half = body.size() / 2;
    std::string first = body.substr(0, half);
    std::string second = body.substr(half);
    auto hex_size = [](size_t n) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx", n);
        return std::string(buf);
    };
    std::string out = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    if (!first.empty()) out += hex_size(first.size()) + "\r\n" + first + "\r\n";
    if (!second.empty()) out += hex_size(second.size()) + "\r\n" + second + "\r\n";
    out += "0\r\n\r\n";
    return out;
}

// ROADMAP.md, раздел 2, пункт 12 (P1): два последовательных fetch() к
// одному и тому же host:port через ОДИН и тот же SimpleHttpFetcher
// должны переиспользовать TCP-соединение — сервер должен увидеть ровно
// один accept(), а не два.
void test_two_requests_to_same_host_reuse_one_connection() {
    std::string body1 = "first-response-body";
    std::string body2 = "second-response-body";
    PersistentHttpServer server({content_length_response(body1), content_length_response(body2)},
                                 /*max_connections=*/1);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto r1 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r1.ok);
    std::string got1(r1.body.begin(), r1.body.end());
    TEST_CHECK(got1 == body1);

    auto r2 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r2.ok);
    std::string got2(r2.body.begin(), r2.body.end());
    TEST_CHECK(got2 == body2);

    TEST_CHECK_EQ(server.accept_count(), 1); // ключевая проверка: ОДНО TCP-соединение на оба запроса
}

// Chunked-ответы тоже должны корректно разбираться при keep-alive
// (framing по инкрементальному разбору chunk'ов, а не по EOF) — и тоже
// давать переиспользование соединения.
void test_chunked_responses_also_reuse_connection() {
    std::string body1 = "chunked-first-body-abcdefgh";
    std::string body2 = "chunked-second-body-ijklmnop";
    PersistentHttpServer server({chunked_response(body1), chunked_response(body2)},
                                 /*max_connections=*/1);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto r1 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r1.ok);
    std::string got1(r1.body.begin(), r1.body.end());
    TEST_CHECK(got1 == body1);

    auto r2 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r2.ok);
    std::string got2(r2.body.begin(), r2.body.end());
    TEST_CHECK(got2 == body2);

    TEST_CHECK_EQ(server.accept_count(), 1);
}

// "Connection: close" в ответе должен помешать переиспользованию — даже
// если framing (Content-Length) был вполне однозначным.
void test_explicit_connection_close_prevents_reuse() {
    std::string body1 = "first-body";
    std::string body2 = "second-body";
    // Сервер настроен принять ДВА соединения — если бы клиент ошибочно
    // попытался переиспользовать первое несмотря на "Connection: close",
    // второй fetch() не достучался бы до второго accept() из-за
    // протухшего соединения, и мы бы поймали расхождение через
    // accept_count() (остался бы 1 вместо ожидаемых 2).
    PersistentHttpServer server(
        {content_length_response(body1, /*explicit_close=*/true)},
        /*max_connections=*/2);
    // На ВТОРОМ соединении — свой набор ответов.
    // (Один PersistentHttpServer обслуживает max_connections
    // соединений, каждое — по своему списку responses_; здесь список
    // один и тот же для простоты, но после Connection: close первого
    // соединения второй fetch() пойдёт на новое соединение и получит TOT
    // ЖЕ единственный сконфигурированный ответ — поэтому body2 не
    // используется здесь, тест ограничивается проверкой accept_count и
    // корректности первого тела.)
    (void)body2;

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto r1 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r1.ok);
    std::string got1(r1.body.begin(), r1.body.end());
    TEST_CHECK(got1 == body1);

    auto r2 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r2.ok); // второй запрос обязан пройти через НОВОЕ соединение и всё равно успеть

    TEST_CHECK_EQ(server.accept_count(), 2); // Connection: close помешал переиспользованию
}

// ROADMAP.md, раздел 2, пункт 12: если сервер закрыл простаивающее
// (пулированное) соединение до того, как клиент успел его переиспользовать
// (типичный race с idle-таймаутом сервера) — fetch() должен прозрачно
// открыть новое соединение и всё равно вернуть корректный результат, а
// не ошибку. PersistentHttpServer с ОДНИМ ответом на соединение и
// max_connections=2 естественным образом моделирует эту ситуацию: сервер
// сам закрывает соединение после первого запроса.
void test_stale_pooled_connection_falls_back_transparently() {
    std::string body = "response-body";
    PersistentHttpServer server({content_length_response(body)}, /*max_connections=*/2);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto r1 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r1.ok);

    // Даём серверу время фактически закрыть соединение после первого
    // ответа (handle_connection() уже вышла из цикла и вызвала close()) —
    // без этой маленькой паузы гонка возможна в обе стороны, а нас
    // интересует именно сценарий "сервер уже закрыл", а не "ещё не
    // успел". Небольшой sleep не делает тест по-настоящему детерминированным
    // против ядра ОС, но практически более чем достаточен.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto r2 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r2.ok); // несмотря на протухшее пулированное соединение — успех
    std::string got2(r2.body.begin(), r2.body.end());
    TEST_CHECK(got2 == body);

    TEST_CHECK_EQ(server.accept_count(), 2); // второй запрос действительно пошёл через новое соединение
}

// Ответ без Content-Length и без chunked (framing неоднозначен) должен
// по-прежнему разбираться корректно (через чтение до EOF, как и раньше,
// до пункта 12) — и такое соединение НЕ должно пытаться переиспользоваться.
void test_ambiguous_framing_falls_back_to_read_until_close() {
    std::string body = "no-framing-body";
    std::string raw_response = "HTTP/1.1 200 OK\r\n\r\n" + body; // ни Content-Length, ни chunked
    PersistentHttpServer server({raw_response}, /*max_connections=*/2);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url = "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto r1 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r1.ok);
    std::string got1(r1.body.begin(), r1.body.end());
    TEST_CHECK(got1 == body);

    auto r2 = fetcher.fetch(Method::Get, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(r2.ok);

    TEST_CHECK_EQ(server.accept_count(), 2); // неоднозначный framing => каждый раз новое соединение
}

} // namespace

int main() {
    RUN_TEST(test_two_requests_to_same_host_reuse_one_connection);
    RUN_TEST(test_chunked_responses_also_reuse_connection);
    RUN_TEST(test_explicit_connection_close_prevents_reuse);
    RUN_TEST(test_stale_pooled_connection_falls_back_transparently);
    RUN_TEST(test_ambiguous_framing_falls_back_to_read_until_close);
    TEST_MAIN_EXIT();
}
