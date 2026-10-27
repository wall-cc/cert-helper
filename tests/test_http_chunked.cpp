// test_http_chunked.cpp
//
// ПУНКТ 2.3 ПЛАНА ДОРАБОТКИ (P0): переполнение в chunked-декодере.
//
// try_decode_chunked_incremental() парсит размер chunk'а через
// std::stoul(size_line, nullptr, 16) и ДО фикса не проверяет его ни на
// что — на 64-битной платформе unsigned long 64-битный, так что сервер,
// ответивший чанком размера 0xFFFFFFFFFFFFFFFF, успешно проходит
// std::stoul() (исключение не бросается, число просто ОГРОМНОЕ). Дальше
// проверка `data_start + chunk_size + 2 > body.size()` сама переполняется
// (arithmetic overflow у size_t), из-за чего может пропустить ранний
// выход "данные ещё не все пришли" — и код формирует итератор на
// ~18*10^18 байт от буфера размером в несколько десятков байт. Это
// неопределённое поведение (построение итератора далеко за границами
// массива); на практике — либо std::length_error из vector::insert
// (воспроизведено под ASan: "terminate called after throwing an
// instance of 'std::length_error'"), либо (в Release-сборке без
// проверок) потенциальная порча памяти.
//
// Это ОСОБЕННО важно после фикса пункта 2.6 (singleflight): раньше
// подобный краш валил весь процесс демона целиком СРАЗУ, что уже плохо,
// но однозначно; теперь исключение из fetch() корректно долетает до
// RequestRouter/dbus_server.cpp и превращается в D-Bus error reply —
// но ТОЛЬКО если оно вообще остаётся C++ исключением, а не неопределённым
// поведением, которое может проявиться как угодно (включая потенциальную
// порчу памяти ДО того, как исключение успеет быть брошено). Поэтому
// здесь важен фикс именно в источнике (отклонить аномальный chunk_size
// ДО арифметики с ним), а не просто "обернуть вызывающий код в try/catch".

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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

// Односоединенный сервер, отдающий заранее заданные сырые байты ответа
// (без дальнейшего ожидания закрытия клиентом — после отправки сразу
// закрывает сокет со своей стороны, если явно не указано иное), затем
// ЗАВИСАЕТ НАДОЛГО перед закрытием (имитация "сервер прислал заголовок
// размера и замолчал" — именно так выглядел ручной эксперимент,
// подтвердивший баг: `send(...); time.sleep(3)`). Таймаут клиента на
// fetch() должен сработать раньше, чем сервер сам закроет соединение —
// тест проверяет, что клиент либо получает ошибку, либо (после фикса)
// ПРАВИЛЬНО определяет chunk_size как недопустимый и сразу отклоняет
// ответ как malformed, не дожидаясь вообще ничего больше по сети.
class RawResponseServer {
public:
    explicit RawResponseServer(
        std::string raw_response,
        std::chrono::milliseconds hold_open = std::chrono::milliseconds(0))
        : response(std::move(raw_response)), hold_open(hold_open) {
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

        server_thread = std::thread([this, hold_open = this->hold_open] {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_fd, &read_fds);
            struct timeval tv {};
            tv.tv_sec = 2;
            int sel = select(listen_fd + 1, &read_fds, nullptr, nullptr, &tv);
            if (sel <= 0) {
                return;
            }
            int client_fd = accept(listen_fd, nullptr, nullptr);
            if (client_fd < 0) {
                return;
            }
            char buf[4096];
            recv(client_fd, buf, sizeof(buf), 0);
            send(client_fd, response.data(), response.size(), MSG_NOSIGNAL);
            if (hold_open.count() > 0) {
                std::this_thread::sleep_for(hold_open);
            }
            ::close(client_fd);
        });
    }

    ~RawResponseServer() {
        if (server_thread.joinable()) {
            server_thread.join();
        }
        ::close(listen_fd);
    }

    uint16_t port() const { return listening_port; }

private:
    std::string response;
    std::chrono::milliseconds hold_open;
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

// Главный регрессионный тест: гигантский заявленный размер chunk'а не
// должен приводить ни к краху процесса (неотловленное исключение/UB),
// ни к зависанию — fetch() обязан вернуться за разумное время с
// result.ok == false.
void test_huge_chunk_size_does_not_crash_or_hang() {
    RawResponseServer server(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "ffffffffffffffff\r\n"
        "AAAA",
        std::chrono::milliseconds(500));

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto const t0 = std::chrono::steady_clock::now();
    auto result = fetcher.fetch(Method::GET, url, {}, "", /*timeout_ms=*/3000,
                                /*max_response_bytes=*/1024 * 1024);
    auto const elapsed = std::chrono::steady_clock::now() - t0;

    TEST_CHECK(!result.ok);
    // С запасом: вся операция, включая задержку сервера (500 мс),
    // обязана уложиться далеко меньше таймаута (3000 мс) — досрочный
    // отказ должен происходить СРАЗУ по размеру chunk'а, не дожидаясь
    // ни остального сетевого трафика, ни истечения таймаута.
    TEST_CHECK(elapsed < std::chrono::milliseconds(2500));
}

// Чуть более тонкий случай: размер chunk'а переполняет unsigned long
// НЕ полностью (не 0xFFFF...FFFF), но всё ещё многократно превышает
// любой разумный max_response_bytes — тоже должен быть отклонён сразу
// по значению, а не только по итоговому переполнению арифметики.
void test_implausibly_large_chunk_size_is_rejected() {
    RawResponseServer server(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "7fffffff\r\n"  // ~2 ГБ — на 3-4 порядка больше max_response_bytes ниже
        "AAAA",
        std::chrono::milliseconds(300));

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto result = fetcher.fetch(Method::GET, url, {}, "", /*timeout_ms=*/3000,
                                /*max_response_bytes=*/64 * 1024);
    TEST_CHECK(!result.ok);
}

// Негативный контроль: обычный, корректный chunked-ответ по-прежнему
// должен разбираться правильно — фикс не должен задеть штатный путь.
void test_normal_chunked_response_still_works() {
    RawResponseServer server(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "Hello\r\n"
        "6\r\n"
        " World\r\n"
        "0\r\n"
        "\r\n");

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto result = fetcher.fetch(Method::GET, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(result.ok);
    std::string body(result.body.begin(), result.body.end());
    TEST_CHECK_EQ(body, std::string("Hello World"));
}

}  // namespace

int main() {
    RUN_TEST(test_huge_chunk_size_does_not_crash_or_hang);
    RUN_TEST(test_implausibly_large_chunk_size_is_rejected);
    RUN_TEST(test_normal_chunked_response_still_works);
    TEST_MAIN_EXIT();
}
