// test_http_slow_server.cpp
//
// ПУНКТ 5 ПЛАНА ДОРАБОТКИ (P1): таймаут был реализован через
// SO_RCVTIMEO/SO_SNDTIMEO, выставленный ОДИН раз на весь timeout_ms и
// больше не трогаемый — то есть ограничивал длительность КАЖДОГО
// ОТДЕЛЬНОГО recv(), а не всей операции fetch() целиком. Сервер,
// отвечающий чуть быстрее, чем истекает таймаут сокета (например, по
// одному байту каждые 0.8 с при timeout_ms=1000), удерживал поток
// воркера сколь угодно долго — воспроизведено вручную: при
// timeout_ms=1000 весь fetch() занял 9.6 с вместо заявленной 1 с.
//
// Фикс — единый Deadline = now() + timeout_ms, посчитанный один раз в
// начале fetch(), и remaining_ms() перед каждой блокирующей операцией
// (попытка connect(), send_all(), каждая итерация чтения ответа).
//
// Этот тест запускает сервер, отдающий тело по одному байту с
// интервалом МЕНЬШЕ timeout_ms (так что КАЖДЫЙ отдельный recv()
// формально укладывается в старый, "посегментный" таймаут), и проверяет,
// что fetch() тем не менее возвращается в пределах небольшого запаса
// сверх заявленного timeout_ms — а не продолжает ждать, пока сервер не
// докапает все байты или сам не закроет соединение.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <thread>

#include "../src/http_client.hpp"
#include "../src/net_policy.hpp"
#include "test_util.hpp"

using namespace cert_helper::http;
using namespace cert_helper::net;

namespace {

// Сервер, отдающий тело ответа по одному байту с заданным интервалом —
// "slow-loris" со стороны ответчика, а не со стороны запроса.
class DripServer {
public:
    DripServer(std::string body, std::chrono::milliseconds byte_interval,
               int byte_count)
        : body(std::move(body)),
          byte_interval(byte_interval),
          byte_count(byte_count) {
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

            std::string header = "HTTP/1.1 200 OK\r\nContent-Length: " +
                                 std::to_string(this->body.size()) + "\r\n\r\n";
            send(client_fd, header.data(), header.size(), MSG_NOSIGNAL);

            for (int i = 0; i < this->byte_count &&
                            static_cast<size_t>(i) < this->body.size();
                 ++i) {
                std::this_thread::sleep_for(this->byte_interval);
                if (send(client_fd, &this->body[static_cast<size_t>(i)], 1,
                         MSG_NOSIGNAL) <= 0) {
                    break;  // клиент уже отключился (ожидаемо после фикса)
                }
            }
            ::close(client_fd);
        });
    }

    ~DripServer() {
        if (server_thread.joinable()) {
            server_thread.join();
        }
        ::close(listen_fd);
    }

    uint16_t port() const { return listening_port; }

private:
    std::string body;
    std::chrono::milliseconds byte_interval;
    int byte_count;
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

// Главный регрессионный тест: сервер тянет тело дольше заявленного
// timeout_ms, отдавая его маленькими порциями БЫСТРЕЕ, чем успевает
// сработать таймаут на отдельный recv(). fetch() обязан вернуться с
// результатом в пределах timeout_ms плюс небольшой разумный запас — а
// не ждать все 12 байт (12 * 300 мс = 3.6 с при объявленном timeout_ms
// = 1000).
void test_fetch_respects_overall_deadline_against_slow_drip_server() {
    DripServer server(
        "Hello World!",                  // 12 байт
        std::chrono::milliseconds(300),  // каждый байт — быстрее, чем
                                         // старый посегментный таймаут
        12);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto const t0 = std::chrono::steady_clock::now();
    auto result = fetcher.fetch(Method::GET, url, {}, "", /*timeout_ms=*/1000,
                                1024 * 1024);
    auto const elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);

    TEST_CHECK(!result.ok);
    TEST_CHECK(result.timed_out);
    // Запас x2.5 от заявленного timeout_ms — с большим зазором покрывает
    // планировщик/нагрузку CI, но железно отсекает старое поведение
    // (которое в ручном эксперименте дало ~9.6x от заявленного таймаута).
    TEST_CHECK(elapsed < std::chrono::milliseconds(2500));
}

// Негативный контроль: сервер, укладывающийся в заявленный timeout_ms
// целиком, по-прежнему отрабатывает успешно — фикс не должен портить
// обычные, не-патологические медленные ответы.
void test_fetch_still_succeeds_within_deadline() {
    DripServer server("Hi", std::chrono::milliseconds(50), 2);

    SimpleHttpFetcher fetcher(make_permissive_policy(server.port()));
    std::string url =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/x";

    auto result = fetcher.fetch(Method::GET, url, {}, "", 2000, 1024 * 1024);
    TEST_CHECK(result.ok);
    std::string body(result.body.begin(), result.body.end());
    TEST_CHECK_EQ(body, std::string("Hi"));
}

}  // namespace

int main() {
    RUN_TEST(test_fetch_respects_overall_deadline_against_slow_drip_server);
    RUN_TEST(test_fetch_still_succeeds_within_deadline);
    TEST_MAIN_EXIT();
}
