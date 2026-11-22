// Пул соединений, переподключение и таймауты redis::Client (redis_client.hpp) на поддельном Redis:
// маленький RESP-сервер в тесте умеет отвечать на AUTH/SET/GET/INCR/SMEMBERS, задерживать ответы, «зависать»,
// обрывать все соединения (рестарт Redis) и останавливаться/подниматься на том же порту. Настоящий Redis для
// этих тестов не нужен.
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "redis_client.hpp"
#include "test_framework.hpp"

namespace {

using namespace std::chrono_literals;

class FakeRedis {
public:
    FakeRedis() { listen_on(0); }
    ~FakeRedis() { stop(); }

    int port() const { return port_; }
    std::atomic<int> accepted{0};
    std::atomic<int> commands{0};
    std::atomic<int> max_parallel{0};
    std::atomic<int> delay_ms{0};
    std::atomic<bool> hang{false};          // принять команду и не отвечать
    std::atomic<bool> reject_auth{false};   // на AUTH отвечать -WRONGPASS
    std::atomic<bool> error_on_set{false};  // на SET отвечать -ERR (ответ-ошибка, а не обрыв)

    // Рестарт Redis: все соединения рвутся, слушатель остаётся.
    void drop_connections() {
        std::lock_guard<std::mutex> lock(mu_);
        for (int fd : conns_) ::shutdown(fd, SHUT_RDWR);
    }
    // Redis «лёг»: слушатель закрыт, соединения оборваны.
    void stop() {
        if (listener_ >= 0) {
            ::shutdown(listener_, SHUT_RDWR);
            ::close(listener_);
            listener_ = -1;
        }
        drop_connections();
        if (acceptor_.joinable()) acceptor_.join();
        std::vector<std::thread> workers;
        {
            std::lock_guard<std::mutex> lock(mu_);
            workers.swap(workers_);
        }
        for (auto& t : workers) {
            if (t.joinable()) t.join();
        }
    }
    // Redis поднялся снова на том же порту.
    void start() { listen_on(port_); }

private:
    void listen_on(int port) {
        listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(static_cast<uint16_t>(port));
        ::bind(listener_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        socklen_t len = sizeof(addr);
        getsockname(listener_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        ::listen(listener_, 64);
        int lfd = listener_;
        acceptor_ = std::thread([this, lfd] {
            for (;;) {
                int fd = ::accept(lfd, nullptr, nullptr);
                if (fd < 0) return;
                ++accepted;
                std::lock_guard<std::mutex> lock(mu_);
                conns_.insert(fd);
                workers_.emplace_back([this, fd] { serve(fd); });
            }
        });
    }

    static bool read_command(int fd, std::vector<std::string>& args) {
        auto line = [&](std::string& out) {
            out.clear();
            char c;
            while (::recv(fd, &c, 1, 0) == 1) {
                if (c == '\n') return true;
                if (c != '\r') out.push_back(c);
            }
            return false;
        };
        std::string l;
        if (!line(l) || l.empty() || l[0] != '*') return false;
        int n = std::stoi(l.substr(1));
        args.clear();
        for (int i = 0; i < n; ++i) {
            if (!line(l) || l.empty() || l[0] != '$') return false;
            int len = std::stoi(l.substr(1));
            std::string data(static_cast<size_t>(len), '\0');
            size_t got = 0;
            while (got < data.size()) {
                ssize_t r = ::recv(fd, data.data() + got, data.size() - got, 0);
                if (r <= 0) return false;
                got += static_cast<size_t>(r);
            }
            char crlf[2];
            if (::recv(fd, crlf, 2, MSG_WAITALL) != 2) return false;
            args.push_back(std::move(data));
        }
        return true;
    }

    void serve(int fd) {
        std::vector<std::string> args;
        while (read_command(fd, args)) {
            ++commands;
            int now = ++active_;
            int prev = max_parallel.load();
            while (now > prev && !max_parallel.compare_exchange_weak(prev, now)) {
            }
            if (hang) {
                while (hang) std::this_thread::sleep_for(20ms);
            }
            if (delay_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms.load()));
            std::string reply;
            const std::string& cmd = args[0];
            if (cmd == "AUTH") {
                reply = reject_auth ? "-WRONGPASS invalid username-password pair\r\n" : "+OK\r\n";
            } else if (cmd == "SET") {
                reply = error_on_set ? "-ERR simulated failure\r\n" : "+OK\r\n";
            } else if (cmd == "GET") {
                reply = "$5\r\nvalue\r\n";
            } else if (cmd == "INCR") {
                reply = ":" + std::to_string(++counter_) + "\r\n";
            } else if (cmd == "SMEMBERS") {
                reply = "*2\r\n$1\r\na\r\n$1\r\nb\r\n";
            } else {
                reply = "-ERR unknown command\r\n";
            }
            --active_;
            if (::send(fd, reply.data(), reply.size(), MSG_NOSIGNAL) < 0) break;
        }
        std::lock_guard<std::mutex> lock(mu_);
        conns_.erase(fd);
        ::close(fd);
    }

    int listener_ = -1;
    int port_ = 0;
    std::thread acceptor_;
    std::mutex mu_;
    std::set<int> conns_;
    std::vector<std::thread> workers_;
    std::atomic<int> active_{0};
    std::atomic<int> counter_{0};
};

redis::Options quick(std::size_t pool = 8) {
    redis::Options o;
    o.pool_size = pool;
    o.connect_timeout_ms = 500;
    o.io_timeout_ms = 600;
    o.wait_timeout_ms = 2000;
    return o;
}

} // namespace

TEST(redis_pool_runs_commands_in_parallel_on_several_connections) {
    FakeRedis server;
    server.delay_ms = 150;
    redis::Client client("127.0.0.1", server.port(), "", "", quick(8));

    const auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;
    std::atomic<int> ok{0};
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            if (client.get("k").value_or("") == "value") ++ok;
        });
    }
    for (auto& t : threads) t.join();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    CHECK_EQ(ok.load(), 8);
    CHECK(server.max_parallel.load() >= 4);   // команды реально шли одновременно
    CHECK(ms < 800);                          // под одним мьютексом было бы ≥ 8 × 150 мс
    CHECK(client.stats().open > 1);
}

TEST(redis_pool_never_opens_more_connections_than_pool_size) {
    FakeRedis server;
    server.delay_ms = 40;
    redis::Client client("127.0.0.1", server.port(), "", "", quick(2));

    std::vector<std::thread> threads;
    std::atomic<int> ok{0};
    for (int t = 0; t < 6; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 4; ++i) {
                if (client.get("k")) ++ok;
            }
        });
    }
    for (auto& t : threads) t.join();
    CHECK_EQ(ok.load(), 24);
    CHECK(server.accepted.load() <= 2);
    CHECK(server.max_parallel.load() <= 2);
    CHECK(client.stats().waited > 0);
}

TEST(redis_restart_is_transparent_one_retry_on_fresh_connection) {
    FakeRedis server;
    redis::Client client("127.0.0.1", server.port(), "", "", quick(4));
    REQUIRE(client.get("k").has_value());

    server.drop_connections(); // рестарт Redis: все соединения пула мертвы
    auto v = client.get("k");  // сбой на «протухшем», повтор на свежем
    REQUIRE(v.has_value());
    CHECK_EQ(*v, std::string("value"));
    CHECK_EQ(client.stats().retried, static_cast<size_t>(1));
    CHECK(server.accepted.load() >= 2);
}

TEST(redis_reconnects_after_server_was_down_without_restarting_the_client) {
    FakeRedis server;
    redis::Client client("127.0.0.1", server.port(), "", "", quick(4));
    REQUIRE(client.get("k").has_value());

    server.stop(); // Redis лёг
    CHECK_THROWS(client.get("k"));
    CHECK_THROWS(client.get("k")); // пока лежит — ошибка, но клиент не «залипает»

    server.start(); // Redis поднялся
    auto v = client.get("k");
    REQUIRE(v.has_value()); // раньше сокет оставался мёртвым до рестарта сервиса
    CHECK_EQ(*v, std::string("value"));
}

TEST(redis_times_out_on_hung_server_and_frees_the_slot) {
    FakeRedis server;
    redis::Client client("127.0.0.1", server.port(), "", "", quick(1));
    REQUIRE(client.get("k").has_value());

    server.hang = true;
    const auto t0 = std::chrono::steady_clock::now();
    CHECK_THROWS(client.get("k"));
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms < 3000); // таймаут чтения (600 мс) и один повтор, а не «навсегда»

    server.hang = false;
    auto v = client.get("k"); // слот освобождён, пул жив (pool_size = 1)
    REQUIRE(v.has_value());
}

TEST(redis_error_reply_keeps_the_connection) {
    FakeRedis server;
    redis::Client client("127.0.0.1", server.port(), "", "", quick(4));
    server.error_on_set = true;
    CHECK_THROWS(client.set_ex("k", "v", 10));    // -ERR: исключение, но соединение годное
    server.error_on_set = false;
    client.set_ex("k", "v", 10);
    CHECK_EQ(server.accepted.load(), 1);          // всё это время одно соединение
    CHECK_EQ(client.stats().retried, static_cast<size_t>(0));
}

TEST(redis_smembers_and_incr_work_through_the_pool) {
    FakeRedis server;
    redis::Client client("127.0.0.1", server.port(), "", "", quick(4));
    auto m = client.smembers("s");
    REQUIRE(m.size() == 2);
    CHECK_EQ(m[0], std::string("a"));
    CHECK_EQ(client.incr("c"), 1);
    CHECK_EQ(client.incr("c"), 2);
}

TEST(redis_wrong_password_fails_at_startup_without_leaking_it) {
    FakeRedis server;
    server.reject_auth = true;
    try {
        redis::Client client("127.0.0.1", server.port(), "super-secret-pw", "user", quick(2));
        CHECK(false); // должно бросить
    } catch (const std::exception& ex) {
        const std::string msg = ex.what();
        CHECK(msg.find("AUTH не прошёл") != std::string::npos);
        CHECK(msg.find("super-secret-pw") == std::string::npos);
    }
}

TEST(redis_auth_is_repeated_on_every_new_connection) {
    FakeRedis server;
    redis::Client client("127.0.0.1", server.port(), "pw", "", quick(4));
    server.drop_connections();
    REQUIRE(client.get("k").has_value());
    // два соединения (старое + новое после рестарта), AUTH на каждом, оборванный GET до сервера не дошёл:
    // 2 × AUTH + 1 × GET
    CHECK_EQ(server.accepted.load(), 2);
    CHECK_EQ(server.commands.load(), 3);
}
#endif
