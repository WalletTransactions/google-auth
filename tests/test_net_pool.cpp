// Пул постоянных клиентов (net/pool из wallet-common, change add-internal-mtls, задача 7.1) и
// переключатели net/tls (settings_from_env): пул держит соединения, повторяет запрос на свежем
// после обрыва простаивающего и не плодит клиентов; INTERNAL_MTLS отделён от TLS_*.
#include "net/pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <vector>

#include "test_framework.hpp"
#include "tls_test_util.hpp"

using namespace tlstest;

namespace {

// Очередь задач, считающая принятые соединения: httplib ставит в неё по одной задаче на
// соединение (запросы по keep-alive обслуживаются внутри той же задачи), так что счётчик — это
// число соединений, а при TLS — число рукопожатий. (set_socket_options настраивает слушающий
// сокет, а не принятые, поэтому для счёта не годится.)
class CountingQueue final : public httplib::TaskQueue {
public:
    explicit CountingQueue(std::atomic<int>* count) : count_(count), inner_(8) {}
    bool enqueue(std::function<void()> fn) override {
        ++*count_;
        return inner_.enqueue(std::move(fn));
    }
    void shutdown() override { inner_.shutdown(); }

private:
    std::atomic<int>* count_;
    httplib::ThreadPool inner_;
};

// Сервер со счётчиком принятых соединений.
struct Counted {
    std::atomic<int> connections{0};
    std::unique_ptr<Running> run;

    Counted(std::unique_ptr<httplib::Server> s, time_t keep_alive_sec = 5) {
        s->set_keep_alive_timeout(keep_alive_sec);
        s->new_task_queue = [this] { return new CountingQueue(&connections); };
        run = std::make_unique<Running>(std::move(s), [](httplib::Server& svr) {
            svr.Get("/ping", [](const httplib::Request&, httplib::Response& res) { res.set_content("pong", "text/plain"); });
            // Медленная ручка: держит соединение занятым (проверка предела max_total).
            svr.Get("/slow", [](const httplib::Request& req, httplib::Response& res) {
                const int ms = req.has_param("ms") ? std::atoi(req.get_param_value("ms").c_str()) : 150;
                std::this_thread::sleep_for(std::chrono::milliseconds(ms));
                res.set_content("slow", "text/plain");
            });
        });
    }
    int port() const { return run->port(); }
};

httplib::Result ping(nettls::ClientPool& pool) {
    return pool.call([](httplib::Client& c) { return c.Get("/ping"); });
}

} // namespace

TEST(pool_reuses_one_connection_for_sequential_requests_over_mtls) {
    Dir d;
    auto ca = issue("ca", "", nullptr);
    auto srv = issue("wallet-api", "IP:127.0.0.1", ca.get());
    auto cl = issue("wallet-gateway", "DNS:wallet-gateway", ca.get());
    Counted server(nettls::make_server(files(d, "srv", *srv, *ca)));

    nettls::ClientPool pool(url(server.port()), files(d, "cl", *cl, *ca));
    for (int i = 0; i < 6; ++i) {
        auto res = ping(pool);
        REQUIRE(static_cast<bool>(res));
        CHECK_EQ(res->status, 200);
    }
    auto st = pool.stats();
    CHECK_EQ(st.created, static_cast<size_t>(1));
    CHECK_EQ(st.reused, static_cast<size_t>(5));
    // шесть запросов — одно рукопожатие (одно соединение), а не шесть
    CHECK_EQ(server.connections.load(), 1);
}

TEST(pool_recovers_after_server_closes_idle_connection) {
    nettls::Config plain;
    Counted server(std::make_unique<httplib::Server>(), /*keep_alive_sec=*/1);

    nettls::ClientPool pool(url(server.port()), plain);
    REQUIRE(static_cast<bool>(ping(pool)));
    std::this_thread::sleep_for(std::chrono::milliseconds(1600)); // сервер закрыл простой
    auto res = ping(pool);
    REQUIRE(static_cast<bool>(res));
    CHECK_EQ(res->status, 200);
    CHECK_EQ(server.connections.load(), 2); // сервер закрыл простой — понадобилось второе соединение
    CHECK(pool.stats().retried <= 1);
}

TEST(pool_concurrent_calls_get_exclusive_clients) {
    nettls::Config plain;
    Counted server(std::make_unique<httplib::Server>());
    nettls::ClientPool pool(url(server.port()), plain);

    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 10; ++i) {
                auto res = ping(pool);
                if (res && res->status == 200) ++ok;
            }
        });
    }
    for (auto& t : threads) t.join();
    CHECK_EQ(ok.load(), 80);
    auto st = pool.stats();
    CHECK(st.created <= 8); // не больше потоков: клиенты возвращаются в пул
    CHECK(server.connections.load() <= 8);
}

TEST(bounded_pool_never_opens_more_connections_than_max_total) {
    nettls::Config plain;
    Counted server(std::make_unique<httplib::Server>());
    // 12 потоков, предел 3: остальные ждут в очереди пула, лишних соединений нет.
    nettls::ClientPool pool(url(server.port()), plain, 3, 30, /*max_idle=*/2, /*max_total=*/3, /*wait_timeout_sec=*/20);

    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 12; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 3; ++i) {
                auto res = pool.call([](httplib::Client& c) { return c.Get("/slow?ms=60"); });
                if (res && res->status == 200) ++ok;
            }
        });
    }
    for (auto& t : threads) t.join();
    CHECK_EQ(ok.load(), 36);
    auto st = pool.stats();
    CHECK(st.created <= 3);
    CHECK(server.connections.load() <= 3); // все 36 запросов — на трёх постоянных соединениях
    CHECK(st.waited > 0);
    CHECK_EQ(st.timed_out, static_cast<size_t>(0));
}

TEST(bounded_pool_times_out_instead_of_opening_extra_connection) {
    nettls::Config plain;
    Counted server(std::make_unique<httplib::Server>());
    nettls::ClientPool pool(url(server.port()), plain, 3, 30, /*max_idle=*/1, /*max_total=*/1, /*wait_timeout_sec=*/1);

    std::atomic<bool> first_ok{false};
    std::thread holder([&] {
        auto res = pool.call([](httplib::Client& c) { return c.Get("/slow?ms=2200"); });
        first_ok = res && res->status == 200;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // holder занял единственный слот
    const auto t0 = std::chrono::steady_clock::now();
    auto res = ping(pool);
    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(!res);
    CHECK(res.error() == httplib::Error::ConnectionTimeout);
    CHECK(waited >= 900 && waited < 1800); // ждал ≈ wait_timeout_sec, не открыл второе соединение
    holder.join();
    CHECK(first_ok.load());
    CHECK_EQ(server.connections.load(), 1);
    CHECK_EQ(pool.stats().timed_out, static_cast<size_t>(1));
    // слот освободился — следующий запрос проходит на том же постоянном соединении
    auto again = ping(pool);
    REQUIRE(static_cast<bool>(again));
    CHECK_EQ(server.connections.load(), 1);
}

TEST(pool_reports_invalid_tls_config_instead_of_crashing) {
    nettls::Config bad{"/nonexistent/c.pem", "/nonexistent/k.pem", "/nonexistent/ca.pem"};
    nettls::ClientPool pool("http://127.0.0.1:1", bad);
    auto res = ping(pool);
    CHECK(!res);
    CHECK(!pool.error().empty());
}

#ifndef _WIN32
namespace {
void set_env(const char* k, const char* v) {
    if (v) {
        setenv(k, v, 1);
    } else {
        unsetenv(k);
    }
}
} // namespace

TEST(settings_pilot_tls_without_internal_mtls_keeps_servers_and_calls_plain) {
    set_env("TLS_CERT", "/c"); set_env("TLS_KEY", "/k"); set_env("TLS_CA", "/ca"); set_env("INTERNAL_MTLS", nullptr);
    auto s = nettls::settings_from_env();
    CHECK(s.error.empty());
    CHECK(s.config.enabled());
    CHECK(!s.serve);
    CHECK(!s.call_internal);
    CHECK(!nettls::server_config(s).enabled());
    CHECK(!nettls::internal_client_config(s).enabled());
}

TEST(settings_internal_mtls_turns_on_serving_and_internal_calls) {
    set_env("TLS_CERT", "/c"); set_env("TLS_KEY", "/k"); set_env("TLS_CA", "/ca"); set_env("INTERNAL_MTLS", "true");
    auto s = nettls::settings_from_env();
    CHECK(s.error.empty());
    CHECK(s.serve);
    CHECK(s.call_internal);
    CHECK(nettls::server_config(s).enabled());
    CHECK(nettls::internal_client_config(s).enabled());
}

TEST(settings_internal_mtls_without_material_is_an_error) {
    set_env("TLS_CERT", nullptr); set_env("TLS_KEY", nullptr); set_env("TLS_CA", nullptr); set_env("INTERNAL_MTLS", "true");
    auto s = nettls::settings_from_env();
    CHECK(!s.error.empty());
    CHECK(!s.serve);
}

TEST(settings_invalid_internal_mtls_value_is_an_error) {
    set_env("TLS_CERT", nullptr); set_env("TLS_KEY", nullptr); set_env("TLS_CA", nullptr); set_env("INTERNAL_MTLS", "yes");
    CHECK(!nettls::settings_from_env().error.empty());
    set_env("INTERNAL_MTLS", nullptr);
    auto off = nettls::settings_from_env();
    CHECK(off.error.empty());
    CHECK(!off.config.enabled());
}
#endif
