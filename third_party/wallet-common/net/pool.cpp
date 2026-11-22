#include "net/pool.hpp"

#include <algorithm>
#include <chrono>

namespace nettls {

namespace {

// Ошибки, после которых переиспользованное соединение считается протухшим.
bool stale_connection(httplib::Error e) {
    return e == httplib::Error::Read || e == httplib::Error::Write || e == httplib::Error::Connection;
}

} // namespace

ClientPool::ClientPool(std::string base_url, Config cfg, int connect_timeout_sec, int read_timeout_sec,
                       std::size_t max_idle, std::size_t max_total, int wait_timeout_sec)
    : base_url_(std::move(base_url)), cfg_(std::move(cfg)), connect_timeout_sec_(connect_timeout_sec),
      read_timeout_sec_(read_timeout_sec), max_idle_(max_idle), max_total_(max_total),
      wait_timeout_sec_(wait_timeout_sec) {}

std::unique_ptr<httplib::Client> ClientPool::make_fresh() {
    std::string err;
    auto client = make_client(base_url_, cfg_, &err);
    if (!client) {
        std::lock_guard<std::mutex> lock(mu_);
        error_ = err;
        return nullptr;
    }
    client->set_keep_alive(true);
    client->set_connection_timeout(connect_timeout_sec_, 0);
    client->set_read_timeout(read_timeout_sec_, 0);
    client->set_write_timeout(read_timeout_sec_, 0);
    return client;
}

std::unique_ptr<httplib::Client> ClientPool::acquire(bool& fresh, bool& timed_out) {
    timed_out = false;
    {
        std::unique_lock<std::mutex> lock(mu_);
        if (max_total_ > 0 && idle_.empty() && in_use_ >= max_total_) {
            // Предел исчерпан: ждём, пока кто-то вернёт клиента (или освободит место).
            ++stats_.waited;
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(wait_timeout_sec_);
            while (idle_.empty() && in_use_ >= max_total_) {
                if (cv_.wait_until(lock, deadline) == std::cv_status::timeout &&
                    idle_.empty() && in_use_ >= max_total_) {
                    ++stats_.timed_out;
                    timed_out = true;
                    return nullptr;
                }
            }
        }
        ++in_use_;
        if (!idle_.empty()) {
            auto client = std::move(idle_.back());
            idle_.pop_back();
            ++stats_.reused;
            fresh = false;
            return client;
        }
    }
    fresh = true;
    auto client = make_fresh();
    std::lock_guard<std::mutex> lock(mu_);
    if (client) {
        ++stats_.created;
    } else {
        --in_use_;
        cv_.notify_one();
    }
    return client;
}

void ClientPool::release(std::unique_ptr<httplib::Client> client) {
    std::lock_guard<std::mutex> lock(mu_);
    --in_use_;
    // При предельном числе клиентов в простое держим столько же, сколько разрешено всего: иначе лишние
    // закрылись бы и следующий запрос снова платил бы рукопожатие.
    const std::size_t idle_cap = max_total_ > 0 ? (std::max)(max_idle_, max_total_) : max_idle_;
    if (idle_.size() < idle_cap) idle_.push_back(std::move(client));
    cv_.notify_one();
}

void ClientPool::discard() {
    std::lock_guard<std::mutex> lock(mu_);
    --in_use_;
    cv_.notify_one();
}

httplib::Result ClientPool::call(const std::function<httplib::Result(httplib::Client&)>& fn) {
    bool fresh = false;
    bool timed_out = false;
    auto client = acquire(fresh, timed_out);
    if (!client) {
        return httplib::Result{nullptr, timed_out ? httplib::Error::ConnectionTimeout : httplib::Error::Connection};
    }
    httplib::Result res = fn(*client);
    if (!res && !fresh && stale_connection(res.error())) {
        // Сервер закрыл простаивающее соединение — один повтор на свежем клиенте (место под max_total
        // остаётся за этим запросом).
        {
            std::lock_guard<std::mutex> lock(mu_);
            ++stats_.retried;
        }
        client = make_fresh();
        if (!client) {
            discard();
            return httplib::Result{nullptr, httplib::Error::Connection};
        }
        {
            std::lock_guard<std::mutex> lock(mu_);
            ++stats_.created;
        }
        res = fn(*client);
    }
    // Битое соединение в пул не возвращаем.
    if (res) {
        release(std::move(client));
    } else {
        discard();
    }
    return res;
}

ClientPool::Stats ClientPool::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

std::string ClientPool::error() const {
    std::lock_guard<std::mutex> lock(mu_);
    return error_;
}

} // namespace nettls
