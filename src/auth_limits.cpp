#include "auth_limits.hpp"

#include <algorithm>
#include <exception>

#include "nlohmann/json.hpp"
#include "util/crypto.hpp"
#include "util/hex.hpp"
#include "util/log.hpp"

namespace auth_limits {

namespace {

constexpr const char* kEmailPrefix = "authfail:email:";
constexpr const char* kIpPrefix = "authfail:ip:";

// Текущее значение счётчика и остаток окна. Нет ключа — count 0.
detail::Counter read_counter(redis::Client& redis, const std::string& key) {
    detail::Counter c;
    auto raw = redis.get(key);
    if (!raw) return c;
    try {
        c.count = std::stoll(*raw);
    } catch (const std::exception&) {
        c.count = 0;
    }
    auto ttl = redis.ttl(key);
    c.ttl_secs = ttl ? *ttl : 0;
    return c;
}

// INCR + срок окна. Срок ставится при создании счётчика (n == 1); если процесс
// умер между INCR и EXPIRE, ключ остался бы без срока — тогда следующая
// неудача его добавит, и блокировка не станет вечной.
void bump(redis::Client& redis, const std::string& key, uint64_t window_secs) {
    int64_t n = redis.incr(key);
    if (n == 1) {
        redis.expire(key, window_secs);
        return;
    }
    auto ttl = redis.ttl(key);
    if (ttl && *ttl == -1) redis.expire(key, window_secs);
}

} // namespace

std::string email_key(const std::string& email) {
    auto digest = crypto::sha256(email);
    return kEmailPrefix + hex::encode(std::string(digest.begin(), digest.end()));
}

std::string ip_key(const std::string& ip) { return kIpPrefix + ip; }

namespace detail {

Decision evaluate(const Counter& email, const Counter& ip, const AuthConfig& config) {
    Decision d;
    bool email_blocked = email.count >= config.fail_max_per_email;
    bool ip_blocked = ip.count >= config.fail_max_per_ip;
    if (!email_blocked && !ip_blocked) return d;

    d.verdict = Verdict::Limited;
    // Retry-After — когда сбросится последний из блокирующих счётчиков. Если
    // у ключа нет срока (-1) или он уже истёк по дороге (<= 0), честного
    // остатка нет — отдаём целое окно, а не 0: клиент с 0 сразу ломился бы снова.
    auto remaining = [&config](const Counter& c) {
        return c.ttl_secs > 0 ? c.ttl_secs : static_cast<int64_t>(config.fail_window_secs);
    };
    int64_t wait = 1;
    if (email_blocked) wait = std::max(wait, remaining(email));
    if (ip_blocked) wait = std::max(wait, remaining(ip));
    d.retry_after_secs = wait;
    return d;
}

} // namespace detail

Decision check(redis::Client& redis, const AuthConfig& config, const std::string& email,
               const std::string& ip) {
    try {
        return detail::evaluate(read_counter(redis, email_key(email)), read_counter(redis, ip_key(ip)), config);
    } catch (const std::exception& ex) {
        applog::error("auth limits: Redis недоступен", {{"event", "auth_limits_unavailable"}, {"error", ex.what()}});
        return Decision{Verdict::Unavailable, 0};
    }
}

Decision check_ip(redis::Client& redis, const AuthConfig& config, const std::string& ip) {
    try {
        // Счётчик email для сравнения — нулевой: его порог здесь не применяется.
        return detail::evaluate(detail::Counter{}, read_counter(redis, ip_key(ip)), config);
    } catch (const std::exception& ex) {
        applog::error("auth limits: Redis недоступен", {{"event", "auth_limits_unavailable"}, {"error", ex.what()}});
        return Decision{Verdict::Unavailable, 0};
    }
}

void record_failure(redis::Client& redis, const AuthConfig& config, const std::string& email,
                    const std::string& ip) {
    try {
        bump(redis, email_key(email), config.fail_window_secs);
        bump(redis, ip_key(ip), config.fail_window_secs);
    } catch (const std::exception& ex) {
        applog::error("auth limits: не удалось записать неудачу", {{"event", "auth_limits_unavailable"}, {"error", ex.what()}});
    }
}

void record_ip_attempt(redis::Client& redis, const AuthConfig& config, const std::string& ip) {
    try {
        bump(redis, ip_key(ip), config.fail_window_secs);
    } catch (const std::exception& ex) {
        applog::error("auth limits: не удалось записать попытку", {{"event", "auth_limits_unavailable"}, {"error", ex.what()}});
    }
}

void reset_email(redis::Client& redis, const std::string& email) {
    try {
        redis.del(email_key(email));
    } catch (const std::exception& ex) {
        applog::error("auth limits: не удалось сбросить счётчик", {{"event", "auth_limits_unavailable"}, {"error", ex.what()}});
    }
}

} // namespace auth_limits
