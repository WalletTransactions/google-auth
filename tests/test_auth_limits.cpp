// auth_limits (change add-password-auth, 2.2): решение по счётчикам и живой
// прогон на Redis из TEST_REDIS_HOST (без переменной — пропускается).
#include "auth_limits.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>

#include "test_framework.hpp"
#include "util/uuid.hpp"

using auth_limits::detail::Counter;
using auth_limits::detail::evaluate;

TEST(limits_below_both_thresholds_is_ok) {
    AuthConfig c; // 5 по email, 30 по IP
    auto d = evaluate(Counter{4, 800}, Counter{29, 800}, c);
    CHECK(d.verdict == auth_limits::Verdict::Ok);
}

TEST(limits_email_threshold_blocks_at_five) {
    AuthConfig c;
    auto d = evaluate(Counter{5, 600}, Counter{1, 800}, c);
    CHECK(d.verdict == auth_limits::Verdict::Limited);
    CHECK_EQ(d.retry_after_secs, static_cast<int64_t>(600)); // остаток окна блокирующего счётчика
}

TEST(limits_ip_threshold_blocks_at_thirty) {
    AuthConfig c;
    auto d = evaluate(Counter{0, 0}, Counter{30, 120}, c);
    CHECK(d.verdict == auth_limits::Verdict::Limited);
    CHECK_EQ(d.retry_after_secs, static_cast<int64_t>(120));
}

TEST(limits_retry_after_is_the_longest_blocking_window) {
    AuthConfig c;
    auto d = evaluate(Counter{7, 100}, Counter{40, 500}, c);
    CHECK_EQ(d.retry_after_secs, static_cast<int64_t>(500));
    // Не блокирующий счётчик на срок ответа не влияет.
    auto only_email = evaluate(Counter{5, 100}, Counter{3, 900}, c);
    CHECK_EQ(only_email.retry_after_secs, static_cast<int64_t>(100));
}

TEST(limits_retry_after_without_ttl_is_whole_window) {
    AuthConfig c;
    c.fail_window_secs = 900;
    // Ключ без срока (-1) или уже истёкший по дороге: честного остатка нет — целое окно, не 0.
    CHECK_EQ(evaluate(Counter{5, -1}, Counter{0, 0}, c).retry_after_secs, static_cast<int64_t>(900));
    CHECK_EQ(evaluate(Counter{5, 0}, Counter{0, 0}, c).retry_after_secs, static_cast<int64_t>(900));
}

TEST(limits_thresholds_come_from_config) {
    AuthConfig c;
    c.fail_max_per_email = 2;
    c.fail_max_per_ip = 3;
    CHECK(evaluate(Counter{1, 10}, Counter{2, 10}, c).verdict == auth_limits::Verdict::Ok);
    CHECK(evaluate(Counter{2, 10}, Counter{0, 0}, c).verdict == auth_limits::Verdict::Limited);
    CHECK(evaluate(Counter{0, 0}, Counter{3, 10}, c).verdict == auth_limits::Verdict::Limited);
}

TEST(limits_keys_do_not_expose_email) {
    std::string key = auth_limits::email_key("victim@mail.com");
    CHECK(key.rfind("authfail:email:", 0) == 0);
    CHECK(key.find("victim") == std::string::npos);
    CHECK(key.find("@") == std::string::npos);
    // sha256 hex = 64 символа после префикса, разные адреса — разные ключи.
    CHECK_EQ(key.size(), std::string("authfail:email:").size() + 64);
    CHECK(auth_limits::email_key("other@mail.com") != key);
    CHECK_EQ(auth_limits::ip_key("203.0.113.7"), std::string("authfail:ip:203.0.113.7"));
}

namespace {
redis::Client* live_redis() {
    static std::unique_ptr<redis::Client> client;
    static bool tried = false;
    if (!tried) {
        tried = true;
        const char* addr = std::getenv("TEST_REDIS_HOST");
        if (addr != nullptr && *addr != '\0') {
            std::string host = addr;
            int port = 6379;
            auto colon = host.find(':');
            if (colon != std::string::npos) {
                port = std::stoi(host.substr(colon + 1));
                host = host.substr(0, colon);
            }
            client = std::make_unique<redis::Client>(host, port, "");
        }
    }
    return client.get();
}
} // namespace

TEST(it_limits_five_failures_then_limited_then_reset) {
    redis::Client* r = live_redis();
    if (r == nullptr) {
        std::cerr << "  [SKIP] it_limits_five_failures_then_limited_then_reset: нет TEST_REDIS_HOST\n";
        return;
    }
    AuthConfig c;
    c.fail_window_secs = 60;
    std::string email = "it-" + uuidgen::v4() + "@limits.example.com";
    std::string ip = "198.51.100." + std::to_string(std::rand() % 200 + 1) + "-" + uuidgen::v4().substr(0, 6);

    for (int i = 0; i < 5; ++i) {
        CHECK(auth_limits::check(*r, c, email, ip).verdict == auth_limits::Verdict::Ok);
        auth_limits::record_failure(*r, c, email, ip);
    }
    // Шестая попытка — отказ с Retry-After в пределах окна.
    auto blocked = auth_limits::check(*r, c, email, ip);
    CHECK(blocked.verdict == auth_limits::Verdict::Limited);
    CHECK(blocked.retry_after_secs > 0 && blocked.retry_after_secs <= 60);

    // Окно поставлено на оба ключа (иначе блокировка была бы вечной).
    auto email_ttl = r->ttl(auth_limits::email_key(email));
    REQUIRE(email_ttl.has_value());
    CHECK(*email_ttl > 0 && *email_ttl <= 60);

    // Другой адрес с того же IP ещё не заблокирован (до 30 по IP).
    CHECK(auth_limits::check(*r, c, "other-" + email, ip).verdict == auth_limits::Verdict::Ok);

    // Успешный вход сбрасывает счётчик по email.
    auth_limits::reset_email(*r, email);
    CHECK(auth_limits::check(*r, c, email, ip).verdict == auth_limits::Verdict::Ok);

    r->del(auth_limits::ip_key(ip));
}

TEST(it_limits_ip_only_attempts_do_not_touch_email_counter) {
    redis::Client* r = live_redis();
    if (r == nullptr) {
        std::cerr << "  [SKIP] it_limits_ip_only_attempts_do_not_touch_email_counter: нет TEST_REDIS_HOST\n";
        return;
    }
    AuthConfig c;
    c.fail_window_secs = 60;
    c.fail_max_per_ip = 3;
    std::string email = "it-" + uuidgen::v4() + "@limits.example.com";
    std::string ip = "203.0.113.9-" + uuidgen::v4().substr(0, 6);

    for (int i = 0; i < 3; ++i) auth_limits::record_ip_attempt(*r, c, ip);
    CHECK(auth_limits::check_ip(*r, c, ip).verdict == auth_limits::Verdict::Limited);
    CHECK(!r->get(auth_limits::email_key(email)).has_value()); // регистрация чужой почты её не блокирует
    r->del(auth_limits::ip_key(ip));
}

TEST(it_limits_counter_without_ttl_gets_window_on_next_failure) {
    redis::Client* r = live_redis();
    if (r == nullptr) {
        std::cerr << "  [SKIP] it_limits_counter_without_ttl_gets_window_on_next_failure: нет TEST_REDIS_HOST\n";
        return;
    }
    AuthConfig c;
    c.fail_window_secs = 60;
    std::string email = "it-" + uuidgen::v4() + "@limits.example.com";
    std::string ip = "192.0.2.1-" + uuidgen::v4().substr(0, 6);

    // Процесс умер между INCR и EXPIRE: ключ есть, срока нет.
    std::string key = auth_limits::email_key(email);
    r->incr(key);
    auto before = r->ttl(key);
    REQUIRE(before.has_value());
    CHECK_EQ(*before, static_cast<int64_t>(-1));

    auth_limits::record_failure(*r, c, email, ip);
    auto after = r->ttl(key);
    REQUIRE(after.has_value());
    CHECK(*after > 0 && *after <= 60);

    r->del(key);
    r->del(auth_limits::ip_key(ip));
}
