// Разбор скалярных ответов Redis для INCR/TTL (change add-password-auth, 2.1) и
// живой прогон команд на Redis из TEST_REDIS_HOST[:PORT] (без переменной —
// пропускается).
#include <cstdlib>
#include <iostream>
#include <memory>

#include "redis_client.hpp"
#include "test_framework.hpp"
#include "util/uuid.hpp"

TEST(redis_parse_integer_values) {
    CHECK_EQ(redis::detail::parse_integer(std::string("1")), 1);
    CHECK_EQ(redis::detail::parse_integer(std::string("42")), 42);
    CHECK_EQ(redis::detail::parse_integer(std::string("0")), 0);
    CHECK_EQ(redis::detail::parse_integer(std::string("-1")), -1);
    CHECK_EQ(redis::detail::parse_integer(std::string("9007199254740993")), 9007199254740993LL);
}

TEST(redis_parse_integer_rejects_garbage) {
    CHECK_THROWS(redis::detail::parse_integer(std::nullopt)); // null bulk
    CHECK_THROWS(redis::detail::parse_integer(std::string("")));
    CHECK_THROWS(redis::detail::parse_integer(std::string("OK")));
    CHECK_THROWS(redis::detail::parse_integer(std::string("12abc")));
    CHECK_THROWS(redis::detail::parse_integer(std::string("1.5")));
}

TEST(redis_parse_ttl_codes) {
    CHECK(!redis::detail::parse_ttl(std::string("-2")).has_value()); // ключа нет
    auto no_expire = redis::detail::parse_ttl(std::string("-1"));    // ключ без срока
    REQUIRE(no_expire.has_value());
    CHECK_EQ(*no_expire, -1);
    auto left = redis::detail::parse_ttl(std::string("899"));
    REQUIRE(left.has_value());
    CHECK_EQ(*left, 899);
    CHECK_THROWS(redis::detail::parse_ttl(std::nullopt));
}

namespace {
redis::Client* test_redis() {
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

TEST(it_redis_incr_expire_ttl) {
    redis::Client* r = test_redis();
    if (r == nullptr) {
        std::cerr << "  [SKIP] it_redis_incr_expire_ttl: нет TEST_REDIS_HOST\n";
        return;
    }
    std::string key = "ga-test:incr:" + uuidgen::v4();

    CHECK(!r->ttl(key).has_value()); // ключа нет
    CHECK_EQ(r->incr(key), 1);
    auto no_ttl = r->ttl(key);
    REQUIRE(no_ttl.has_value());
    CHECK_EQ(*no_ttl, -1); // INCR срок не ставит
    CHECK_EQ(r->incr(key), 2);
    CHECK_EQ(r->incr(key), 3);

    r->expire(key, 100);
    auto left = r->ttl(key);
    REQUIRE(left.has_value());
    CHECK(*left > 0 && *left <= 100);

    r->del(key);
    CHECK(!r->ttl(key).has_value());
}

TEST(redis_auth_command_without_user_is_password_only) {
    auto cmd = redis::detail::auth_command("", "s3cret");
    CHECK_EQ(cmd.size(), static_cast<size_t>(2));
    CHECK_EQ(cmd[0], std::string("AUTH"));
    CHECK_EQ(cmd[1], std::string("s3cret"));
}

TEST(redis_auth_command_with_user_puts_user_first) {
    auto cmd = redis::detail::auth_command("google-auth", "s3cret");
    CHECK_EQ(cmd.size(), static_cast<size_t>(3));
    CHECK_EQ(cmd[0], std::string("AUTH"));
    CHECK_EQ(cmd[1], std::string("google-auth"));
    CHECK_EQ(cmd[2], std::string("s3cret"));
}
