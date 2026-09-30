// Юнит-тесты telegram.cpp — чистые помощники (telegram::detail) и
// reject-пути POST /internal/telegram/exchange, которые отвечают до похода в
// Redis/Postgres (state.redis/db_pool == nullptr здесь безопасны — тот же
// приём, что в test_auth.cpp). Сам обмен кода (GETDEL + issue_tokens)
// требует живого Redis — проверяется вживую, см. tests/README.md.
#include "telegram.hpp"

#include <thread>

#include "httplib.h"
#include "nlohmann/json.hpp"
#include "test_framework.hpp"
#include "token_claims.hpp"
#include "types.hpp"
#include "util/uuid.hpp"

using nlohmann::json;

// ---- device_id_for ----

TEST(telegram_device_id_is_valid_uuid) {
    std::string id = telegram::detail::device_id_for("3f1c0000-0000-4000-8000-000000000001", "211959201");
    CHECK(uuidgen::looks_valid(id));
    CHECK_EQ(id[14], '5');  // версия
    CHECK(id[19] == '8' || id[19] == '9' || id[19] == 'a' || id[19] == 'b');  // вариант RFC 4122
}

TEST(telegram_device_id_is_deterministic) {
    CHECK_EQ(telegram::detail::device_id_for("u1", "42"), telegram::detail::device_id_for("u1", "42"));
}

TEST(telegram_device_id_differs_per_user_and_per_chat) {
    // Один Telegram-аккаунт у двух пользователей — два разных устройства
    // (device.id в wallet-api — PK, см. комментарий в telegram.hpp).
    CHECK(telegram::detail::device_id_for("u1", "42") != telegram::detail::device_id_for("u2", "42"));
    CHECK(telegram::detail::device_id_for("u1", "42") != telegram::detail::device_id_for("u1", "43"));
}

// ---- normalize_tg_user_id ----

TEST(telegram_normalize_tg_user_id_accepts_digits) {
    CHECK_EQ(telegram::detail::normalize_tg_user_id("211959201"), std::string("211959201"));
}

TEST(telegram_normalize_tg_user_id_rejects_garbage) {
    CHECK(telegram::detail::normalize_tg_user_id("").empty());
    CHECK(telegram::detail::normalize_tg_user_id("0").empty());
    CHECK(telegram::detail::normalize_tg_user_id("007").empty());
    CHECK(telegram::detail::normalize_tg_user_id("-5").empty());
    CHECK(telegram::detail::normalize_tg_user_id("12a").empty());
    CHECK(telegram::detail::normalize_tg_user_id("123456789012345678901").empty()); // 21 цифра
}

// ---- device_name_for ----

TEST(telegram_device_name_prefers_username) {
    CHECK_EQ(telegram::detail::device_name_for("ivan", "1"), std::string("Telegram @ivan"));
    CHECK_EQ(telegram::detail::device_name_for("@ivan", "1"), std::string("Telegram @ivan"));
    CHECK_EQ(telegram::detail::device_name_for("", "211959201"), std::string("Telegram 211959201"));
}

TEST(telegram_device_name_truncates_long_username) {
    std::string name = telegram::detail::device_name_for(std::string(200, 'x'), "1");
    CHECK_EQ(name.size(), std::string("Telegram @").size() + 64);
}

// ---- secret_matches ----

TEST(telegram_secret_matches) {
    CHECK(telegram::detail::secret_matches("s3cret", "s3cret"));
    CHECK(!telegram::detail::secret_matches("s3cret", "s3creT"));
    CHECK(!telegram::detail::secret_matches("s3cret", ""));
    // Незаданный секрет не совпадает ни с чем, даже с пустым заголовком.
    CHECK(!telegram::detail::secret_matches("", ""));
}

// ---- is_mobile_login_platform (types.hpp) ----

TEST(types_mobile_login_platform_whitelist) {
    CHECK(is_mobile_login_platform("android"));
    CHECK(is_mobile_login_platform("ios"));
    CHECK(is_mobile_login_platform("other"));
    CHECK(!is_mobile_login_platform("telegram")); // только через обмен кода
    CHECK(!is_mobile_login_platform("foo"));
    CHECK(!is_mobile_login_platform("Android"));
}

// ---- POST /internal/telegram/exchange: reject-пути без Redis ----

namespace {

httplib::Response call(AppState& state, const std::string& method, const std::string& path,
                       const std::string& secret_header, const std::string& body) {
    httplib::Server svr;
    telegram::register_routes(svr, state);
    // Обработчики скрыты в анонимном namespace telegram.cpp — дёргаем их
    // так же, как бот: HTTP-запросом к локальному серверу на свободном порту.
    int port = svr.bind_to_any_port("127.0.0.1");
    std::thread t([&] { svr.listen_after_bind(); });
    httplib::Client cli("127.0.0.1", port);
    httplib::Headers headers;
    if (!secret_header.empty()) headers.emplace("X-Service-Secret", secret_header);
    httplib::Result res = method == "GET"      ? cli.Get(path, headers)
                          : method == "DELETE" ? cli.Delete(path, headers)
                                               : cli.Post(path, headers, body, "application/json");
    svr.stop();
    t.join();
    httplib::Response out;
    if (res) {
        out.status = res->status;
        out.body = res->body;
    }
    return out;
}

httplib::Response post_exchange(AppState& state, const std::string& secret_header, const std::string& body) {
    return call(state, "POST", "/internal/telegram/exchange", secret_header, body);
}

} // namespace

TEST(telegram_exchange_disabled_without_secret) {
    AppState state;
    CHECK_EQ(post_exchange(state, "anything", "{}").status, 503);
}

TEST(telegram_exchange_rejects_wrong_secret) {
    AppState state;
    state.telegram_service_secret = "s3cret";
    CHECK_EQ(post_exchange(state, "wrong", "{}").status, 401);
    CHECK_EQ(post_exchange(state, "", "{}").status, 401);
}

TEST(telegram_exchange_rejects_bad_body) {
    AppState state;
    state.telegram_service_secret = "s3cret";
    CHECK_EQ(post_exchange(state, "s3cret", "not json").status, 400);
    CHECK_EQ(post_exchange(state, "s3cret", R"({"code":"abc"})").status, 400);
    CHECK_EQ(post_exchange(state, "s3cret", R"({"code":"abc","tg_user_id":-1})").status, 400);
    CHECK_EQ(post_exchange(state, "s3cret", R"({"tg_user_id":42})").status, 400);
}

// ---- POST /internal/telegram/token и /auth/telegram/links: reject-пути без БД ----

TEST(telegram_token_requires_bot_secret) {
    AppState disabled;
    CHECK_EQ(call(disabled, "POST", "/internal/telegram/token", "x", R"({"tg_user_id":42})").status, 503);

    AppState state;
    state.telegram_service_secret = "s3cret";
    CHECK_EQ(call(state, "POST", "/internal/telegram/token", "wrong", R"({"tg_user_id":42})").status, 401);
    CHECK_EQ(call(state, "POST", "/internal/telegram/token", "", R"({"tg_user_id":42})").status, 401);
}

TEST(telegram_token_rejects_bad_body) {
    AppState state;
    state.telegram_service_secret = "s3cret";
    CHECK_EQ(call(state, "POST", "/internal/telegram/token", "s3cret", "not json").status, 400);
    CHECK_EQ(call(state, "POST", "/internal/telegram/token", "s3cret", "{}").status, 400);
    CHECK_EQ(call(state, "POST", "/internal/telegram/token", "s3cret", R"({"tg_user_id":"007"})").status, 400);
    CHECK_EQ(call(state, "POST", "/internal/telegram/token", "s3cret", R"({"tg_user_id":-5})").status, 400);
}

TEST(telegram_internal_unlink_requires_bot_secret_and_valid_id) {
    AppState state;
    state.telegram_service_secret = "s3cret";
    CHECK_EQ(call(state, "DELETE", "/internal/telegram/links/42", "wrong", "").status, 401);
    CHECK_EQ(call(state, "DELETE", "/internal/telegram/links/42", "", "").status, 401);
    CHECK_EQ(call(state, "DELETE", "/internal/telegram/links/007", "s3cret", "").status, 400);
    CHECK_EQ(call(state, "DELETE", "/internal/telegram/links/abc", "s3cret", "").status, 400);
}

// Ручки веба — только с пользовательским токеном; сервисный секрет бота их
// не открывает.
TEST(telegram_links_require_user_session) {
    AppState state;
    state.telegram_service_secret = "s3cret";
    CHECK_EQ(call(state, "GET", "/auth/telegram/links", "s3cret", "").status, 401);
    CHECK_EQ(call(state, "DELETE", "/auth/telegram/links/42", "s3cret", "").status, 401);
}

// Подписанный токен бота: claims — из token_claims (урезанный aud без
// google-auth, узкий scope, 5 минут).
TEST(telegram_bot_claims) {
    json payload = {{"sub", "u1"}};
    token_claims::add_telegram_bot_claims(payload);
    CHECK_EQ(payload.at("iss").get<std::string>(), std::string("google-auth"));
    CHECK_EQ(payload.at("scope").get<std::string>(), std::string("reports:read expense:write"));
    REQUIRE(payload.at("aud").size() == 2u);
    CHECK_EQ(payload.at("aud")[0].get<std::string>(), std::string("wallet-report"));
    CHECK_EQ(payload.at("aud")[1].get<std::string>(), std::string("wallet-api"));
    CHECK_EQ(token_claims::kTelegramBotTokenTtlSecs, 300);
}
