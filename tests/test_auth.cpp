// Юнит-тесты auth.cpp — только та часть, что не требует живых Postgres/
// Redis. authenticate() дереференсит state.redis ТОЛЬКО на "счастливом"
// пути (подпись верна И токен не истёк, см. auth.cpp) — все тесты ниже
// специально не доходят до этой точки, поэтому AppState с db/redis == nullptr
// безопасен. Что здесь НЕ покрыто и почему — см. tests/README.md.
#include "auth.hpp"

#include <memory>

#include "httplib.h"
#include "nlohmann/json.hpp"
#include "rsa_test_key.hpp"
#include "test_framework.hpp"
#include "util/jwt.hpp"
#include "util/time.hpp"
#include "util/uuid.hpp"

using nlohmann::json;

namespace {

void configure_state(AppState& state, const std::string& key_path) {
    // AppState нельзя вернуть по значению (внутри std::mutex — не копируется
    // и не гарантированно перемещается стандартом), поэтому настраиваем
    // существующий объект, а не строим и возвращаем новый.
    state.jwt_signing_key = std::make_unique<crypto::RsaSigningKey>(key_path);
    state.cookie_secure = false;
    state.access_token_ttl_secs = 900;
    state.refresh_token_ttl_secs = 60ULL * 60 * 24 * 30;
}

std::string make_signed_token(const AppState& state, json payload, std::uint64_t exp) {
    payload["exp"] = exp;
    return jwt::sign_rs256(payload, *state.jwt_signing_key);
}

} // namespace

// ---- authenticate(): reject-пути, не требующие Redis ----

// iss/aud/scope (TODO_telegram_tokens.md, шаг 2) проверяются ДО Redis:
// state.redis здесь не поднят — если бы проверка не отклонила токен,
// authenticate() полез бы в пустой указатель.
TEST(auth_authenticate_rejects_token_for_other_audience_or_scope) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());
    auto exp = timeutil::now_epoch() + 900;

    // Токен Telegram-бота: google-auth в aud нет.
    json bot = {{"sub", "u1"},
                {"iss", "google-auth"},
                {"aud", json::array({"wallet-report", "wallet-api"})},
                {"scope", "reports:read expense:write"}};
    httplib::Request req_bot;
    req_bot.set_header("Authorization", "Bearer " + make_signed_token(state, bot, exp));
    CHECK(!auth::authenticate(req_bot, state).has_value());

    // aud верный, но без scope account.
    json no_account = {{"sub", "u1"}, {"iss", "google-auth"}, {"aud", "google-auth"}, {"scope", "wallet:read"}};
    httplib::Request req_scope;
    req_scope.set_header("Authorization", "Bearer " + make_signed_token(state, no_account, exp));
    CHECK(!auth::authenticate(req_scope, state).has_value());

    // Чужой iss.
    json evil = {{"sub", "u1"}, {"iss", "evil"}, {"aud", "google-auth"}, {"scope", "account"}};
    httplib::Request req_iss;
    req_iss.set_header("Authorization", "Bearer " + make_signed_token(state, evil, exp));
    CHECK(!auth::authenticate(req_iss, state).has_value());

    // Старый токен без aud (шаг 3) — отказ по claims, до Redis.
    json legacy = {{"sub", "u1"}};
    httplib::Request req_legacy;
    req_legacy.set_header("Authorization", "Bearer " + make_signed_token(state, legacy, exp));
    CHECK(!auth::authenticate(req_legacy, state).has_value());
}

TEST(auth_authenticate_returns_nullopt_without_any_token) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());

    httplib::Request req;
    CHECK(!auth::authenticate(req, state).has_value());
}

TEST(auth_authenticate_rejects_garbage_bearer_token) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());

    httplib::Request req;
    req.set_header("Authorization", "Bearer not-a-real-jwt");
    CHECK(!auth::authenticate(req, state).has_value());
}

TEST(auth_authenticate_ignores_non_bearer_authorization_header) {
    // "Authorization: Basic ..." — не наш формат; extract_bearer() (см.
    // auth.cpp) должен просто не найти токен, а не пытаться разобрать это
    // как JWT.
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());

    httplib::Request req;
    req.set_header("Authorization", "Basic dXNlcjpwYXNz");
    CHECK(!auth::authenticate(req, state).has_value());
}

TEST(auth_authenticate_rejects_token_signed_by_a_different_key) {
    TempRsaKeyFile key_file;
    TempRsaKeyFile other_key_file;
    AppState state;
    configure_state(state, key_file.path());
    crypto::RsaSigningKey other_key(other_key_file.path());

    std::string token =
        jwt::sign_rs256(json{{"sub", "u1"}, {"exp", timeutil::now_epoch() + 900}}, other_key);

    httplib::Request req;
    req.set_header("Authorization", "Bearer " + token);
    CHECK(!auth::authenticate(req, state).has_value());
}

TEST(auth_authenticate_rejects_expired_token) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());

    std::string token = make_signed_token(state, json{{"sub", "u1"}}, timeutil::now_epoch() - 3600);

    httplib::Request req;
    req.set_header("Authorization", "Bearer " + token);
    CHECK(!auth::authenticate(req, state).has_value());
}

TEST(auth_authenticate_rejects_token_without_exp_claim) {
    // Отсутствие "exp" трактуется как "истёк" (см. `!payload->contains("exp")`
    // в auth.cpp) — токен без срока действия не должен работать вечно.
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());
    std::string token = jwt::sign_rs256(json{{"sub", "u1"}}, *state.jwt_signing_key);

    httplib::Request req;
    req.set_header("Authorization", "Bearer " + token);
    CHECK(!auth::authenticate(req, state).has_value());
}

TEST(auth_authenticate_also_checks_token_from_session_cookie) {
    // Тот же контракт (подпись + exp), только источник токена — cookie
    // "session", а не заголовок Authorization (см. extract_cookie() в
    // auth.cpp).
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());
    std::string token = make_signed_token(state, json{{"sub", "u1"}}, timeutil::now_epoch() - 3600);

    httplib::Request req;
    req.set_header("Cookie", "other=1; session=" + token + "; another=2");
    CHECK(!auth::authenticate(req, state).has_value());
}

// ---- set_session_cookies() / clear_session_cookies() ----

TEST(auth_set_session_cookies_sets_both_cookies_with_expected_values) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());
    auth::TokenPair tokens{"access-value", "refresh-value"};

    httplib::Response res;
    auth::set_session_cookies(res, state, tokens);

    CHECK_EQ(res.get_header_value_count("Set-Cookie"), static_cast<std::size_t>(2));
    std::string access_cookie = res.get_header_value("Set-Cookie", "", 0);
    std::string refresh_cookie = res.get_header_value("Set-Cookie", "", 1);

    CHECK(access_cookie.find("session=access-value") != std::string::npos);
    CHECK(access_cookie.find("Path=/;") != std::string::npos);
    CHECK(access_cookie.find("HttpOnly") != std::string::npos);
    CHECK(access_cookie.find("SameSite=Lax") != std::string::npos);

    CHECK(refresh_cookie.find("refresh_token=refresh-value") != std::string::npos);
    // Path=/auth — не /: браузер не должен слать refresh-токен на /api/*.
    CHECK(refresh_cookie.find("Path=/auth;") != std::string::npos);
    CHECK(refresh_cookie.find("Max-Age=" + std::to_string(state.refresh_token_ttl_secs)) !=
          std::string::npos);
}

TEST(auth_set_session_cookies_access_cookie_has_no_max_age) {
    // Access-cookie — session cookie (без Max-Age): сам JWT истекает по exp,
    // см. комментарий над set_session_cookies() в auth.cpp.
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());
    auth::TokenPair tokens{"a", "b"};

    httplib::Response res;
    auth::set_session_cookies(res, state, tokens);

    CHECK(res.get_header_value("Set-Cookie", "", 0).find("Max-Age") == std::string::npos);
}

TEST(auth_set_session_cookies_marks_secure_when_configured) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());
    state.cookie_secure = true;
    auth::TokenPair tokens{"a", "b"};

    httplib::Response res;
    auth::set_session_cookies(res, state, tokens);

    CHECK(res.get_header_value("Set-Cookie", "", 0).find("; Secure") != std::string::npos);
    CHECK(res.get_header_value("Set-Cookie", "", 1).find("; Secure") != std::string::npos);
}

TEST(auth_set_session_cookies_omits_secure_when_not_configured) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());
    state.cookie_secure = false;
    auth::TokenPair tokens{"a", "b"};

    httplib::Response res;
    auth::set_session_cookies(res, state, tokens);

    CHECK(res.get_header_value("Set-Cookie", "", 0).find("Secure") == std::string::npos);
}

TEST(auth_clear_session_cookies_expires_both_cookies_immediately) {
    TempRsaKeyFile key_file;
    AppState state;
    configure_state(state, key_file.path());

    httplib::Response res;
    auth::clear_session_cookies(res, state);

    CHECK_EQ(res.get_header_value_count("Set-Cookie"), static_cast<std::size_t>(2));
    CHECK(res.get_header_value("Set-Cookie", "", 0).find("session=;") != std::string::npos);
    CHECK(res.get_header_value("Set-Cookie", "", 0).find("Max-Age=0") != std::string::npos);
    CHECK(res.get_header_value("Set-Cookie", "", 1).find("refresh_token=;") != std::string::npos);
    CHECK(res.get_header_value("Set-Cookie", "", 1).find("Max-Age=0") != std::string::npos);
}

// ---- ensure_browser_device_id(): ленивая выдача device_id браузеру ----
// Сам rotate_refresh_token здесь не вызвать (Redis), поэтому проверяется
// функция, которую он применяет к устройству старой сессии перед issue_tokens.

TEST(auth_ensure_browser_device_id_fills_empty_web_device) {
    DeviceInfo device;
    device.platform = "web";
    auth::ensure_browser_device_id(device);
    CHECK(uuidgen::looks_valid(device.device_id));
}

TEST(auth_ensure_browser_device_id_keeps_existing_web_device_id) {
    DeviceInfo device;
    device.platform = "web";
    device.device_id = "11111111-2222-4333-8444-555555555555";
    auth::ensure_browser_device_id(device);
    CHECK_EQ(device.device_id, std::string("11111111-2222-4333-8444-555555555555"));
}

TEST(auth_ensure_browser_device_id_ignores_non_web_platforms) {
    DeviceInfo device;
    device.platform = "android";
    auth::ensure_browser_device_id(device);
    CHECK(device.device_id.empty());
}

TEST(auth_ensure_browser_device_id_gives_each_session_its_own_id) {
    DeviceInfo a, b;
    a.platform = b.platform = "web";
    auth::ensure_browser_device_id(a);
    auth::ensure_browser_device_id(b);
    CHECK(a.device_id != b.device_id);
}
