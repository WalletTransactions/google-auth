// Обмен токена (change add-token-exchange): таблица политики, разбор
// TOKEN_EXCHANGE_SECRETS и form-тела, и сам обработчик POST
// /internal/token/exchange целиком — он не ходит ни в Redis, ни в Postgres,
// поэтому AppState с db/redis == nullptr ему достаточно.
#include "token_exchange.hpp"

#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "auth.hpp"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "rsa_test_key.hpp"
#include "test_framework.hpp"
#include "util/jwt.hpp"
#include "util/log.hpp"
#include "util/time.hpp"

using nlohmann::json;
using token_exchange::detail::Outcome;

namespace {

constexpr const char* kAiSecret = "ai-secret-value-123";
constexpr const char* kMcpSecret = "mcp-secret-value-456";

// Один ключ на файл: генерация RSA-2048 — заметная доля времени тестов.
TempRsaKeyFile& key_file() {
    static TempRsaKeyFile f;
    return f;
}

void configure(AppState& state, bool enabled = true) {
    state.jwt_signing_key = std::make_unique<crypto::RsaSigningKey>(key_file().path());
    if (enabled) state.token_exchange_secrets = {{"wallet-ai", kAiSecret}, {"wallet-mcp", kMcpSecret}};
}

// JWT бота (/internal/telegram/token) — типичный subject для wallet-ai.
json bot_claims(std::uint64_t exp) {
    return {{"sub", "user-1"},
            {"iss", "google-auth"},
            {"aud", json::array({"wallet-report", "wallet-api", "wallet-ai"})},
            {"scope", "reports:read expense:write ai:use"},
            {"device_id", "dev-1"},
            {"platform", "telegram"},
            {"iat", timeutil::now_epoch()},
            {"exp", exp}};
}

// JWT веб-сессии администратора.
json web_admin_claims(std::uint64_t exp) {
    return {{"sub", "admin-1"},
            {"iss", "google-auth"},
            {"aud", json::array({"wallet-api", "wallet-report", "google-auth", "wallet-ai"})},
            {"scope", "wallet:read wallet:write reports:read account ai:use"},
            {"role", "admin"},
            {"email", "admin@example.com"},
            {"name", "Admin"},
            {"device_id", "web-1"},
            {"platform", "web"},
            {"exp", exp}};
}

std::string sign(const AppState& state, const json& payload) {
    return jwt::sign_rs256(payload, *state.jwt_signing_key);
}

httplib::Request make_request(const std::string& secret, const httplib::Params& form) {
    httplib::Request req;
    req.method = "POST";
    req.path = "/internal/token/exchange";
    if (!secret.empty()) req.set_header("X-Service-Secret", secret);
    req.set_header("Content-Type", "application/x-www-form-urlencoded");
    req.body = httplib::detail::params_to_query_str(form);
    return req;
}

// Форма ровно как у wallet-mcp (../wallet-mcp/src/auth_client.cpp,
// HttpAuthApi::exchange_jwt): без scope.
httplib::Params exchange_form(const std::string& subject_token, const std::string& audience) {
    return {{"grant_type", token_exchange::kGrantType},
            {"subject_token", subject_token},
            {"subject_token_type", token_exchange::kTokenTypeAccessToken},
            {"audience", audience}};
}

struct Result {
    int status = 0;
    json body;
};

Result call(AppState& state, const httplib::Request& req) {
    httplib::Response res;
    token_exchange::detail::handle_exchange(state, req, res);
    return {res.status, json::parse(res.body, nullptr, false)};
}

std::string error_of(const Result& r) { return r.body.is_object() ? r.body.value("error", std::string()) : ""; }

json verify(const AppState& state, const std::string& token) {
    auto p = jwt::verify_rs256(token, state.jwt_signing_key->modulus(), state.jwt_signing_key->exponent());
    if (!p) throw std::runtime_error("выданный токен не проверяется ключом google-auth");
    return *p;
}

} // namespace

// ---- decide(): таблица политики ----

TEST(exchange_decide_wallet_ai_to_wallet_mcp) {
    auto d = token_exchange::detail::decide("wallet-ai", bot_claims(9999999999), "wallet-mcp", std::nullopt);
    CHECK(d.outcome == Outcome::Ok);
    CHECK_EQ(d.audience, std::string("wallet-mcp"));
    CHECK_EQ(d.scope, std::string("mcp:read"));
}

TEST(exchange_decide_wallet_mcp_to_wallet_report) {
    json subject = {{"sub", "u"}, {"iss", "google-auth"}, {"aud", json::array({"wallet-mcp"})}, {"scope", "mcp:read"}};
    auto d = token_exchange::detail::decide("wallet-mcp", subject, "wallet-report", std::string("reports:read"));
    CHECK(d.outcome == Outcome::Ok);
    CHECK_EQ(d.audience, std::string("wallet-report"));
    CHECK_EQ(d.scope, std::string("reports:read"));
}

// change docs-mcp-audience: пара wallet-mcp → wallet-docs.
TEST(exchange_decide_wallet_mcp_to_wallet_docs) {
    json subject = {{"sub", "u"}, {"iss", "google-auth"}, {"aud", json::array({"wallet-mcp"})}, {"scope", "mcp:read"}};
    auto d = token_exchange::detail::decide("wallet-mcp", subject, "wallet-docs", std::nullopt);
    CHECK(d.outcome == Outcome::Ok);
    CHECK_EQ(d.audience, std::string("wallet-docs"));
    CHECK_EQ(d.scope, std::string("docs:ask"));
    CHECK(token_exchange::detail::decide("wallet-mcp", subject, "wallet-docs", std::string("docs:ask")).outcome ==
          Outcome::Ok);
    // scope нельзя расширить и подменить на чужой.
    CHECK(token_exchange::detail::decide("wallet-mcp", subject, "wallet-docs", std::string("docs:ask reports:read"))
              .outcome == Outcome::InvalidScope);
    CHECK(token_exchange::detail::decide("wallet-mcp", subject, "wallet-docs", std::string("reports:read")).outcome ==
          Outcome::InvalidScope);
    // subject без wallet-mcp в aud — invalid_grant.
    CHECK(token_exchange::detail::decide("wallet-mcp", web_admin_claims(9999999999), "wallet-docs", std::nullopt)
              .outcome == Outcome::InvalidGrant);
    // wallet-ai справку не получает.
    CHECK(token_exchange::detail::decide("wallet-ai", bot_claims(9999999999), "wallet-docs", std::nullopt).outcome ==
          Outcome::InvalidTarget);
}

TEST(exchange_wallet_mcp_docs_token_inherits_platform_without_role) {
    AppState state;
    configure(state);
    json subject = {{"sub", "u1"},
                    {"iss", "google-auth"},
                    {"aud", json::array({"wallet-mcp"})},
                    {"scope", "mcp:read"},
                    {"role", "admin"},
                    {"device_id", "dev-9"},
                    {"platform", "android"},
                    {"exp", timeutil::now_epoch() + 300}};
    auto r = call(state, make_request(kMcpSecret, exchange_form(sign(state, subject), "wallet-docs")));
    CHECK_EQ(r.status, 200);
    json p = verify(state, r.body.at("access_token").get<std::string>());
    CHECK_EQ(p.at("aud"), (json::array({"wallet-docs"})));
    CHECK_EQ(p.at("scope").get<std::string>(), std::string("docs:ask"));
    CHECK_EQ(p.at("platform").get<std::string>(), std::string("android"));
    CHECK_EQ(p.at("device_id").get<std::string>(), std::string("dev-9"));
    CHECK(!p.contains("role"));
}

TEST(exchange_decide_foreign_audience_is_invalid_target) {
    json bot = bot_claims(9999999999);
    CHECK(token_exchange::detail::decide("wallet-ai", bot, "wallet-api", std::nullopt).outcome ==
          Outcome::InvalidTarget);
    CHECK(token_exchange::detail::decide("wallet-ai", bot, "wallet-report", std::nullopt).outcome ==
          Outcome::InvalidTarget);
    CHECK(token_exchange::detail::decide("wallet-mcp", bot, "wallet-mcp", std::nullopt).outcome ==
          Outcome::InvalidTarget);
    CHECK(token_exchange::detail::decide("stranger", bot, "wallet-mcp", std::nullopt).outcome ==
          Outcome::InvalidTarget);
}

TEST(exchange_decide_subject_without_aud_or_scope_is_invalid_grant) {
    // Веб-сессия: aud без wallet-mcp — wallet-mcp её менять не может.
    CHECK(token_exchange::detail::decide("wallet-mcp", web_admin_claims(9999999999), "wallet-report", std::nullopt)
              .outcome == Outcome::InvalidGrant);
    // aud wallet-ai есть, scope ai:use нет.
    json no_scope = {{"sub", "u"}, {"iss", "google-auth"}, {"aud", json::array({"wallet-ai"})}, {"scope", "reports:read"}};
    CHECK(token_exchange::detail::decide("wallet-ai", no_scope, "wallet-mcp", std::nullopt).outcome ==
          Outcome::InvalidGrant);
    // scope есть, aud нет.
    json no_aud = {{"sub", "u"}, {"iss", "google-auth"}, {"aud", json::array({"wallet-report"})}, {"scope", "ai:use"}};
    CHECK(token_exchange::detail::decide("wallet-ai", no_aud, "wallet-mcp", std::nullopt).outcome ==
          Outcome::InvalidGrant);
}

TEST(exchange_decide_scope_cannot_widen) {
    json bot = bot_claims(9999999999);
    CHECK(token_exchange::detail::decide("wallet-ai", bot, "wallet-mcp", std::string("mcp:read reports:read"))
              .outcome == Outcome::InvalidScope);
    CHECK(token_exchange::detail::decide("wallet-ai", bot, "wallet-mcp", std::string("reports:read")).outcome ==
          Outcome::InvalidScope);
    CHECK(token_exchange::detail::decide("wallet-ai", bot, "wallet-mcp", std::string("mcp:read")).outcome ==
          Outcome::Ok);
    CHECK(token_exchange::detail::decide("wallet-ai", bot, "wallet-mcp", std::string("")).outcome == Outcome::Ok);
}

// ---- parse_secrets(): TOKEN_EXCHANGE_SECRETS ----

TEST(exchange_parse_secrets_empty_disables) {
    CHECK(token_exchange::detail::parse_secrets("").empty());
    CHECK(token_exchange::detail::parse_secrets("  ").empty());
}

TEST(exchange_parse_secrets_two_services) {
    auto s = token_exchange::detail::parse_secrets(" wallet-ai = a1 ,wallet-mcp=m2,");
    REQUIRE(s.size() == 2u);
    CHECK_EQ(s[0].first, std::string("wallet-ai"));
    CHECK_EQ(s[0].second, std::string("a1"));
    CHECK_EQ(s[1].first, std::string("wallet-mcp"));
    CHECK_EQ(s[1].second, std::string("m2"));
    // '=' внутри секрета допустим (base64 с паддингом).
    auto p = token_exchange::detail::parse_secrets("wallet-ai=abc==");
    REQUIRE(p.size() == 1u);
    CHECK_EQ(p[0].second, std::string("abc=="));
}

TEST(exchange_parse_secrets_garbage_is_startup_error) {
    CHECK_THROWS(token_exchange::detail::parse_secrets("wallet-ai"));
    CHECK_THROWS(token_exchange::detail::parse_secrets("wallet-ai=a1,garbage"));
    CHECK_THROWS(token_exchange::detail::parse_secrets("=a1"));
    CHECK_THROWS(token_exchange::detail::parse_secrets("wallet-ai="));
    CHECK_THROWS(token_exchange::detail::parse_secrets("wallet-api=a1"));             // не actor политики
    CHECK_THROWS(token_exchange::detail::parse_secrets("wallet-ai=a1,wallet-ai=a2")); // повтор
    CHECK_THROWS(token_exchange::detail::parse_secrets("wallet-ai=same,wallet-mcp=same"));
    // Текст ошибки секрета не содержит.
    try {
        token_exchange::detail::parse_secrets("wallet-ai=topsecret,wallet-ai=topsecret2");
        CHECK(false);
    } catch (const std::invalid_argument& e) {
        CHECK(std::string(e.what()).find("topsecret") == std::string::npos);
    }
}

TEST(exchange_identify_actor_by_secret) {
    std::vector<std::pair<std::string, std::string>> s = {{"wallet-ai", "a1"}, {"wallet-mcp", "m2"}};
    CHECK_EQ(token_exchange::detail::identify_actor(s, "a1"), std::string("wallet-ai"));
    CHECK_EQ(token_exchange::detail::identify_actor(s, "m2"), std::string("wallet-mcp"));
    CHECK(token_exchange::detail::identify_actor(s, "a2").empty());
    CHECK(token_exchange::detail::identify_actor(s, "").empty());
    CHECK(token_exchange::detail::identify_actor({}, "").empty());
}

// ---- parse_form() / error_body() ----

TEST(exchange_parse_form_decodes_and_rejects_repeats) {
    auto f = token_exchange::detail::parse_form("grant_type=urn%3Aietf%3Aparams&scope=mcp%3Aread+reports%3Aread");
    REQUIRE(f.has_value());
    CHECK_EQ(f->find("grant_type")->second, std::string("urn:ietf:params"));
    CHECK_EQ(f->find("scope")->second, std::string("mcp:read reports:read"));
    CHECK(!token_exchange::detail::parse_form("audience=wallet-mcp&audience=wallet-report").has_value());
    CHECK(token_exchange::detail::parse_form("").has_value());
}

TEST(exchange_error_body_is_rfc6749_shape) {
    CHECK_EQ(json::parse(token_exchange::detail::error_body("invalid_grant")), (json{{"error", "invalid_grant"}}));
}

// ---- handle_exchange(): весь обработчик ----

TEST(exchange_disabled_returns_503) {
    AppState state;
    configure(state, /*enabled=*/false);
    auto r = call(state, make_request(kAiSecret, exchange_form("x", "wallet-mcp")));
    CHECK_EQ(r.status, 503);
    CHECK_EQ(r.body, (json{{"error", "unavailable"}}));
}

// Неверный или пустой секрет — 401 invalid_client, subject не смотрим (тут он
// мусор — при проверке был бы invalid_grant). wallet-mcp различает этот ответ
// как ошибку конфигурации.
TEST(exchange_wrong_secret_is_invalid_client) {
    AppState state;
    configure(state);
    auto r1 = call(state, make_request("wrong", exchange_form("garbage", "wallet-mcp")));
    CHECK_EQ(r1.status, 401);
    CHECK_EQ(r1.body, (json{{"error", "invalid_client"}}));
    auto r2 = call(state, make_request("", exchange_form("garbage", "wallet-mcp")));
    CHECK_EQ(r2.status, 401);
    CHECK_EQ(error_of(r2), std::string("invalid_client"));
}

TEST(exchange_bad_grant_type_and_token_type) {
    AppState state;
    configure(state);
    std::string subject = sign(state, bot_claims(timeutil::now_epoch() + 300));

    auto form = exchange_form(subject, "wallet-mcp");
    form.erase("grant_type");
    form.emplace("grant_type", "refresh_token");
    auto r1 = call(state, make_request(kAiSecret, form));
    CHECK_EQ(r1.status, 400);
    CHECK_EQ(error_of(r1), std::string("unsupported_grant_type"));

    form = exchange_form(subject, "wallet-mcp");
    form.erase("subject_token_type");
    form.emplace("subject_token_type", "urn:ietf:params:oauth:token-type:refresh_token");
    auto r2 = call(state, make_request(kAiSecret, form));
    CHECK_EQ(r2.status, 400);
    CHECK_EQ(error_of(r2), std::string("invalid_request"));

    // Без audience, с resource (RFC 8707, D2 — не принимается), повтор поля,
    // не form-тело.
    form = exchange_form(subject, "wallet-mcp");
    form.erase("audience");
    CHECK_EQ(error_of(call(state, make_request(kAiSecret, form))), std::string("invalid_request"));
    form = exchange_form(subject, "wallet-mcp");
    form.emplace("resource", "http://wallet-mcp/api/mcp/");
    CHECK_EQ(error_of(call(state, make_request(kAiSecret, form))), std::string("invalid_request"));
    auto dup = make_request(kAiSecret, exchange_form(subject, "wallet-mcp"));
    dup.body += "&audience=wallet-report";
    CHECK_EQ(error_of(call(state, dup)), std::string("invalid_request"));
    auto as_json = make_request(kAiSecret, exchange_form(subject, "wallet-mcp"));
    as_json.headers.erase("Content-Type");
    as_json.set_header("Content-Type", "application/json");
    CHECK_EQ(error_of(call(state, as_json)), std::string("invalid_request"));
}

TEST(exchange_bad_subject_is_invalid_grant) {
    AppState state;
    configure(state);
    auto now = timeutil::now_epoch();

    // Истёкший.
    auto r1 = call(state, make_request(kAiSecret, exchange_form(sign(state, bot_claims(now - 10)), "wallet-mcp")));
    CHECK_EQ(r1.status, 400);
    CHECK_EQ(r1.body, (json{{"error", "invalid_grant"}}));
    // MCP-токен вместо JWT.
    auto r2 = call(state, make_request(kAiSecret, exchange_form("wmcp_" + std::string(43, 'A'), "wallet-mcp")));
    CHECK_EQ(error_of(r2), std::string("invalid_grant"));
    // Чужой ключ.
    TempRsaKeyFile other;
    crypto::RsaSigningKey other_key(other.path());
    auto r3 = call(state, make_request(kAiSecret, exchange_form(jwt::sign_rs256(bot_claims(now + 300), other_key),
                                                                "wallet-mcp")));
    CHECK_EQ(error_of(r3), std::string("invalid_grant"));
    // Чужой iss.
    json evil = bot_claims(now + 300);
    evil["iss"] = "evil";
    CHECK_EQ(error_of(call(state, make_request(kAiSecret, exchange_form(sign(state, evil), "wallet-mcp")))),
             std::string("invalid_grant"));
    // Нет sub.
    json no_sub = bot_claims(now + 300);
    no_sub.erase("sub");
    CHECK_EQ(error_of(call(state, make_request(kAiSecret, exchange_form(sign(state, no_sub), "wallet-mcp")))),
             std::string("invalid_grant"));
    // Веб-сессия от имени wallet-mcp: aud без wallet-mcp.
    auto r4 = call(state, make_request(kMcpSecret, exchange_form(sign(state, web_admin_claims(now + 300)),
                                                                 "wallet-report")));
    CHECK_EQ(r4.status, 400);
    CHECK_EQ(error_of(r4), std::string("invalid_grant"));
}

TEST(exchange_policy_errors_target_and_scope) {
    AppState state;
    configure(state);
    std::string subject = sign(state, bot_claims(timeutil::now_epoch() + 300));

    auto r1 = call(state, make_request(kAiSecret, exchange_form(subject, "wallet-api")));
    CHECK_EQ(r1.status, 400);
    CHECK_EQ(r1.body, (json{{"error", "invalid_target"}}));

    auto form = exchange_form(subject, "wallet-mcp");
    form.emplace("scope", "mcp:read reports:read");
    auto r2 = call(state, make_request(kAiSecret, form));
    CHECK_EQ(r2.status, 400);
    CHECK_EQ(r2.body, (json{{"error", "invalid_scope"}}));
}

// Сквозная цепочка в юнит-тесте: токен бота → (wallet-ai) → wallet-mcp →
// (wallet-mcp) → wallet-report. Плюс совместимость с разбором ответа в
// wallet-mcp (parse_token_exchange_response: access_token — непустая
// строка, expires_in — целое > 0).
TEST(exchange_chain_wallet_ai_then_wallet_mcp) {
    AppState state;
    configure(state);
    auto now = timeutil::now_epoch();
    std::string bot = sign(state, bot_claims(now + 300));

    auto r1 = call(state, make_request(kAiSecret, exchange_form(bot, "wallet-mcp")));
    REQUIRE(r1.status == 200);
    CHECK_EQ(r1.body.at("token_type").get<std::string>(), std::string("Bearer"));
    CHECK_EQ(r1.body.at("issued_token_type").get<std::string>(),
             std::string("urn:ietf:params:oauth:token-type:access_token"));
    REQUIRE(r1.body.at("access_token").is_string());
    REQUIRE(r1.body.at("expires_in").is_number_integer());
    CHECK(r1.body.at("expires_in").get<int>() > 0);
    CHECK(r1.body.at("expires_in").get<int>() <= 300);

    json t1 = verify(state, r1.body.at("access_token").get<std::string>());
    CHECK_EQ(t1.at("aud"), json::array({"wallet-mcp"}));
    CHECK_EQ(t1.at("scope").get<std::string>(), std::string("mcp:read"));
    CHECK_EQ(t1.at("sub").get<std::string>(), std::string("user-1"));
    CHECK_EQ(t1.at("device_id").get<std::string>(), std::string("dev-1"));
    CHECK_EQ(t1.at("platform").get<std::string>(), std::string("telegram"));
    CHECK_EQ(t1.at("act"), (json{{"sub", "wallet-ai"}}));
    CHECK_EQ(t1.at("iss").get<std::string>(), std::string("google-auth"));

    // Второе звено — ровно та форма, что шлёт wallet-mcp (без scope).
    auto r2 = call(state, make_request(kMcpSecret, exchange_form(r1.body.at("access_token").get<std::string>(), "wallet-report")));
    REQUIRE(r2.status == 200);
    json t2 = verify(state, r2.body.at("access_token").get<std::string>());
    CHECK_EQ(t2.at("aud"), json::array({"wallet-report"}));
    CHECK_EQ(t2.at("scope").get<std::string>(), std::string("reports:read"));
    CHECK_EQ(t2.at("sub").get<std::string>(), std::string("user-1"));
    CHECK_EQ(t2.at("act"), json::parse(R"({"sub":"wallet-mcp","act":{"sub":"wallet-ai"}})"));
    CHECK(t2.at("exp").get<std::uint64_t>() <= t1.at("exp").get<std::uint64_t>());

    // wallet-ai не может сам получить токен для wallet-report, минуя wallet-mcp.
    auto r3 = call(state, make_request(kAiSecret, exchange_form(bot, "wallet-report")));
    CHECK_EQ(error_of(r3), std::string("invalid_target"));
}

// Срок не продлевается: subject истекает через 60 с — expires_in <= 60.
TEST(exchange_does_not_extend_subject_lifetime) {
    AppState state;
    configure(state);
    auto now = timeutil::now_epoch();
    std::string subject = sign(state, bot_claims(now + 60));
    auto r = call(state, make_request(kAiSecret, exchange_form(subject, "wallet-mcp")));
    REQUIRE(r.status == 200);
    CHECK(r.body.at("expires_in").get<int>() <= 60);
    json t = verify(state, r.body.at("access_token").get<std::string>());
    CHECK_EQ(t.at("exp").get<std::uint64_t>(), now + 60);
}

// Subject администратора: role/email/name в выданный токен не попадают.
TEST(exchange_admin_subject_loses_role) {
    AppState state;
    configure(state);
    std::string subject = sign(state, web_admin_claims(timeutil::now_epoch() + 900));
    auto r = call(state, make_request(kAiSecret, exchange_form(subject, "wallet-mcp")));
    REQUIRE(r.status == 200);
    json t = verify(state, r.body.at("access_token").get<std::string>());
    CHECK(!t.contains("role"));
    CHECK(!t.contains("email"));
    CHECK(!t.contains("name"));
    CHECK(t.at("exp").get<std::uint64_t>() <= timeutil::now_epoch() + 300);
}

// Задача 2.4 юнит-тестом: выданный токен ручки /auth/* не примут — в aud нет
// google-auth, а в Redis активных он не регистрируется (D6). Отказ — по
// claims, до Redis (state.redis == nullptr: дойди authenticate() до Redis,
// тест упал бы).
TEST(exchange_issued_token_rejected_by_authenticate) {
    AppState state;
    configure(state);
    std::string subject = sign(state, web_admin_claims(timeutil::now_epoch() + 900));
    auto r = call(state, make_request(kAiSecret, exchange_form(subject, "wallet-mcp")));
    REQUIRE(r.status == 200);
    httplib::Request me;
    me.set_header("Authorization", "Bearer " + r.body.at("access_token").get<std::string>());
    CHECK(!auth::authenticate(me, state).has_value());
}

// Журнал: actor/sub/audience/result есть, токенов и секретов нет. Метрика:
// оба исхода посчитаны с лейблами actor и result.
TEST(exchange_log_has_no_tokens_and_metrics_count_results) {
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path() / ("google_auth_exchange_log_" + std::to_string(std::rand()));
    fs::remove_all(dir);
    applog::init(dir.string(), "google-auth-test");

    AppState state;
    configure(state);
    std::string subject = sign(state, bot_claims(timeutil::now_epoch() + 300));
    auto ok = call(state, make_request(kAiSecret, exchange_form(subject, "wallet-mcp")));
    auto bad_target = call(state, make_request(kAiSecret, exchange_form(subject, "wallet-api")));
    auto bad_client = call(state, make_request("wrong-secret", exchange_form(subject, "wallet-mcp")));
    applog::clear_request_context();

    applog::init("", "google-auth"); // назад в stdout, файл закрыт
    std::string log;
    for (const auto& entry : fs::directory_iterator(dir)) {
        std::ifstream in(entry.path());
        std::stringstream ss;
        ss << in.rdbuf();
        log += ss.str();
    }
    fs::remove_all(dir);

    REQUIRE(ok.status == 200);
    CHECK_EQ(bad_target.status, 400);
    CHECK_EQ(bad_client.status, 401);
    std::string access_token = ok.body.at("access_token").get<std::string>();

    CHECK(!log.empty());
    CHECK(log.find(subject) == std::string::npos);
    CHECK(log.find(access_token) == std::string::npos);
    // Ни одна часть JWT (подпись) — тоже.
    CHECK(log.find(subject.substr(subject.rfind('.') + 1)) == std::string::npos);
    CHECK(log.find(kAiSecret) == std::string::npos);
    CHECK(log.find("wrong-secret") == std::string::npos);
    CHECK(log.find("subject_token") == std::string::npos);

    // Успешный обмен — запись с actor, sub, audience, result.
    bool found_ok = false;
    std::istringstream lines(log);
    std::string line;
    while (std::getline(lines, line)) {
        json j = json::parse(line, nullptr, false);
        if (!j.is_object() || j.value("event", "") != "token_exchange") continue;
        if (j.value("result", "") == "ok") {
            found_ok = j.value("actor", "") == "wallet-ai" && j.value("sub", "") == "user-1" &&
                       j.value("audience", "") == "wallet-mcp";
        }
    }
    CHECK(found_ok);

    std::string metrics = token_exchange::render_metrics();
    CHECK(metrics.find("# TYPE token_exchange_total counter") != std::string::npos);
    CHECK(metrics.find("token_exchange_total{actor=\"wallet-ai\",result=\"ok\"}") != std::string::npos);
    CHECK(metrics.find("token_exchange_total{actor=\"wallet-ai\",result=\"invalid_target\"}") != std::string::npos);
    CHECK(metrics.find("token_exchange_total{actor=\"none\",result=\"invalid_client\"}") != std::string::npos);
}

// Настоящий HTTP через httplib — так же, как зовёт wallet-mcp
// (HttpAuthApi::exchange_jwt: Client::Post(path, headers, Params)). Ловит то,
// чего не видно на голом Request: разбор form-тела сервером httplib.
TEST(exchange_over_http_like_wallet_mcp_client) {
    AppState state;
    configure(state);
    httplib::Server svr;
    token_exchange::register_routes(svr, state);
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    svr.wait_until_ready();

    httplib::Client client("127.0.0.1", port);
    httplib::Headers headers{{"X-Service-Secret", kAiSecret}};
    std::string subject = sign(state, bot_claims(timeutil::now_epoch() + 300));
    auto ok = client.Post("/internal/token/exchange", headers, exchange_form(subject, "wallet-mcp"));
    auto bad = client.Post("/internal/token/exchange", httplib::Headers{{"X-Service-Secret", "nope"}},
                           exchange_form(subject, "wallet-mcp"));
    svr.stop();
    th.join();

    REQUIRE(ok);
    CHECK_EQ(ok->status, 200);
    CHECK_EQ(ok->get_header_value("Cache-Control"), std::string("no-store"));
    json body = json::parse(ok->body, nullptr, false);
    REQUIRE(body.is_object());
    CHECK(body.at("access_token").is_string());
    CHECK(body.at("expires_in").is_number_integer());
    REQUIRE(bad);
    CHECK_EQ(bad->status, 401);
    CHECK_EQ(json::parse(bad->body, nullptr, false), (json{{"error", "invalid_client"}}));
}
