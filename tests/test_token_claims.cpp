// token_claims.hpp — iss/aud/scope пользовательского токена
// (org/docs/TODO_telegram_tokens.md, шаг 1).
#include "token_claims.hpp"

#include <tuple>

#include "test_framework.hpp"

using nlohmann::json;

TEST(user_claims_have_issuer_audience_and_scope) {
    json payload = {{"sub", "u1"}};
    token_claims::add_user_claims(payload);

    CHECK_EQ(payload.at("iss").get<std::string>(), std::string("google-auth"));
    CHECK_EQ(payload.at("scope").get<std::string>(),
             std::string("wallet:read wallet:write reports:read account ai:use docs:ask"));
    REQUIRE(payload.at("aud").is_array());
    CHECK_EQ(payload.at("aud").size(), 5u);
    CHECK_EQ(payload.at("aud")[0].get<std::string>(), std::string("wallet-api"));
    CHECK_EQ(payload.at("aud")[1].get<std::string>(), std::string("wallet-report"));
    CHECK_EQ(payload.at("aud")[2].get<std::string>(), std::string("google-auth"));
    CHECK_EQ(payload.at("aud")[3].get<std::string>(), std::string("wallet-ai"));
    CHECK_EQ(payload.at("aud")[4].get<std::string>(), std::string("wallet-docs"));
    // Остальные claims не трогает.
    CHECK_EQ(payload.at("sub").get<std::string>(), std::string("u1"));
}

// change docs-audience: wallet-docs/docs:ask — только у пользовательского
// токена. Бот, MCP-токен и обмен их не получают, даже если subject обмена —
// пользовательский токен, где они есть.
static bool aud_has(const json& payload, const char* aud) {
    for (const auto& a : payload.at("aud"))
        if (a.get<std::string>() == aud) return true;
    return false;
}
static bool scope_has(const json& payload, const std::string& scope) {
    std::string s = " " + payload.at("scope").get<std::string>() + " ";
    return s.find(" " + scope + " ") != std::string::npos;
}

TEST(docs_audience_only_in_user_token) {
    json user = {{"sub", "u1"}};
    token_claims::add_user_claims(user);
    CHECK(aud_has(user, "wallet-docs"));
    CHECK(scope_has(user, "docs:ask"));

    json bot = {{"sub", "u1"}};
    token_claims::add_telegram_bot_claims(bot);
    CHECK(!aud_has(bot, "wallet-docs"));
    CHECK(!scope_has(bot, "docs:ask"));

    json mcp = {{"sub", "u1"}};
    token_claims::add_mcp_claims(mcp);
    CHECK(!aud_has(mcp, "wallet-docs"));
    CHECK(!scope_has(mcp, "docs:ask"));

    json subject = user;
    subject["exp"] = 2000;
    for (auto [aud, scope, actor] : {std::tuple{"wallet-mcp", "mcp:read", "wallet-ai"},
                                     std::tuple{"wallet-report", "reports:read", "wallet-mcp"}}) {
        json exchanged = {{"iat", 1000}};
        token_claims::add_exchange_claims(exchanged, aud, scope, actor, subject);
        CHECK(!aud_has(exchanged, "wallet-docs"));
        CHECK(!scope_has(exchanged, "docs:ask"));
    }
}

// change add-mcp-personal-tokens, D4: JWT обмена MCP-токена — только
// wallet-report и reports:read, и без role/email/name. Регрессия здесь
// (например, общий helper, добавивший role) была бы тихой: wallet-report
// принял бы админа через MCP и отдал бы чужой леджер по as_user_id.
TEST(mcp_claims_are_read_only_report_without_role) {
    json payload = {{"sub", "u1"}, {"device_id", "d1"}, {"platform", "mcp"}};
    token_claims::add_mcp_claims(payload);

    CHECK_EQ(payload.at("iss").get<std::string>(), std::string("google-auth"));
    CHECK_EQ(payload.at("scope").get<std::string>(), std::string("reports:read"));
    REQUIRE(payload.at("aud").is_array());
    CHECK_EQ(payload.at("aud").size(), 1u);
    CHECK_EQ(payload.at("aud")[0].get<std::string>(), std::string("wallet-report"));
    CHECK(!payload.contains("role"));
    CHECK(!payload.contains("email"));
    CHECK(!payload.contains("name"));
    CHECK_EQ(payload.at("platform").get<std::string>(), std::string("mcp"));
    CHECK_EQ(token_claims::kMcpTokenTtlSecs, 300);
}

TEST(mcp_claims_strip_role_email_name_if_present) {
    json payload = {{"sub", "u1"}, {"role", "admin"}, {"email", "a@b"}, {"name", "N"}};
    token_claims::add_mcp_claims(payload);
    CHECK(!payload.contains("role"));
    CHECK(!payload.contains("email"));
    CHECK(!payload.contains("name"));
}

// ---- add_exchange_claims (change add-token-exchange, D5, D7) ----

// Новый адресат и scope — только через обмен: в пользовательский набор их
// не добавили (веб-сессия не ходит в wallet-mcp напрямую).
TEST(exchange_constants_not_in_user_set) {
    CHECK_EQ(std::string(token_claims::kAudWalletMcp), std::string("wallet-mcp"));
    CHECK_EQ(std::string(token_claims::kScopeMcpRead), std::string("mcp:read"));
    for (const auto& a : token_claims::user_audience()) CHECK(a.get<std::string>() != "wallet-mcp");
    CHECK(std::string(token_claims::kScopeUser).find("mcp:read") == std::string::npos);
}

TEST(exchange_claims_copy_subject_and_set_target) {
    json subject = {{"sub", "u1"},     {"iss", "google-auth"}, {"aud", json::array({"wallet-ai"})},
                    {"scope", "ai:use"}, {"exp", 2000},        {"device_id", "d1"},
                    {"platform", "telegram"}};
    json payload = {{"iat", 1000}};
    token_claims::add_exchange_claims(payload, "wallet-mcp", "mcp:read", "wallet-ai", subject);

    CHECK_EQ(payload.at("sub").get<std::string>(), std::string("u1"));
    CHECK_EQ(payload.at("iss").get<std::string>(), std::string("google-auth"));
    CHECK_EQ(payload.at("aud"), json::array({"wallet-mcp"}));
    CHECK_EQ(payload.at("scope").get<std::string>(), std::string("mcp:read"));
    CHECK_EQ(payload.at("device_id").get<std::string>(), std::string("d1"));
    CHECK_EQ(payload.at("platform").get<std::string>(), std::string("telegram"));
    CHECK_EQ(payload.at("act"), (json{{"sub", "wallet-ai"}}));
    CHECK_EQ(payload.at("iat").get<std::uint64_t>(), 1000u);
}

// RFC 8693 §4.1: act subject'а вкладывается внутрь нового act.
TEST(exchange_claims_nest_act_chain) {
    json subject = {{"sub", "u1"}, {"exp", 2000}, {"act", {{"sub", "wallet-ai"}}}};
    json payload = {{"iat", 1000}};
    token_claims::add_exchange_claims(payload, "wallet-report", "reports:read", "wallet-mcp", subject);
    CHECK_EQ(payload.at("act"), json::parse(R"({"sub":"wallet-mcp","act":{"sub":"wallet-ai"}})"));
    CHECK_EQ(payload.at("sub").get<std::string>(), std::string("u1"));
}

// exp = min(subject.exp, iat + 300): обмен не продлевает жизнь токена.
TEST(exchange_claims_exp_not_longer_than_subject_or_300s) {
    json short_subject = {{"sub", "u1"}, {"exp", 1060}};
    json p1 = {{"iat", 1000}};
    token_claims::add_exchange_claims(p1, "wallet-mcp", "mcp:read", "wallet-ai", short_subject);
    CHECK_EQ(p1.at("exp").get<std::uint64_t>(), 1060u);

    json long_subject = {{"sub", "u1"}, {"exp", 1000 + 900}};
    json p2 = {{"iat", 1000}};
    token_claims::add_exchange_claims(p2, "wallet-mcp", "mcp:read", "wallet-ai", long_subject);
    CHECK_EQ(p2.at("exp").get<std::uint64_t>(), 1300u);
    CHECK_EQ(token_claims::kExchangeTokenMaxTtlSecs, 300);
}

// role/email/name не переносятся ни из payload, ни из subject; чужой act в
// payload заменяется.
TEST(exchange_claims_drop_role_email_name) {
    json subject = {{"sub", "u1"}, {"exp", 2000}, {"role", "admin"}, {"email", "a@b"}, {"name", "N"}};
    json payload = {{"iat", 1000}, {"role", "admin"}, {"email", "a@b"}, {"name", "N"}, {"act", {{"sub", "x"}}}};
    token_claims::add_exchange_claims(payload, "wallet-mcp", "mcp:read", "wallet-ai", subject);
    CHECK(!payload.contains("role"));
    CHECK(!payload.contains("email"));
    CHECK(!payload.contains("name"));
    CHECK(!payload.contains("device_id"));
    CHECK_EQ(payload.at("act"), (json{{"sub", "wallet-ai"}}));
}
