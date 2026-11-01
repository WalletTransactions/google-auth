// token_claims.hpp — iss/aud/scope пользовательского токена
// (org/docs/TODO_telegram_tokens.md, шаг 1).
#include "token_claims.hpp"

#include "test_framework.hpp"

using nlohmann::json;

TEST(user_claims_have_issuer_audience_and_scope) {
    json payload = {{"sub", "u1"}};
    token_claims::add_user_claims(payload);

    CHECK_EQ(payload.at("iss").get<std::string>(), std::string("google-auth"));
    CHECK_EQ(payload.at("scope").get<std::string>(),
             std::string("wallet:read wallet:write reports:read account ai:use"));
    REQUIRE(payload.at("aud").is_array());
    CHECK_EQ(payload.at("aud").size(), 4u);
    CHECK_EQ(payload.at("aud")[0].get<std::string>(), std::string("wallet-api"));
    CHECK_EQ(payload.at("aud")[1].get<std::string>(), std::string("wallet-report"));
    CHECK_EQ(payload.at("aud")[2].get<std::string>(), std::string("google-auth"));
    CHECK_EQ(payload.at("aud")[3].get<std::string>(), std::string("wallet-ai"));
    // Остальные claims не трогает.
    CHECK_EQ(payload.at("sub").get<std::string>(), std::string("u1"));
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
