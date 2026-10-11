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
