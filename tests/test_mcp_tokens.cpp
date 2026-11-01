// mcp_tokens::detail и repo::detail (change add-mcp-personal-tokens): имя
// токена, формат wmcp_…, скользящий срок с потолком, формат записи в Redis.
#include "mcp_tokens.hpp"
#include "repo.hpp"

#include "test_framework.hpp"

namespace {
constexpr uint64_t kDay = 60ULL * 60 * 24;
}

TEST(mcp_name_is_trimmed) {
    auto name = mcp_tokens::detail::normalize_name(" LM Studio дома ");
    REQUIRE(name.has_value());
    CHECK_EQ(*name, std::string("LM Studio дома"));
    CHECK_EQ(*mcp_tokens::detail::normalize_name("\tClaude Code\n"), std::string("Claude Code"));
}

TEST(mcp_name_rejects_empty_and_blank) {
    CHECK(!mcp_tokens::detail::normalize_name("").has_value());
    CHECK(!mcp_tokens::detail::normalize_name("   ").has_value());
    CHECK(!mcp_tokens::detail::normalize_name(" \t\r\n ").has_value());
}

TEST(mcp_name_length_counts_characters_not_bytes) {
    // 64 кириллических символа — 128 байт, но имя допустимо.
    std::string cyr;
    for (int i = 0; i < 64; ++i) cyr += "ж";
    CHECK(mcp_tokens::detail::normalize_name(cyr).has_value());
    CHECK(!mcp_tokens::detail::normalize_name(cyr + "ж").has_value());

    CHECK(mcp_tokens::detail::normalize_name(std::string(64, 'a')).has_value());
    CHECK(!mcp_tokens::detail::normalize_name(std::string(65, 'a')).has_value());
    // Пробелы по краям в длину не входят.
    CHECK(mcp_tokens::detail::normalize_name("  " + std::string(64, 'a') + "  ").has_value());
    CHECK(mcp_tokens::detail::normalize_name("x").has_value());
}

TEST(mcp_generated_token_is_well_formed_and_unique) {
    std::string a = mcp_tokens::detail::generate_token();
    std::string b = mcp_tokens::detail::generate_token();
    CHECK_EQ(a.size(), std::size_t{48});
    CHECK_EQ(a.rfind("wmcp_", 0), std::size_t{0});
    CHECK(mcp_tokens::detail::is_well_formed_token(a));
    CHECK(mcp_tokens::detail::is_well_formed_token(b));
    CHECK(a != b);
    CHECK(a.find('=') == std::string::npos);
}

TEST(mcp_token_format_rejects_garbage) {
    std::string body43(43, 'A');
    CHECK(mcp_tokens::detail::is_well_formed_token("wmcp_" + body43));
    CHECK(!mcp_tokens::detail::is_well_formed_token(""));
    CHECK(!mcp_tokens::detail::is_well_formed_token("abc"));
    CHECK(!mcp_tokens::detail::is_well_formed_token("wmcp_" + std::string(42, 'A')));
    CHECK(!mcp_tokens::detail::is_well_formed_token("wmcp_" + std::string(44, 'A')));
    CHECK(!mcp_tokens::detail::is_well_formed_token("wmcx_" + body43));
    CHECK(!mcp_tokens::detail::is_well_formed_token("WMCP_" + body43));
    CHECK(!mcp_tokens::detail::is_well_formed_token("wmcp_" + std::string(42, 'A') + "="));
    CHECK(!mcp_tokens::detail::is_well_formed_token("wmcp_" + std::string(42, 'A') + "+"));
    CHECK(!mcp_tokens::detail::is_well_formed_token("wmcp_" + std::string(42, 'A') + "/"));
    CHECK(mcp_tokens::detail::is_well_formed_token("wmcp_" + std::string(41, 'z') + "-_"));
    // refresh-токен — base64url от 32 байт без префикса — не MCP-токен.
    CHECK(!mcp_tokens::detail::is_well_formed_token(body43));
}

TEST(mcp_token_hash_is_base64url_sha256) {
    std::string h = mcp_tokens::detail::hash_token("wmcp_x");
    CHECK_EQ(h.size(), std::size_t{43});
    CHECK(h != mcp_tokens::detail::hash_token("wmcp_y"));
    CHECK_EQ(h, mcp_tokens::detail::hash_token("wmcp_x"));
}

TEST(mcp_expiry_slides_30_days) {
    uint64_t issued = 1'800'000'000ULL;
    uint64_t cap = issued + 90 * kDay;
    // Выпуск: через 30 дней.
    CHECK_EQ(*repo::detail::next_mcp_expiry(issued, cap), issued + 30 * kDay);
    // Обмен на 10-й день — срок на 40-й (сценарий «Продление»).
    CHECK_EQ(*repo::detail::next_mcp_expiry(issued + 10 * kDay, cap), issued + 40 * kDay);
}

TEST(mcp_expiry_is_capped_at_90_days) {
    uint64_t issued = 1'800'000'000ULL;
    uint64_t cap = issued + 90 * kDay;
    // На 70-й день продление упирается в потолок, а не на 100-й.
    CHECK_EQ(*repo::detail::next_mcp_expiry(issued + 70 * kDay, cap), cap);
    CHECK_EQ(*repo::detail::next_mcp_expiry(cap - 1, cap), cap);
    // На потолке и после — токен недействителен (сценарий «Активный токен у потолка»).
    CHECK(!repo::detail::next_mcp_expiry(cap, cap).has_value());
    CHECK(!repo::detail::next_mcp_expiry(cap + kDay, cap).has_value());
}

TEST(mcp_record_json_roundtrip) {
    repo::McpTokenRecord r;
    r.user_id = "u1";
    r.device_id = "d1";
    r.name = "LM Studio дома";
    r.created_at = 100;
    r.cap_at = 200;
    r.last_used_at = 0;
    auto back = repo::detail::mcp_record_from_json(repo::detail::mcp_record_to_json(r));
    REQUIRE(back.has_value());
    CHECK_EQ(back->user_id, r.user_id);
    CHECK_EQ(back->device_id, r.device_id);
    CHECK_EQ(back->name, r.name);
    CHECK_EQ(back->created_at, r.created_at);
    CHECK_EQ(back->cap_at, r.cap_at);
    CHECK_EQ(back->last_used_at, uint64_t{0});
    // Хранится только хэш токена — в записи самого токена нет.
    CHECK(repo::detail::mcp_record_to_json(r).find("wmcp_") == std::string::npos);
}

TEST(mcp_record_rejects_foreign_values) {
    CHECK(!repo::detail::mcp_record_from_json("not json").has_value());
    CHECK(!repo::detail::mcp_record_from_json("\"u1\"").has_value());
    CHECK(!repo::detail::mcp_record_from_json("{\"device_id\":\"d\"}").has_value());
    CHECK(!repo::detail::mcp_record_from_json("{\"user_id\":\"u\",\"cap_at\":\"x\"}").has_value());
    CHECK(!repo::detail::mcp_record_from_json("{\"user_id\":\"u\"}").has_value()); // нет потолка
}
