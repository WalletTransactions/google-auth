#include "util/uuid.hpp"

#include <cctype>
#include <unordered_set>

#include "test_framework.hpp"

TEST(uuid_v4_has_valid_format) {
    CHECK(uuidgen::looks_valid(uuidgen::v4()));
}

TEST(uuid_v4_sets_version_and_variant_bits) {
    std::string id = uuidgen::v4();
    REQUIRE(id.size() == 36);
    CHECK_EQ(id[14], '4'); // версия 4 (RFC 4122) — третья группа начинается с "4"
    char variant = static_cast<char>(std::tolower(static_cast<unsigned char>(id[19])));
    CHECK(variant == '8' || variant == '9' || variant == 'a' || variant == 'b');
}

TEST(uuid_v4_is_unique_across_many_calls) {
    std::unordered_set<std::string> seen;
    for (int i = 0; i < 1000; ++i) {
        CHECK(seen.insert(uuidgen::v4()).second);
    }
}

TEST(uuid_looks_valid_rejects_wrong_length) {
    CHECK(!uuidgen::looks_valid(""));
    CHECK(!uuidgen::looks_valid("too-short"));
    CHECK(!uuidgen::looks_valid(uuidgen::v4() + "x"));
}

TEST(uuid_looks_valid_rejects_wrong_dash_positions) {
    std::string broken = uuidgen::v4();
    broken[8] = 'a'; // здесь должен быть '-'
    CHECK(!uuidgen::looks_valid(broken));
}

TEST(uuid_looks_valid_rejects_non_hex_chars) {
    CHECK(!uuidgen::looks_valid("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"));
}

TEST(uuid_looks_valid_accepts_uppercase_hex) {
    CHECK(uuidgen::looks_valid("A1B2C3D4-E5F6-4789-8ABC-DEF012345678"));
}
