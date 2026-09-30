#include "util/url.hpp"

#include "test_framework.hpp"

TEST(url_encode_component_leaves_unreserved_chars_untouched) {
    CHECK_EQ(urlutil::encode_component("abcXYZ019-_.~"), std::string("abcXYZ019-_.~"));
}

TEST(url_encode_component_escapes_special_chars) {
    CHECK_EQ(urlutil::encode_component("a b"), std::string("a%20b"));
    CHECK_EQ(urlutil::encode_component("a+b"), std::string("a%2Bb"));
    CHECK_EQ(urlutil::encode_component("a/b"), std::string("a%2Fb"));
    CHECK_EQ(urlutil::encode_component("a=b&c"), std::string("a%3Db%26c"));
}

TEST(url_encode_component_empty_string) {
    CHECK_EQ(urlutil::encode_component(""), std::string(""));
}

TEST(url_encode_component_uses_uppercase_hex) {
    // RFC 3986 разрешает оба регистра, но принято отдавать в верхнем —
    // именно так, как это ожидают на другом конце (Google OAuth).
    CHECK_EQ(urlutil::encode_component("\xFF"), std::string("%FF"));
}

TEST(url_build_query_joins_with_ampersand) {
    CHECK_EQ(urlutil::build_query({{"a", "1"}, {"b", "2"}}), std::string("a=1&b=2"));
}

TEST(url_build_query_encodes_keys_and_values) {
    std::string q = urlutil::build_query({{"redirect uri", "http://x/y?z"}});
    CHECK_EQ(q, std::string("redirect%20uri=http%3A%2F%2Fx%2Fy%3Fz"));
}

TEST(url_build_query_empty) {
    CHECK_EQ(urlutil::build_query({}), std::string(""));
}

TEST(url_build_query_single_param_has_no_trailing_ampersand) {
    CHECK_EQ(urlutil::build_query({{"only", "one"}}), std::string("only=one"));
}
