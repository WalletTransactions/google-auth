#include "util/jwt.hpp"

#include <algorithm>

#include "nlohmann/json.hpp"
#include "rsa_test_key.hpp"
#include "test_framework.hpp"
#include "util/crypto.hpp"

using nlohmann::json;

TEST(jwt_sign_and_verify_roundtrip) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());

    json payload = {{"sub", "user-1"}, {"exp", 9999999999ULL}};
    std::string token = jwt::sign_rs256(payload, key);

    auto verified = jwt::verify_rs256(token, key.modulus(), key.exponent());
    REQUIRE(verified.has_value());
    CHECK_EQ(verified->at("sub").get<std::string>(), std::string("user-1"));
    CHECK_EQ(verified->at("exp").get<std::uint64_t>(), 9999999999ULL);
}

TEST(jwt_token_has_three_dot_separated_parts) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());
    std::string token = jwt::sign_rs256(json{{"a", 1}}, key);
    CHECK_EQ(static_cast<std::size_t>(std::count(token.begin(), token.end(), '.')),
             static_cast<std::size_t>(2));
}

TEST(jwt_verify_rejects_tampered_payload) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());
    std::string token = jwt::sign_rs256(json{{"role", "user"}}, key);

    // Меняем один символ в payload-части (между первой и второй точкой) —
    // подпись, посчитанная над оригиналом, больше не должна сходиться.
    std::size_t first_dot = token.find('.');
    std::size_t second_dot = token.find('.', first_dot + 1);
    REQUIRE(first_dot != std::string::npos);
    REQUIRE(second_dot != std::string::npos);
    REQUIRE(second_dot > first_dot + 1);

    std::string tampered = token;
    char& c = tampered[first_dot + 1];
    c = (c == 'A') ? 'B' : 'A';

    CHECK(!jwt::verify_rs256(tampered, key.modulus(), key.exponent()).has_value());
}

TEST(jwt_verify_rejects_tampered_signature) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());
    std::string token = jwt::sign_rs256(json{{"a", 1}}, key);

    // Портим ПЕРВЫЙ символ сегмента подписи (не последний!): в base64url
    // без паддинга у ПОСЛЕДНЕГO символа неполной группы могут быть "лишние"
    // младшие биты, которые decode() всё равно отбрасывает (см.
    // util/base64.cpp) — подмена именно там иногда не меняет ни одного
    // реального байта подписи. Первый символ любой группы такой проблемы не
    // имеет — его биты всегда участвуют в первом декодированном байте.
    std::size_t last_dot = token.rfind('.');
    REQUIRE(last_dot != std::string::npos);
    REQUIRE(last_dot + 1 < token.size());

    std::string tampered = token;
    char& c = tampered[last_dot + 1];
    c = (c == 'A') ? 'B' : 'A';

    CHECK(!jwt::verify_rs256(tampered, key.modulus(), key.exponent()).has_value());
}

TEST(jwt_verify_rejects_wrong_key) {
    TempRsaKeyFile key_file_a;
    TempRsaKeyFile key_file_b;
    crypto::RsaSigningKey key_a(key_file_a.path());
    crypto::RsaSigningKey key_b(key_file_b.path());

    std::string token = jwt::sign_rs256(json{{"sub", "x"}}, key_a);
    CHECK(!jwt::verify_rs256(token, key_b.modulus(), key_b.exponent()).has_value());
}

TEST(jwt_verify_rejects_malformed_token) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());
    CHECK(!jwt::verify_rs256("not.a.valid.jwt.at.all", key.modulus(), key.exponent()).has_value());
    CHECK(!jwt::verify_rs256("onlyonepart", key.modulus(), key.exponent()).has_value());
    CHECK(!jwt::verify_rs256("", key.modulus(), key.exponent()).has_value());
}

TEST(jwt_verify_rejects_expired_and_missing_exp) {
    // exp обязателен: токен без него был бы бессрочным.
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());
    jwt::VerifyError why{};

    std::string expired = jwt::sign_rs256(json{{"exp", 1}}, key); // истёк ещё в 1970
    CHECK(!jwt::verify_rs256(expired, key.modulus(), key.exponent(), &why).has_value());
    CHECK(why == jwt::VerifyError::Expired);

    std::string no_exp = jwt::sign_rs256(json{{"sub", "u"}}, key);
    CHECK(!jwt::verify_rs256(no_exp, key.modulus(), key.exponent(), &why).has_value());
    CHECK(why == jwt::VerifyError::Expired);

    std::string bad_exp = jwt::sign_rs256(json{{"exp", "tomorrow"}}, key);
    CHECK(!jwt::verify_rs256(bad_exp, key.modulus(), key.exponent(), &why).has_value());
    CHECK(why == jwt::VerifyError::Expired);
}

TEST(jwt_verify_reports_signature_and_format_errors) {
    TempRsaKeyFile key_a;
    TempRsaKeyFile key_b;
    crypto::RsaSigningKey a(key_a.path());
    crypto::RsaSigningKey b(key_b.path());
    jwt::VerifyError why{};

    std::string token = jwt::sign_rs256(json{{"exp", 9999999999ULL}}, a);
    CHECK(!jwt::verify_rs256(token, b.modulus(), b.exponent(), &why).has_value());
    CHECK(why == jwt::VerifyError::BadSignature);

    CHECK(!jwt::verify_rs256("onlyonepart", a.modulus(), a.exponent(), &why).has_value());
    CHECK(why == jwt::VerifyError::Malformed);
}

TEST(jwt_peek_kid_matches_signing_key) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());
    std::string token = jwt::sign_rs256(json{{"a", 1}}, key);

    auto kid = jwt::peek_kid(token);
    REQUIRE(kid.has_value());
    CHECK_EQ(*kid, key.kid());
}

TEST(jwt_peek_kid_does_not_check_signature) {
    // peek_kid() читает заголовок ДО проверки подписи (см. комментарий в
    // jwt.hpp) — должен вернуть kid, даже если сама подпись/payload битые.
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());
    std::string token = jwt::sign_rs256(json{{"a", 1}}, key);
    std::string with_broken_signature = token.substr(0, token.size() - 1) + "!";

    auto kid = jwt::peek_kid(with_broken_signature);
    REQUIRE(kid.has_value());
    CHECK_EQ(*kid, key.kid());
}

TEST(jwt_peek_kid_on_malformed_token) {
    CHECK(!jwt::peek_kid("garbage").has_value());
    CHECK(!jwt::peek_kid("").has_value());
}
