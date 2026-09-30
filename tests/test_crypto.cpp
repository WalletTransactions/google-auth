#include "util/crypto.hpp"

#include "rsa_test_key.hpp"
#include "test_framework.hpp"
#include "util/base64.hpp"

TEST(crypto_sha256_known_vector) {
    // sha256("") — общеизвестный тестовый вектор
    // (e3b0c442...b855, здесь в виде base64url — см. util/base64.hpp).
    auto digest = crypto::sha256("");
    CHECK_EQ(b64::encode(digest), std::string("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"));
}

TEST(crypto_sha256_deterministic_and_sensitive_to_input) {
    CHECK(crypto::sha256("hello") == crypto::sha256("hello"));
    CHECK(crypto::sha256("hello") != crypto::sha256("Hello"));
}

TEST(crypto_random_bytes_length_and_variability) {
    auto a = crypto::random_bytes(32);
    auto b = crypto::random_bytes(32);
    CHECK_EQ(a.size(), static_cast<std::size_t>(32));
    // Теоретически могут совпасть, но шанс исчезающе мал (2^-256) — обычный
    // способ поймать регрессию "генератор всегда отдаёт одно и то же".
    CHECK(a != b);
}

TEST(crypto_constant_time_equal) {
    std::vector<unsigned char> a{1, 2, 3};
    std::vector<unsigned char> b{1, 2, 3};
    std::vector<unsigned char> c{1, 2, 4};
    std::vector<unsigned char> shorter{1, 2};
    CHECK(crypto::constant_time_equal(a, b));
    CHECK(!crypto::constant_time_equal(a, c));
    CHECK(!crypto::constant_time_equal(a, shorter));
    CHECK(crypto::constant_time_equal({}, {}));
}

TEST(crypto_rsa_sign_and_verify_roundtrip) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());

    std::string data = "signing_input.payload";
    auto signature = key.sign(data);

    CHECK(crypto::rsa_sha256_verify(key.modulus(), key.exponent(), data, signature));
}

TEST(crypto_rsa_verify_rejects_tampered_data) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key(key_file.path());

    auto signature = key.sign("original");
    CHECK(!crypto::rsa_sha256_verify(key.modulus(), key.exponent(), "tampered", signature));
}

TEST(crypto_rsa_verify_rejects_wrong_key) {
    TempRsaKeyFile key_file_a;
    TempRsaKeyFile key_file_b;
    crypto::RsaSigningKey key_a(key_file_a.path());
    crypto::RsaSigningKey key_b(key_file_b.path());

    auto signature = key_a.sign("data");
    CHECK(!crypto::rsa_sha256_verify(key_b.modulus(), key_b.exponent(), "data", signature));
}

TEST(crypto_rsa_key_kid_is_stable_for_the_same_key_file) {
    TempRsaKeyFile key_file;
    crypto::RsaSigningKey key1(key_file.path());
    crypto::RsaSigningKey key2(key_file.path());
    CHECK_EQ(key1.kid(), key2.kid());
    CHECK(!key1.kid().empty());
}

TEST(crypto_rsa_key_different_keys_get_different_kid) {
    TempRsaKeyFile key_file_a;
    TempRsaKeyFile key_file_b;
    crypto::RsaSigningKey key_a(key_file_a.path());
    crypto::RsaSigningKey key_b(key_file_b.path());
    CHECK(key_a.kid() != key_b.kid());
}

TEST(crypto_rsa_key_rejects_missing_file) {
    CHECK_THROWS(crypto::RsaSigningKey("/path/does/not/exist.pem"));
}
