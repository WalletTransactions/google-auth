#include "util/base64.hpp"

#include "test_framework.hpp"

TEST(base64_encode_empty) {
    CHECK_EQ(b64::encode(std::vector<unsigned char>{}), std::string(""));
}

TEST(base64_encode_known_vectors) {
    // RFC 4648 §10 тестовые векторы, без '=' — base64url здесь всегда без
    // паддинга (см. заголовок base64.hpp).
    CHECK_EQ(b64::encode(std::string("f")), std::string("Zg"));
    CHECK_EQ(b64::encode(std::string("fo")), std::string("Zm8"));
    CHECK_EQ(b64::encode(std::string("foo")), std::string("Zm9v"));
    CHECK_EQ(b64::encode(std::string("foob")), std::string("Zm9vYg"));
    CHECK_EQ(b64::encode(std::string("fooba")), std::string("Zm9vYmE"));
    CHECK_EQ(b64::encode(std::string("foobar")), std::string("Zm9vYmFy"));
}

TEST(base64_uses_url_safe_alphabet) {
    // Эти байты в стандартном (не url-safe) base64 дают символы '+'/'/' —
    // здесь на их месте должны быть '-'/'_' (RFC 4648 §5).
    std::vector<unsigned char> data{0xFB, 0xFF, 0xBE};
    std::string encoded = b64::encode(data);
    CHECK(encoded.find('+') == std::string::npos);
    CHECK(encoded.find('/') == std::string::npos);
}

TEST(base64_roundtrip_all_byte_values) {
    std::vector<unsigned char> data{0, 1, 2, 3, 4, 5, 127, 128, 200, 250, 251, 252, 253, 254, 255};
    auto decoded = b64::decode(b64::encode(data));
    CHECK(decoded == data);
}

TEST(base64_decode_tolerates_padding) {
    // "Zg==" — то же значение, что и "Zg", просто с классическим паддингом;
    // decode() должен молча его проигнорировать (см. комментарий в base64.cpp).
    CHECK(b64::decode("Zg") == b64::decode("Zg=="));
}

TEST(base64_decode_rejects_invalid_char) {
    CHECK_THROWS(b64::decode("not valid base64!"));
}

TEST(base64_decode_rejects_invalid_length) {
    // Остаток длины 1 по модулю 4 невозможен ни для одной корректной
    // base64url-строки без паддинга.
    CHECK_THROWS(b64::decode("A"));
}
