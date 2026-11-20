// passwords (change add-password-auth): PBKDF2-хэш, пересчёт, проверка email и
// длины пароля. Постоянное время сравнения тестом не проверяется (CRYPTO_memcmp
// — гарантия OpenSSL), проверяется только результат.
#include "passwords.hpp"

#include "test_framework.hpp"

namespace {
// Мало итераций — чтобы набор тестов не считал PBKDF2 на 600 000 по десять раз.
constexpr int kFast = 1000;
} // namespace

TEST(passwords_record_has_expected_shape) {
    auto r = passwords::make_record("correct horse battery", kFast);
    CHECK_EQ(r.algo, std::string(passwords::kAlgoPbkdf2));
    CHECK_EQ(r.salt.size(), passwords::kSaltBytes);
    CHECK_EQ(r.hash.size(), passwords::kHashBytes);
    CHECK_EQ(r.iterations, kFast);
    // Пароль нигде в записи не лежит.
    CHECK(r.salt.find("correct") == std::string::npos);
    CHECK(r.hash.find("correct") == std::string::npos);
}

TEST(passwords_correct_password_verifies) {
    auto r = passwords::make_record("correct horse battery", kFast);
    CHECK(passwords::verify("correct horse battery", r));
}

TEST(passwords_wrong_password_rejected) {
    auto r = passwords::make_record("correct horse battery", kFast);
    CHECK(!passwords::verify("correct horse batterY", r));
    CHECK(!passwords::verify("", r));
    CHECK(!passwords::verify("correct horse battery ", r));
}

TEST(passwords_same_password_gets_different_salt_and_hash) {
    auto a = passwords::make_record("correct horse battery", kFast);
    auto b = passwords::make_record("correct horse battery", kFast);
    CHECK(a.salt != b.salt);
    CHECK(a.hash != b.hash);
}

TEST(passwords_known_vector_pbkdf2_sha256) {
    // RFC 7914 §11: PBKDF2-HMAC-SHA-256(P="passwd", S="salt", c=1, dkLen=64),
    // здесь берём первые 32 байта — их значение не зависит от dkLen.
    passwords::Record r;
    r.salt = "salt";
    r.iterations = 1;
    const unsigned char expected[] = {0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
                                      0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
                                      0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
                                      0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc};
    r.hash.assign(reinterpret_cast<const char*>(expected), sizeof(expected));
    CHECK(passwords::verify("passwd", r));
    CHECK(!passwords::verify("Passwd", r));
}

TEST(passwords_malformed_record_rejected) {
    auto r = passwords::make_record("correct horse battery", kFast);

    auto unknown_algo = r;
    unknown_algo.algo = "md5";
    CHECK(!passwords::verify("correct horse battery", unknown_algo));

    auto short_hash = r;
    short_hash.hash.resize(10);
    CHECK(!passwords::verify("correct horse battery", short_hash));

    auto no_salt = r;
    no_salt.salt.clear();
    CHECK(!passwords::verify("correct horse battery", no_salt));

    auto zero_iter = r;
    zero_iter.iterations = 0;
    CHECK(!passwords::verify("correct horse battery", zero_iter));
}

TEST(passwords_rehash_when_iterations_outdated) {
    auto r = passwords::make_record("correct horse battery", kFast);
    CHECK(!passwords::needs_rehash(r, kFast));
    CHECK(!passwords::needs_rehash(r, kFast - 1));
    CHECK(passwords::needs_rehash(r, kFast + 1));

    // Пересчёт: после проверки старой записи новая с большим числом итераций
    // принимает тот же пароль, а старые параметры ею заменяются.
    CHECK(passwords::verify("correct horse battery", r));
    auto upgraded = passwords::make_record("correct horse battery", kFast * 2);
    CHECK_EQ(upgraded.iterations, kFast * 2);
    CHECK(passwords::verify("correct horse battery", upgraded));
    CHECK(!passwords::needs_rehash(upgraded, kFast * 2));
}

TEST(passwords_make_record_rejects_bad_iterations) {
    CHECK_THROWS(passwords::make_record("correct horse battery", 0));
    CHECK_THROWS(passwords::make_record("correct horse battery", -5));
}

TEST(passwords_dummy_verify_never_matches) {
    CHECK(!passwords::verify_dummy("correct horse battery", kFast));
    CHECK(!passwords::verify_dummy("", kFast));
    CHECK(!passwords::verify_dummy("x", 0)); // 0 -> число итераций по умолчанию не падает
}

TEST(passwords_email_normalized) {
    CHECK_EQ(*passwords::normalize_email("User@Mail.COM"), std::string("user@mail.com"));
    CHECK_EQ(*passwords::normalize_email("  a.b+c@sub.example.org \n"), std::string("a.b+c@sub.example.org"));
}

TEST(passwords_email_rejected) {
    CHECK(!passwords::normalize_email("").has_value());
    CHECK(!passwords::normalize_email("   ").has_value());
    CHECK(!passwords::normalize_email("plain").has_value());
    CHECK(!passwords::normalize_email("@mail.com").has_value());
    CHECK(!passwords::normalize_email("user@").has_value());
    CHECK(!passwords::normalize_email("user@localhost").has_value());
    CHECK(!passwords::normalize_email("a@@b.com").has_value());
    CHECK(!passwords::normalize_email("a@b@c.com").has_value());
    CHECK(!passwords::normalize_email("a b@mail.com").has_value());
    CHECK(!passwords::normalize_email("a@mail..com").has_value());
    CHECK(!passwords::normalize_email("a@.mail.com").has_value());
    CHECK(!passwords::normalize_email("a@mail.com.").has_value());
    CHECK(!passwords::normalize_email("a@-mail.com").has_value());
    CHECK(!passwords::normalize_email(std::string("a\0b@mail.com", 12)).has_value());
}

TEST(passwords_email_length_limit) {
    std::string local(64, 'a');
    // 64 + 1 + домен: 254 байта ровно — допустимо, 255 — нет.
    std::string domain_ok(254 - 65, 'b');
    domain_ok.replace(domain_ok.size() - 4, 4, ".com");
    std::string ok = local + "@" + domain_ok;
    CHECK_EQ(ok.size(), static_cast<std::size_t>(254));
    CHECK(passwords::normalize_email(ok).has_value());
    CHECK(!passwords::normalize_email(ok + "c").has_value());
    CHECK(!passwords::normalize_email(std::string(65, 'a') + "@mail.com").has_value());
}

TEST(passwords_length_counts_characters_not_bytes) {
    CHECK(!passwords::password_length_ok(""));
    CHECK(!passwords::password_length_ok("123456789"));    // 9
    CHECK(passwords::password_length_ok("1234567890"));    // 10
    CHECK(passwords::password_length_ok(std::string(128, 'x')));
    CHECK(!passwords::password_length_ok(std::string(129, 'x')));
    // 10 кириллических символов — 20 байт, но допустимо; 9 — нет.
    std::string cyr10;
    for (int i = 0; i < 10; ++i) cyr10 += "ж";
    CHECK(passwords::password_length_ok(cyr10));
    CHECK(!passwords::password_length_ok(cyr10.substr(2)));
}
