#include "passwords.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <stdexcept>
#include <vector>

#include "util/crypto.hpp"

namespace passwords {

namespace {

// PBKDF2-HMAC-SHA256 -> kHashBytes байт.
std::string derive(const std::string& password, const std::string& salt, int iterations) {
    std::string out(kHashBytes, '\0');
    int ok = PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                               reinterpret_cast<const unsigned char*>(salt.data()),
                               static_cast<int>(salt.size()), iterations, EVP_sha256(),
                               static_cast<int>(out.size()),
                               reinterpret_cast<unsigned char*>(&out[0]));
    if (ok != 1) throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    return out;
}

std::string random_salt() {
    auto bytes = crypto::random_bytes(kSaltBytes);
    return std::string(bytes.begin(), bytes.end());
}

bool is_ctl_or_space(unsigned char c) { return c <= 0x20 || c == 0x7F; }

} // namespace

Record make_record(const std::string& password, int iterations) {
    if (iterations <= 0) throw std::invalid_argument("iterations должно быть > 0");
    Record r;
    r.salt = random_salt();
    r.iterations = iterations;
    r.hash = derive(password, r.salt, iterations);
    return r;
}

bool verify(const std::string& password, const Record& record) {
    if (record.algo != kAlgoPbkdf2 || record.salt.empty() || record.hash.size() != kHashBytes ||
        record.iterations <= 0) {
        return false;
    }
    std::string got = derive(password, record.salt, record.iterations);
    // Длины равны (kHashBytes) — CRYPTO_memcmp безопасен и не зависит от
    // позиции первого отличия.
    return CRYPTO_memcmp(got.data(), record.hash.data(), kHashBytes) == 0;
}

bool needs_rehash(const Record& record, int configured_iterations) {
    return record.algo != kAlgoPbkdf2 || record.iterations < configured_iterations;
}

bool verify_dummy(const std::string& password, int iterations) {
    // Фиксированная соль и «эталонный» хэш от неё: нужно лишь, чтобы PBKDF2
    // отработал с теми же параметрами, что и на настоящей записи. Совпасть с
    // чем-то реальным результат не может — возвращаем false безусловно.
    static const std::string kSalt(kSaltBytes, '\x5a');
    if (iterations <= 0) iterations = kDefaultIterations;
    std::string got = derive(password, kSalt, iterations);
    volatile unsigned char sink = static_cast<unsigned char>(got[0]);
    (void)sink;
    return false;
}

std::optional<std::string> normalize_email(const std::string& raw) {
    std::size_t begin = 0;
    std::size_t end = raw.size();
    while (begin < end && is_ctl_or_space(static_cast<unsigned char>(raw[begin]))) ++begin;
    while (end > begin && is_ctl_or_space(static_cast<unsigned char>(raw[end - 1]))) --end;
    std::string email = raw.substr(begin, end - begin);
    if (email.empty() || email.size() > kMaxEmailBytes) return std::nullopt;

    for (char& ch : email) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (is_ctl_or_space(c)) return std::nullopt; // пробелы и управляющие внутри адреса
        if (c >= 'A' && c <= 'Z') ch = static_cast<char>(c - 'A' + 'a');
    }

    auto at = email.find('@');
    if (at == std::string::npos || at != email.rfind('@')) return std::nullopt; // ровно одна @
    std::string local = email.substr(0, at);
    std::string domain = email.substr(at + 1);
    if (local.empty() || local.size() > 64 || domain.empty()) return std::nullopt;

    // Домен: метки через точку, каждая непустая, без дефиса по краям; хотя бы
    // одна точка (admin@localhost не годится — реальный адрес нужен с доменом).
    if (domain.find('.') == std::string::npos) return std::nullopt;
    std::size_t start = 0;
    while (start <= domain.size()) {
        std::size_t dot = domain.find('.', start);
        std::size_t stop = dot == std::string::npos ? domain.size() : dot;
        if (stop == start) return std::nullopt; // пустая метка: "a..b", ".a", "a."
        if (domain[start] == '-' || domain[stop - 1] == '-') return std::nullopt;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return email;
}

bool password_length_ok(const std::string& password) {
    // Кодовые точки UTF-8: байты вида 10xxxxxx — продолжения, их не считаем
    // (корректность UTF-8 уже проверил json::parse).
    std::size_t chars = static_cast<std::size_t>(std::count_if(
        password.begin(), password.end(),
        [](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; }));
    return chars >= kMinPasswordChars && chars <= kMaxPasswordChars;
}

} // namespace passwords
