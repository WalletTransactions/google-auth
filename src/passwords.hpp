// Пароли для входа без Google (change add-password-auth, спека password-auth):
// хэш PBKDF2-HMAC-SHA256 на OpenSSL (без новых зависимостей — тот же приём,
// что util/crypto поверх OpenSSL) и проверка введённых email/пароля.
//
// Здесь только чистая логика без БД/Redis/HTTP — чтобы её можно было покрыть
// юнит-тестами (tests/test_passwords.cpp); хранение — repo::*password*.
#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace passwords {

// Идентификатор алгоритма в user_passwords.algo. Пока единственный; колонка
// нужна, чтобы позже перейти на другой (например, argon2id), не ломая старые
// записи (design D2).
inline constexpr const char* kAlgoPbkdf2 = "pbkdf2-sha256";

inline constexpr int kDefaultIterations = 600000;
inline constexpr std::size_t kSaltBytes = 16;
inline constexpr std::size_t kHashBytes = 32;

inline constexpr std::size_t kMinPasswordChars = 10;
inline constexpr std::size_t kMaxPasswordChars = 128;
inline constexpr std::size_t kMaxEmailBytes = 254;

// Запись в user_passwords. salt/hash — сырые байты (std::string, как в
// util/hex), не hex: в БД они лежат BYTEA, hex — только на границе SQL.
struct Record {
    std::string algo = kAlgoPbkdf2;
    std::string salt;
    int iterations = 0;
    std::string hash;
};

// Новая запись: случайная соль kSaltBytes байт и PBKDF2 с `iterations`
// итерациями. Бросает std::runtime_error, если OpenSSL отказал, и
// std::invalid_argument при iterations <= 0.
Record make_record(const std::string& password, int iterations);

// Совпадает ли пароль с записью. Хэши сравниваются за постоянное время
// (CRYPTO_memcmp). Запись с неизвестным algo или пустой солью/хэшем — false.
bool verify(const std::string& password, const Record& record);

// true, если запись нужно пересчитать после успешной проверки: итераций
// меньше, чем требует конфигурация (PASSWORD_PBKDF2_ITERATIONS), или другой
// алгоритм.
bool needs_rehash(const Record& record, int configured_iterations);

// Проверка пароля по фиктивной записи с теми же параметрами — вход для
// несуществующего email, чтобы время ответа не выдавало, есть ли такой
// пользователь (design D3). Всегда false, но PBKDF2 считает по-настоящему.
bool verify_dummy(const std::string& password, int iterations);

// Email: обрезка пробелов по краям и нижний регистр (ASCII). nullopt —
// недопустимый адрес: не `local@domain`, пробелы/управляющие символы внутри,
// пустая часть, домен без точки, длина больше kMaxEmailBytes.
std::optional<std::string> normalize_email(const std::string& raw);

// Длина пароля в символах (кодовых точках UTF-8) от kMinPasswordChars до
// kMaxPasswordChars. Других требований к составу нет (спека).
bool password_length_ok(const std::string& password);

} // namespace passwords
