// Настройки входа по паролю (change add-password-auth, спека password-auth):
// какие способы входа включены, открыта ли регистрация, лимиты попыток. Только
// данные и разбор строк — без Redis/HTTP, чтобы всё проверялось юнит-тестом
// (tests/test_auth_config.cpp).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// AUTH_METHODS. Другое значение — ошибка старта (см. parse_auth_methods).
enum class AuthMethods { Password, Google, Both };

struct AuthConfig {
    AuthMethods methods = AuthMethods::Both;
    // REGISTRATION=open|closed — самостоятельная регистрация по паролю.
    bool registration_open = true;
    // ALLOW_INSECURE_AUTH — принимать пароль и без X-Forwarded-Proto: https.
    bool allow_insecure = false;

    // PASSWORD_PBKDF2_ITERATIONS. Не меньше kMinPbkdf2Iterations (спека:
    // «не меньше 600 000»); меньшее значение — ошибка старта.
    int pbkdf2_iterations = 600000;

    // AUTH_FAIL_MAX_PER_EMAIL / AUTH_FAIL_MAX_PER_IP / AUTH_FAIL_WINDOW_SECS.
    int64_t fail_max_per_email = 5;
    int64_t fail_max_per_ip = 30;
    uint64_t fail_window_secs = 900;

    bool password_enabled() const { return methods != AuthMethods::Google; }
    bool google_enabled() const { return methods != AuthMethods::Password; }
    // «Регистрация открыта» для GET /auth/methods: включён пароль и open.
    bool registration_available() const { return password_enabled() && registration_open; }
};

inline constexpr int kMinPbkdf2Iterations = 600000;

// "password" | "google" | "both" (точное совпадение, без регистра не
// приводится: опечатка в конфиге должна ломать старт, а не молча работать).
// nullopt — недопустимое значение.
std::optional<AuthMethods> parse_auth_methods(const std::string& value);

// "open" | "closed". nullopt — недопустимое значение.
std::optional<bool> parse_registration_open(const std::string& value);

// Включённые способы в порядке для GET /auth/methods: password, затем google.
std::vector<std::string> enabled_method_names(const AuthConfig& config);
