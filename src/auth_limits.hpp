// Защита входа по паролю от перебора (change add-password-auth, design D4):
// счётчики неудач в Redis по email и по IP в фиксированном окне. Недоступный
// Redis — отказ (503), а не проверка пароля без лимитов.
#pragma once

#include <cstdint>
#include <string>

#include "auth_config.hpp"
#include "redis_client.hpp"

namespace auth_limits {

enum class Verdict {
    Ok,          // можно проверять пароль
    Limited,     // слишком много попыток — 429 с Retry-After
    Unavailable, // Redis недоступен — 503
};

struct Decision {
    Verdict verdict = Verdict::Ok;
    // Секунды до сброса блокирующего счётчика (для Retry-After), только при Limited.
    int64_t retry_after_secs = 0;
};

// Ключи Redis. email приходит нормализованным; в ключ идёт sha256(email), а не
// сам адрес — почта не светится в ключах и дампах Redis.
std::string email_key(const std::string& email);
std::string ip_key(const std::string& ip);

// Решение до проверки пароля: Limited, если неудач по email не меньше
// fail_max_per_email или по IP не меньше fail_max_per_ip. Ничего не
// увеличивает. Любая ошибка Redis — Unavailable.
Decision check(redis::Client& redis, const AuthConfig& config, const std::string& email,
               const std::string& ip);

// Решение только по IP — для регистрации, где email-счётчик трогать нельзя:
// иначе любой мог бы заблокировать вход чужому адресу, «регистрируя» его.
Decision check_ip(redis::Client& redis, const AuthConfig& config, const std::string& ip);

// Одна неудача: INCR по email и по IP; срок окна ставится при создании
// счётчика (и если ключ вдруг остался без срока, чтобы не блокировать
// навсегда). Ошибки Redis наружу не бросает — результат только в логе: ответ
// клиенту к этому моменту уже определён.
void record_failure(redis::Client& redis, const AuthConfig& config, const std::string& email,
                    const std::string& ip);

// Одна попытка, учитываемая только по IP (регистрация).
void record_ip_attempt(redis::Client& redis, const AuthConfig& config, const std::string& ip);

// Успешный вход сбрасывает счётчик по email (по IP — нет: он про всех, кто
// сидит за этим адресом).
void reset_email(redis::Client& redis, const std::string& email);

namespace detail {

// Оценка блокировки по уже прочитанным значениям — отдельно от Redis, ради
// юнит-теста. count < 0 — ключа нет. ttl_secs — остаток окна (-1 — без срока).
struct Counter {
    int64_t count = 0;
    int64_t ttl_secs = 0;
};
Decision evaluate(const Counter& email, const Counter& ip, const AuthConfig& config);

} // namespace detail

} // namespace auth_limits
