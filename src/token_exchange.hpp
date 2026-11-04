// Обмен токена по RFC 8693 (change add-token-exchange):
//
//   POST /internal/token/exchange — сервис-actor (wallet-ai, wallet-mcp) по
//   своему X-Service-Secret меняет JWT пользователя (subject) на короткий JWT
//   для следующего сервиса. Тело — application/x-www-form-urlencoded:
//   grant_type, subject_token, subject_token_type, audience, scope (необяз.).
//   Ответ 200 {access_token, issued_token_type, token_type, expires_in};
//   ошибки — {"error": "<код RFC 6749 §5.2 / RFC 8707>"}.
//
// Права только сужаются (D4, D5): адресат и scope — из жёсткой таблицы
// kPolicy, срок — не дольше subject и не дольше 300 с, role/email/name
// срезаются, в act видно, кто действует от имени пользователя. Выданный токен
// не регистрируется в Redis активных (D6) — ручки /auth/* его не примут.
//
// Не проксируется wallet-gateway (как все /internal/*). Тело запроса и ответа
// не пишется в debug-журнал (main.cpp, secret_body — префикс /internal/).
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "app_state.hpp"
#include "httplib.h"
#include "nlohmann/json.hpp"

namespace token_exchange {

inline constexpr const char* kGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
inline constexpr const char* kTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token";

// Строка таблицы политики (D4): actor может обменять subject, у которого в aud
// есть subject_aud и в scope — subject_scope, на токен для audience со scope.
// Таблица в коде, а не в env: изменение политики — изменение поведения
// безопасности, оно проходит через ревью и тесты.
struct PolicyRule {
    const char* actor;
    const char* subject_aud;
    const char* subject_scope;
    const char* audience;
    const char* scope;
};

inline constexpr PolicyRule kPolicy[] = {
    {"wallet-ai", "wallet-ai", "ai:use", "wallet-mcp", "mcp:read"},
    {"wallet-mcp", "wallet-mcp", "mcp:read", "wallet-report", "reports:read"},
};

void register_routes(httplib::Server& svr, AppState& state);

// Строки token_exchange_total{actor,result} для GET /metrics (docs.cpp
// дописывает их после metrics::render()). util/metrics из wallet-common умеет
// только один лейбл, а wallet-common здесь не правится — поэтому свой
// маленький счётчик. Пусто, пока не было ни одного обмена.
std::string render_metrics();

// Чистые помощники — в заголовке ради юнит-тестов (tests/test_token_exchange.cpp).
namespace detail {

enum class Outcome { Ok, InvalidTarget, InvalidGrant, InvalidScope };

struct Decision {
    Outcome outcome = Outcome::InvalidTarget;
    // Заполнены только при Ok.
    std::string audience;
    std::string scope;
};

// Решение по таблице политики (D4) для уже проверенного subject-токена
// (подпись, iss, exp — у вызывающего). Порядок: строка таблицы для actor и
// audience (иначе InvalidTarget) → aud/scope subject (InvalidGrant) → scope
// запроса (InvalidScope). scope — nullopt или пустая строка: выдаётся scope
// из таблицы; иначе набор scope запроса обязан совпасть со scope таблицы.
Decision decide(const std::string& actor, const nlohmann::json& subject_claims, const std::string& audience,
                const std::optional<std::string>& scope);

// Разбор TOKEN_EXCHANGE_SECRETS: "wallet-ai=<секрет>,wallet-mcp=<секрет>".
// Пробелы вокруг элементов и вокруг '=' обрезаются, пустые элементы
// пропускаются; пустая строка — пустой список (обмен выключен). Бросает
// std::invalid_argument (ошибка старта): элемент без '=', пустое имя или
// секрет, имя не из kPolicy, повтор имени, одинаковый секрет у двух actor'ов
// (иначе actor определялся бы неоднозначно). Текст исключения секретов не
// содержит.
std::vector<std::pair<std::string, std::string>> parse_secrets(const std::string& raw);

// Actor по X-Service-Secret: сравнение за постоянное время
// (telegram::detail::secret_matches) со ВСЕМИ секретами, без раннего выхода.
// Пусто — ни один не совпал.
std::string identify_actor(const std::vector<std::pair<std::string, std::string>>& secrets,
                           const std::string& provided);

// Разбор form-urlencoded тела. nullopt — одно и то же поле с разными
// значениями (RFC 6749 §3.2: параметр не повторяется) или поле без имени.
std::optional<httplib::Params> parse_form(const std::string& body);

// Тело ответа об ошибке: {"error":"<code>"}.
std::string error_body(const std::string& code);

// Сам обработчик — без Redis и Postgres (только ключ подписи и секреты из
// state), поэтому тестируется целиком на httplib::Request/Response.
void handle_exchange(AppState& state, const httplib::Request& req, httplib::Response& res);

} // namespace detail

} // namespace token_exchange
