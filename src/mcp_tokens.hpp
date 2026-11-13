// Персональные MCP-токены (change add-mcp-personal-tokens): MCP-клиент
// (LM Studio, Claude Code и др.) держит в конфиге статичный заголовок и не
// умеет ни входить через Google, ни ротировать refresh. Поэтому:
//
//   POST /auth/mcp-tokens   — вошедший пользователь (веб, «Мои устройства»)
//                             выпускает непрозрачный токен wmcp_<43 символа
//                             base64url> с именем. Показывается один раз, в
//                             Redis — только хэш (repo::store_mcp_token).
//   POST /internal/mcp/token — wallet-mcp меняет MCP-токен на JWT на 300 с:
//                             aud wallet-report, scope reports:read, без role
//                             (token_claims::add_mcp_claims). Не проксируется
//                             гейтвеем; общий секрет не нужен — доказательство
//                             сам токен (256 бит).
//
// Срок: 30 дней без обмена, каждый обмен продлевает, но не дальше 90 дней от
// выпуска (repo::detail::next_mcp_expiry). MCP-токен — сессия устройства:
// виден в GET /auth/devices (platform "mcp") и отзывается теми же ручками.
#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include "app_state.hpp"
#include "httplib.h"
#include "nlohmann/json.hpp"

namespace mcp_tokens {

inline constexpr const char* kTokenPrefix = "wmcp_";
// Больше — 409: токенов «на каждый клиент» хватает с запасом, а бесконечный
// выпуск раздувал бы список устройств.
inline constexpr std::size_t kMaxTokensPerUser = 10;

void register_routes(httplib::Server& svr, AppState& state);

// Строки mcp_token_exchanges_total{audience,result} для GET /metrics (docs.cpp
// дописывает их после metrics::render(): util/metrics умеет один лейбл).
// Пусто, пока не было ни одного обмена.
std::string render_metrics();

// Чистые помощники — в заголовке ради юнит-тестов (tests/test_mcp_tokens.cpp).
namespace detail {

// Имя токена: обрезка пробельных символов по краям, затем 1..64 символа
// (кодовых точек UTF-8, не байт: «LM Studio дома» — 14 символов). nullopt —
// не прошло.
std::optional<std::string> normalize_name(const std::string& raw);

// "wmcp_" + ровно 43 символа [A-Za-z0-9_-] (base64url от 32 байт без '=').
// Проверка до похода в Redis: мусор отсекается сразу.
bool is_well_formed_token(const std::string& token);

// Новый токен: "wmcp_" + base64url(32 случайных байта).
std::string generate_token();

// base64url(sha256(token)) — ключ в Redis и token_hash в GET /auth/devices.
std::string hash_token(const std::string& token);

// Адресат из тела POST /internal/mcp/token: нет поля — "wallet-report";
// "wallet-report" и "wallet-docs" — как есть; всё остальное (другое имя, не
// строка, null) — nullopt, то есть 400 invalid_audience. body — уже
// разобранный JSON-объект.
std::optional<std::string> parse_audience(const nlohmann::json& body);

} // namespace detail

} // namespace mcp_tokens
