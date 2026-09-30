// Собственная сессия поверх разовой Google-верификации.
//
// Google id_token живёт ~1 час и не предназначен для использования как
// долгоживущий пропуск ко всему API. Поэтому после его проверки (см.
// google.cpp) сервис заводит/находит внутреннего пользователя и выпускает
// СВОЮ пару токенов:
//   - access-токен  — JWT RS256, короткий TTL (см. AppState::access_token_ttl_secs,
//     по умолчанию 15 минут). Его проверяют другие сервисы (wallet-api,
//     wallet-gateway) по JWKS — локально, без повторных походов
//     в auth на каждый запрос. Дополнительно его хэш кладётся в Redis с тем
//     же TTL (см. repo::store_access_token) — это даёт /auth/logout
//     возможность отозвать токен мгновенно, но ТОЛЬКО для проверок внутри
//     этого сервиса (auth::authenticate() смотрит в Redis); wallet-api/
//     wallet-gateway о таком отзыве не узнают — они не спрашивают auth ни о
//     чём, кроме JWKS.
//   - refresh-токен — непрозрачная случайная строка, долгий TTL (по
//     умолчанию 30 дней), хранится в Redis (см. repo::store_refresh_token —
//     AOF-персистентность + volume, см. compose.yaml, иначе пересоздание
//     контейнера разлогинило бы всех разом) ТОЛЬКО в виде
//     base64url(SHA-256)-хэша. Обменивается на новую пару через
//     POST /auth/refresh — это единственное, для чего он годится, сам по
//     себе доступа к API не даёт. При каждом обмене СТАРЫЙ refresh-токен
//     инвалидируется (ротация, теперь атомарным Redis GETDEL — см.
//     repo::take_refresh_token) — повторное предъявление уже потраченного
//     токена (например, украденной копии) получает отказ, а не вторую
//     попытку (детект кражи с отзывом всей цепочки при этом не реализован —
//     для демо-уровня достаточно ротации).
//
// RS256 с публичным ключом через /.well-known/jwks.json — ровно то же, что
// сам этот сервис делает для проверки id_token Google (см.
// google_auth::verify_id_token) — только тут auth-service в роли Google, а
// wallet-api/wallet-gateway в роли себя самого: сами качают JWKS (см. их
// util/jwks.hpp), сами проверяют подпись, без общего секрета в конфиге и без
// похода в auth на каждый запрос. Раньше (пока всё было одним процессом) был
// общий HS256-секрет (JWT_SECRET) — от него отказались именно при разъезде
// на отдельные сервисы.
#pragma once

#include <optional>
#include <string>

#include "app_state.hpp"
#include "httplib.h"

namespace auth {

inline constexpr const char* kSessionCookie = "session";
inline constexpr const char* kRefreshCookie = "refresh_token";

void register_routes(httplib::Server& svr, AppState& state);

// Заводит нового пользователя или обновляет изменившиеся поля у уже
// существующего (email/имя/аватар с Google, роль из ADMIN_EMAILS/
// SUPPORT_EMAILS) — атомарный UPSERT по google_sub, см. repo::upsert_user.
// Берёт сырые поля, а не GoogleClaims — auth.hpp сознательно не зависит от
// google.hpp: вызывающий код (google.cpp) сам решает, откуда эти поля взять
// (из только что проверенного id_token или из отложенной PendingSignup —
// см. AppState::pending_signups).
UserRecord get_or_create_user(AppState& state, const std::string& google_sub,
                               const std::string& email, bool email_verified,
                               const std::string& name, const std::string& picture);

struct TokenPair {
    std::string access_token;
    std::string refresh_token;
};

// Выпускает новую пару токенов для пользователя (после логина через Google
// или при рефреше). Каждый вызов кладёт НОВУЮ запись в Redis (и под
// access-, и под refresh-токен, см. repo.hpp) — старую (если рефреш)
// вызывающий код должен инвалидировать сам (rotate_refresh_token делает это
// атомарно через GETDEL).
//
// device — см. DeviceInfo (types.hpp), по умолчанию пусто (браузерный
// логин может не передавать). Непустой device.device_id дополнительно
// попадает в сам access-JWT (claim "device_id") — см. issue_access_token в
// auth.cpp и org/docs/TODO_mobile_sync.md, п. 1.2.
TokenPair issue_tokens(AppState& state, const UserRecord& user, const DeviceInfo& device = {});

// Проверяет refresh-токен и, если он валиден и не истёк, атомарно ротирует
// его: старый инвалидируется даже при последующей ошибке. nullopt — токен
// неизвестен или истёк (в т.ч. если уже был использован раньше). Устройство,
// которому был выпущен старый токен (см. DeviceInfo), переносится на новую
// пару без изменений — иначе "какое это устройство" терялось бы уже на
// первом рефреше.
std::optional<TokenPair> rotate_refresh_token(AppState& state,
                                               const std::string& refresh_token_plaintext);

// Отзывает refresh-токен (logout). Не ошибка, если его и так нет в хранилище.
void revoke_refresh_token(AppState& state, const std::string& refresh_token_plaintext);

// Выставляет обе cookie (session + refresh_token) под выданную пару токенов.
// Используется и после логина (google.cpp), и после успешного рефреша.
void set_session_cookies(httplib::Response& res, const AppState& state, const TokenPair& tokens);

// Стирает обе cookie (Max-Age=0) — logout или неудавшийся рефреш.
void clear_session_cookies(httplib::Response& res, const AppState& state);

// То, что достаём из валидного access-токена и отдаём хендлерам.
struct AuthUser {
    std::string user_id;
    std::string email;
    std::string name;
    Role role = Role::User; // см. AppState::admin_emails/support_emails, types.hpp
    // Пусто, если токен выпущен без устройства (браузер) — см. DeviceInfo,
    // types.hpp, и claim "device_id" в issue_access_token (auth.cpp).
    std::string device_id;
    std::string platform;
};

// Проверяет запрос: сначала заголовок Authorization: Bearer, иначе cookie
// "session" (её выставляет google_auth::register_routes после логина).
// nullopt — токена нет или он недействителен/истёк; вызывающий хендлер сам
// решает, что с этим делать (обычно 401). Про истёкший access-токен: клиент
// должен сходить в POST /auth/refresh за новым, а не логиниться заново.
std::optional<AuthUser> authenticate(const httplib::Request& req, AppState& state);

// Извлекает refresh-токен из запроса — cookie "refresh_token" (Path=/auth),
// а если её нет — JSON-поле "refresh_token" тела (curl/Postman/мобильный
// клиент без cookie jar). Тот же порядок, что и POST /auth/refresh (см. его
// хендлер) — вынесено наружу, чтобы devices.cpp мог определить, какая из
// сессий пользователя "текущая" (та, чей refresh-токен реально пришёл с этим
// запросом), не дублируя разбор cookie/body самостоятельно.
std::string extract_refresh_token(const httplib::Request& req);

// base64url(sha256(token)) — тот же хэш, что кладётся ключом в Redis (см.
// repo::store_refresh_token/repo::list_user_sessions). Нужен снаружи по той
// же причине, что и extract_refresh_token выше: сравнить "текущий"
// refresh-токен запроса с SessionSummary::token_hash.
std::string hash_refresh_token(const std::string& token_plaintext);

} // namespace auth
