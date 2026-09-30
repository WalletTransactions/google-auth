// Общее состояние процесса — прямой аналог AppState из Rust-версии этого же
// сервиса (см. соседний проект google-auth), но с реальной персистентностью:
// users/wallets/refresh_tokens живут в Postgres (см. db.hpp/repo.hpp), а не
// в памяти процесса — переживают рестарт сервиса. В памяти остался только
// `pending` (PKCE code_verifier + redirect_uri на время одного логина) —
// терять его при рестарте не страшно: пользователь просто начнёт вход заново.
//
// Специально не включает google.hpp/auth.hpp — только чистые
// данные (types.hpp, db.hpp), которым всем этим модулям и нужен AppState.
// Если бы AppState жил в одном файле с логикой одного из них — остальные не
// смогли бы на него сослаться, не зависев от чужой логики.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "db.hpp"
#include "redis_client.hpp"
#include "types.hpp"
#include "util/crypto.hpp"

// PKCE-состояние одного незавершённого браузерного входа (см.
// google.cpp::handle_login/handle_callback). redirect_uri хранится ЗДЕСЬ, а
// не берётся заново в handle_callback: OAuth 2.0 требует передавать ровно
// тот же redirect_uri что при запросе кода, что и при обмене его на токен
// (RFC 6749 §4.1.3) — а он теперь не один статический (AppState::redirect_url),
// а выбирается по входящему Host/X-Forwarded-Host (см. resolve_redirect_uri).
struct PendingLogin {
    std::string code_verifier;
    std::string redirect_uri;
};

struct AppState {
    std::string google_client_id;
    std::string google_client_secret;

    // Дефолт и одновременно фолбэк, когда Host запроса не совпал ни с одной
    // записью allowed_redirect_uris ниже (см. google.cpp::resolve_redirect_uri) —
    // прежнее поведение (одно статическое значение из REDIRECT_URL)
    // сохранено как безопасный фолбэк, не как единственный вариант.
    std::string redirect_url;

    // Дополнительные redirect_uri, которые можно выбрать динамически по
    // Host/X-Forwarded-Host входящего запроса — нужно, когда с одним и тем
    // же google-auth логинятся и локально (localhost), и с LAN-устройств
    // (см. ALLOWED_REDIRECT_URIS в .env, README "Вход и с localhost, и по
    // LAN одновременно"). Каждая запись здесь ОБЯЗАНА быть заодно
    // зарегистрирована в Google Cloud Console как Authorized redirect URI
    // того же Client ID — иначе Google просто отклонит обмен (собственная
    // проверка Google — это и есть основная защита; allowlist здесь нужен,
    // чтобы не пытаться слать Google то, что заведомо не пройдёт, и не
    // доверять слепо чужому Host в остальном коде). redirect_url выше сюда
    // тоже входит — resolve_redirect_uri проверяет объединение обоих полей.
    std::unordered_set<std::string> allowed_redirect_uris;

    // RSA-ключ для подписи СВОИХ access-токенов (RS256) — не путать с
    // google_client_secret, это разные вещи с разным временем жизни.
    // Публичная часть отдаётся наружу через GET /.well-known/jwks.json (см.
    // auth.cpp) — wallet-api/wallet-gateway проверяют токены по ней, без
    // общего секрета в конфиге. unique_ptr — тот же приём, что и с db:
    // RsaSigningKey не копируется, а конструируется по пути из .env уже
    // после его чтения в main().
    std::unique_ptr<crypto::RsaSigningKey> jwt_signing_key;

    // Email'ы (в нижнем регистре) из ADMIN_EMAILS/SUPPORT_EMAILS — таким
    // пользователям при логине выставляется соответствующая UserRecord::role
    // (см. types.hpp — Role::Admin/Role::Support): admin получает доступ к
    // /admin/users (см. admin.cpp); support пока зарезервирован — сама роль
    // долетает в payload access-токена (claim `role`), и другие сервисы
    // (например, wallet-api) могут её прочитать, если им это понадобится.
    // Требуется email_verified — см. auth::get_or_create_user. Если email
    // есть в обоих списках — побеждает admin (более высокая привилегия).
    std::unordered_set<std::string> admin_emails;
    std::unordered_set<std::string> support_emails;

    // true только за HTTPS в проде; для http://localhost — false.
    bool cookie_secure = false;

    // TTL access-токена короткий специально: скомпрометированный токен
    // перестаёт работать быстро. Долгая сессия без повторного логина через
    // Google обеспечивается refresh-токеном (см. auth.hpp), а не увеличением
    // этого значения.
    uint64_t access_token_ttl_secs = 60 * 15;                // 15 минут
    uint64_t refresh_token_ttl_secs = 60ULL * 60 * 24 * 30;  // 30 дней

    // Необязательный путь к CA-бандлу для HTTPS-запросов к Google. Пусто —
    // используется системное хранилище сертификатов (по умолчанию для
    // Windows/Linux этого достаточно). См. README про CA_BUNDLE_PATH.
    std::string ca_bundle_path;

    std::mutex pending_mutex;
    std::unordered_map<std::string, PendingLogin> pending; // csrf state -> {code_verifier, redirect_uri}

    // Верифицированные Google-claims человека, которого ещё нет в users —
    // ждут подтверждения на POST /auth/google/confirm-signup (см. google.cpp).
    // В памяти, как и pending: рестарт сервиса просто отправит его логиниться
    // заново, ничего не потеряно (аккаунт ещё не создан).
    std::mutex pending_signups_mutex;
    std::unordered_map<std::string, PendingSignup> pending_signups; // confirm token -> claims

    // Мобильный вход (Credential Manager, см. google.cpp::handle_mobile_login):
    // выданные, ещё не предъявленные nonce — POST /auth/nonce добавляет,
    // успешный POST /auth/google/mobile удаляет. Тот же уровень строгости,
    // что у pending/pending_signups выше: в памяти, без TTL — заброшенный
    // на середине вход просто оставляет неиспользуемую строку, а не риск
    // (nonce нельзя предъявить повторно, только один раз найти и стереть).
    std::mutex issued_nonces_mutex;
    std::unordered_set<std::string> issued_nonces;

    // users/wallets/refresh_tokens — в Postgres, см. repo.hpp. Пул, а не
    // одна Database (2026-09-17, см. db.hpp::Pool, зачем) — google-auth
    // общая точка входа для JWKS/логина/refresh для всех остальных сервисов,
    // один медленный/зависший запрос на единственном соединении раньше блокировал
    // бы вообще все остальные. unique_ptr, а не значение: конструктор Pool
    // требует строку подключения, а AppState собирается по частям в main()
    // уже после чтения .env.
    std::unique_ptr<db::Pool> db_pool;

    // Активные access-токены — в Redis (см. repo::store_access_token/
    // is_access_token_active/revoke_access_token), НЕ в Postgres и не в
    // памяти процесса: TTL здесь тот же, что и в claim'е "exp" самого JWT
    // (access_token_ttl_secs выше), но проверяется отдельно — это и даёт
    // logout возможность отозвать токен раньше срока (хотя бы для этого
    // сервиса, см. auth::authenticate() и README, "Мгновенный logout —
    // только в auth-сервисе"). unique_ptr — тот же приём, что и с db.
    std::unique_ptr<redis::Client> redis;

    // Связывание Telegram-бота (см. telegram.hpp). Пустой username —
    // POST /auth/telegram/link-code отвечает 503; пустой секрет — выключен
    // POST /internal/telegram/exchange (тоже 503, а не "открыт всем").
    std::string telegram_bot_username;
    std::string telegram_service_secret;
    uint64_t telegram_link_code_ttl_secs = 60 * 10; // 10 минут
};
