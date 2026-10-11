#include "auth.hpp"

#include <algorithm>
#include <cctype>

#include "nlohmann/json.hpp"
#include "repo.hpp"
#include "token_claims.hpp"
#include "util/base64.hpp"
#include "util/crypto.hpp"
#include "util/jwt.hpp"
#include "util/jwt_claims.hpp"
#include "util/log.hpp"
#include "util/metrics.hpp"
#include "util/time.hpp"

using nlohmann::json;

namespace auth {

namespace {

std::string extract_bearer(const httplib::Request& req) {
    std::string header = req.get_header_value("Authorization");
    static const std::string prefix = "Bearer ";
    if (header.size() > prefix.size() && header.compare(0, prefix.size(), prefix) == 0) {
        return header.substr(prefix.size());
    }
    return {};
}

// cpp-httplib не разбирает куки за нас — парсим заголовок "Cookie" вручную:
// "name1=value1; name2=value2".
std::string extract_cookie(const httplib::Request& req, const std::string& name) {
    std::string header = req.get_header_value("Cookie");
    size_t pos = 0;
    while (pos <= header.size()) {
        size_t semi = header.find(';', pos);
        std::string piece =
            header.substr(pos, semi == std::string::npos ? std::string::npos : semi - pos);

        size_t key_start = piece.find_first_not_of(' ');
        if (key_start != std::string::npos) {
            size_t eq = piece.find('=', key_start);
            if (eq != std::string::npos) {
                std::string key = piece.substr(key_start, eq - key_start);
                if (key == name) return piece.substr(eq + 1);
            }
        }

        if (semi == std::string::npos) break;
        pos = semi + 1;
    }
    return {};
}

// Из тела JSON-запроса достаём refresh_token, если он не пришёл в cookie
// (сценарий curl/Postman без cookie jar). Пустая/некорректная строка тела —
// не ошибка, просто нет токена в body.
std::string extract_body_refresh_token(const httplib::Request& req) {
    try {
        auto body = json::parse(req.body);
        return body.value("refresh_token", std::string{});
    } catch (const std::exception&) {
        return {};
    }
}

std::string lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Требуем email_verified — иначе непроверенный email из чужого аккаунта мог
// бы притвориться привилегированным адресом. Admin и Support не пересекаются
// по смыслу, но если email оказался в обоих списках — побеждает admin.
Role compute_role(const AppState& state, const std::string& email, bool email_verified) {
    if (!email_verified || email.empty()) return Role::User;
    std::string lower = lowercase(email);
    if (state.admin_emails.count(lower) > 0) return Role::Admin;
    if (state.support_emails.count(lower) > 0) return Role::Support;
    return Role::User;
}

// base64url(sha256(token)) — печатаемый текст, безопасный как значение
// TEXT-колонки/параметра SQL (сырые байты sha256 почти наверняка содержат
// 0x00 где-нибудь внутри, что сломало бы текстовый параметр PQexecParams —
// libpq ждёт C-строку).
std::string hash_token(const std::string& token) {
    return b64::encode(crypto::sha256(token));
}

std::string issue_access_token(const crypto::RsaSigningKey& key, const UserRecord& user,
                                const DeviceInfo& device, uint64_t ttl_secs) {
    uint64_t now = timeutil::now_epoch();
    json payload = {
        {"sub", user.id},
        {"email", user.email},
        {"name", user.name},
        {"role", to_string(user.role)},
        {"iat", now},
        {"exp", now + ttl_secs},
    };
    // Только если реально известно — браузерный вход не обязан его давать
    // (см. DeviceInfo, types.hpp), и старый формат токена (без этого claim'а)
    // не должен становиться недействительным для тех, кто его не проверяет.
    if (!device.device_id.empty()) {
        payload["device_id"] = device.device_id;
        payload["platform"] = device.platform;
    }
    // iss/aud/scope — org/docs/TODO_telegram_tokens.md, шаг 1. Сессия
    // Telegram-бота (platform=telegram) пока получает тот же полный набор:
    // урезанный токен бота появится вместе с POST /internal/telegram/token
    // (шаг 4), до тех пор бот ходит с обычным токеном устройства.
    token_claims::add_user_claims(payload);
    return jwt::sign_rs256(payload, key);
}

std::string cookie_header(const std::string& name, const std::string& value,
                           const std::string& path, bool secure, long max_age) {
    std::string h = name + "=" + value + "; Path=" + path + "; HttpOnly; SameSite=Lax";
    if (secure) h += "; Secure";
    if (max_age >= 0) h += "; Max-Age=" + std::to_string(max_age);
    return h;
}

} // namespace

void set_session_cookies(httplib::Response& res, const AppState& state, const TokenPair& tokens) {
    // access-токен — кука без Max-Age (session cookie): сам JWT истекает по
    // exp быстро (см. access_token_ttl_secs), отдельный срок жизни куки не нужен.
    res.set_header("Set-Cookie",
                    cookie_header(kSessionCookie, tokens.access_token, "/", state.cookie_secure, -1));
    // refresh-токен — Path=/auth: браузер не станет слать этот секрет с
    // каждым запросом к /api/*, только на сами /auth/refresh и /auth/logout.
    res.set_header("Set-Cookie",
                    cookie_header(kRefreshCookie, tokens.refresh_token, "/auth", state.cookie_secure,
                                  static_cast<long>(state.refresh_token_ttl_secs)));
}

void clear_session_cookies(httplib::Response& res, const AppState& state) {
    res.set_header("Set-Cookie", cookie_header(kSessionCookie, "", "/", state.cookie_secure, 0));
    res.set_header("Set-Cookie",
                    cookie_header(kRefreshCookie, "", "/auth", state.cookie_secure, 0));
}

UserRecord get_or_create_user(AppState& state, const std::string& google_sub,
                               const std::string& email, bool email_verified,
                               const std::string& name, const std::string& picture) {
    // Роль по спискам — только дефолт для НОВОГО пользователя (см.
    // repo::upsert_user: role_id не трогается при повторном логине уже
    // существующего). Если email добавили в ADMIN_EMAILS/SUPPORT_EMAILS
    // позже — на уже заведённых пользователей это не подействует, только на
    // тех, кто заведётся впервые после этого.
    Role role = compute_role(state, email, email_verified);
    std::string display_name = name.empty() ? "Пользователь" : name;
    // Атомарный UPSERT по google_sub — Postgres сам решает "уже есть или
    // новый", id существующей строки при этом не трогается (см. repo.cpp).
    return repo::upsert_user(*state.db_pool->acquire(), google_sub, email, email_verified, display_name, picture,
                              role);
}

TokenPair issue_tokens(AppState& state, const UserRecord& user, const DeviceInfo& device) {
    TokenPair pair;
    pair.access_token =
        issue_access_token(*state.jwt_signing_key, user, device, state.access_token_ttl_secs);
    pair.refresh_token = b64::encode(crypto::random_bytes(32));

    // Схлопывание по device_id: у мобильного входа (device_id непустой)
    // может накопиться несколько независимых активных refresh-сессий одного
    // и того же физического устройства — не через /auth/refresh (та просто
    // ротирует ОДНУ существующую запись, см. rotate_refresh_token), а через
    // повторный POST /auth/google/mobile, пока старая сессия того же
    // устройства ещё не истекла (переустановка приложения, повторный вход
    // без выхода из старого). Раньше это тихо копило "невидимые" активные
    // сессии одного устройства — до этого места единственным способом их
    // увидеть/закрыть было дождаться естественного TTL. Вместо схлопывания
    // ТОЛЬКО на экране "Устройства" (repo::list_user_sessions просто
    // сгруппировал бы дубли визуально, не убирая лишнее из Redis) решили
    // держать инвариант "не больше одной активной сессии на (user, device_id)"
    // здесь, в единственной точке выпуска токенов — тогда список устройств
    // ниже (devices.cpp) вообще не видит дублей, ему нечего группировать.
    // Браузер (device_id пуст) НЕ участвует — у него нет стабильного
    // идентификатора устройства, и разные вкладки/браузеры одного человека
    // обязаны оставаться разными сессиями (см. DeviceInfo, types.hpp).
    if (!device.device_id.empty()) {
        repo::revoke_user_sessions_if(*state.redis, user.id, [&device](const repo::SessionSummary& s) {
            return s.device.device_id == device.device_id;
        });
    }

    // Обе записи — в Redis (см. repo.hpp): refresh с TTL в 30 дней
    // (по умолчанию) и access с TTL в 15 минут. Redis EXPIRE сам чистит
    // просроченное — отдельная проверка "не истёк ли" (как раньше для
    // refresh_tokens в Postgres) больше не нужна ни для одного из двух.
    //
    // access_hash считается один раз и кладётся ОБОИМИ записями — refresh
    // несёт его как обратную связку на свой парный access-токен (см.
    // комментарий store_refresh_token в repo.hpp), а не только затем, чтобы
    // сохранить сам access-токен. Именно эта связка (не device_id — тот
    // всегда пуст у браузера и не различает несколько его сессий) даёт
    // repo::revoke_user_sessions_if погасить ровно ОДИН, а не все
    // access-токены пользователя при отзыве одной сессии (см. её README).
    std::string access_hash = hash_token(pair.access_token);
    repo::store_refresh_token(*state.redis, hash_token(pair.refresh_token), user.id, device,
                               access_hash, state.refresh_token_ttl_secs);
    // authenticate() ниже проверяет access-токен в Redis ДОПОЛНИТЕЛЬНО к
    // подписи/exp, а /auth/logout может удалить эту запись раньше срока.
    repo::store_access_token(*state.redis, access_hash, user.id, state.access_token_ttl_secs);

    return pair;
}

std::optional<TokenPair> rotate_refresh_token(AppState& state,
                                               const std::string& refresh_token_plaintext) {
    // take_refresh_token — атомарный Redis GETDEL: читает и тут же удаляет
    // запись, сразу отдавая АКТУАЛЬНОГО пользователя (не снимок на момент
    // выдачи, как было при хранении в памяти) — повторное предъявление того
    // же токена (например, украденной копии) уже ничего не найдёт. Заодно
    // возвращает устройство, которому был выпущен старый токен (см.
    // DeviceInfo) — переносим его на новую пару без изменений.
    auto owner = repo::take_refresh_token(*state.redis, *state.db_pool->acquire(), hash_token(refresh_token_plaintext));
    if (!owner) return std::nullopt;
    // Этот путь не идёт через authenticate() (предъявляется refresh-, не
    // access-токен) — user_id не выставился бы сам, делаем явно.
    applog::set_user(owner->user.id);
    return issue_tokens(state, owner->user, owner->device);
}

void revoke_refresh_token(AppState& state, const std::string& refresh_token_plaintext) {
    repo::revoke_refresh_token(*state.redis, hash_token(refresh_token_plaintext));
}

std::optional<AuthUser> authenticate(const httplib::Request& req, AppState& state) {
    std::string token = extract_bearer(req);
    if (token.empty()) token = extract_cookie(req, kSessionCookie);
    if (token.empty()) return std::nullopt;

    // Подпись и exp (обязательный) — util/jwt.
    auto payload = jwt::verify_rs256(token, state.jwt_signing_key->modulus(),
                                      state.jwt_signing_key->exponent());
    if (!payload) return std::nullopt;

    try {
        // iss/aud/scope (org/docs/TODO_telegram_tokens.md, шаг 2): все ручки
        // google-auth с access-токеном — управление аккаунтом (устройства,
        // связывание Telegram, удаление, /auth/me), отсюда один scope на
        // сервис. Токен Telegram-бота (шаг 4) сюда не пройдёт: в его aud
        // google-auth нет. Токен без aud — старый, пропускается до шага 3.
        jwt_claims::Result claims = jwt_claims::check(*payload, token_claims::kAudGoogleAuth, "account");
        metrics::inc_counter("jwt_claims_total", "Проверки iss/aud/scope access-токена по результату.", "result",
                             jwt_claims::to_string(claims));
        if (claims == jwt_claims::Result::Legacy) {
            applog::warn("access token without aud (legacy), accepted",
                         {{"event", "jwt_legacy"}, {"sub", payload->value("sub", std::string{})}});
        } else if (claims != jwt_claims::Result::Ok) {
            applog::warn("access token rejected",
                         {{"event", "jwt_rejected"}, {"reason", jwt_claims::to_string(claims)}});
            return std::nullopt;
        }

        // Подпись и exp в порядке — но сам токен мог быть отозван раньше
        // срока (logout, см. /auth/logout ниже): проверяем присутствие его
        // хэша в Redis (см. repo::store_access_token/revoke_access_token).
        // Действует только для этого сервиса — wallet-api/wallet-gateway
        // проверяют токен по JWKS локально и про отзыв не узнают (см.
        // README, "Мгновенный logout — только в auth-сервисе").
        if (!repo::is_access_token_active(*state.redis, hash_token(token))) {
            return std::nullopt;
        }

        AuthUser user;
        user.user_id = payload->at("sub").get<std::string>();
        user.email = payload->value("email", std::string{});
        user.name = payload->value("name", std::string{});
        user.role = role_from_string(payload->value("role", std::string("user")));
        user.device_id = payload->value("device_id", std::string{});
        user.platform = payload->value("platform", std::string{});
        // Токен проверен — дальнейшие строки лога этого запроса (route,
        // db query, финальная request_finished) сами унаследуют user_id
        // (см. applog::set_user в log.hpp), без протаскивания параметром.
        applog::set_user(user.user_id);
        return user;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void register_routes(httplib::Server& svr, AppState& state) {
    // Для SPA (wallet-web) — единственный способ узнать "залогинен ли я",
    // раз cookie "session" httpOnly (JS её не прочитает, и не должен — см.
    // README wallet-web). Тот же authenticate(), что и везде — просто здесь
    // отдаёт результат как JSON, а не решает сам, что показать.
    svr.Get("/auth/me", [&state](const httplib::Request& req, httplib::Response& res) {
        applog::set_route("GET /auth/me"); // литерал из паттерна регистрации выше
        auto user = authenticate(req, state);
        if (!user) {
            res.status = 401;
            res.set_content(json{{"error", "unauthenticated"}}.dump(), "application/json");
            return;
        }
        // picture — НЕ claim JWT (см. README, "Аватарка"): это чисто
        // презентационное поле, ему нечего делать в токене, который летает
        // с каждым запросом ко всему /api/*. Здесь, в единственном месте,
        // которое SPA дёргает один раз при загрузке, — отдельный поход в
        // Postgres. find_user_by_id() возвращает nullopt только если
        // пользователя успели удалить между выдачей ещё живого токена и
        // этим запросом — в таком случае просто "" (то есть 401 здесь
        // намеренно не отдаём: сама аутентификация уже прошла, отсутствие
        // аватарки — не повод рвать сессию).
        auto record = repo::find_user_by_id(*state.db_pool->acquire(), user->user_id);
        std::string picture = record ? record->picture : std::string{};
        json body = {
            {"id", user->user_id},
            {"email", user->email},
            {"name", user->name},
            {"picture", picture},
            {"role", to_string(user->role)},
        };
        res.set_content(body.dump(), "application/json");
    });

    // Самообслуживание — "Удалить аккаунт" в настройках wallet-web
    // (см. README wallet-web). Здесь удаляется только ИДЕНТИЧНОСТЬ (сама
    // строка users) — данные в wallet-api (леджер, счета, операции) удаляет
    // ОТДЕЛЬНЫЙ вызов DELETE /api/account там же (см. README wallet-api,
    // "Удаление аккаунта"): это два разных сервиса с разными базами, общей
    // транзакции между ними нет и быть не может. wallet-web вызывает ИХ по
    // порядку — сначала wallet-api (данные), потом этот эндпоинт
    // (идентичность) — так что если что-то и останется рассинхронизированным
    // при сетевом сбое посреди, это переживший чужие данные user БЕЗ них
    // (безопасно повторить весь сценарий заново), а не наоборот "данные без
    // идентичности, которой они принадлежат".
    svr.Delete("/auth/me", [&state](const httplib::Request& req, httplib::Response& res) {
        applog::set_route("DELETE /auth/me"); // литерал из паттерна регистрации выше
        auto user = authenticate(req, state);
        if (!user) {
            res.status = 401;
            res.set_content(json{{"error", "unauthenticated"}}.dump(), "application/json");
            return;
        }
        // Сначала токены (Redis), потом строка users (Postgres) — см.
        // комментарий у repo::delete_user, почему именно в этом порядке.
        repo::revoke_all_user_tokens(*state.redis, user->user_id);
        repo::delete_user(*state.db_pool->acquire(), user->user_id);
        clear_session_cookies(res, state);
        res.status = 204;
    });

    // Публичные ключи для проверки НАШИХ access-токенов (RS256) — без
    // авторизации, это и есть весь смысл: wallet-api/wallet-gateway (и
    // потенциально другие сервисы) проверяют подпись сами, без общего
    // секрета в конфиге и без похода в auth на каждый запрос (кроме самого
    // первого раза/смены ключа — см. util/jwks.hpp в тех сервисах).
    // Один ключ в массиве сейчас — формат уже готов к ротации (несколько
    // ключей одновременно, verify по "kid" из заголовка токена).
    svr.Get("/.well-known/jwks.json", [&state](const httplib::Request&, httplib::Response& res) {
        applog::set_route("GET /.well-known/jwks.json"); // литерал из паттерна регистрации выше
        json jwk = {
            {"kty", "RSA"},
            {"kid", state.jwt_signing_key->kid()},
            {"use", "sig"},
            {"alg", "RS256"},
            {"n", b64::encode(state.jwt_signing_key->modulus())},
            {"e", b64::encode(state.jwt_signing_key->exponent())},
        };
        json body = {{"keys", json::array({jwk})}};
        res.set_content(body.dump(), "application/json");
    });

    svr.Post("/auth/refresh", [&state](const httplib::Request& req, httplib::Response& res) {
        applog::set_route("POST /auth/refresh"); // литерал из паттерна регистрации выше
        std::string from_cookie = extract_cookie(req, kRefreshCookie);
        std::string from_body = from_cookie.empty() ? extract_body_refresh_token(req) : std::string{};
        std::string refresh_token = from_cookie.empty() ? from_body : from_cookie;

        if (refresh_token.empty()) {
            res.status = 400;
            res.set_content(
                "refresh_token не передан (cookie refresh_token или JSON-поле refresh_token)",
                "text/plain; charset=utf-8");
            return;
        }

        auto tokens = rotate_refresh_token(state, refresh_token);
        if (!tokens) {
            clear_session_cookies(res, state);
            res.status = 401;
            res.set_content(
                "refresh-токен недействителен, истёк или уже использован — войдите заново "
                "через /auth/google",
                "text/plain; charset=utf-8");
            return;
        }

        set_session_cookies(res, state, *tokens);

        json body_out = {
            {"access_token", tokens->access_token},
            {"expires_in", state.access_token_ttl_secs},
        };
        // Клиент без cookie jar (curl/Postman/мобильное приложение) должен
        // получить новый refresh-токен явно — иначе продолжить цепочку
        // рефрешей ему будет нечем, а старый уже инвалидирован.
        if (from_cookie.empty()) body_out["refresh_token"] = tokens->refresh_token;

        res.set_content(body_out.dump(), "application/json");
    });

    svr.Post("/auth/logout", [&state](const httplib::Request& req, httplib::Response& res) {
        applog::set_route("POST /auth/logout"); // литерал из паттерна регистрации выше
        // Отзываем access-токен в Redis раньше его естественного истечения —
        // тем же способом, каким authenticate() его туда искал (Bearer,
        // иначе cookie "session"). Не ошибка, если токена нет/уже истёк —
        // logout должен снести cookie в любом случае.
        std::string access_token = extract_bearer(req);
        if (access_token.empty()) access_token = extract_cookie(req, kSessionCookie);
        if (!access_token.empty()) repo::revoke_access_token(*state.redis, hash_token(access_token));

        std::string refresh_token = extract_cookie(req, kRefreshCookie);
        if (refresh_token.empty()) refresh_token = extract_body_refresh_token(req);
        if (!refresh_token.empty()) revoke_refresh_token(state, refresh_token);

        clear_session_cookies(res, state);
        res.status = 204;
    });
}

std::string extract_refresh_token(const httplib::Request& req) {
    std::string token = extract_cookie(req, kRefreshCookie);
    if (token.empty()) token = extract_body_refresh_token(req);
    return token;
}

std::string hash_refresh_token(const std::string& token_plaintext) { return hash_token(token_plaintext); }

} // namespace auth
