#include "google.hpp"

#include <random>

#include "auth.hpp"
#include "nlohmann/json.hpp"
#include "pages.hpp"
#include "repo.hpp"
#include "util/base64.hpp"
#include "util/crypto.hpp"
#include "util/jwt.hpp"
#include "util/log.hpp"
#include "util/time.hpp"
#include "util/url.hpp"

using nlohmann::json;

namespace google_auth {

namespace {

constexpr const char* kHtmlContentType = "text/html; charset=utf-8";

std::string random_string(size_t len) {
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2); // без '\0'

    std::string out(len, '\0');
    for (auto& c : out) c = charset[dist(rng)];
    return out;
}

std::string pkce_challenge(const std::string& verifier) {
    return b64::encode(crypto::sha256(verifier));
}

// Настраивает HTTPS-клиент к Google: системное хранилище сертификатов по
// умолчанию (см. README про CA_BUNDLE_PATH), таймауты, явная проверка TLS.
void configure_client(httplib::Client& cli, const AppState& state) {
    if (!state.ca_bundle_path.empty()) {
        cli.set_ca_cert_path(state.ca_bundle_path);
    }
    cli.enable_server_certificate_verification(true);
    cli.set_connection_timeout(10, 0);
    cli.set_read_timeout(10, 0);

    // Принудительно IPv4 — оба гугловских хоста (oauth2.googleapis.com,
    // www.googleapis.com) резолвятся и в A, и в AAAA, а cpp-httplib пробует
    // адреса из getaddrinfo() по порядку (обычно IPv6 первым) БЕЗ отдельного
    // таймаута на каждый: если попытка connect() именно зависает (не
    // получает ни успеха, ни явного отказа) и упирается в
    // connection_timeout, httplib взводит внутренний "quit" и не пробует
    // следующий адрес вообще (см. detail::create_client_socket — на
    // Error::ConnectionTimeout выставляется quit=true, и цикл по
    // rp->ai_next обрывается) — то есть рабочий IPv4-адрес так и не
    // используется. В сетях, где исходящий IPv6 в интернет не роутится
    // (частый случай в офисных/корпоративных сетях — ровно так и
    // проявилось: "Connection timed out" на обмене code/JWKS, хотя тот же
    // хост по IPv4 отвечает мгновенно), это выглядит как сломанный логин,
    // хотя проблема в сети, а не в Google/коде. AF_INET тут всегда
    // безопасен — оба хоста доступны по IPv4 в любом случае.
    cli.set_address_family(AF_INET);
}

void handle_verified_claims(AppState& state, const GoogleClaims& claims, const DeviceInfo& device,
                             httplib::Response& res);

// Браузер не даёт стабильного id устройства (в отличие от мобильного —
// см. DeviceInfo, types.hpp) — единственное, что тут есть "для показа
// человеку", это его собственный User-Agent. device_id остаётся пустым.
DeviceInfo browser_device(const httplib::Request& req) {
    DeviceInfo device;
    device.platform = "web";
    device.device_name = req.get_header_value("User-Agent");
    return device;
}

void handle_index(const httplib::Request&, httplib::Response& res) {
    applog::set_route("GET /"); // литерал из register_routes ниже
    res.set_content(pages::index(), kHtmlContentType);
}

// Какой redirect_uri слать Google для ЭТОГО конкретного запроса. Раньше было
// одно статическое значение (AppState::redirect_url) — этого хватало, пока
// сервис был доступен только с одного адреса. Теперь тот же сервис должен
// пускать и локально (localhost — с этой же машины), и с устройств в LAN
// (см. чат про self-hairpin и nip.io) одновременно, а Google Console не
// позволяет один redirect_uri — только СПИСОК заранее известных точных
// значений (см. AppState::allowed_redirect_uris). Поэтому: смотрим, с каким
// Host реально пришёл браузер, и если он совпадает с одним из уже
// зарегистрированных в Google Console redirect_uri — используем его; иначе
// — безопасный фолбэк (state.redirect_url), а не то, что попросил клиент
// (Host — заголовок, который шлёт сам клиент, доверять ему напрямую без
// сверки со списком нельзя).
//
// X-Forwarded-Host, если есть — приоритетнее Host: браузер обычно ходит
// через wallet-gateway (см. его main.cpp, proxy_request), а тот НАМЕРЕННО
// не форвардит сырой Host (апстрим иначе получил бы "google-auth:8080"
// вместо адреса, которым пользовался браузер) и кладёт исходный Host сюда
// отдельно. Прямые запросы мимо гейтвея (см. README, ":8080") этого
// заголовка не несут — тогда используем обычный Host.
//
// Домашняя подсеть 192.168.*: устройство в LAN обычно набирает голый IP
// (`http://192.168.1.105:8090`, проще запомнить), а Google принимает в
// redirect_uri только доменные имена ("must use a domain that is a valid
// top private domain") — отсюда nip.io-адрес в ALLOWED_REDIRECT_URIS (см.
// .env.example). Голый Host из этой подсети побайтово НЕ совпадал с
// зарегистрированной nip.io-строкой, и вход молча падал в фолбэк на
// REDIRECT_URL (localhost) — здесь IP переписывается в свой nip.io-
// эквивалент ДО сверки со списком ниже, поэтому набирать длинный nip.io-адрес
// руками больше не нужно. Другие подсети (10.*, 172.16-31.*) и уже готовые
// домены (localhost, сам nip.io) не трогает — не тот случай, который просил
// исправить пользователь, и не обязаны совпадать с этим костылём. Сверка
// allowed_redirect_uris.count(...) ниже не ослабляется этим переписыванием:
// не зарегистрированный nip.io-адрес всё равно уйдёт в фолбэк, как и раньше.
std::string rewrite_lan_ip_to_nip_io(const std::string& host) {
    if (host.rfind("192.168.", 0) != 0) return host;
    std::string::size_type colon = host.find(':');
    std::string ip = colon == std::string::npos ? host : host.substr(0, colon);
    std::string rest = colon == std::string::npos ? std::string() : host.substr(colon);
    return ip + ".nip.io" + rest;
}

std::string resolve_redirect_uri(const AppState& state, const httplib::Request& req) {
    std::string host = req.get_header_value("X-Forwarded-Host");
    if (host.empty()) host = req.get_header_value("Host");
    if (host.empty()) return state.redirect_url;

    host = rewrite_lan_ip_to_nip_io(host);

    // LAN-only на этом этапе проекта — TLS нет ни у гейтвея, ни у прямого
    // доступа (см. org/docs/TODO_mobile_sync.md, 1.4), поэтому схема всегда
    // http, не строим её из запроса.
    std::string candidate = "http://" + host + "/auth/google/callback";
    if (state.allowed_redirect_uris.count(candidate) > 0) return candidate;
    return state.redirect_url;
}

// Шаг 2: строим ссылку на Google OAuth 2.0 с PKCE и CSRF-state, редиректим.
void handle_login(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("GET /auth/google"); // литерал из register_routes ниже
    std::string csrf_state = random_string(32);
    std::string code_verifier = random_string(64);
    std::string code_challenge = pkce_challenge(code_verifier);
    std::string redirect_uri = resolve_redirect_uri(state, req);

    {
        std::lock_guard<std::mutex> lock(state.pending_mutex);
        state.pending[csrf_state] = PendingLogin{code_verifier, redirect_uri};
    }

    std::string query = urlutil::build_query({
        {"client_id", state.google_client_id},
        {"redirect_uri", redirect_uri},
        {"response_type", "code"},
        {"scope", "openid email profile"},
        {"state", csrf_state},
        {"code_challenge", code_challenge},
        {"code_challenge_method", "S256"},
        {"access_type", "online"},
        {"prompt", "select_account"},
    });

    res.set_redirect("https://accounts.google.com/o/oauth2/v2/auth?" + query);
}

// Шаг 3-4: обмен code -> токены, верификация id_token. Дальше — развилка:
// если такой google_sub уже есть в users, сразу логиним (выпускаем пару
// access+refresh, auth::issue_tokens, обе — в httpOnly cookie). Если нет —
// НЕ создаём аккаунт молча, показываем страницу с подтверждением
// (см. handle_confirm_signup).
void handle_callback(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("GET /auth/google/callback"); // литерал из register_routes ниже
    if (req.has_param("error")) {
        res.set_content(
            pages::error("Google вернул ошибку авторизации: " + req.get_param_value("error")),
            kHtmlContentType);
        return;
    }
    if (!req.has_param("code") || !req.has_param("state")) {
        res.set_content(pages::error("В ответе Google отсутствует code или state"),
                         kHtmlContentType);
        return;
    }

    std::string code = req.get_param_value("code");
    std::string csrf_state = req.get_param_value("state");

    std::string code_verifier;
    std::string redirect_uri;
    {
        std::lock_guard<std::mutex> lock(state.pending_mutex);
        auto it = state.pending.find(csrf_state);
        if (it == state.pending.end()) {
            res.set_content(
                pages::error("Неизвестный или уже использованный state — возможная "
                              "CSRF-атака либо повторный переход по старой ссылке. "
                              "Начните вход заново."),
                kHtmlContentType);
            return;
        }
        code_verifier = it->second.code_verifier;
        redirect_uri = it->second.redirect_uri;
        state.pending.erase(it);
    }

    httplib::Client token_client("https://oauth2.googleapis.com");
    configure_client(token_client, state);

    httplib::Params params;
    params.emplace("code", code);
    params.emplace("client_id", state.google_client_id);
    params.emplace("client_secret", state.google_client_secret);
    // Тот же redirect_uri, что был отправлен Google на шаге handle_login —
    // не state.redirect_url заново: OAuth 2.0 требует их совпадения (см.
    // комментарий у PendingLogin в app_state.hpp), а сейчас это не всегда
    // одно и то же значение (см. resolve_redirect_uri).
    params.emplace("redirect_uri", redirect_uri);
    params.emplace("grant_type", "authorization_code");
    params.emplace("code_verifier", code_verifier);

    auto token_res = token_client.Post("/token", params);
    if (!token_res) {
        res.set_content(pages::error("Не удалось обратиться к Google: " +
                                      httplib::to_string(token_res.error())),
                         kHtmlContentType);
        return;
    }
    if (token_res->status != 200) {
        res.set_content(pages::error("Google отклонил обмен кода на токен (" +
                                      std::to_string(token_res->status) + "): " +
                                      token_res->body),
                         kHtmlContentType);
        return;
    }

    json token_json;
    try {
        token_json = json::parse(token_res->body);
    } catch (const std::exception& ex) {
        res.set_content(pages::error(std::string("Не удалось разобрать ответ Google: ") +
                                      ex.what()),
                         kHtmlContentType);
        return;
    }

    if (!token_json.contains("id_token")) {
        res.set_content(pages::error("Google не вернул id_token"), kHtmlContentType);
        return;
    }
    std::string id_token = token_json.at("id_token").get<std::string>();

    std::string verify_error;
    auto claims = verify_id_token(state, id_token, verify_error);
    if (!claims) {
        res.set_content(pages::error("Не удалось верифицировать учётную запись: " + verify_error),
                         kHtmlContentType);
        return;
    }

    handle_verified_claims(state, *claims, browser_device(req), res);
}

// Общий хвост для уже проверенных Google-claims (не важно, откуда — из
// handle_callback после реальной верификации id_token, или из тестового
// пути): логин, если такой google_sub уже есть, иначе — отложенное
// подтверждение регистрации.
void handle_verified_claims(AppState& state, const GoogleClaims& claims, const DeviceInfo& device,
                             httplib::Response& res) {
    // Уже есть аккаунт с этим google_sub — просто логиним, без лишних шагов.
    if (repo::find_user_by_google_sub(*state.db_pool->acquire(), claims.sub)) {
        UserRecord user = auth::get_or_create_user(state, claims.sub, claims.email,
                                                    claims.email_verified, claims.name,
                                                    claims.picture);
        applog::set_user(user.id); // см. комментарий у handle_mobile_login, тот же случай
        auth::TokenPair tokens = auth::issue_tokens(state, user, device);
        auth::set_session_cookies(res, state, tokens);
        // Раньше здесь рендерилась своя HTML-страница успеха — теперь просто
        // редирект на "/": та же cookie уже лежит в браузере, а "/" (через
        // гейтвей) — это SPA (wallet-web), которая сама дёрнет GET /auth/me
        // и покажет дашборд. См. README wallet-web.
        res.set_redirect("/");
        return;
    }

    // Личность Google подтвердил, но аккаунта у нас ещё нет — не создаём
    // молча. Откладываем проверенные claims и ждём явного подтверждения на
    // POST /auth/google/confirm-signup (см. ниже).
    PendingSignup pending;
    pending.google_sub = claims.sub;
    pending.email = claims.email;
    pending.email_verified = claims.email_verified;
    pending.name = claims.name;
    pending.picture = claims.picture;

    std::string confirm_token = random_string(32);
    {
        std::lock_guard<std::mutex> lock(state.pending_signups_mutex);
        state.pending_signups[confirm_token] = pending;
    }
    res.set_content(pages::confirm_signup(pending, confirm_token), kHtmlContentType);
}

// Явное подтверждение регистрации — единственное место, где реально
// создаётся новый UserRecord (см. handle_callback выше).
void handle_confirm_signup(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/google/confirm-signup"); // литерал из register_routes ниже
    std::string confirm_token = req.get_param_value("token");

    PendingSignup pending;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(state.pending_signups_mutex);
        auto it = state.pending_signups.find(confirm_token);
        if (it != state.pending_signups.end()) {
            pending = it->second;
            found = true;
            state.pending_signups.erase(it); // одноразовый
        }
    }
    if (!found) {
        res.set_content(
            pages::error("Заявка на регистрацию не найдена или уже обработана — начните вход "
                          "заново."),
            kHtmlContentType);
        return;
    }

    UserRecord user = auth::get_or_create_user(state, pending.google_sub, pending.email,
                                                pending.email_verified, pending.name,
                                                pending.picture);
    applog::set_user(user.id); // см. комментарий у handle_mobile_login, тот же случай
    auth::TokenPair tokens = auth::issue_tokens(state, user, browser_device(req));
    auth::set_session_cookies(res, state, tokens);
    res.set_redirect("/"); // см. комментарий в handle_verified_claims выше
}

// Мобильный вход (Android Credential Manager) — см. README, "Мобильный
// вход". В отличие от браузерного флоу (handle_login/handle_callback)
// здесь нет ни редиректа, ни code exchange: Android получает id_token от
// Google напрямую через Play Services, сюда прилетает уже готовый токен.
//
// POST /auth/nonce -> {"nonce": "..."}. Android передаёт этот nonce в
// GetGoogleIdOption.setNonce(...) ДО вызова Credential Manager — Google
// подписывает его внутрь id_token, и это единственное, что не даёт
// перехваченный на лету id_token предъявить повторно (сам id_token
// подписан Google и не привязан к получателю иначе).
void handle_nonce(AppState& state, const httplib::Request&, httplib::Response& res) {
    applog::set_route("POST /auth/nonce"); // литерал из register_routes ниже
    std::string nonce = random_string(32);
    {
        std::lock_guard<std::mutex> lock(state.issued_nonces_mutex);
        state.issued_nonces.insert(nonce);
    }
    res.set_content(json{{"nonce", nonce}}.dump(), "application/json");
}

// POST /auth/google/mobile {"id_token", "device_id", "device_name"?,
// "platform"?} -> {"access_token", "refresh_token", "expires_in"} — тот же
// формат, что тело /auth/refresh для клиента без cookie jar (см. auth.cpp).
// Никаких cookie здесь не выставляется: у мобильного клиента их нет, токены
// он хранит сам (см. org/docs/TODO_mobile_sync.md, Фаза 3 —
// EncryptedSharedPreferences).
//
// device_id обязателен (в отличие от браузерного входа, см. DeviceInfo) —
// без него нет смысла в этом эндпоинте отдельно от браузерного: сам смысл
// "мобильного" входа тут в том, что дальше это устройство можно узнавать
// повторно (перевыпуск токена по рефрешу переносит те же поля, см.
// auth::rotate_refresh_token) и когда-нибудь показать/отозвать поштучно
// (см. README, "Мобильный вход").
//
// Регистрация — без страницы подтверждения: сам тап «Войти через Google» в
// приложении уже и есть явное действие пользователя (см. план, п. 3.4);
// рендерить HTML пришлось бы через WebView, что хуже, чем нативный экран.
void handle_mobile_login(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/google/mobile"); // литерал из register_routes ниже
    json body;
    try {
        body = json::parse(req.body);
    } catch (const std::exception&) {
        res.status = 400;
        res.set_content(json{{"error", "invalid JSON body"}}.dump(), "application/json");
        return;
    }
    std::string id_token = body.value("id_token", std::string{});
    if (id_token.empty()) {
        res.status = 400;
        res.set_content(json{{"error", "id_token отсутствует"}}.dump(), "application/json");
        return;
    }
    DeviceInfo device;
    device.device_id = body.value("device_id", std::string{});
    device.device_name = body.value("device_name", std::string{});
    device.platform = body.value("platform", std::string("android"));
    if (device.device_id.empty()) {
        res.status = 400;
        res.set_content(json{{"error", "device_id отсутствует"}}.dump(), "application/json");
        return;
    }
    if (!is_mobile_login_platform(device.platform)) {
        res.status = 400;
        res.set_content(json{{"error", "недопустимый platform (android/ios/web/other)"}}.dump(),
                        "application/json");
        return;
    }

    std::string verify_error;
    auto claims = verify_id_token(state, id_token, verify_error);
    if (!claims) {
        res.status = 401;
        res.set_content(json{{"error", verify_error}}.dump(), "application/json");
        return;
    }

    // Nonce обязателен для этого пути (в отличие от браузерного, где вместо
    // него от повтора защищает одноразовый code) и предъявляется РОВНО один
    // раз — erase() по найденному ключу убирает его из набора сразу.
    bool nonce_ok = false;
    if (!claims->nonce.empty()) {
        std::lock_guard<std::mutex> lock(state.issued_nonces_mutex);
        nonce_ok = state.issued_nonces.erase(claims->nonce) > 0;
    }
    if (!nonce_ok) {
        res.status = 401;
        res.set_content(
            json{{"error", "nonce отсутствует, неизвестен или уже использован — "
                            "запросите новый через POST /auth/nonce"}}
                .dump(),
            "application/json");
        return;
    }

    UserRecord user = auth::get_or_create_user(state, claims->sub, claims->email,
                                                claims->email_verified, claims->name,
                                                claims->picture);
    // Этот путь не проходит через auth::authenticate() (нет входящего своего
    // JWT — сам id_token Google верифицируется выше отдельно), поэтому
    // user_id не выставился автоматически — делаем явно, для строки
    // request_finished ниже по этому же запросу.
    applog::set_user(user.id);
    auth::TokenPair tokens = auth::issue_tokens(state, user, device);

    json body_out = {
        {"access_token", tokens.access_token},
        {"refresh_token", tokens.refresh_token},
        {"expires_in", state.access_token_ttl_secs},
    };
    res.set_content(body_out.dump(), "application/json");
}

} // namespace

void register_routes(httplib::Server& svr, AppState& state) {
    svr.Get("/", handle_index);

    svr.Get("/auth/google", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_login(state, req, res);
    });

    svr.Get("/auth/google/callback",
            [&state](const httplib::Request& req, httplib::Response& res) {
                handle_callback(state, req, res);
            });

    svr.Post("/auth/google/confirm-signup",
             [&state](const httplib::Request& req, httplib::Response& res) {
                 handle_confirm_signup(state, req, res);
             });

    svr.Post("/auth/nonce", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_nonce(state, req, res);
    });

    svr.Post("/auth/google/mobile",
             [&state](const httplib::Request& req, httplib::Response& res) {
                 handle_mobile_login(state, req, res);
             });
}

std::optional<GoogleClaims> verify_id_token(AppState& state, const std::string& id_token,
                                             std::string& error_out) {
    auto kid = jwt::peek_kid(id_token);
    if (!kid) {
        error_out = "в токене отсутствует kid";
        return std::nullopt;
    }

    httplib::Client jwks_client("https://www.googleapis.com");
    configure_client(jwks_client, state);

    auto jwks_res = jwks_client.Get("/oauth2/v3/certs");
    if (!jwks_res || jwks_res->status != 200) {
        error_out = "не удалось получить публичные ключи Google (JWKS)";
        return std::nullopt;
    }

    json jwks;
    try {
        jwks = json::parse(jwks_res->body);
    } catch (const std::exception&) {
        error_out = "не удалось разобрать JWKS Google";
        return std::nullopt;
    }

    std::vector<unsigned char> n_bytes;
    std::vector<unsigned char> e_bytes;
    bool found = false;
    for (const auto& key : jwks.value("keys", json::array())) {
        if (key.value("kid", std::string{}) != *kid) continue;
        try {
            n_bytes = b64::decode(key.at("n").get<std::string>());
            e_bytes = b64::decode(key.at("e").get<std::string>());
        } catch (const std::exception&) {
            error_out = "некорректный формат ключа в JWKS";
            return std::nullopt;
        }
        found = true;
        break;
    }
    if (!found) {
        error_out = "не найден подходящий публичный ключ Google (kid не совпал)";
        return std::nullopt;
    }

    auto payload = jwt::verify_rs256(id_token, n_bytes, e_bytes);
    if (!payload) {
        error_out = "подпись/claims id_token не прошли проверку";
        return std::nullopt;
    }

    std::string iss = payload->value("iss", std::string{});
    if (iss != "https://accounts.google.com" && iss != "accounts.google.com") {
        error_out = "неверный issuer в id_token";
        return std::nullopt;
    }
    if (payload->value("aud", std::string{}) != state.google_client_id) {
        error_out = "неверный audience в id_token";
        return std::nullopt;
    }
    try {
        if (!payload->contains("exp") || payload->at("exp").get<uint64_t>() <= timeutil::now_epoch()) {
            error_out = "id_token истёк";
            return std::nullopt;
        }
    } catch (const std::exception&) {
        error_out = "некорректное поле exp в id_token";
        return std::nullopt;
    }

    GoogleClaims claims;
    claims.sub = payload->value("sub", std::string{});
    claims.email = payload->value("email", std::string{});
    claims.email_verified = payload->value("email_verified", false);
    claims.name = payload->value("name", std::string{});
    claims.picture = payload->value("picture", std::string{});
    claims.nonce = payload->value("nonce", std::string{});

    if (claims.sub.empty()) {
        error_out = "в id_token отсутствует sub";
        return std::nullopt;
    }
    return claims;
}

} // namespace google_auth
