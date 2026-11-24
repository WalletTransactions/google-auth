#include "password_auth.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <stdexcept>

#include "auth.hpp"
#include "auth_limits.hpp"
#include "devices.hpp"
#include "nlohmann/json.hpp"
#include "passwords.hpp"
#include "repo.hpp"
#include "request_info.hpp"
#include "util/log.hpp"
#include "util/metrics.hpp"

using nlohmann::json;

namespace password_auth {

namespace {

constexpr const char* kJson = "application/json";
constexpr const char* kLengthError = "пароль должен быть от 10 до 128 символов";
constexpr const char* kLoginDenied = "неверный email или пароль";
constexpr std::size_t kMaxNameChars = 100;

void json_error(httplib::Response& res, int status, const std::string& message) {
    res.status = status;
    res.set_content(json{{"error", message}}.dump(), kJson);
}

// Строковое поле JSON-тела; не строка или нет поля -> "". Так число или null
// вместо строки не бросает type_error из json::value, а даёт обычный отказ валидации.
std::string str_field(const json& body, const char* key) {
    auto it = body.find(key);
    if (it == body.end() || !it->is_string()) return {};
    return it->get<std::string>();
}

std::optional<json> parse_body(const httplib::Request& req, httplib::Response& res) {
    try {
        json body = json::parse(req.body);
        if (!body.is_object()) throw std::runtime_error("not an object");
        return body;
    } catch (const std::exception&) {
        json_error(res, 400, "invalid JSON body");
        return std::nullopt;
    }
}

// Одна строка журнала и одно приращение счётчика на событие. event —
// "login" | "register" | "change" | "reset"; в журнал уходит как
// password_<event>. Ни пароля, ни хэша, ни email: только результат, причина
// и (если известен) user_id.
void audit(const std::string& event, const std::string& result, const std::string& reason,
           const std::string& ip, const std::string& user_id = {}) {
    json details = {{"event", "password_" + event}, {"result", result}, {"reason", reason}, {"ip", ip}};
    if (!user_id.empty()) details["user_id"] = user_id;
    std::string message = "password " + event + " " + result;
    if (result == "ok" || result == "accepted") {
        applog::info(message, details);
    } else {
        applog::warn(message, details);
    }
    metrics::inc_counter("password_auth_total", "События входа и регистрации по паролю по результату.",
                         "outcome", event + "_" + result);
}

// Общие условия для ручек, принимающих пароль: способ включён и запрос по
// защищённому соединению. false — ответ уже записан. Тело здесь не читается.
bool gate(const AppState& state, const httplib::Request& req, httplib::Response& res) {
    if (!state.auth_config.password_enabled()) {
        json_error(res, 403, "auth_method_disabled");
        return false;
    }
    if (!state.auth_config.allow_insecure && !request_info::is_https(req)) {
        json_error(res, 403, "insecure_transport");
        return false;
    }
    return true;
}

// Лимиты попыток -> ответ. false — отказ записан (429/503), пароль проверять нельзя.
bool apply_limit(const auth_limits::Decision& decision, httplib::Response& res) {
    switch (decision.verdict) {
        case auth_limits::Verdict::Ok:
            return true;
        case auth_limits::Verdict::Limited:
            res.set_header("Retry-After", std::to_string(decision.retry_after_secs));
            json_error(res, 429, "слишком много попыток — повторите позже");
            return false;
        case auth_limits::Verdict::Unavailable:
            json_error(res, 503, "сервис временно недоступен — повторите позже");
            return false;
    }
    return false;
}

std::string truncate_chars(const std::string& s, std::size_t max_chars) {
    std::size_t chars = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) {
            if (chars == max_chars) return s.substr(0, i);
            ++chars;
        }
    }
    return s;
}

std::string trim(const std::string& s) {
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])) != 0) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])) != 0) --e;
    return s.substr(b, e - b);
}

// Имя для новой учётной записи: из тела, а если пусто — часть email до '@'.
std::string display_name(const std::string& raw, const std::string& email) {
    std::string name = truncate_chars(trim(raw), kMaxNameChars);
    if (name.empty()) name = email.substr(0, email.find('@'));
    return name;
}

// Email и пароль из тела по правилам «Проверка email и пароля»: порядок
// проверок — JSON (выше), email, длина пароля. false — 400 записан.
bool read_credentials(const json& body, httplib::Response& res, std::string& email, std::string& password) {
    auto normalized = passwords::normalize_email(str_field(body, "email"));
    if (!normalized) {
        json_error(res, 400, "недопустимый email");
        return false;
    }
    email = *normalized;
    password = str_field(body, "password");
    if (!passwords::password_length_ok(password)) {
        json_error(res, 400, kLengthError);
        return false;
    }
    return true;
}

// ---- POST /auth/register ----------------------------------------------------

void handle_register(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/register"); // литерал из register_routes ниже
    if (!gate(state, req, res)) return;
    std::string ip = request_info::client_ip(req);

    if (!state.auth_config.registration_open) {
        audit("register", "denied", "registration_closed", ip);
        json_error(res, 403, "registration_closed");
        return;
    }

    auto body = parse_body(req, res);
    if (!body) return;
    std::string email;
    std::string password;
    if (!read_credentials(*body, res, email, password)) return;

    // Лимиты: те же счётчики, что у входа (спека «Отказ при превышении лимита»).
    // Каждая попытка регистрации считается по IP — это и есть защита от спама
    // аккаунтов (design, «Риски»); по email не считается: иначе чужой адрес
    // можно было бы заблокировать, «регистрируя» его.
    if (!apply_limit(auth_limits::check(*state.redis, state.auth_config, email, ip), res)) {
        audit("register", "limited", "too_many_attempts", ip);
        return;
    }
    auth_limits::record_ip_attempt(*state.redis, state.auth_config, ip);

    // Хэш считается ВСЕГДА, и для занятого email тоже: иначе время ответа
    // выдавало бы, свободен ли адрес (спека: ответ одинаковый).
    passwords::Record record = passwords::make_record(password, state.auth_config.pbkdf2_iterations);
    auto created = repo::create_password_user(*state.db_pool->acquire(), email,
                                              display_name(str_field(*body, "name"), email), record);

    audit("register", "accepted", created ? "created" : "email_taken", ip, created ? created->id : std::string{});
    res.status = 202;
    res.set_content(json{{"status", "accepted"}}.dump(), kJson);
}

// ---- POST /auth/login -------------------------------------------------------

void handle_login(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/login"); // литерал из register_routes ниже
    if (!gate(state, req, res)) return;
    std::string ip = request_info::client_ip(req);

    auto body = parse_body(req, res);
    if (!body) return;
    std::string email;
    std::string password;
    if (!read_credentials(*body, res, email, password)) return;

    // platform не указан или web -> браузерная сессия; иначе мобильная
    // (как в mobile-sign-in): допустимое значение и обязательный device_id.
    std::string platform = str_field(*body, "platform");
    bool web = platform.empty() || platform == "web";
    DeviceInfo device;
    if (web) {
        device.platform = "web";
        device.device_name = req.get_header_value("User-Agent");
        auth::ensure_browser_device_id(device); // новый device_id на каждый вход
    } else {
        device.platform = platform;
        device.device_id = str_field(*body, "device_id");
        device.device_name = str_field(*body, "device_name");
        if (!is_mobile_login_platform(device.platform)) {
            json_error(res, 400, "недопустимый platform (android/ios/web/other)");
            return;
        }
        if (device.device_id.empty()) {
            json_error(res, 400, "device_id отсутствует");
            return;
        }
    }

    if (!apply_limit(auth_limits::check(*state.redis, state.auth_config, email, ip), res)) {
        audit("login", "limited", "too_many_attempts", ip);
        return;
    }

    auto user = repo::find_user_by_email(*state.db_pool->acquire(), email);
    std::optional<passwords::Record> stored;
    if (user) stored = repo::find_password(*state.db_pool->acquire(), user->id);

    // Для несуществующего email и для Google-аккаунта без пароля PBKDF2
    // считается по фиктивной записи — время ответа не отличается (design D3).
    bool ok = stored ? passwords::verify(password, *stored)
                     : passwords::verify_dummy(password, state.auth_config.pbkdf2_iterations);
    if (!ok) {
        auth_limits::record_failure(*state.redis, state.auth_config, email, ip);
        audit("login", "denied", !user ? "no_such_user" : (stored ? "wrong_password" : "no_password"), ip,
              user ? user->id : std::string{});
        json_error(res, 401, kLoginDenied);
        return;
    }

    auth_limits::reset_email(*state.redis, email);
    // Число итераций в конфигурации повысили — пересчитываем запись, пока
    // пароль в руках (спека «Хранение пароля»).
    if (passwords::needs_rehash(*stored, state.auth_config.pbkdf2_iterations)) {
        repo::set_password(*state.db_pool->acquire(), user->id, passwords::make_record(password, state.auth_config.pbkdf2_iterations));
    }
    repo::touch_last_login(*state.db_pool->acquire(), user->id);
    applog::set_user(user->id); // этот путь не идёт через authenticate()

    auth::TokenPair tokens = auth::issue_tokens(state, *user, device);
    audit("login", "ok", web ? "web" : "mobile", ip, user->id);

    if (web) {
        auth::set_session_cookies(res, state, tokens);
        json out = {{"id", user->id},
                    {"email", user->email},
                    {"name", user->name},
                    {"picture", user->picture},
                    {"role", to_string(user->role)}};
        res.set_content(out.dump(), kJson);
    } else {
        json out = {{"access_token", tokens.access_token},
                    {"refresh_token", tokens.refresh_token},
                    {"expires_in", state.access_token_ttl_secs}};
        res.set_content(out.dump(), kJson);
    }
}

// ---- POST /auth/password ----------------------------------------------------

void handle_change_password(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/password"); // литерал из register_routes ниже
    if (!gate(state, req, res)) return;
    std::string ip = request_info::client_ip(req);

    auto user = auth::authenticate(req, state);
    if (!user) {
        json_error(res, 401, "unauthenticated");
        return;
    }
    auto body = parse_body(req, res);
    if (!body) return;
    std::string new_password = str_field(*body, "password");
    if (!passwords::password_length_ok(new_password)) {
        json_error(res, 400, kLengthError);
        return;
    }

    auto record = repo::find_user_by_id(*state.db_pool->acquire(), user->user_id);
    if (!record) {
        json_error(res, 401, "unauthenticated"); // пользователя удалили при ещё живом токене
        return;
    }

    auto stored = repo::find_password(*state.db_pool->acquire(), record->id);
    if (stored) {
        // Текущий пароль подбирается так же, как при входе, — поэтому те же
        // лимиты (по email учётной записи и по IP), и пароль при превышении не проверяется.
        std::string email = passwords::normalize_email(record->email).value_or(record->email);
        if (!apply_limit(auth_limits::check(*state.redis, state.auth_config, email, ip), res)) {
            audit("change", "limited", "too_many_attempts", ip, record->id);
            return;
        }
        std::string current = str_field(*body, "current_password");
        if (current.empty() || !passwords::verify(current, *stored)) {
            if (current.empty()) {
                // verify не вызывался — выравниваем время, чтобы пустое поле не отвечало быстрее неверного.
                passwords::verify_dummy("", stored->iterations);
            }
            auth_limits::record_failure(*state.redis, state.auth_config, email, ip);
            audit("change", "denied", "wrong_current_password", ip, record->id);
            json_error(res, 401, "неверный текущий пароль");
            return;
        }
        auth_limits::reset_email(*state.redis, email);
    }

    repo::set_password(*state.db_pool->acquire(), record->id,
                       passwords::make_record(new_password, state.auth_config.pbkdf2_iterations));
    // Все остальные сессии (и MCP-токены) теряют силу; текущая остаётся.
    int revoked = devices::revoke_other_sessions(state, req, *user);
    audit("change", "ok", stored ? "changed" : "set", ip, record->id);
    applog::info("password sessions revoked", {{"event", "password_change"}, {"revoked_sessions", revoked}});
    res.status = 204;
}

// ---- POST /admin/users/:id/password -----------------------------------------

void handle_admin_reset(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /admin/users/:id/password"); // литерал из register_routes ниже
    // Пароль и тут идёт в теле запроса — по HTTP без ALLOW_INSECURE_AUTH его не принимаем.
    if (!state.auth_config.allow_insecure && !request_info::is_https(req)) {
        json_error(res, 403, "insecure_transport");
        return;
    }
    std::string ip = request_info::client_ip(req);

    auto admin = auth::authenticate(req, state);
    if (!admin) {
        json_error(res, 401, "unauthenticated");
        return;
    }
    if (admin->role != Role::Admin) {
        json_error(res, 403, "forbidden");
        return;
    }

    auto it = req.path_params.find("id");
    std::string target_id = it != req.path_params.end() ? it->second : std::string();
    auto target = target_id.empty() ? std::nullopt : repo::find_user_by_id(*state.db_pool->acquire(), target_id);
    if (!target) {
        json_error(res, 404, "user not found");
        return;
    }

    auto body = parse_body(req, res);
    if (!body) return;
    std::string new_password = str_field(*body, "password");
    if (!passwords::password_length_ok(new_password)) {
        json_error(res, 400, kLengthError);
        return;
    }

    auto lease = state.db_pool->acquire();
    repo::set_password(*lease, target->id,
                       passwords::make_record(new_password, state.auth_config.pbkdf2_iterations));
    // Сброс — «выкинуть всех»: и сессии в Redis, и связки Telegram в Postgres
    // (иначе бот, привязанный тем, кто знал старый пароль, остаётся при данных).
    repo::revoke_all_user_tokens(*state.redis, target->id);
    repo::delete_all_telegram_links(*lease, target->id);
    audit("reset", "ok", "admin_reset", ip, target->id);
    res.status = 204;
}

} // namespace

void register_routes(httplib::Server& svr, AppState& state) {
    // Без аутентификации и при любом AUTH_METHODS: клиенты по нему выбирают кнопки.
    svr.Get("/auth/methods", [&state](const httplib::Request&, httplib::Response& res) {
        applog::set_route("GET /auth/methods");
        json out = {{"methods", enabled_method_names(state.auth_config)},
                    {"registration", state.auth_config.registration_available()}};
        res.set_content(out.dump(), kJson);
    });
    svr.Post("/auth/register", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_register(state, req, res);
    });
    svr.Post("/auth/login", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_login(state, req, res);
    });
    svr.Post("/auth/password", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_change_password(state, req, res);
    });
    svr.Post("/admin/users/:id/password", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_admin_reset(state, req, res);
    });
}

} // namespace password_auth
