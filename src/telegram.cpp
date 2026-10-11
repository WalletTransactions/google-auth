#include "telegram.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>

#include "auth.hpp"
#include "nlohmann/json.hpp"
#include "repo.hpp"
#include "token_claims.hpp"
#include "util/base64.hpp"
#include "util/crypto.hpp"
#include "util/jwt.hpp"
#include "util/log.hpp"
#include "util/time.hpp"

using nlohmann::json;

namespace telegram {

namespace detail {

std::string device_id_for(const std::string& user_id, const std::string& tg_user_id) {
    // Не настоящий UUIDv5 (тот — SHA-1 от namespace+name), а тот же приём
    // на sha256 из уже имеющегося util/crypto: первые 16 байт хэша, биты
    // версии (5) и варианта RFC 4122 — чтобы строка проходила uuid-колонку
    // wallet-api и uuidgen::looks_valid. Уникальность обеспечивает сам
    // хэш, "официальность" версии здесь ни на что не влияет.
    auto h = crypto::sha256("wallet-telegram-device:" + user_id + ":" + tg_user_id);
    h[6] = static_cast<unsigned char>((h[6] & 0x0F) | 0x50);
    h[8] = static_cast<unsigned char>((h[8] & 0x3F) | 0x80);
    char buf[37];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11],
                  h[12], h[13], h[14], h[15]);
    return std::string(buf);
}

std::string normalize_tg_user_id(const std::string& raw) {
    // 1..20 цифр (int64 максимум), без знака и ведущих нулей — иначе "007" и
    // "7" дали бы два разных device_id одному и тому же чату.
    if (raw.empty() || raw.size() > 20 || raw[0] == '0') return {};
    for (unsigned char c : raw) {
        if (std::isdigit(c) == 0) return {};
    }
    return raw;
}

std::string device_name_for(const std::string& tg_username, const std::string& tg_user_id) {
    std::string name = tg_username;
    if (!name.empty() && name[0] == '@') name.erase(0, 1);
    if (name.size() > 64) name.resize(64);
    return name.empty() ? "Telegram " + tg_user_id : "Telegram @" + name;
}

bool secret_matches(const std::string& expected, const std::string& provided) {
    if (expected.empty()) return false;
    return crypto::constant_time_equal(crypto::sha256(expected), crypto::sha256(provided));
}

} // namespace detail

namespace {

constexpr const char* kJson = "application/json";

// Хэш, а не сам код в ключе — тот же приём, что у refresh-токенов (см.
// auth::hash_token): дамп Redis не даёт готовых к предъявлению кодов.
std::string link_code_key(const std::string& code) {
    return "tg_link_code:" + b64::encode(crypto::sha256(code));
}

void send_error(httplib::Response& res, int status, const std::string& message) {
    res.status = status;
    res.set_content(json{{"error", message}}.dump(), kJson);
}

// POST /auth/telegram/link-code -> {code, deep_link, expires_in}
//
// Код — 24 случайных байта в base64url (32 символа): влезает в параметр
// start Telegram (до 64 символов из [A-Za-z0-9_-]) и не перебирается.
// Одноразовый: POST /internal/telegram/exchange забирает его GETDEL.
// Выдать несколько кодов подряд можно — каждый живёт свой TTL, до обмена
// они ни на что не влияют.
void handle_link_code(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/telegram/link-code"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        send_error(res, 401, "unauthenticated");
        return;
    }
    if (state.telegram_bot_username.empty()) {
        send_error(res, 503, "Telegram-бот не настроен (TELEGRAM_BOT_USERNAME)");
        return;
    }

    std::string code = b64::encode(crypto::random_bytes(24));
    state.redis->set_ex(link_code_key(code), user->user_id, state.telegram_link_code_ttl_secs);

    json body = {
        {"code", code},
        {"deep_link", "https://t.me/" + state.telegram_bot_username + "?start=" + code},
        {"expires_in", state.telegram_link_code_ttl_secs},
    };
    res.set_content(body.dump(), kJson);
}

// Аутентификация бота на /internal/telegram/* — общий секрет. false — уже
// ответили (503: выключено, 401: неверный секрет).
bool authenticate_bot(AppState& state, const httplib::Request& req, httplib::Response& res) {
    // Секрет не задан — эндпоинт выключен целиком, а не открыт всем.
    if (state.telegram_service_secret.empty()) {
        send_error(res, 503, "Telegram-бот выключен (TELEGRAM_SERVICE_SECRET)");
        return false;
    }
    if (!detail::secret_matches(state.telegram_service_secret, req.get_header_value("X-Service-Secret"))) {
        send_error(res, 401, "неверный X-Service-Secret");
        return false;
    }
    return true;
}

// tg_user_id из тела — JSON-число или строка из цифр; пусто — не прошёл
// проверку (см. detail::normalize_tg_user_id).
std::string tg_user_id_from(const json& body) {
    std::string raw;
    if (body.contains("tg_user_id")) {
        const auto& v = body.at("tg_user_id");
        if (v.is_number_unsigned()) raw = std::to_string(v.get<std::uint64_t>());
        else if (v.is_string()) raw = v.get<std::string>();
    }
    return detail::normalize_tg_user_id(raw);
}

// POST /internal/telegram/exchange {code, tg_user_id, tg_username?}
//   -> {user_id, device_id}
//
// Записывает связку в telegram_links — по ней бот получает токен на каждую
// команду (POST /internal/telegram/token). Сессии устройства (refresh) боту
// больше не выдаётся (TODO_telegram_tokens.md, шаг 6): держать её было
// некому, а отзыв доступа — удаление связки.
void handle_exchange(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /internal/telegram/exchange"); // литерал из register_routes ниже
    if (!authenticate_bot(state, req, res)) return;

    json body;
    try {
        body = json::parse(req.body);
    } catch (const std::exception&) {
        send_error(res, 400, "invalid JSON body");
        return;
    }
    std::string code = body.value("code", std::string{});
    std::string tg_user_id = tg_user_id_from(body);
    std::string tg_username = body.value("tg_username", std::string{});
    if (code.empty() || tg_user_id.empty()) {
        send_error(res, 400, "нужны code и tg_user_id (положительное целое)");
        return;
    }

    auto user_id = state.redis->getdel(link_code_key(code));
    if (!user_id) {
        send_error(res, 410, "код связывания истёк или уже использован");
        return;
    }
    // Пользователя могли удалить между выдачей кода и обменом.
    auto user = repo::find_user_by_id(*state.db_pool->acquire(), *user_id);
    if (!user) {
        send_error(res, 410, "пользователь кода связывания больше не существует");
        return;
    }
    applog::set_user(user->id);

    std::string device_id = detail::device_id_for(user->id, tg_user_id);
    auto previous = repo::find_telegram_link(*state.db_pool->acquire(), tg_user_id);

    // Сессии устройства бота, выпущенные до шага 6 (тогда бот держал
    // refresh), — и этого пользователя, и прежнего, если чат был связан с
    // другим: больше им жить незачем.
    auto revoke_device = [&state](const std::string& owner, const std::string& dev) {
        repo::revoke_user_sessions_if(*state.redis, owner,
                                      [&dev](const repo::SessionSummary& s) { return s.device.device_id == dev; });
    };
    revoke_device(user->id, device_id);
    if (previous && previous->user_id != user->id) revoke_device(previous->user_id, previous->device_id);

    repo::TelegramLink link;
    link.tg_user_id = tg_user_id;
    link.user_id = user->id;
    link.device_id = device_id;
    link.tg_username = tg_username;
    repo::upsert_telegram_link(*state.db_pool->acquire(), link);
    applog::info("telegram linked", {{"event", "tg_linked"},
                                     {"tg_user_id", tg_user_id},
                                     {"device_id", device_id},
                                     {"relinked_other_user", previous && previous->user_id != user->id}});

    res.set_content(json{{"user_id", user->id}, {"device_id", device_id}}.dump(), kJson);
}

// DELETE /internal/telegram/links/{tg_user_id} -> 204; 404 — связки нет.
// /unlink из самого бота: у бота нет пользовательского токена со scope
// account (его токен и не адресован google-auth), поэтому отдельная
// служебная ручка по X-Service-Secret, а не веб-ручка ниже.
void handle_internal_unlink(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("DELETE /internal/telegram/links/:tg_user_id"); // литерал из register_routes ниже
    if (!authenticate_bot(state, req, res)) return;
    std::string tg_user_id = detail::normalize_tg_user_id(req.path_params.at("tg_user_id"));
    if (tg_user_id.empty()) {
        send_error(res, 400, "tg_user_id — положительное целое");
        return;
    }
    auto removed = repo::delete_telegram_link_by_tg(*state.db_pool->acquire(), tg_user_id);
    if (!removed) {
        send_error(res, 404, "нет такой связки");
        return;
    }
    applog::set_user(removed->user_id);
    std::string device_id = removed->device_id;
    repo::revoke_user_sessions_if(*state.redis, removed->user_id, [&device_id](const repo::SessionSummary& s) {
        return s.device.device_id == device_id;
    });
    applog::info("telegram unlinked from bot", {{"event", "tg_unlinked"}, {"tg_user_id", tg_user_id}});
    res.status = 204;
}

// POST /internal/telegram/token {tg_user_id} -> {access_token, expires_in,
// user_id, device_id}; 404 — связки нет (не связан или отключён из веба).
//
// Токен бота на одну команду (TODO_telegram_tokens.md, шаг 4): aud
// wallet-report + wallet-api + wallet-ai, scope reports:read expense:write
// ai:use, 5 минут. В
// Redis не кладётся — google-auth такие токены не принимает (нет его aud),
// а отзыв доступа бота — удаление связки: следующий токен уже не выдадут.
void handle_token(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /internal/telegram/token"); // литерал из register_routes ниже
    if (!authenticate_bot(state, req, res)) return;

    json body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
    std::string tg_user_id = body.is_object() ? tg_user_id_from(body) : std::string{};
    if (tg_user_id.empty()) {
        send_error(res, 400, "нужен tg_user_id (положительное целое)");
        return;
    }

    auto link = repo::find_telegram_link(*state.db_pool->acquire(), tg_user_id);
    if (!link) {
        send_error(res, 404, "Telegram-аккаунт не связан с кошельком");
        return;
    }
    applog::set_user(link->user_id);

    uint64_t now = timeutil::now_epoch();
    json payload = {
        {"sub", link->user_id},
        {"iat", now},
        {"exp", now + token_claims::kTelegramBotTokenTtlSecs},
        {"device_id", link->device_id},
        {"platform", "telegram"},
    };
    token_claims::add_telegram_bot_claims(payload);

    json out = {
        {"access_token", jwt::sign_rs256(payload, *state.jwt_signing_key)},
        {"expires_in", token_claims::kTelegramBotTokenTtlSecs},
        {"user_id", link->user_id},
        {"device_id", link->device_id},
    };
    res.set_content(out.dump(), kJson);
}

// GET /auth/telegram/links -> {links: [{tg_user_id, tg_username, created_at}]}
// — связанные Telegram-аккаунты текущего пользователя (веб, «Доступ и
// приглашения → Telegram-бот»).
void handle_list_links(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("GET /auth/telegram/links"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        send_error(res, 401, "unauthenticated");
        return;
    }
    json links = json::array();
    for (const auto& l : repo::list_telegram_links(*state.db_pool->acquire(), user->user_id)) {
        links.push_back({{"tg_user_id", l.tg_user_id},
                         {"tg_username", l.tg_username},
                         {"name", detail::device_name_for(l.tg_username, l.tg_user_id)},
                         {"created_at", l.created_at}});
    }
    res.set_content(json{{"links", links}}.dump(), kJson);
}

// DELETE /auth/telegram/links/:tg_user_id -> 204; 404 — не ваша связка.
// Удаляет связку (токены бота больше не выдаются) и гасит сессию
// устройства бота — ту, что пока хранит бот (до шага 6).
void handle_delete_link(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("DELETE /auth/telegram/links/:tg_user_id"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        send_error(res, 401, "unauthenticated");
        return;
    }
    std::string tg_user_id = detail::normalize_tg_user_id(req.path_params.at("tg_user_id"));
    std::optional<repo::TelegramLink> link;
    if (!tg_user_id.empty()) link = repo::find_telegram_link(*state.db_pool->acquire(), tg_user_id);
    if (!link || link->user_id != user->user_id ||
        !repo::delete_telegram_link(*state.db_pool->acquire(), user->user_id, tg_user_id)) {
        send_error(res, 404, "нет такой связки");
        return;
    }
    std::string device_id = link->device_id;
    repo::revoke_user_sessions_if(*state.redis, user->user_id, [&device_id](const repo::SessionSummary& s) {
        return s.device.device_id == device_id;
    });
    applog::info("telegram unlinked", {{"event", "tg_unlinked"}, {"tg_user_id", tg_user_id}});
    res.status = 204;
}

} // namespace

void register_routes(httplib::Server& svr, AppState& state) {
    svr.Post("/auth/telegram/link-code", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_link_code(state, req, res);
    });
    svr.Post("/internal/telegram/exchange", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_exchange(state, req, res);
    });
    svr.Post("/internal/telegram/token", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_token(state, req, res);
    });
    svr.Delete("/internal/telegram/links/:tg_user_id", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_internal_unlink(state, req, res);
    });
    svr.Get("/auth/telegram/links", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_list_links(state, req, res);
    });
    svr.Delete("/auth/telegram/links/:tg_user_id", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_delete_link(state, req, res);
    });
}

} // namespace telegram
