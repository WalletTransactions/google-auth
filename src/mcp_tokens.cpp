#include "mcp_tokens.hpp"

#include <algorithm>
#include <cctype>

#include "auth.hpp"
#include "nlohmann/json.hpp"
#include "repo.hpp"
#include "token_claims.hpp"
#include "util/base64.hpp"
#include "util/crypto.hpp"
#include "util/jwt.hpp"
#include "util/log.hpp"
#include "util/metrics.hpp"
#include "util/time.hpp"
#include "util/uuid.hpp"

using nlohmann::json;

namespace mcp_tokens {

namespace detail {

namespace {

bool is_space(unsigned char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }

bool is_base64url_char(unsigned char c) { return std::isalnum(c) != 0 || c == '-' || c == '_'; }

// Число кодовых точек: байты вида 10xxxxxx — продолжения, их не считаем.
// Корректность UTF-8 уже проверил json::parse.
std::size_t utf8_length(const std::string& s) {
    return static_cast<std::size_t>(
        std::count_if(s.begin(), s.end(), [](char c) { return (static_cast<unsigned char>(c) & 0xC0) != 0x80; }));
}

} // namespace

std::optional<std::string> normalize_name(const std::string& raw) {
    std::size_t begin = 0;
    std::size_t end = raw.size();
    while (begin < end && is_space(static_cast<unsigned char>(raw[begin]))) ++begin;
    while (end > begin && is_space(static_cast<unsigned char>(raw[end - 1]))) --end;
    std::string name = raw.substr(begin, end - begin);
    std::size_t len = utf8_length(name);
    if (len < 1 || len > 64) return std::nullopt;
    return name;
}

bool is_well_formed_token(const std::string& token) {
    static const std::string prefix = kTokenPrefix;
    if (token.size() != prefix.size() + 43) return false;
    if (token.compare(0, prefix.size(), prefix) != 0) return false;
    return std::all_of(token.begin() + static_cast<std::ptrdiff_t>(prefix.size()), token.end(),
                       [](char c) { return is_base64url_char(static_cast<unsigned char>(c)); });
}

std::string generate_token() { return std::string(kTokenPrefix) + b64::encode(crypto::random_bytes(32)); }

std::string hash_token(const std::string& token) { return b64::encode(crypto::sha256(token)); }

} // namespace detail

namespace {

constexpr const char* kJson = "application/json";
constexpr const char* kNameError = "нужно имя токена — от 1 до 64 символов";
constexpr const char* kLimitError =
    "слишком много MCP-токенов — отзовите ненужные в «Моих устройствах» (максимум 10)";

void send_error(httplib::Response& res, int status, const std::string& message) {
    res.status = status;
    res.set_content(json{{"error", message}}.dump(), kJson);
}

// POST /auth/mcp-tokens {name} -> 201 {token, device_id, name, expires_at}
//
// Тело ответа несёт сам токен — main.cpp не пишет его в debug-журнал тел
// (см. secret_body в set_logger).
void handle_issue(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/mcp-tokens"); // литерал из register_routes ниже
    // Тот же authenticate, что у всех ручек аккаунта: aud google-auth и scope
    // account. Токен бота и JWT обмена MCP сюда не пройдут — у них нет aud
    // google-auth, MCP-токен не выпускает сам себе преемника.
    auto user = auth::authenticate(req, state);
    if (!user) {
        send_error(res, 401, "unauthenticated");
        return;
    }

    json body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
    std::optional<std::string> name;
    if (body.is_object() && body.contains("name") && body.at("name").is_string()) {
        name = detail::normalize_name(body.at("name").get<std::string>());
    }
    if (!name) {
        send_error(res, 400, kNameError);
        return;
    }

    // Лимит считается по живым ключам: отозванные и истёкшие в список не
    // попадают. Два одновременных выпуска у границы могут дать 11 — это не
    // нарушение безопасности (design, «Риски»).
    auto sessions = repo::list_user_sessions(*state.redis, user->user_id);
    auto active = static_cast<std::size_t>(std::count_if(sessions.begin(), sessions.end(), [](const auto& s) {
        return s.kind == repo::SessionKind::Mcp;
    }));
    if (active >= kMaxTokensPerUser) {
        send_error(res, 409, kLimitError);
        return;
    }

    std::string token = detail::generate_token();
    uint64_t now = timeutil::now_epoch();
    repo::McpTokenRecord record;
    record.user_id = user->user_id;
    record.device_id = uuidgen::v4();
    record.name = *name;
    record.created_at = now;
    record.cap_at = now + repo::detail::kMcpCapSecs;
    uint64_t expires_at = repo::store_mcp_token(*state.redis, detail::hash_token(token), record);

    metrics::inc_counter("mcp_tokens_issued_total", "Выпущенные персональные MCP-токены.", "result", "ok");
    applog::info("mcp token issued",
                 {{"event", "mcp_token_issued"}, {"user_id", record.user_id}, {"device_id", record.device_id}});

    res.status = 201;
    res.set_content(json{{"token", token},
                         {"device_id", record.device_id},
                         {"name", record.name},
                         {"expires_at", timeutil::iso8601_utc(expires_at)}}
                        .dump(),
                    kJson);
}

// POST /internal/mcp/token {token} -> 200 {access_token, expires_in, user_id,
// device_id}; любой отказ — 401 {"error":"invalid_token"}, причины наружу не
// различаются (только в журнале, без токена и его хэша).
void handle_exchange(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /internal/mcp/token"); // литерал из register_routes ниже

    auto reject = [&res](const char* reason) {
        metrics::inc_counter("mcp_token_exchanges_total", "Обмены MCP-токена на JWT по результату.", "result",
                             "invalid");
        applog::warn("mcp token rejected", {{"event", "mcp_token_rejected"}, {"reason", reason}});
        send_error(res, 401, "invalid_token");
    };

    json body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
    std::string token;
    if (body.is_object() && body.contains("token") && body.at("token").is_string()) {
        token = body.at("token").get<std::string>();
    }
    if (!detail::is_well_formed_token(token)) {
        reject("malformed");
        return;
    }

    std::string hash = detail::hash_token(token);
    auto record = repo::find_mcp_token(*state.redis, hash);
    if (!record) {
        reject("unknown");
        return;
    }
    applog::set_user(record->user_id);

    uint64_t now = timeutil::now_epoch();
    if (!repo::detail::next_mcp_expiry(now, record->cap_at)) {
        // Потолок прошёл, а ключ ещё жив — сдвиг часов. Ключ больше не нужен.
        repo::revoke_mcp_token(*state.redis, record->user_id, hash);
        reject("cap_reached");
        return;
    }

    // Страховка (D3): аккаунт удалён, а ключ почему-то остался.
    if (!repo::find_user_by_id(*state.db_pool->acquire(), record->user_id)) {
        repo::revoke_mcp_token(*state.redis, record->user_id, hash);
        reject("user_missing");
        return;
    }

    if (!repo::touch_mcp_token(*state.redis, hash, *record, now)) {
        reject("revoked_concurrently");
        return;
    }

    json payload = {
        {"sub", record->user_id},
        {"iat", now},
        {"exp", now + token_claims::kMcpTokenTtlSecs},
        {"device_id", record->device_id},
        {"platform", "mcp"},
    };
    token_claims::add_mcp_claims(payload);

    metrics::inc_counter("mcp_token_exchanges_total", "Обмены MCP-токена на JWT по результату.", "result", "ok");
    applog::info("mcp token exchanged",
                 {{"event", "mcp_token_exchanged"}, {"user_id", record->user_id}, {"device_id", record->device_id}});

    res.set_content(json{{"access_token", jwt::sign_rs256(payload, *state.jwt_signing_key)},
                         {"expires_in", token_claims::kMcpTokenTtlSecs},
                         {"user_id", record->user_id},
                         {"device_id", record->device_id}}
                        .dump(),
                    kJson);
}

} // namespace

void register_routes(httplib::Server& svr, AppState& state) {
    svr.Post("/auth/mcp-tokens", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_issue(state, req, res);
    });
    svr.Post("/internal/mcp/token", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_exchange(state, req, res);
    });
}

} // namespace mcp_tokens
