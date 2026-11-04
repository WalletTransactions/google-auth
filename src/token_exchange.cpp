#include "token_exchange.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>

#include "telegram.hpp"
#include "token_claims.hpp"
#include "util/jwt.hpp"
#include "util/jwt_claims.hpp"
#include "util/log.hpp"
#include "util/time.hpp"

using nlohmann::json;

namespace token_exchange {

namespace {

constexpr const char* kJson = "application/json";
// Лейбл actor, когда actor не определён (обмен выключен, неверный секрет).
constexpr const char* kNoActor = "none";

std::mutex g_metrics_mutex;
std::map<std::pair<std::string, std::string>, std::uint64_t> g_counts; // (actor, result) -> n

void count(const std::string& actor, const std::string& result) {
    std::lock_guard<std::mutex> lock(g_metrics_mutex);
    ++g_counts[{actor, result}];
}

std::string trim(const std::string& s) {
    auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
    auto b = std::find_if(s.begin(), s.end(), not_space);
    auto e = std::find_if(s.rbegin(), s.rend(), not_space).base();
    return b < e ? std::string(b, e) : std::string();
}

std::set<std::string> split_scope(const std::string& scope) {
    std::set<std::string> out;
    std::istringstream ss(scope);
    std::string item;
    while (ss >> item) out.insert(item);
    return out;
}

bool is_policy_actor(const std::string& name) {
    return std::any_of(std::begin(kPolicy), std::end(kPolicy),
                       [&](const PolicyRule& r) { return name == r.actor; });
}

// audience в журнал: это ввод вызывающего — обрезаем, чтобы мусор не
// раздувал строку.
std::string loggable(const std::string& s) { return s.size() <= 64 ? s : s.substr(0, 64) + "..."; }

std::string single_param(const httplib::Params& params, const char* key) {
    auto it = params.find(key);
    return it != params.end() ? it->second : std::string();
}

} // namespace

std::string render_metrics() {
    std::lock_guard<std::mutex> lock(g_metrics_mutex);
    if (g_counts.empty()) return {};
    std::ostringstream out;
    out << "# HELP token_exchange_total Обмены токена (POST /internal/token/exchange) по actor и результату.\n";
    out << "# TYPE token_exchange_total counter\n";
    // Значения лейблов — имена из kPolicy и литералы результатов, экранировать
    // нечего.
    for (const auto& [key, n] : g_counts) {
        out << "token_exchange_total{actor=\"" << key.first << "\",result=\"" << key.second << "\"} " << n << "\n";
    }
    return out.str();
}

namespace detail {

Decision decide(const std::string& actor, const json& subject_claims, const std::string& audience,
                const std::optional<std::string>& scope) {
    Decision d;
    const PolicyRule* rule = nullptr;
    for (const auto& r : kPolicy) {
        if (actor == r.actor && audience == r.audience) {
            rule = &r;
            break;
        }
    }
    if (rule == nullptr) {
        d.outcome = Outcome::InvalidTarget;
        return d;
    }
    if (jwt_claims::check(subject_claims, rule->subject_aud, rule->subject_scope) != jwt_claims::Result::Ok) {
        d.outcome = Outcome::InvalidGrant;
        return d;
    }
    if (scope && !scope->empty() && split_scope(*scope) != split_scope(rule->scope)) {
        d.outcome = Outcome::InvalidScope;
        return d;
    }
    d.outcome = Outcome::Ok;
    d.audience = rule->audience;
    d.scope = rule->scope;
    return d;
}

std::vector<std::pair<std::string, std::string>> parse_secrets(const std::string& raw) {
    std::vector<std::pair<std::string, std::string>> out;
    std::stringstream ss(raw);
    std::string item;
    int index = 0;
    while (std::getline(ss, item, ',')) {
        ++index;
        item = trim(item);
        if (item.empty()) continue;
        auto eq = item.find('=');
        std::string where = "TOKEN_EXCHANGE_SECRETS, элемент " + std::to_string(index);
        if (eq == std::string::npos) throw std::invalid_argument(where + ": нужно имя=секрет");
        std::string name = trim(item.substr(0, eq));
        std::string secret = trim(item.substr(eq + 1));
        if (name.empty() || secret.empty()) throw std::invalid_argument(where + ": пустое имя или секрет");
        if (!is_policy_actor(name)) {
            throw std::invalid_argument(where + ": неизвестный сервис '" + loggable(name) +
                                        "' (допустимы actor'ы из таблицы политики)");
        }
        for (const auto& [n, s] : out) {
            if (n == name) throw std::invalid_argument(where + ": сервис '" + name + "' указан дважды");
            if (s == secret) throw std::invalid_argument(where + ": у '" + name + "' тот же секрет, что у '" + n + "'");
        }
        out.emplace_back(name, secret);
    }
    return out;
}

std::string identify_actor(const std::vector<std::pair<std::string, std::string>>& secrets,
                           const std::string& provided) {
    std::string actor;
    for (const auto& [name, secret] : secrets) {
        // Без break: время не зависит от того, какой по счёту секрет совпал.
        if (telegram::detail::secret_matches(secret, provided)) actor = name;
    }
    return actor;
}

std::optional<httplib::Params> parse_form(const std::string& body) {
    httplib::Params params;
    httplib::detail::parse_query_text(body, params);
    for (const auto& kv : params) {
        if (kv.first.empty() || params.count(kv.first) > 1) return std::nullopt;
    }
    return params;
}

std::string error_body(const std::string& code) { return json{{"error", code}}.dump(); }

void handle_exchange(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /internal/token/exchange"); // литерал из register_routes ниже
    // RFC 6749 §5.1: ответы с токенами и ошибками не кешируются.
    res.set_header("Cache-Control", "no-store");
    res.set_header("Pragma", "no-cache");

    std::string actor_label = kNoActor;
    std::string audience;
    std::string sub;

    // Единая точка ответа: метрика + запись журнала (actor, sub, audience,
    // result — без токенов и секретов) + тело.
    auto finish = [&](int status, const char* result, const char* error) {
        count(actor_label, result);
        json details = {{"event", "token_exchange"}, {"actor", actor_label}, {"result", result}};
        if (!sub.empty()) details["sub"] = sub;
        if (!audience.empty()) details["audience"] = loggable(audience);
        if (error != nullptr && std::string(error) != result) details["error"] = error;
        if (status == 200) {
            applog::info("token exchanged", details);
        } else {
            applog::warn("token exchange rejected", details);
            res.status = status;
            res.set_content(error_body(error != nullptr ? error : result), kJson);
        }
    };

    // Обмен выключен — 503 на любой запрос, а не «открыт всем».
    if (state.token_exchange_secrets.empty()) {
        finish(503, "unavailable", nullptr);
        return;
    }

    // 1. Actor по секрету. Subject-токен при неверном секрете не смотрим.
    std::string actor = identify_actor(state.token_exchange_secrets, req.get_header_value("X-Service-Secret"));
    if (actor.empty()) {
        finish(401, "invalid_client", nullptr);
        return;
    }
    actor_label = actor;

    std::string content_type = req.get_header_value("Content-Type");
    std::optional<httplib::Params> form;
    if (content_type.rfind("application/x-www-form-urlencoded", 0) == 0) form = parse_form(req.body);
    if (!form) {
        finish(400, "invalid_request", nullptr);
        return;
    }
    audience = single_param(*form, "audience");

    // 2. grant_type. В метрике — invalid_request: набор result задан спекой.
    if (single_param(*form, "grant_type") != kGrantType) {
        finish(400, "invalid_request", "unsupported_grant_type");
        return;
    }
    // 3. subject_token_type и обязательные поля.
    std::string subject_token = single_param(*form, "subject_token");
    if (single_param(*form, "subject_token_type") != kTokenTypeAccessToken || subject_token.empty() ||
        audience.empty() || form->count("resource") != 0 || form->count("actor_token") != 0) {
        finish(400, "invalid_request", nullptr);
        return;
    }

    // 4. Subject: подпись нашим ключом, exp (util/jwt), iss, sub, числовой exp.
    // Причина отказа наружу не различается.
    auto subject = jwt::verify_rs256(subject_token, state.jwt_signing_key->modulus(),
                                     state.jwt_signing_key->exponent());
    if (!subject || subject->value("iss", std::string()) != token_claims::kIssuer || !subject->contains("sub") ||
        !subject->at("sub").is_string() || subject->at("sub").get<std::string>().empty() ||
        !subject->at("exp").is_number_unsigned()) {
        finish(400, "invalid_grant", nullptr);
        return;
    }
    sub = subject->at("sub").get<std::string>();
    applog::set_user(sub);

    // 5–7. Таблица политики: invalid_target → invalid_grant → invalid_scope.
    std::optional<std::string> scope;
    if (form->count("scope") != 0) scope = single_param(*form, "scope");
    Decision d = decide(actor, *subject, audience, scope);
    switch (d.outcome) {
    case Outcome::InvalidTarget:
        finish(400, "invalid_target", nullptr);
        return;
    case Outcome::InvalidGrant:
        finish(400, "invalid_grant", nullptr);
        return;
    case Outcome::InvalidScope:
        finish(400, "invalid_scope", nullptr);
        return;
    case Outcome::Ok:
        break;
    }

    std::uint64_t now = timeutil::now_epoch();
    json payload = {{"iat", now}};
    token_claims::add_exchange_claims(payload, d.audience, d.scope, actor, *subject);
    std::uint64_t exp = payload.at("exp").get<std::uint64_t>();
    // verify_rs256 уже отбросил subject с exp <= now — expires_in >= 1.
    std::uint64_t expires_in = exp > now ? exp - now : 0;

    // D6: в Redis активных не кладётся.
    json out = {
        {"access_token", jwt::sign_rs256(payload, *state.jwt_signing_key)},
        {"issued_token_type", kTokenTypeAccessToken},
        {"token_type", "Bearer"},
        {"expires_in", expires_in},
    };
    finish(200, "ok", nullptr);
    res.status = 200;
    res.set_content(out.dump(), kJson);
}

} // namespace detail

void register_routes(httplib::Server& svr, AppState& state) {
    svr.Post("/internal/token/exchange", [&state](const httplib::Request& req, httplib::Response& res) {
        detail::handle_exchange(state, req, res);
    });
}

} // namespace token_exchange
