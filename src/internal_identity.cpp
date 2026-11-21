#include "internal_identity.hpp"

#include <algorithm>

#include "httplib.h"
#include "net/tls.hpp"
#include "nlohmann/json.hpp"
#include "util/log.hpp"
#include "util/metrics.hpp"

using nlohmann::json;

namespace internal_identity {

namespace {

constexpr const char* kGroups[] = {"telegram", "mcp-token", "exchange"};

bool known_group(const std::string& g) {
    return std::find(std::begin(kGroups), std::end(kGroups), g) != std::end(kGroups);
}

std::optional<Mode> parse_mode(const std::string& s) {
    if (s == "off") return Mode::Off;
    if (s == "observe") return Mode::Observe;
    if (s == "enforce-tls") return Mode::EnforceTls;
    if (s == "enforce") return Mode::Enforce;
    return std::nullopt;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

void set_error(std::string* out, const std::string& msg) {
    if (out) *out = msg;
}

} // namespace

const char* mode_name(Mode mode) {
    switch (mode) {
    case Mode::Off: return "off";
    case Mode::Observe: return "observe";
    case Mode::EnforceTls: return "enforce-tls";
    case Mode::Enforce: return "enforce";
    }
    return "off";
}

const char* finding_name(Finding finding) {
    switch (finding) {
    case Finding::Ok: return "ok";
    case Finding::NoCert: return "no_cert";
    case Finding::Forbidden: return "forbidden";
    case Finding::ActorMismatch: return "actor_mismatch";
    }
    return "ok";
}

std::optional<Config> parse_config(const std::string& text, std::string* error) {
    Config cfg;
    size_t pos = 0;
    bool first = true;
    while (pos <= text.size()) {
        size_t comma = text.find(',', pos);
        std::string item = trim(text.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos));
        pos = comma == std::string::npos ? text.size() + 1 : comma + 1;
        if (item.empty()) {
            first = false;
            continue;
        }
        size_t eq = item.find('=');
        if (eq == std::string::npos) {
            // Режим по умолчанию — только первым и один раз.
            auto mode = parse_mode(item);
            if (!mode || !first) {
                set_error(error, "INTERNAL_IDENTITY: '" + item +
                                     "' — ожидался режим (off, observe, enforce-tls, enforce) первым элементом");
                return std::nullopt;
            }
            cfg.default_mode = *mode;
        } else {
            std::string group = trim(item.substr(0, eq));
            auto mode = parse_mode(trim(item.substr(eq + 1)));
            if (!known_group(group)) {
                set_error(error, "INTERNAL_IDENTITY: неизвестная группа '" + group + "' (telegram, mcp-token, exchange)");
                return std::nullopt;
            }
            if (!mode) {
                set_error(error, "INTERNAL_IDENTITY: неизвестный режим в '" + item + "'");
                return std::nullopt;
            }
            cfg.by_group[group] = *mode;
        }
        first = false;
    }
    return cfg;
}

std::string group_of(const std::string& path) {
    if (path.rfind("/internal/telegram/", 0) == 0) return "telegram";
    if (path == "/internal/mcp/token") return "mcp-token";
    if (path == "/internal/token/exchange") return "exchange";
    return "";
}

const std::vector<std::string>& allowed_services(const std::string& group) {
    static const std::vector<std::string> telegram = {"wallet-telegram"};
    static const std::vector<std::string> mcp_token = {"wallet-mcp", "wallet-ai"};
    static const std::vector<std::string> exchange = {"wallet-mcp", "wallet-ai", "wallet-telegram"};
    static const std::vector<std::string> none;
    if (group == "telegram") return telegram;
    if (group == "mcp-token") return mcp_token;
    if (group == "exchange") return exchange;
    return none;
}

Verdict judge_rights(Mode mode, const std::string& group, const std::string& peer_cn) {
    if (mode == Mode::Off) return {};
    if (peer_cn.empty()) return {Finding::NoCert, mode >= Mode::EnforceTls};
    const auto& allowed = allowed_services(group);
    if (std::find(allowed.begin(), allowed.end(), peer_cn) == allowed.end()) {
        return {Finding::Forbidden, mode == Mode::Enforce};
    }
    return {};
}

Verdict judge_actor(Mode mode, const std::string& peer_cn, const std::string& actor) {
    if (mode == Mode::Off) return {};
    // Нет сертификата — это уже отмечено check_rights, второй раз не считаем.
    if (peer_cn.empty() || actor.empty()) return {};
    if (peer_cn != actor) return {Finding::ActorMismatch, mode >= Mode::EnforceTls};
    return {};
}

namespace {

// Журнал и метрика одного решения; false — запрос надо отклонить (403 записан).
bool apply(const std::string& group, Mode mode, const Verdict& v, const std::string& peer_cn,
           const std::string& actor, const httplib::Request& req, httplib::Response& res) {
    if (mode == Mode::Off) return true;
    metrics::inc_counter("internal_identity_total",
                         "Решения по идентичности вызывающего на /internal/* (группа.результат)", "finding",
                         group + "." + finding_name(v.finding));
    json details = {{"event", "internal_identity"},
                    {"group", group},
                    {"mode", mode_name(mode)},
                    {"finding", finding_name(v.finding)},
                    {"peer_service", peer_cn.empty() ? json(nullptr) : json(peer_cn)},
                    {"path", req.path},
                    {"reject", v.reject}};
    // actor — имя, не секрет; значение секрета сюда не попадает никогда.
    if (!actor.empty()) details["actor"] = actor;
    if (v.finding == Finding::Ok) {
        applog::info("internal identity ok", details);
        return true;
    }
    applog::warn(v.reject ? "internal identity rejected" : "internal identity mismatch (observe)", details);
    if (v.reject) {
        res.status = 403;
        res.set_content(json{{"error", "forbidden"}}.dump(), "application/json");
        return false;
    }
    return true;
}

} // namespace

bool check_rights(const Config& cfg, const httplib::Request& req, httplib::Response& res) {
    std::string group = group_of(req.path);
    if (group.empty()) return true;
    Mode mode = cfg.mode_for(group);
    std::string cn = nettls::peer_service(req);
    return apply(group, mode, judge_rights(mode, group, cn), cn, "", req, res);
}

bool check_actor(const Config& cfg, const httplib::Request& req, httplib::Response& res,
                 const std::string& actor) {
    std::string group = group_of(req.path);
    if (group.empty()) return true;
    Mode mode = cfg.mode_for(group);
    std::string cn = nettls::peer_service(req);
    Verdict v = judge_actor(mode, cn, actor);
    // Совпадение (Ok) здесь не пишем: строка «ok» уже есть после check_rights.
    if (v.finding == Finding::Ok) return true;
    return apply(group, mode, v, cn, actor, req, res);
}

} // namespace internal_identity
