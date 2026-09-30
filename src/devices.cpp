#include "devices.hpp"

#include <algorithm>

#include "auth.hpp"
#include "nlohmann/json.hpp"
#include "repo.hpp"
#include "util/log.hpp"

using nlohmann::json;

namespace devices {

namespace {

// "Эта сессия — та, из которой пришёл запрос". Ровно один из двух признаков
// заполнен (никогда оба и никогда ни одного, если known):
//   - token_hash — ТОЧНОЕ совпадение: хэш refresh-токена, который реально
//     пришёл с этим запросом (браузер — cookie Path=/auth; клиент без
//     cookie jar, в т.ч. мобильный, — то же JSON-поле "refresh_token" в
//     теле, что уже принимает POST /auth/refresh, см.
//     auth::extract_refresh_token), сверенный с SessionSummary::token_hash.
//     Предпочитается всегда, когда токен вообще передан — однозначно
//     называет РОВНО ОДНУ сессию, в отличие от device_id ниже.
//   - device_id — эвристика на случай, если явного refresh-токена в запросе
//     нет (мобильный Bearer-only клиент, не приложивший "refresh_token" в
//     теле): ЛЮБАЯ сессия с тем же device_id из access-JWT считается
//     текущей. Корректно только потому, что auth::issue_tokens уже
//     гарантирует не больше одной активной сессии на (user, device_id) —
//     см. её комментарий про схлопывание; сама по себе она не различает
//     сессии ТАК ТОЧНО, как явный токен, поэтому это запасной, а не
//     основной путь. У браузера device_id всегда пуст (нет стабильного
//     идентификатора устройства) — этот путь ему в принципе не доступен.
// known=false — определить нечем ни тем, ни другим способом (браузерный
// Bearer-only запрос без refresh-токена ни в cookie, ни в теле) — тогда ни
// одна сессия не считается текущей.
struct CurrentSession {
    bool known = false;
    std::string device_id;
    std::string token_hash;
};

CurrentSession resolve_current_session(const httplib::Request& req, const auth::AuthUser& user) {
    CurrentSession current;
    std::string refresh = auth::extract_refresh_token(req);
    if (!refresh.empty()) {
        current.known = true;
        current.token_hash = auth::hash_refresh_token(refresh);
        return current;
    }
    if (!user.device_id.empty()) {
        current.known = true;
        current.device_id = user.device_id;
    }
    return current; // known остаётся false, если не сработал ни один способ
}

bool is_current(const repo::SessionSummary& session, const CurrentSession& current) {
    if (!current.known) return false;
    if (!current.device_id.empty()) return session.device.device_id == current.device_id;
    return session.token_hash == current.token_hash;
}

json session_to_json(const repo::SessionSummary& session, bool current) {
    return json{
        {"token_hash", session.token_hash},
        {"device_id", session.device.device_id},
        {"device_name", session.device.device_name},
        {"platform", session.device.platform},
        {"is_current", current},
    };
}

// GET /auth/devices — все активные сессии текущего пользователя (см.
// repo::list_user_sessions), помеченные, какая из них "эта".
void handle_list(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("GET /auth/devices"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        res.status = 401;
        res.set_content(json{{"error", "unauthenticated"}}.dump(), "application/json");
        return;
    }

    CurrentSession current = resolve_current_session(req, *user);
    auto sessions = repo::list_user_sessions(*state.redis, user->user_id);

    json list = json::array();
    for (const auto& session : sessions) {
        list.push_back(session_to_json(session, is_current(session, current)));
    }
    res.set_content(json{{"devices", list}}.dump(), "application/json");
}

// POST /auth/devices/revoke {"token_hash"} — отзывает ОДНУ конкретную сессию
// СВОЕГО (не чужого) списка. Ownership-проверка через сам список
// (list_user_sessions), а не голый repo::revoke_user_sessions_if по хэшу
// напрямую — иначе пользователь A, каким-то образом узнавший token_hash
// сессии пользователя B (сам хэш не секрет — его же отдаёт GET /auth/devices
// владельцу), смог бы разлогинить чужое устройство при том, что revoke ищет
// по ГЛОБАЛЬНОМУ ключу refresh_token:<hash> в Redis, а не в неймспейсе
// вызывающего пользователя.
void handle_revoke_one(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/devices/revoke"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        res.status = 401;
        res.set_content(json{{"error", "unauthenticated"}}.dump(), "application/json");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (const std::exception&) {
        res.status = 400;
        res.set_content(json{{"error", "invalid JSON body"}}.dump(), "application/json");
        return;
    }
    std::string target_hash = body.value("token_hash", std::string{});
    if (target_hash.empty()) {
        res.status = 400;
        res.set_content(json{{"error", "token_hash отсутствует"}}.dump(), "application/json");
        return;
    }

    CurrentSession current = resolve_current_session(req, *user);
    auto sessions = repo::list_user_sessions(*state.redis, user->user_id);
    auto it = std::find_if(sessions.begin(), sessions.end(), [&](const repo::SessionSummary& s) {
        return s.token_hash == target_hash;
    });
    if (it == sessions.end()) {
        res.status = 404;
        res.set_content(json{{"error", "session not found"}}.dump(), "application/json");
        return;
    }
    if (is_current(*it, current)) {
        res.status = 400;
        res.set_content(
            json{{"error", "нельзя отозвать текущую сессию — используйте POST /auth/logout"}}.dump(),
            "application/json");
        return;
    }

    repo::revoke_user_sessions_if(*state.redis, user->user_id,
                                   [&](const repo::SessionSummary& s) { return s.token_hash == target_hash; });
    res.status = 204;
}

// POST /auth/devices/revoke-others — отзывает все сессии пользователя, КРОМЕ
// текущей (см. resolve_current_session выше). Требует, чтобы текущую сессию
// вообще можно было определить — у браузерного запроса без refresh-токена
// (ни cookie, ни тела) это невозможно, и слепое "отозвать все" было бы куда
// опаснее ошибочного отказа: свежесозданная сессия читателя внезапно перестала
// бы работать сама на себя.
void handle_revoke_others(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /auth/devices/revoke-others"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        res.status = 401;
        res.set_content(json{{"error", "unauthenticated"}}.dump(), "application/json");
        return;
    }

    CurrentSession current = resolve_current_session(req, *user);
    if (!current.known) {
        res.status = 400;
        res.set_content(
            json{{"error", "не удалось определить текущую сессию — refresh-токен не передан"}}.dump(),
            "application/json");
        return;
    }

    int revoked = repo::revoke_user_sessions_if(
        *state.redis, user->user_id,
        [&](const repo::SessionSummary& s) { return !is_current(s, current); });
    res.set_content(json{{"revoked", revoked}}.dump(), "application/json");
}

} // namespace

void register_routes(httplib::Server& svr, AppState& state) {
    svr.Get("/auth/devices", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_list(state, req, res);
    });
    svr.Post("/auth/devices/revoke", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_revoke_one(state, req, res);
    });
    svr.Post("/auth/devices/revoke-others", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_revoke_others(state, req, res);
    });
}

} // namespace devices
