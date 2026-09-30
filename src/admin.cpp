#include "admin.hpp"

#include "auth.hpp"
#include "nlohmann/json.hpp"
#include "repo.hpp"
#include "util/log.hpp"

using nlohmann::json;

namespace admin {

namespace {

// active_sessions — repo::list_user_sessions уже умеет отличать реально
// живую сессию от висячей ссылки в индексе (подчищает её попутно, см.
// repo.hpp) — счётчик "залогинен ли сейчас, и на скольких устройствах"
// пригодится и для показа в таблице, и как повод для кнопки force-logout,
// которая уже есть на этом же экране.
//
// N дополнительных походов в Redis на список из N пользователей — для
// staff-таблицы, открываемой вручную и нечасто, это приемлемо; переделывать
// под один batch-запрос стоит, только если список пользователей вырастет
// на порядки (см. README, "Список пользователей").
json user_to_json(AppState& state, const UserRecord& u) {
    auto sessions = repo::list_user_sessions(*state.redis, u.id);
    return json{
        {"id", u.id},
        {"email", u.email},
        {"email_verified", u.email_verified},
        {"name", u.name},
        {"role", to_string(u.role)},
        {"created_at", u.created_at},
        {"last_login_at", u.last_login_at},
        {"active_sessions", sessions.size()},
    };
}

// GET /admin/users — список всех пользователей как JSON. Раньше отдавал
// server-rendered HTML (см. историю pages.cpp) — теперь обычный JSON API,
// тем же приёмом, что GET /auth/me: SPA (wallet-web/site/app.js,
// renderAdmin()) сам рисует таблицу и сортировку на клиенте.
void handle_list_users(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("GET /admin/users"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        res.status = 401;
        res.set_content(json{{"error", "unauthenticated"}}.dump(), "application/json");
        return;
    }
    if (user->role != Role::Admin) {
        res.status = 403;
        res.set_content(json{{"error", "forbidden"}}.dump(), "application/json");
        return;
    }

    json users = json::array();
    for (const auto& u : repo::list_users(*state.db_pool->acquire())) users.push_back(user_to_json(state, u));
    res.set_content(json{{"users", users}}.dump(), "application/json");
}

// Принудительный logout конкретного пользователя (кнопка на SPA-странице
// /admin/users, см. app.js::renderAdmin()) — отзывает разом все его активные
// access- и refresh-токены (см. repo::revoke_all_user_tokens), не только
// один токен из cookie текущего запроса, как обычный /auth/logout.
void handle_force_logout(AppState& state, const httplib::Request& req, httplib::Response& res) {
    applog::set_route("POST /admin/users/:id/logout"); // литерал из register_routes ниже
    auto user = auth::authenticate(req, state);
    if (!user) {
        res.status = 401;
        res.set_content(json{{"error", "unauthenticated"}}.dump(), "application/json");
        return;
    }
    if (user->role != Role::Admin) {
        res.status = 403;
        res.set_content(json{{"error", "forbidden"}}.dump(), "application/json");
        return;
    }

    auto it = req.path_params.find("id");
    std::string target_id = it != req.path_params.end() ? it->second : std::string();
    if (target_id.empty() || !repo::find_user_by_id(*state.db_pool->acquire(), target_id)) {
        res.status = 404;
        res.set_content(json{{"error", "user not found"}}.dump(), "application/json");
        return;
    }

    // Отзывает и access-, и refresh-токены разом (см. repo.hpp) — мгновенно,
    // но ТОЛЬКО для проверок внутри этого сервиса (см. README google-auth,
    // "Мгновенный logout — только в auth-сервисе"): wallet-api/wallet-gateway
    // проверяют access-токен по JWKS локально и про отзыв не узнают, их
    // сессия "работает" до истечения exp (обычно 15 минут).
    repo::revoke_all_user_tokens(*state.redis, target_id);
    res.status = 204;
}

} // namespace

void register_routes(httplib::Server& svr, AppState& state) {
    svr.Get("/admin/users", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_list_users(state, req, res);
    });
    svr.Post("/admin/users/:id/logout", [&state](const httplib::Request& req, httplib::Response& res) {
        handle_force_logout(state, req, res);
    });
}

} // namespace admin
