// Экран "Устройства" (self-service, не admin) — показать пользователю его же
// активные сессии (по одной на устройство, см. auth::issue_tokens —
// схлопывание по device_id уже гарантирует, что здесь нет дублей одного и
// того же мобильного устройства) и дать их отозвать: одну конкретную или все,
// кроме той, из которой пришёл сам запрос. Ровно то, чего не хватало по
// org/docs/TODO_mobile_sync.md, "Открытые вопросы" — "данные для этого уже в
// Redis (Фаза 1), эндпоинта нет".
//
// В отличие от admin.cpp (тот управляет ЧУЖИМИ сессиями, только Role::Admin)
// — здесь пользователь управляет только своими: id проверяемого пользователя
// берётся из его же access-токена (auth::authenticate), не из path/body.
#pragma once

#include "app_state.hpp"
#include "auth.hpp"
#include "httplib.h"

namespace devices {

// Отзывает все сессии пользователя (refresh и MCP-токены), кроме той, из
// которой пришёл запрос — после смены пароля. «Текущая» определяется так же,
// как на экране устройств: по refresh-токену запроса, иначе по device_id из
// access-JWT. Если определить её нечем, отзываются все сессии, включая
// вызывающую: безопаснее выйти самому, чем оставить чужую сессию живой.
// Возвращает число отозванных refresh-сессий.
int revoke_other_sessions(AppState& state, const httplib::Request& req, const auth::AuthUser& user);

void register_routes(httplib::Server& svr, AppState& state);

} // namespace devices
