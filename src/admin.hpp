// Админ-эндпоинты — JSON REST, а не HTML (см. ../wallet-api/src/wallet.cpp
// для другого примера защищённого JSON REST в проекте). Раньше GET
// /admin/users отдавал server-rendered HTML-страницу — теперь это обычный
// JSON API, список пользователей рисует SPA (см. ../wallet-web/site/app.js,
// renderAdmin()), тем же приёмом, что и дашборд кошельков по GET /auth/me.
// Доступ только Role::Admin; support сюда намеренно не допущен — список
// email/id всех пользователей не диагностическая задача (см. README,
// "Роли").
#pragma once

#include "app_state.hpp"
#include "httplib.h"

namespace admin {

void register_routes(httplib::Server& svr, AppState& state);

} // namespace admin
