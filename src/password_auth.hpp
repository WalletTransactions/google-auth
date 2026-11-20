// Вход, регистрация и смена пароля (change add-password-auth, спека
// password-auth). Выпускает сессию тем же кодом, что и вход через Google
// (auth::issue_tokens), поэтому claim'ы токена и потребители JWKS не меняются
// (design D7).
//
//   GET  /auth/methods                — какие способы входа включены
//   POST /auth/register               — регистрация по email и паролю
//   POST /auth/login                  — вход (web: cookie, Android: тело)
//   POST /auth/password               — установка и смена своего пароля
//   POST /admin/users/:id/password    — сброс пароля админом
#pragma once

#include "app_state.hpp"
#include "httplib.h"

namespace password_auth {

void register_routes(httplib::Server& svr, AppState& state);

} // namespace password_auth
