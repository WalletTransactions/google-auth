// Sign in with Google: OAuth 2.0 Authorization Code + PKCE, затем
// криптографическая верификация id_token по JWKS Google.
//
// Это только АУТЕНТИФИКАЦИЯ (разовое подтверждение личности). Дальнейшая
// авторизация запросов к остальному API идёт уже через свой токен —
// см. auth.hpp.
#pragma once

#include <optional>
#include <string>

#include "app_state.hpp"
#include "httplib.h"

struct GoogleClaims {
    std::string sub;
    std::string email;
    bool email_verified = false;
    std::string name;
    std::string picture;
    // Пусто в браузерном флоу (там его нет и не нужно — CSRF уже закрыт
    // отдельным `state`, см. handle_login). Заполнено в мобильном флоу —
    // см. handle_mobile_login: nonce туда кладёт Android при вызове
    // Credential Manager, Google возвращает его внутри подписанного
    // id_token, сверка — по этому полю.
    std::string nonce;
};

namespace google_auth {

void register_routes(httplib::Server& svr, AppState& state);

// Настоящая верификация: подпись RS256 по публичному ключу Google (JWKS),
// issuer, audience и срок действия. Без этого "верификация" была бы просто
// доверием к чужому ответу без проверки. При неудаче error_out заполняется
// человекочитаемой причиной.
std::optional<GoogleClaims> verify_id_token(AppState& state, const std::string& id_token,
                                             std::string& error_out);

} // namespace google_auth
