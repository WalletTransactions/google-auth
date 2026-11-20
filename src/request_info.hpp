// Разбор заголовков запроса, которые проставляет wallet-gateway (или другой
// reverse proxy): адрес клиента, схема, адрес для redirect_uri Google. Вынесено
// из обработчиков, чтобы проверяться юнит-тестом без поднятия сервера.
#pragma once

#include <string>

#include "app_state.hpp"
#include "httplib.h"

namespace request_info {

// IP клиента для лимитов попыток: первый адрес в X-Forwarded-For (гейтвей его
// перезаписывает, см. design D4), иначе адрес соединения. Пусто быть не
// может — на крайний случай "unknown", чтобы ключ счётчика не был пустым.
std::string client_ip(const httplib::Request& req);

// Пришёл ли запрос по защищённому соединению: X-Forwarded-Proto: https
// (регистр не важен; при списке "https, http" берётся первый — тот, что
// видел первый прокси).
bool is_https(const httplib::Request& req);

// "192.168.1.105:8090" -> "192.168.1.105.nip.io:8090". Только голый IP из
// 192.168.*; остальные хосты возвращаются как есть (подробности — в google.cpp
// истории и README, «Вход и с localhost, и по LAN одновременно»).
std::string rewrite_lan_ip_to_nip_io(const std::string& host);

// redirect_uri Google для этого запроса: "<схема>://<хост>/auth/google/callback",
// где хост — X-Forwarded-Host, иначе Host (голый LAN-IP переписывается в nip.io),
// а схема — https при X-Forwarded-Proto: https, иначе http. Берётся, только
// если есть в allowed_redirect_uris; иначе — запасной state.redirect_url.
std::string resolve_redirect_uri(const AppState& state, const httplib::Request& req);

} // namespace request_info
