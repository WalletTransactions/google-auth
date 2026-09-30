// Связывание Telegram-чата с пользователем — сторона google-auth для бота
// wallet-telegram (org/docs/TODO_telegram_bot.md, §1.2):
//
//   POST /auth/telegram/link-code        — залогиненный пользователь (веб)
//                                           получает одноразовый код и
//                                           deep link t.me/<bot>?start=<code>;
//   POST /internal/telegram/exchange     — бот меняет код на связку
//                                           tg_user_id → user_id (таблица
//                                           telegram_links);
//   POST /internal/telegram/token        — токен бота на команду по связке
//                                           (5 мин, aud wallet-report +
//                                           wallet-api, scope reports:read
//                                           expense:write);
//   DELETE /internal/telegram/links/:id  — /unlink из самого бота;
//   GET/DELETE /auth/telegram/links[/:id] — веб: список и отключение.
//
// /internal/* защищены общим секретом X-Service-Secret (client assertion —
// отложено, org/docs/TODO_service_auth_tls.md) и НЕ видны через wallet-gateway (тот /internal/*
// не маршрутизирует).
//
// Сессии устройства (refresh) у бота нет с шага 6
// org/docs/TODO_telegram_tokens.md: доступ бота = наличие связки.
#pragma once

#include <string>

#include "app_state.hpp"
#include "httplib.h"

namespace telegram {

void register_routes(httplib::Server& svr, AppState& state);

// Чистые помощники — в заголовке ради юнит-тестов (tests/test_telegram.cpp).
namespace detail {

// Детерминированный device_id (UUID-строка) для пары (пользователь,
// Telegram-пользователь) — claim device_id токена бота, от его имени
// операции в wallet-api (updated_by). Детерминированный — чтобы повторное
// связывание того же чата с тем же пользователем давало то же устройство, а
// не копило новые. Зависит и от user_id: в
// wallet-api device.id — первичный ключ, и ON CONFLICT (id) не переносит
// устройство к другому user_id (см. provisioning.cpp) — один и тот же
// Telegram-аккаунт, связанный поочерёдно с двумя пользователями, обязан
// давать им два разных устройства.
std::string device_id_for(const std::string& user_id, const std::string& tg_user_id);

// Telegram user id — положительное целое (до 52 бит по документации Bot
// API). Принимается и JSON-числом, и строкой из цифр; nullopt-аналог —
// пустая строка на выходе.
std::string normalize_tg_user_id(const std::string& raw);

// "Telegram @username" / "Telegram 211959201" — поле name в GET
// /auth/telegram/links, только для показа. username обрезается до 64
// символов, ведущий '@' убирается.
std::string device_name_for(const std::string& tg_username, const std::string& tg_user_id);

// Сравнение секрета за постоянное время и без утечки длины (сравниваются
// sha256 обеих строк). Пустой expected — всегда false: незаданный секрет не
// должен совпадать с пустым заголовком.
bool secret_matches(const std::string& expected, const std::string& provided);

} // namespace detail

} // namespace telegram
