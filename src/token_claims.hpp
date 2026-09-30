// Общие claims access-токенов (org/docs/TODO_telegram_tokens.md, «Решения»,
// п. 4–6): кто выпустил (iss), каким сервисам токен адресован (aud), что по
// нему можно (scope). Один источник значений — для issue_access_token
// (auth.cpp) и для tools/mint_loadtest_token.cpp, чтобы токены нагрузочного
// контура не разъехались с настоящими.
//
// Шаг 1 перехода: google-auth кладёт эти claims в каждый токен, сервисы их
// пока не проверяют. Проверка — шаг 2, отказ токену без aud — шаг 3.
#pragma once

#include "nlohmann/json.hpp"

namespace token_claims {

inline constexpr const char* kIssuer = "google-auth";

// Сервисы, которые сами проверяют access-токен и что-то по нему разрешают.
// Имена, не URL: адреса разные в compose, k8s и при нативном запуске.
inline constexpr const char* kAudWalletApi = "wallet-api";
inline constexpr const char* kAudWalletReport = "wallet-report";
inline constexpr const char* kAudGoogleAuth = "google-auth";

// Полный набор пользователя (браузер, телефон). Явный, а не «нет scope —
// можно всё»: одна ошибка при выпуске урезанного токена (бот) иначе дала бы
// ему полный доступ.
inline constexpr const char* kScopeUser = "wallet:read wallet:write reports:read account";

inline nlohmann::json user_audience() {
    return nlohmann::json::array({kAudWalletApi, kAudWalletReport, kAudGoogleAuth});
}

// Дописывает iss/aud/scope пользовательского токена в payload.
inline void add_user_claims(nlohmann::json& payload) {
    payload["iss"] = kIssuer;
    payload["aud"] = user_audience();
    payload["scope"] = kScopeUser;
}

// Токен Telegram-бота для пользователя (POST /internal/telegram/token,
// TODO_telegram_tokens.md, шаг 4). google-auth в aud нет: украденным токеном
// бота не посмотреть и не отозвать устройства, не выпустить код связывания,
// не удалить аккаунт. expense:write — только создание новой операции.
inline constexpr const char* kScopeTelegramBot = "reports:read expense:write";
// Бот берёт токен на команду — долго жить ему незачем.
inline constexpr int kTelegramBotTokenTtlSecs = 300;

inline nlohmann::json telegram_bot_audience() {
    return nlohmann::json::array({kAudWalletReport, kAudWalletApi});
}

inline void add_telegram_bot_claims(nlohmann::json& payload) {
    payload["iss"] = kIssuer;
    payload["aud"] = telegram_bot_audience();
    payload["scope"] = kScopeTelegramBot;
}

} // namespace token_claims
