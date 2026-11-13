// Общие claims access-токенов (org/docs/TODO_telegram_tokens.md, «Решения»,
// п. 4–6): кто выпустил (iss), каким сервисам токен адресован (aud), что по
// нему можно (scope). Один источник значений — для issue_access_token
// (auth.cpp) и для tools/mint_loadtest_token.cpp, чтобы токены нагрузочного
// контура не разъехались с настоящими.
//
// Шаг 1 перехода: google-auth кладёт эти claims в каждый токен, сервисы их
// пока не проверяют. Проверка — шаг 2, отказ токену без aud — шаг 3.
#pragma once

#include <cstdint>
#include <string>

#include "nlohmann/json.hpp"

namespace token_claims {

inline constexpr const char* kIssuer = "google-auth";

// Сервисы, которые сами проверяют access-токен и что-то по нему разрешают.
// Имена, не URL: адреса разные в compose, k8s и при нативном запуске.
inline constexpr const char* kAudWalletApi = "wallet-api";
inline constexpr const char* kAudWalletReport = "wallet-report";
inline constexpr const char* kAudGoogleAuth = "google-auth";
// LLM-функции (org/docs/TODO_wallet_ai.md, §2): разбор трат текстом, импорт,
// чат. Сам ничего не пишет; со своим токеном пользователя читает wallet-report.
inline constexpr const char* kAudWalletAi = "wallet-ai";
// Инструменты чата (change add-token-exchange, D7). В user_audience() НЕТ:
// веб-сессия не ходит в wallet-mcp напрямую, токен для него выдаёт только
// обмен (POST /internal/token/exchange, token_exchange.hpp).
inline constexpr const char* kAudWalletMcp = "wallet-mcp";
// Справка по OpenSpec-спекам (change docs-audience): необязательный сервис,
// адресат выдаётся всегда — без апстрима гейтвей отвечает 404 до проверки
// токена. Область документации wallet-docs выбирает сам по role/platform.
// Только пользовательский токен: боту и обмену справка не нужна.
inline constexpr const char* kAudWalletDocs = "wallet-docs";

// Полный набор пользователя (браузер, телефон). Явный, а не «нет scope —
// можно всё»: одна ошибка при выпуске урезанного токена (бот) иначе дала бы
// ему полный доступ. ai:use — доступ к wallet-ai; выключить ИИ кому-то —
// не выдавать этот scope. docs:ask — вопросы к wallet-docs.
inline constexpr const char* kScopeUser = "wallet:read wallet:write reports:read account ai:use docs:ask";

inline nlohmann::json user_audience() {
    return nlohmann::json::array({kAudWalletApi, kAudWalletReport, kAudGoogleAuth, kAudWalletAi, kAudWalletDocs});
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
// не удалить аккаунт. expense:write — только создание новой операции;
// ai:use — разбор трат свободным текстом через wallet-ai.
inline constexpr const char* kScopeTelegramBot = "reports:read expense:write ai:use";
// Бот берёт токен на команду — долго жить ему незачем.
inline constexpr int kTelegramBotTokenTtlSecs = 300;

inline nlohmann::json telegram_bot_audience() {
    return nlohmann::json::array({kAudWalletReport, kAudWalletApi, kAudWalletAi});
}

inline void add_telegram_bot_claims(nlohmann::json& payload) {
    payload["iss"] = kIssuer;
    payload["aud"] = telegram_bot_audience();
    payload["scope"] = kScopeTelegramBot;
}

// JWT обмена персонального MCP-токена (POST /internal/mcp/token, change
// add-mcp-personal-tokens, D4): только чтение отчётов. Адресован одному
// wallet-report — ни записи в wallet-api, ни ИИ, ни ручек google-auth.
// Вызывающий НЕ кладёт в payload role/email/name: без role wallet-report
// видит обычного пользователя, и админский as_user_id через MCP недоступен.
inline constexpr const char* kScopeMcp = "reports:read";
// wallet-mcp кеширует JWT до exp и меняет MCP-токен не чаще раза в 5 минут.
inline constexpr int kMcpTokenTtlSecs = 300;

inline nlohmann::json mcp_audience() { return nlohmann::json::array({kAudWalletReport}); }

// Вопросы к wallet-docs (change docs-mcp-audience): второй адресат JWT
// обмена MCP-токена — для инструмента ask_docs в wallet-mcp.
inline constexpr const char* kScopeDocsAsk = "docs:ask";

// Дописывает iss/aud/scope и убирает role/email/name, если их кто-то
// положил по ошибке: регрессия здесь была бы тихой (см.
// tests/test_token_claims.cpp). audience — wallet-report (по умолчанию,
// reports:read) или wallet-docs (docs:ask); значение проверяет вызывающий
// по белому списку, другое здесь трактуется как wallet-report.
inline void add_mcp_claims(nlohmann::json& payload, const std::string& audience = kAudWalletReport) {
    payload.erase("role");
    payload.erase("email");
    payload.erase("name");
    payload["iss"] = kIssuer;
    if (audience == kAudWalletDocs) {
        payload["aud"] = nlohmann::json::array({kAudWalletDocs});
        payload["scope"] = kScopeDocsAsk;
    } else {
        payload["aud"] = mcp_audience();
        payload["scope"] = kScopeMcp;
    }
}

// JWT обмена токена (POST /internal/token/exchange, change add-token-exchange,
// D5, D7). mcp:read — чтение данных через инструменты wallet-mcp; в kScopeUser
// его нет, получить можно только обменом.
inline constexpr const char* kScopeMcpRead = "mcp:read";
// Потолок срока выданного токена: обмен не продлевает жизнь subject-токена и
// сам живёт не дольше 5 минут.
inline constexpr int kExchangeTokenMaxTtlSecs = 300;

// Claims токена обмена. payload должен уже содержать iat (время выпуска);
// subject — проверенный payload subject-токена (подпись, iss, exp — у
// вызывающего, см. token_exchange.cpp). Как add_mcp_claims, сначала стирает
// role/email/name/act — права и личные данные subject не переносятся, —
// потом пишет:
//   sub, device_id, platform — из subject (если есть);
//   iss/aud/scope — aud массивом из одного адресата;
//   act — {"sub": actor}, а act subject'а вкладывается внутрь (RFC 8693 §4.1):
//         wallet-mcp, меняющий токен от wallet-ai, получает
//         {"sub":"wallet-mcp","act":{"sub":"wallet-ai"}};
//   exp — min(subject.exp, iat + kExchangeTokenMaxTtlSecs).
// Бросает nlohmann::json::exception, если у payload нет iat или у subject нет
// числового exp/строкового sub — вызывающий проверяет их заранее.
inline void add_exchange_claims(nlohmann::json& payload, const std::string& aud, const std::string& scope,
                                const std::string& actor, const nlohmann::json& subject) {
    payload.erase("role");
    payload.erase("email");
    payload.erase("name");
    payload.erase("act");

    payload["sub"] = subject.at("sub").get<std::string>();
    for (const char* key : {"device_id", "platform"}) {
        auto it = subject.find(key);
        if (it != subject.end() && it->is_string()) payload[key] = *it;
        else payload.erase(key);
    }

    payload["iss"] = kIssuer;
    payload["aud"] = nlohmann::json::array({aud});
    payload["scope"] = scope;

    nlohmann::json act = {{"sub", actor}};
    auto prev = subject.find("act");
    if (prev != subject.end() && prev->is_object()) act["act"] = *prev;
    payload["act"] = act;

    std::uint64_t iat = payload.at("iat").get<std::uint64_t>();
    std::uint64_t subject_exp = subject.at("exp").get<std::uint64_t>();
    std::uint64_t cap = iat + static_cast<std::uint64_t>(kExchangeTokenMaxTtlSecs);
    payload["exp"] = subject_exp < cap ? subject_exp : cap;
}

} // namespace token_claims
