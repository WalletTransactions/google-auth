# Proposal

## Why

Чат с ИИ по данным кошелька (Telegram, позже веб) решено строить так:
агентный цикл живёт в wallet-ai, инструменты исполняет wallet-mcp. Но
wallet-mcp сейчас принимает только персональный токен `wmcp_…`, а у wallet-ai
на руках лишь JWT пользователя (aud `wallet-ai`). Передавать этот JWT дальше
нельзя: спека MCP запрещает серверу принимать токены, выпущенные не для него,
и пробрасывать полученный токен вниз (token passthrough). Нужен стандартный
способ получить для того же пользователя новый короткий токен под другого
адресата. Это и есть обмен токена по RFC 8693. Тот же обмен понадобится
wallet-mcp, чтобы из входящего JWT получить JWT для wallet-report, и позже
OAuth 2.1 для внешних MCP-клиентов.

## What Changes

- Новый служебный эндпоинт `POST /internal/token/exchange` в форме RFC 8693
  (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
  `subject_token`, `subject_token_type`, `audience`, `scope`). Гейтвей его не
  проксирует, как и остальные `/internal/*`.
- Вызывающий сервис (actor) аутентифицируется своим `X-Service-Secret`.
  Секреты задаются переменной `TOKEN_EXCHANGE_SECRETS`
  (`wallet-ai=…,wallet-mcp=…`). Пустая переменная выключает эндпоинт.
- Обмен разрешён только по фиксированной таблице политики:
  - `wallet-ai`: subject с `aud` ∋ `wallet-ai` и `scope` ∋ `ai:use` → токен
    `aud` `["wallet-mcp"]`, `scope` `mcp:read`;
  - `wallet-mcp`: subject с `aud` ∋ `wallet-mcp` и `scope` ∋ `mcp:read` →
    токен `aud` `["wallet-report"]`, `scope` `reports:read`.
- Выпущенный токен:
  - сохраняет `sub`, `device_id` и `platform` subject-токена;
  - теряет `role`, `email`, `name`;
  - получает claim `act` (кто действует, с вложенной цепочкой);
  - живёт не дольше subject-токена и не дольше 300 с;
  - не регистрируется как активный access-токен google-auth.
- Новые константы claims: адресат `wallet-mcp`, scope `mcp:read`.
- Метрика `token_exchange_total{actor,result}`, журнал без токенов.
- Существующий `POST /internal/mcp/token` (обмен `wmcp_…`) не меняется.

## Capabilities

### New Capabilities

- `token-exchange`: обмен JWT пользователя на JWT для другого сервиса от
  имени вызывающего сервиса. Охватывает аутентификацию actor'а, таблицу
  политики, claims выпущенного токена и отказы.

### Modified Capabilities

(нет. `mcp-tokens` и `session-tokens` не меняются)

## Impact

- **Код:** `src/token_exchange.{hpp,cpp}` (новый), `src/token_claims.hpp`
  (адресат `wallet-mcp`, scope `mcp:read`, функция claims обмена),
  `src/main.cpp` (конфиг, регистрация маршрута, маскировка тела в журнале),
  `src/app_state.hpp`.
- **API:** `openapi.yaml` (новый путь в разделе internal), `README.md`.
- **Конфиг:** `TOKEN_EXCHANGE_SECRETS` в `.env.example`. Значения для
  контуров задаются в wallet-infra (`.env` google-auth, wallet-ai, wallet-mcp).
- **Потребители:** wallet-ai (change `add-chat-agent`) и wallet-mcp (change
  `add-jwt-access`). До их выката эндпоинт никто не вызывает, обратная
  совместимость не затронута.
- **Порядок выкатки:** google-auth → wallet-mcp → wallet-ai → wallet-telegram.
- **Вне объёма:** OAuth 2.1 для внешних MCP-клиентов (authorize, DCR/CIMD,
  метаданные), публичный доступ к эндпоинту.
