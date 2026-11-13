# Proposal

## Why

Change `wallet-mcp/docs-tool` добавляет MCP-инструмент `ask_docs`: модель спрашивает
«как работает система», wallet-mcp передаёт вопрос в `wallet-docs`. Тот принимает только
JWT с `aud` ∋ `wallet-docs` и `scope` ∋ `docs:ask`. Change `docs-audience` выдал этот
адресат лишь пользовательским токенам Android и web; MCP-токен (`wmcp_…`) и обмен RFC 8693
его намеренно не получают, поэтому wallet-mcp не может получить JWT для wallet-docs.

## What Changes

- `POST /internal/mcp/token` принимает необязательное поле `audience`: `wallet-report`
  (по умолчанию, прежний JWT) или `wallet-docs` (`aud` = `["wallet-docs"]`, `scope` =
  `docs:ask`, `platform` = `mcp`, без `role`/`email`/`name`, `exp` 300 с). Другое значение —
  `400` `{"error":"invalid_audience"}`; существующее поведение без поля не меняется.
- Таблица политики обмена RFC 8693 получает вторую пару для actor `wallet-mcp`:
  subject с `aud` ∋ `wallet-mcp` и `scope` ∋ `mcp:read` → `audience` `wallet-docs`,
  `scope` `docs:ask`. Выданный JWT, как и все JWT обмена, наследует `platform` и
  `device_id` исходной сессии и не несёт `role`.
- Токены, выданные пользователю, боту Telegram и актору `wallet-ai`, не меняются.

## Capabilities

### New Capabilities

### Modified Capabilities
- `mcp-tokens`: обмен `wmcp_…` на JWT — необязательный адресат `wallet-docs`.
- `token-exchange`: таблица политики — пара «`wallet-mcp` → `wallet-docs`».

## Impact

- **google-auth**: `src/mcp_tokens.cpp` (разбор `audience`, выбор claim'ов), таблица
  политики в `src/token_exchange.cpp`, тесты `test_mcp_tokens.cpp` и
  `test_token_exchange.cpp`, `openapi.yaml`, `README.md`, метрика `mcp_token_exchanges_total`
  (лейбл `audience`).
- **Потребители**: wallet-mcp (change `docs-tool`) — единственный вызывающий обе ручки;
  wallet-docs проверяет `aud`/`scope` и выбирает область по `platform` (change `mcp-scope`).
- Изменение аддитивно: wallet-api, wallet-report, wallet-ai, wallet-gateway не затронуты;
  вызовы без `audience` ведут себя как раньше.
- Порядок выкатки: google-auth → wallet-docs → wallet-mcp → `WALLET_DOCS_URL`.
