# Tasks

## 1. Обмен MCP-токена

- [ ] 1.1 `audience` в теле `POST /internal/mcp/token`: белый список `wallet-report` (по умолчанию) и `wallet-docs`, другое значение — `400 {"error":"invalid_audience"}` до проверки токена; выбор `aud`/`scope` по таблице. Проверка: юнит-тесты — без поля прежний JWT (`aud` `wallet-report`, `reports:read`), `wallet-docs` даёт `aud` `["wallet-docs"]`, `scope` `docs:ask`, `platform` `mcp`, без `role`/`email`/`name`; `wallet-api` — `400`, токен при этом не продлевается.
- [ ] 1.2 Метка `audience` у `mcp_token_exchanges_total`. Проверка: тест на значения лейбла; `/metrics` на живом стеке показывает оба адресата после двух вызовов.

## 2. Обмен RFC 8693

- [ ] 2.1 Пара «`wallet-mcp` → `wallet-docs`, `docs:ask`» в таблице политики (subject `aud` ∋ `wallet-mcp`, `scope` ∋ `mcp:read`). Проверка: юнит-тесты — выданный JWT наследует `platform`/`device_id`, роль не несёт; `scope=docs:ask reports:read` — `invalid_scope`; `wallet-ai` с `audience=wallet-docs` — `invalid_target`; subject без `wallet-mcp` в `aud` — `invalid_grant`.

## 3. Контракт и документация

- [ ] 3.1 `openapi.yaml`: поле `audience` в `exchangeMcpToken`, код `400`, новая строка таблицы политики в `exchangeToken`; README. Проверка: Swagger UI на `/docs` показывает поле и строку, примеры `curl` из README работают.

## 4. Сборка и проверка на стенде

- [ ] 4.1 Сборка образа одним сервисом за раз (`docker build --memory=3g --build-arg BUILD_JOBS=3 --target test`). Проверка: все юнит-тесты проходят.
- [ ] 4.2 Выкат на test через rc-тег. Проверка: `curl` к `/internal/mcp/token` изнутри контура — `audience: "wallet-docs"` даёт JWT с нужными claim'ами, без поля — прежний JWT; wallet-report принимает второй и отвергает первый; остальные сервисы не перезапускались.

## Заметки к выкату

- Порядок: google-auth → wallet-docs `mcp-scope` → wallet-mcp `docs-tool`.
- Откат: прежний образ; wallet-mcp без `WALLET_DOCS_URL` ничего нового не запрашивает.
- Архивировать change после выката и проверки на test.
