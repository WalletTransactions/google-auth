## MODIFIED Requirements

### Requirement: Таблица политики
Обмен SHALL разрешаться только по парам: actor `wallet-ai` — subject с `aud` ∋
`wallet-ai` и `scope` ∋ `ai:use` → `audience` `wallet-mcp`, `scope` `mcp:read`;
actor `wallet-mcp` — subject с `aud` ∋ `wallet-mcp` и `scope` ∋ `mcp:read` →
`audience` `wallet-report`, `scope` `reports:read`, либо `audience` `wallet-docs`,
`scope` `docs:ask`. Другой `audience` для actor'а — `400` `{"error":"invalid_target"}`.
Выданный JWT SHALL NOT нести `role`, `email` и `name` и наследует `platform` и
`device_id` исходной сессии.

#### Scenario: wallet-mcp получает токен для wallet-report
- **WHEN** wallet-mcp передаёт JWT с `aud` `["wallet-mcp"]`, `scope` `mcp:read` и `audience=wallet-report`
- **THEN** ответ `200`, выданный JWT адресован `["wallet-report"]` со `scope` `reports:read`

#### Scenario: wallet-mcp получает токен для wallet-docs
- **WHEN** wallet-mcp передаёт JWT с `aud` `["wallet-mcp"]`, `scope` `mcp:read`, `platform` `android` и `audience=wallet-docs`
- **THEN** ответ `200`, выданный JWT адресован `["wallet-docs"]` со `scope` `docs:ask`, `platform` `android`, без `role`

#### Scenario: Scope справки нельзя подменить
- **WHEN** wallet-mcp просит `audience=wallet-docs` и `scope=docs:ask reports:read`
- **THEN** ответ `400` `{"error":"invalid_scope"}`

#### Scenario: wallet-ai просит токен для wallet-docs
- **WHEN** actor `wallet-ai` передаёт `audience=wallet-docs`
- **THEN** ответ `400` `{"error":"invalid_target"}`

#### Scenario: wallet-ai просит токен для wallet-api
- **WHEN** actor `wallet-ai` передаёт `audience=wallet-api`
- **THEN** ответ `400` `{"error":"invalid_target"}`

#### Scenario: Subject не подходит actor'у
- **WHEN** actor `wallet-mcp` передаёт JWT веб-сессии (`aud` без `wallet-mcp`)
- **THEN** ответ `400` `{"error":"invalid_grant"}`
