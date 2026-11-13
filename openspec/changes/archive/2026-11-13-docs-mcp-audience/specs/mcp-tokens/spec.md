## MODIFIED Requirements

### Requirement: Обмен MCP-токена на JWT
`POST /internal/mcp/token` `{"token"}` или `{"token","audience"}` SHALL для действующего
MCP-токена выпускать JWT RS256 с `sub` (id пользователя), `iat`, `exp` (`iat` + 300),
`iss` = `google-auth`, `device_id` токена и `platform` = `mcp` и отвечать `200`
`{"access_token", "expires_in": 300, "user_id", "device_id"}`. Без `audience` или с
`audience` = `wallet-report` JWT адресован `["wallet-report"]` со `scope` `reports:read`;
с `audience` = `wallet-docs` — `["wallet-docs"]` со `scope` `docs:ask`. Любое другое
значение `audience` — `400` `{"error":"invalid_audience"}` до проверки токена. Общий
секрет не требуется: доказательство — сам токен.

#### Scenario: Обмен из wallet-mcp
- **WHEN** wallet-mcp шлёт действующий `wmcp_…` без `audience`
- **THEN** ответ `200`, JWT принимает wallet-report (`aud` `wallet-report`, scope `reports:read`)

#### Scenario: Обмен для справки
- **WHEN** wallet-mcp шлёт действующий `wmcp_…` с `audience: "wallet-docs"`
- **THEN** ответ `200`, JWT с `aud` `["wallet-docs"]`, `scope` `docs:ask`, `platform` `mcp`, без `role`; wallet-report такой JWT не принимает

#### Scenario: Чужой адресат
- **WHEN** wallet-mcp шлёт `audience: "wallet-api"`
- **THEN** ответ `400` `{"error":"invalid_audience"}`, токен не проверяется и не продлевается

#### Scenario: JWT не годится для записи и для google-auth
- **WHEN** полученным JWT вызывают `POST /sync/push` через гейтвей или `GET /auth/me`
- **THEN** гейтвей отвечает `401` (нет `wallet-api` в `aud`), google-auth — `401` `{"error":"unauthenticated"}`
