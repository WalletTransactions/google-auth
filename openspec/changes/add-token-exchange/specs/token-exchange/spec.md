# Spec Delta

## Purpose

Обмен JWT пользователя на короткий JWT для другого сервиса от имени
вызывающего сервиса (RFC 8693). Так wallet-ai и wallet-mcp обращаются к
следующему сервису, не пробрасывая полученный токен и не расширяя права
пользователя.

## ADDED Requirements

### Requirement: Эндпоинт обмена
`POST /internal/token/exchange` SHALL принимать тело
`application/x-www-form-urlencoded` с полями `grant_type`
(`urn:ietf:params:oauth:grant-type:token-exchange`), `subject_token`,
`subject_token_type` (`urn:ietf:params:oauth:token-type:access_token`),
`audience` и необязательным `scope`. Успешный ответ — `200` с
`access_token`, `issued_token_type`, `token_type` `Bearer` и `expires_in`
(схема — `openapi.yaml`).

#### Scenario: wallet-ai получает токен для wallet-mcp
- **WHEN** wallet-ai со своим `X-Service-Secret` передаёт действующий JWT пользователя с `aud` ∋ `wallet-ai` и `scope` ∋ `ai:use` и `audience=wallet-mcp`
- **THEN** ответ `200`, `token_type` `Bearer`, `issued_token_type` `urn:ietf:params:oauth:token-type:access_token`, выданный JWT адресован `["wallet-mcp"]` со `scope` `mcp:read`

#### Scenario: Гейтвей не пропускает
- **WHEN** `POST /internal/token/exchange` приходит через wallet-gateway
- **THEN** гейтвей не маршрутизирует путь, google-auth запрос не получает

### Requirement: Аутентификация вызывающего сервиса
Вызывающий сервис SHALL предъявлять `X-Service-Secret`, совпадающий с секретом
одного из сервисов в `TOKEN_EXCHANGE_SECRETS`. Совпавший сервис становится
actor'ом обмена. Неверный или пустой секрет — `401` `{"error":"invalid_client"}`.
Пустая `TOKEN_EXCHANGE_SECRETS` — `503` `{"error":"unavailable"}` на любой запрос.

#### Scenario: Неверный секрет
- **WHEN** запрос несёт `X-Service-Secret`, которого нет в `TOKEN_EXCHANGE_SECRETS`
- **THEN** ответ `401` `{"error":"invalid_client"}`, subject-токен не проверяется

#### Scenario: Обмен выключен
- **WHEN** `TOKEN_EXCHANGE_SECRETS` пуста
- **THEN** любой запрос получает `503` `{"error":"unavailable"}`

### Requirement: Таблица политики
Обмен SHALL разрешаться только по парам: actor `wallet-ai` — subject с `aud` ∋
`wallet-ai` и `scope` ∋ `ai:use` → `audience` `wallet-mcp`, `scope` `mcp:read`;
actor `wallet-mcp` — subject с `aud` ∋ `wallet-mcp` и `scope` ∋ `mcp:read` →
`audience` `wallet-report`, `scope` `reports:read`. Другой `audience` для
actor'а — `400` `{"error":"invalid_target"}`.

#### Scenario: wallet-mcp получает токен для wallet-report
- **WHEN** wallet-mcp передаёт JWT с `aud` `["wallet-mcp"]`, `scope` `mcp:read` и `audience=wallet-report`
- **THEN** ответ `200`, выданный JWT адресован `["wallet-report"]` со `scope` `reports:read`

#### Scenario: wallet-ai просит токен для wallet-api
- **WHEN** actor `wallet-ai` передаёт `audience=wallet-api`
- **THEN** ответ `400` `{"error":"invalid_target"}`

#### Scenario: Subject не подходит actor'у
- **WHEN** actor `wallet-mcp` передаёт JWT веб-сессии (`aud` без `wallet-mcp`)
- **THEN** ответ `400` `{"error":"invalid_grant"}`

### Requirement: Scope не расширяется
Если `scope` указан, он SHALL совпадать со scope из таблицы политики для
пары actor–`audience`. Иначе ответ `400` `{"error":"invalid_scope"}`. Без
`scope` выдаётся scope из таблицы.

#### Scenario: Попытка расширить scope
- **WHEN** actor `wallet-ai` просит `audience=wallet-mcp` и `scope=mcp:read reports:read`
- **THEN** ответ `400` `{"error":"invalid_scope"}`

### Requirement: Проверка subject-токена
Subject-токен SHALL быть JWT RS256, подписанным действующим ключом google-auth,
с `iss` `google-auth` и неистёкшим `exp`. Любой другой — `400`
`{"error":"invalid_grant"}` без уточнения причины. Неверные `grant_type` или
`subject_token_type` — `400` `{"error":"unsupported_grant_type"}` и `400`
`{"error":"invalid_request"}` соответственно.

#### Scenario: Истёкший subject
- **WHEN** `subject_token` — JWT с `exp` в прошлом
- **THEN** ответ `400` `{"error":"invalid_grant"}`

#### Scenario: MCP-токен вместо JWT
- **WHEN** `subject_token` — `wmcp_…`
- **THEN** ответ `400` `{"error":"invalid_grant"}`, MCP-токен не продлевается

#### Scenario: Чужой grant_type
- **WHEN** `grant_type=refresh_token`
- **THEN** ответ `400` `{"error":"unsupported_grant_type"}`

### Requirement: Claims выданного токена
Выданный JWT SHALL нести `sub`, `device_id` и `platform` subject-токена, `iss`
`google-auth`, `aud` и `scope` из таблицы, `iat` и
`exp` = min(`exp` subject, `iat` + 300). `act` SHALL быть `{"sub": "<actor>"}`,
а если у subject был `act`, он вкладывается внутрь. `role`, `email` и
`name` SHALL NOT попадать в токен.

#### Scenario: Цепочка wallet-ai → wallet-mcp
- **WHEN** wallet-mcp меняет токен, который wallet-ai получил обменом
- **THEN** у выданного JWT `act` = `{"sub":"wallet-mcp","act":{"sub":"wallet-ai"}}`, `sub` прежний

#### Scenario: Subject администратора
- **WHEN** wallet-ai меняет JWT администратора с `role` `admin`
- **THEN** в выданном JWT нет `role`, wallet-report не считает его администратором

#### Scenario: Срок не продлевается
- **WHEN** subject-токен истекает через 60 с
- **THEN** `expires_in` выданного токена не больше 60

### Requirement: Выданный токен не регистрируется
Выданный обменом JWT SHALL NOT регистрироваться как активный access-токен
google-auth и SHALL NOT приниматься ручками `/auth/*`.

#### Scenario: Токен обмена на /auth/me
- **WHEN** `GET /auth/me` с JWT, выданным обменом
- **THEN** ответ `401` `{"error":"unauthenticated"}`

### Requirement: Журнал и метрики обмена
Каждый обмен SHALL учитываться в `token_exchange_total{actor,result}`
(`result`: `ok`, `invalid_client`, `invalid_grant`, `invalid_target`,
`invalid_scope`, `invalid_request`, `unavailable`). В журнал попадают actor,
`sub`, `audience` и исход. Токены и секреты в журнал SHALL NOT попадать,
тело запроса маскируется.

#### Scenario: Успешный обмен в журнале
- **WHEN** wallet-ai успешно меняет токен
- **THEN** в журнале есть запись с `actor` `wallet-ai`, `sub`, `audience` `wallet-mcp`, `result` `ok`, а значения `subject_token` и `access_token` отсутствуют
