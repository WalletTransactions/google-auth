# mcp-tokens Specification

## Purpose
Персональный MCP-токен: пользователь выпускает его сам, чтобы MCP-клиент
(LM Studio, Claude Code и др.) читал его кошелёк через `wallet-mcp`. Здесь же
описаны скользящий срок токена с потолком и обмен на короткий read-only JWT.

## Requirements

### Requirement: Выпуск MCP-токена
`POST /auth/mcp-tokens` SHALL для принятого токена (см. `session-tokens`,
«Проверка токена на ручках google-auth») с телом `{"name"}` выпускать токен
`wmcp_<base64url от 32 случайных байт>` с новым `device_id` (UUID) и отвечать
`201` `{"token", "device_id", "name", "expires_at"}`. `name` перед проверкой
обрезается по краям и должен содержать от 1 до 64 символов.

#### Scenario: Выпуск из браузера
- **WHEN** вошедший пользователь шлёт `POST /auth/mcp-tokens` `{"name": " LM Studio дома "}` с cookie `session`
- **THEN** ответ `201`, `token` начинается с `wmcp_`, `name` = `LM Studio дома`, `expires_at` — момент через 30 дней (ISO 8601 UTC)

#### Scenario: Без токена пользователя
- **WHEN** `POST /auth/mcp-tokens` без cookie и без `Authorization`
- **THEN** ответ `401` `{"error":"unauthenticated"}`

#### Scenario: Токен бота или MCP-обмена
- **WHEN** запрос несёт JWT без `google-auth` в `aud` (токен бота или полученный обменом MCP-токена)
- **THEN** ответ `401` `{"error":"unauthenticated"}`, токен не выпускается

#### Scenario: Некорректное имя
- **WHEN** тело не JSON, `name` отсутствует, пуст после обрезки или длиннее 64 символов
- **THEN** ответ `400` `{"error":"нужно имя токена — от 1 до 64 символов"}`

### Requirement: Токен показывается один раз
Сервис SHALL хранить только SHA-256-хэш MCP-токена вместе с пользователем,
`device_id`, именем, моментом выпуска и моментом последнего использования.
Сам токен SHALL возвращаться только в ответе на выпуск, и никакая ручка не
отдаёт его повторно.

#### Scenario: Дамп хранилища
- **WHEN** кто-то читает хранилище сессий
- **THEN** готовых к предъявлению MCP-токенов там нет, только их хэши

#### Scenario: Список устройств
- **WHEN** пользователь запрашивает `GET /auth/devices` после выпуска
- **THEN** MCP-токен виден как сессия, но значения `wmcp_…` в ответе нет

### Requirement: Лимит MCP-токенов
У пользователя SHALL быть не больше 10 активных MCP-токенов. Выпуск сверх
лимита SHALL отклоняться ответом `409` `{"error":"слишком много MCP-токенов —
отзовите ненужные в «Моих устройствах» (максимум 10)"}`. Отозванные и
истёкшие токены в лимит не входят.

#### Scenario: Одиннадцатый токен
- **WHEN** у пользователя 10 активных MCP-токенов, и он выпускает ещё один
- **THEN** ответ `409` с этим текстом, новый токен не создаётся

#### Scenario: Место освободилось
- **WHEN** пользователь отозвал один из 10 токенов и выпускает новый
- **THEN** ответ `201`

### Requirement: Скользящий срок с потолком
MCP-токен SHALL переставать действовать через 30 дней без успешного обмена
и в любом случае через 90 дней после выпуска. Каждый успешный обмен SHALL
переносить срок на `min(момент обмена + 30 дней, выпуск + 90 дней)`.
Продлить токен за потолок нельзя, нужно выпустить новый.

#### Scenario: Забытый токен
- **WHEN** токен не обменивался 30 дней
- **THEN** следующий обмен получает `401` `{"error":"invalid_token"}`

#### Scenario: Активный токен у потолка
- **WHEN** токен обменивается каждый день, и с выпуска прошло 90 дней
- **THEN** обмен получает `401` `{"error":"invalid_token"}`, хотя последний обмен был вчера

#### Scenario: Продление
- **WHEN** токен на 10-й день после выпуска успешно обменян
- **THEN** его `expires_at` в `GET /auth/devices` — 40-й день после выпуска

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

### Requirement: JWT обмена без роли и без регистрации
JWT, выпущенный обменом MCP-токена, SHALL NOT содержать claim'ов `role`,
`email` и `name` и SHALL NOT регистрироваться как активный access-токен
google-auth. Поэтому потребители видят обычного пользователя, и админские
возможности (`as_user_id` в wallet-report) через MCP недоступны даже
администратору.

#### Scenario: MCP-токен администратора
- **WHEN** администратор обменивает свой MCP-токен и запрашивает отчёт wallet-report с `as_user_id` другого пользователя
- **THEN** wallet-report не считает его администратором, чужие данные не отдаются

### Requirement: Отказ обмена
`POST /internal/mcp/token` SHALL отвечать `401` `{"error":"invalid_token"}`
одинаково для всех недействующих токенов: неизвестного, отозванного,
истёкшего, без префикса `wmcp_`, неверной длины, а также если тело не JSON
или поле `token` отсутствует. Ответ SHALL NOT различать эти причины.

#### Scenario: Отозванный токен
- **WHEN** пользователь отозвал MCP-сессию в «Моих устройствах», и wallet-mcp обменивает этот токен
- **THEN** ответ `401` `{"error":"invalid_token"}`

#### Scenario: Мусор вместо токена
- **WHEN** тело `{"token": "abc"}` или не JSON
- **THEN** ответ `401` `{"error":"invalid_token"}`

#### Scenario: Refresh-токен вместо MCP-токена
- **WHEN** на обмен приходит действующий refresh-токен пользователя
- **THEN** ответ `401` `{"error":"invalid_token"}`, refresh-токен не тратится

### Requirement: MCP-токен не обменивается как refresh
`POST /auth/refresh` SHALL NOT принимать MCP-токен: предъявленный в cookie
или в теле, он обрабатывается как недействительный refresh-токен, и
MCP-токен при этом не гасится.

#### Scenario: Попытка получить полную сессию
- **WHEN** на `POST /auth/refresh` приходит `{"refresh_token": "wmcp_…"}` с действующим MCP-токеном
- **THEN** ответ `401` «refresh-токен недействителен, истёк или уже использован — войдите заново через /auth/google», MCP-токен продолжает обмениваться

### Requirement: Отзыв вместе со всеми сессиями пользователя
MCP-токены пользователя SHALL отзываться вместе с остальными его токенами
при удалении аккаунта (`DELETE /auth/me`) и при принудительном выходе
(`POST /admin/users/{id}/logout`).

#### Scenario: Удаление аккаунта
- **WHEN** пользователь с двумя MCP-токенами вызывает `DELETE /auth/me`
- **THEN** оба токена при обмене получают `401` `{"error":"invalid_token"}`

#### Scenario: Принудительный выход
- **WHEN** администратор разлогинивает пользователя
- **THEN** его MCP-токены перестают обмениваться

### Requirement: Журнал и метрики MCP-токенов
Сервис SHALL считать выпуски в `mcp_tokens_issued_total` и обмены в
`mcp_token_exchanges_total{result}` (`ok`, `invalid`). Журнал SHALL NOT
содержать сам MCP-токен и выпущенный JWT. Успешный обмен пишет `user_id` и
`device_id`, отказ пишет событие `mcp_token_rejected` без хэша токена.

#### Scenario: Отказ обмена
- **WHEN** обмен отклонён
- **THEN** `mcp_token_exchanges_total{result="invalid"}` растёт, в журнале `event=mcp_token_rejected` без токена и его хэша
