# Spec Delta

## Purpose

Связывание Telegram-чата с пользователем для бота wallet-telegram: веб
выдаёт одноразовый код, бот обменивает его на связку и по связке получает
короткий урезанный токен на каждую команду. Доступ бота к пользователю —
это наличие связки.

## ADDED Requirements

### Requirement: Код связывания
`POST /auth/telegram/link-code` SHALL для принятого токена (см.
`session-tokens`) отвечать `200` `{"code", "deep_link", "expires_in"}`: `code`
— base64url от 24 случайных байт (32 символа), `deep_link` —
`https://t.me/<TELEGRAM_BOT_USERNAME без @>?start=<code>`, `expires_in` —
`TELEGRAM_LINK_CODE_TTL_SECS` (по умолчанию 600). Код SHALL храниться только
хэшем и быть одноразовым. Без `TELEGRAM_BOT_USERNAME` — `503` `{"error":"Telegram-бот не настроен (TELEGRAM_BOT_USERNAME)"}`.

#### Scenario: Подключение бота из веба
- **WHEN** залогиненный пользователь запрашивает код
- **THEN** получает ссылку `t.me/...?start=<code>`, действующую 10 минут

### Requirement: Аутентификация бота
Ручки `/internal/telegram/*` SHALL требовать заголовок `X-Service-Secret`,
равный `TELEGRAM_SERVICE_SECRET` (сравнение за постоянное время). Без
настроенного секрета они SHALL отвечать `503` `{"error":"Telegram-бот
выключен (TELEGRAM_SERVICE_SECRET)"}`, при неверном секрете — `401`
`{"error":"неверный X-Service-Secret"}`. wallet-gateway `/internal/*` не
проксирует.

#### Scenario: Пустой заголовок при пустом секрете
- **WHEN** секрет не задан и запрос пришёл без `X-Service-Secret`
- **THEN** ответ `503`, а не успех

### Requirement: Идентификатор Telegram-пользователя
`tg_user_id` SHALL приниматься JSON-числом или строкой из 1–20 цифр без
ведущего нуля; другое значение считается отсутствующим.

#### Scenario: Ведущий ноль
- **WHEN** `tg_user_id` = `"007"`
- **THEN** значение отклоняется как некорректное

### Requirement: Обмен кода на связку
`POST /internal/telegram/exchange` `{"code", "tg_user_id", "tg_username"?}`
SHALL однократно погасить код, записать связку `tg_user_id` → пользователь с
`device_id`, детерминированно вычисленным из пары (id пользователя,
`tg_user_id`) в формате UUID, и ответить `200` `{"user_id", "device_id"}`.
Повторное связывание того же `tg_user_id` SHALL заменять прежнюю связку, в
том числе с другим пользователем; сессии устройства бота, оставшиеся от
прежней схемы, у обоих пользователей SHALL отзываться.

#### Scenario: Пользователь жмёт Start
- **WHEN** бот обменивает свежий код
- **THEN** связка записана, ответ содержит `user_id` и `device_id`

#### Scenario: Некорректное тело
- **WHEN** тело не JSON или в нём нет `code` или корректного `tg_user_id`
- **THEN** ответ `400` `invalid JSON body` или `нужны code и tg_user_id (положительное целое)`

#### Scenario: Тот же код второй раз
- **WHEN** код обменивается повторно или истёк
- **THEN** ответ `410` `код связывания истёк или уже использован`

#### Scenario: Пользователь удалён до обмена
- **WHEN** владелец кода удалил аккаунт до того, как бот обменял код
- **THEN** ответ `410` `пользователь кода связывания больше не существует`

### Requirement: Токен бота на команду
`POST /internal/telegram/token` `{"tg_user_id"}` SHALL по связке выпускать
JWT RS256 с `sub` (id пользователя), `iat`, `exp` (`iat` + 300), `device_id`
связки, `platform` = `telegram`, `iss` = `google-auth`, `aud` =
`["wallet-report", "wallet-api", "wallet-ai"]`, `scope` = `reports:read
expense:write ai:use` и отвечать `200` `{"access_token", "expires_in": 300,
"user_id", "device_id"}`. Токен SHALL NOT регистрироваться как активный
access-токен google-auth.

#### Scenario: Команда пользователя
- **WHEN** бот запрашивает токен для связанного чата
- **THEN** получает токен на 5 минут, которым нельзя вызвать ручки google-auth

#### Scenario: Некорректный tg_user_id
- **WHEN** тело не JSON или `tg_user_id` некорректен
- **THEN** ответ `400` `нужен tg_user_id (положительное целое)`

#### Scenario: Связка удалена из веба
- **WHEN** пользователь отключил бота, и бот запрашивает токен
- **THEN** ответ `404` `Telegram-аккаунт не связан с кошельком`

### Requirement: Связки в вебе
`GET /auth/telegram/links` SHALL для принятого токена отвечать `200`
`{"links": [{"tg_user_id", "tg_username", "name", "created_at"}]}`, где `name`
— `Telegram @<username>` (не длиннее 64 символов) или `Telegram <tg_user_id>`.
`DELETE /auth/telegram/links/{tg_user_id}` SHALL удалять только свою связку
и отвечать `204`; чужая, несуществующая или некорректная — `404` `нет такой
связки`.

#### Scenario: Отключить бота
- **WHEN** пользователь удаляет свою связку
- **THEN** ответ `204`, следующий запрос токена ботом — `404`

### Requirement: Отключение из бота
`DELETE /internal/telegram/links/{tg_user_id}` SHALL удалять связку этого
Telegram-аккаунта и отвечать `204`; некорректный `tg_user_id` — `400`
`tg_user_id — положительное целое`; связки нет — `404` `нет такой связки`.

#### Scenario: /unlink в боте
- **WHEN** бот вызывает отключение для связанного чата
- **THEN** ответ `204`, связка исчезает из `GET /auth/telegram/links`
