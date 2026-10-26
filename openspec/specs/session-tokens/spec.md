# session-tokens Specification

## Purpose

Своя сессия поверх разовой проверки Google: короткий access-JWT, который
другие сервисы проверяют сами по JWKS, и долгий непрозрачный refresh-токен,
который обменивается только здесь. Плюс ручки самого пользователя
(`/auth/me`) и роли.

## Requirements

### Requirement: Access-токен
Access-токен SHALL быть JWT RS256 с `kid` в заголовке и claim'ами `sub` (id
пользователя), `email`, `name`, `role` (`user`/`support`/`admin`), `iat`,
`exp` (`iat` + `ACCESS_TOKEN_TTL_SECS`, по умолчанию 900), `iss` =
`google-auth`, `aud` = `["wallet-api", "wallet-report", "google-auth",
"wallet-ai"]`, `scope` = `wallet:read wallet:write reports:read account
ai:use`. Если у сессии есть `device_id`, токен SHALL также нести `device_id` и
`platform`. Аватар в токен SHALL NOT попадать.

#### Scenario: Вход из браузера
- **WHEN** пользователь вошёл через Google в браузере
- **THEN** access-токен несёт `device_id` (UUID этого входа) и `platform: "web"`

### Requirement: Refresh-токен
Refresh-токен SHALL быть base64url от 32 случайных байт. Сервис SHALL хранить
только его SHA-256-хэш вместе с пользователем, устройством и хэшем парного
access-токена, со сроком `REFRESH_TOKEN_TTL_SECS` (по умолчанию 30 дней).
Хэш access-токена SHALL храниться со сроком жизни access-токена.

#### Scenario: Дамп хранилища
- **WHEN** кто-то читает хранилище сессий
- **THEN** готовых к предъявлению refresh- или access-токенов там нет, только хэши

### Requirement: Cookie сессии
Браузерный вход и обмен refresh SHALL выставлять два `Set-Cookie`:
`session=<access>; Path=/; HttpOnly; SameSite=Lax` без `Max-Age` и
`refresh_token=<refresh>; Path=/auth; HttpOnly; SameSite=Lax;
Max-Age=<REFRESH_TOKEN_TTL_SECS>`; при `COOKIE_SECURE=true` к обоим
добавляется `; Secure`. Сброс cookie SHALL выставлять те же имена и пути с
пустым значением и `Max-Age=0`.

#### Scenario: Запрос к API из браузера
- **WHEN** браузер обращается к `/api/*`
- **THEN** он шлёт cookie `session`, но не `refresh_token` (её путь — `/auth`)

### Requirement: Публикация ключа
`GET /.well-known/jwks.json` SHALL без аутентификации отдавать
`{"keys": [{"kty":"RSA","kid","use":"sig","alg":"RS256","n","e"}]}` с
публичной частью ключа из `JWT_RSA_PRIVATE_KEY_PATH`.

#### Scenario: Гейтвей проверяет токен
- **WHEN** сервис-потребитель встречает access-токен с этим `kid`
- **THEN** он проверяет подпись по `n`/`e` из JWKS, не обращаясь к google-auth за каждым запросом

### Requirement: Проверка токена на ручках google-auth
Ручки google-auth, требующие пользователя, SHALL брать токен из
`Authorization: Bearer <токен>`, иначе из cookie `session`, и принимать его,
только если подпись RS256 верна собственным ключом, `exp` не истёк, `iss` =
`google-auth`, `aud` содержит `google-auth`, `scope` содержит `account`, и
токен не отозван. Иначе ручка SHALL отвечать `401`
`{"error":"unauthenticated"}`.

#### Scenario: Токен Telegram-бота
- **WHEN** на `GET /auth/me` приходит токен бота (без `google-auth` в `aud`)
- **THEN** ответ `401`, метрика `jwt_claims_total` растёт с причиной отказа, в журнале строка `event=jwt_rejected`

#### Scenario: После logout
- **WHEN** access-токен отозван через `/auth/logout`, но `exp` ещё не наступил
- **THEN** ручки google-auth отвечают `401`, а сервисы, проверяющие по JWKS, продолжают принимать токен до `exp`

### Requirement: Обмен refresh-токена
`POST /auth/refresh` SHALL брать refresh-токен из cookie `refresh_token`, а
если её нет — из JSON-поля `refresh_token`, атомарно гасить его и выпускать
новую пару для того же пользователя и устройства (браузерной сессии без
`device_id` он выдаётся сейчас): новые cookie и тело `{"access_token",
"expires_in"}`. Если токен пришёл в теле, а не в cookie, тело SHALL содержать
и `refresh_token`.

#### Scenario: Мобильный клиент
- **WHEN** приложение шлёт `{"refresh_token": "..."}` без cookie
- **THEN** ответ содержит новый `refresh_token`, старый больше не принимается

#### Scenario: Без токена
- **WHEN** нет ни cookie, ни поля в теле
- **THEN** ответ `400` `text/plain` «refresh_token не передан (cookie refresh_token или JSON-поле refresh_token)»

#### Scenario: Повтор украденной копии
- **WHEN** тот же refresh-токен предъявлен второй раз
- **THEN** ответ `401` `text/plain` «refresh-токен недействителен, истёк или уже использован — войдите заново через /auth/google» со сбросом обеих cookie

### Requirement: Выход
`POST /auth/logout` SHALL отзывать access-токен запроса (Bearer или cookie
`session`) и refresh-токен (cookie `refresh_token` или JSON-поле), если они
есть, сбрасывать cookie и всегда отвечать `204`.

#### Scenario: Выход без токенов
- **WHEN** `POST /auth/logout` без cookie и тела
- **THEN** ответ `204` со сбросом обеих cookie

### Requirement: Текущий пользователь
`GET /auth/me` SHALL для принятого токена отвечать `200` `{"id", "email",
"name", "picture", "role"}`: `id`, `email`, `name`, `role` — из токена,
`picture` — из учётной записи (пустая строка, если записи уже нет).

#### Scenario: SPA проверяет вход
- **WHEN** wallet-web вызывает `GET /auth/me` с cookie `session`
- **THEN** получает профиль; без cookie — `401` `{"error":"unauthenticated"}`

### Requirement: Удаление аккаунта
`DELETE /auth/me` SHALL отозвать все access- и refresh-токены пользователя,
затем удалить учётную запись вместе с её связками Telegram, сбросить cookie и
ответить `204`. Данные в wallet-api эта ручка не трогает.

#### Scenario: Пользователь удаляет аккаунт
- **WHEN** `DELETE /auth/me` с действующим токеном
- **THEN** ответ `204`, все его сессии больше не обмениваются, следующий вход через Google снова попросит подтвердить регистрацию

### Requirement: Роли
Роль SHALL назначаться только при создании учётной записи: `admin`, если email
(без учёта регистра) есть в `ADMIN_EMAILS`, иначе `support`, если в
`SUPPORT_EMAILS`, иначе `user`; при `email_verified=false` — всегда `user`.
Повторный вход SHALL NOT менять роль.

#### Scenario: Email добавлен в ADMIN_EMAILS позже
- **WHEN** уже заведённый пользователь входит после добавления его email в `ADMIN_EMAILS`
- **THEN** его роль остаётся прежней
