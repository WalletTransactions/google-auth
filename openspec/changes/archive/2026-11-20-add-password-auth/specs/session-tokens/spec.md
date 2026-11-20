# Spec Delta

## MODIFIED Requirements

### Requirement: Access-токен
Access-токен SHALL быть JWT RS256 с `kid` в заголовке и claim'ами `sub` (id
пользователя), `email`, `name`, `role` (`user`/`support`/`admin`), `iat`,
`exp` (`iat` + `ACCESS_TOKEN_TTL_SECS`, по умолчанию 900), `iss` =
`google-auth`, `aud` = `["wallet-api", "wallet-report", "google-auth",
"wallet-ai", "wallet-docs"]`, `scope` = `wallet:read wallet:write reports:read account
ai:use docs:ask`. Если у сессии есть `device_id`, токен SHALL также нести `device_id` и
`platform`. Аватар в токен SHALL NOT попадать. Токен SHALL выпускаться одинаково
после входа через Google и после входа по паролю; способ входа в claim'ах не отражается.

#### Scenario: Вход из браузера
- **WHEN** пользователь вошёл через Google в браузере
- **THEN** access-токен несёт `device_id` (UUID этого входа) и `platform: "web"`

#### Scenario: Вход по паролю из браузера
- **WHEN** пользователь вошёл через `POST /auth/login` без `platform`
- **THEN** access-токен несёт `device_id` (UUID этого входа) и `platform: "web"`, набор `aud` и `scope` тот же, что после Google

#### Scenario: Вход по паролю с телефона
- **WHEN** пользователь вошёл через `POST /auth/login` с `platform: "android"` и своим `device_id`
- **THEN** access-токен несёт этот `device_id` и `platform: "android"`

#### Scenario: Адресат документации
- **WHEN** пользователь вошёл любым способом (браузер или Android) и получил access-токен
- **THEN** в `aud` есть `wallet-docs`, а в `scope` есть `docs:ask`

#### Scenario: Токен бота и обмена
- **WHEN** выпущен токен для Telegram-бота или токен обменом для wallet-mcp или wallet-report
- **THEN** в его `aud` нет `wallet-docs`, а в `scope` нет `docs:ask`

### Requirement: Роли
Роль SHALL назначаться только при создании учётной записи: `admin`, если email
(без учёта регистра) есть в `ADMIN_EMAILS`, иначе `support`, если в
`SUPPORT_EMAILS`, иначе `user`; при `email_verified=false` — всегда `user`.
Учётная запись, созданная регистрацией по паролю, всегда создаётся с
`email_verified=false`, поэтому её роль всегда `user`. Повторный вход и
привязка Google к такой записи SHALL NOT менять роль.

#### Scenario: Email добавлен в ADMIN_EMAILS позже
- **WHEN** уже заведённый пользователь входит после добавления его email в `ADMIN_EMAILS`
- **THEN** его роль остаётся прежней

#### Scenario: Регистрация по паролю с email админа
- **WHEN** по паролю регистрируется email из `ADMIN_EMAILS`
- **THEN** создаётся пользователь с ролью `user`

#### Scenario: Google забрал парольный аккаунт
- **WHEN** владелец email из `ADMIN_EMAILS` входит через Google и забирает свою неподтверждённую парольную запись
- **THEN** роль записи остаётся `user` и автоматически не повышается
