# Spec Delta

## MODIFIED Requirements

### Requirement: Access-токен
Access-токен SHALL быть JWT RS256 с `kid` в заголовке и claim'ами `sub` (id
пользователя), `email`, `name`, `role` (`user`/`support`/`admin`), `iat`,
`exp` (`iat` + `ACCESS_TOKEN_TTL_SECS`, по умолчанию 900), `iss` =
`google-auth`, `aud` = `["wallet-api", "wallet-report", "google-auth",
"wallet-ai", "wallet-docs"]`, `scope` = `wallet:read wallet:write reports:read account
ai:use docs:ask`. Если у сессии есть `device_id`, токен SHALL также нести `device_id` и
`platform`. Аватар в токен SHALL NOT попадать.

#### Scenario: Вход из браузера
- **WHEN** пользователь вошёл через Google в браузере
- **THEN** access-токен несёт `device_id` (UUID этого входа) и `platform: "web"`

#### Scenario: Адресат документации
- **WHEN** пользователь вошёл любым способом (браузер или Android) и получил access-токен
- **THEN** в `aud` есть `wallet-docs`, а в `scope` есть `docs:ask`

#### Scenario: Токен бота и обмена
- **WHEN** выпущен токен для Telegram-бота или токен обменом для wallet-mcp или wallet-report
- **THEN** в его `aud` нет `wallet-docs`, а в `scope` нет `docs:ask`
