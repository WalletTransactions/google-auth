## Why

Сейчас войти в стек можно только через Google. Нужен способ входа без
Google: логин (email) и пароль, которые хранятся и проверяются на
серверной части. Google остаётся дополнительной опцией, а какие способы
включены — задаёт конфигурация сервиса (это же упрощает миграцию и служит
аварийным выключателем).

## What Changes

- Новые ручки `POST /auth/register`, `POST /auth/login`, `POST /auth/password`
  (установка и смена пароля залогиненным пользователем), сброс пароля админом и
  `GET /auth/methods` (какие способы входа и регистрация включены — по нему
  клиенты выбирают кнопки).
- `redirect_uri` Google строится со схемой из `X-Forwarded-Proto` (https за TLS).
- Пароль хранится только как соль + хэш (PBKDF2-HMAC-SHA256 на OpenSSL),
  в Postgres, отдельной таблицей учётных данных.
- Конфигурация сервиса: `AUTH_METHODS=password|google|both` (какие способы входа
  включены), `REGISTRATION=open|closed` (самостоятельная регистрация),
  `ALLOW_INSECURE_AUTH` (принимать пароль по HTTP, по умолчанию выключено).
- Регистрация открытая, без подтверждения email (SMTP — отдельный change позже).
  Аккаунт с паролем создаётся с `email_verified=false`, поэтому всегда получает
  роль `user`.
- Защита от перебора: лимиты попыток по email и по IP (Redis), `429`, одинаковый
  ответ на «нет такого email» и «неверный пароль», регистрация не раскрывает,
  занят ли email. Пароли не попадают в журнал.
- Вход через Google с тем же email, что у **неподтверждённого** парольного
  аккаунта, забирает этот аккаунт: Google подтверждает владение почтой, пароль
  сбрасывается, сессии отзываются.
- `GET /auth/google` и `POST /auth/google/mobile` отвечают отказом при
  `AUTH_METHODS=password`; `/auth/login` и `/auth/register` — при `AUTH_METHODS=google`.
- Пароль принимается только по HTTPS (по `X-Forwarded-Proto`), если не включён
  `ALLOW_INSECURE_AUTH`.
- Выпуск access/refresh после входа по паролю — тот же, что для Google
  (JWT, `device_id`, `platform`, cookie для web, тело для Android).
- Другие сервисы затрагиваются отдельными change: wallet-gateway, wallet-web,
  android-wallet (экраны, `network_security_config`), wallet-infra (TLS, `COOKIE_SECURE`).
  claim'ы токена и wallet-api не меняются.

## Capabilities

### New Capabilities
- `password-auth`: вход и регистрация по email и паролю, хранение учётных данных,
  защита от перебора, режимы `AUTH_METHODS`/`REGISTRATION`, установка и сброс пароля.

### Modified Capabilities
- `browser-sign-in`: кнопка и `GET /auth/google` зависят от `AUTH_METHODS`;
  Google-вход забирает неподтверждённый парольный аккаунт с тем же email;
  `redirect_uri` получает схему из `X-Forwarded-Proto`.
- `session-tokens`: сессия выпускается и после входа по паролю; роль парольного
  аккаунта всегда `user`.

## Impact

- **google-auth**: миграция `000005` (таблица учётных данных, `users.google_sub`
  допускает NULL), новый модуль паролей и лимитов, правки `auth.cpp`, `repo.cpp`,
  `main.cpp`, `openapi.yaml`, README, `.env`.
- **wallet-infra**: TLS (reverse proxy), `COOKIE_SECURE=true`, новые переменные
  окружения — отдельный change, выкатывается первым.
- **wallet-gateway**: новые пути уже проксируются (`/auth/*`), тела `/auth/*` в
  журнал не пишутся никогда; нужно только надёжно передавать `X-Forwarded-Proto` и
  `X-Forwarded-For` (отдельный change).
- **wallet-web**, **android-wallet**: формы входа и регистрации.
- **Зависимости**: новых библиотек нет (OpenSSL, libpq, Redis уже используются).
