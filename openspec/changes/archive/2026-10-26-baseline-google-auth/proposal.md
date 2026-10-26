# Proposal: базовая спецификация google-auth

## Why

google-auth выпускает токены, по которым работают все остальные сервисы стека:
веб, телефон и Telegram-бот входят через него, wallet-gateway, wallet-api,
wallet-report и wallet-ai проверяют подпись по его JWKS. Поведение сервиса
(какие claim'ы и `aud` у токенов, как ротируется refresh, что считается
«текущей» сессией, кто и как получает токен бота) описано только в
комментариях `src/`, в `README.md` на ~1000 строк и в `openapi.yaml`. README
уже местами разошёлся с кодом (бот больше не получает пару токенов, страницы
успеха с кнопками-самотестами нет, `db` — пул, а не одно соединение).
Следующие изменения сервиса (например, client assertion вместо общего
секрета, `org/docs/TODO_service_auth_tls.md`) должны идти дельтой к явной
спецификации, поэтому сначала фиксируем текущее поведение как базу, не меняя
код.

## What Changes

- В репозитории появляется OpenSpec: `openspec/config.yaml` (контекст и
  правила на русском) и `.claude/` с командами `/opsx:*` от `openspec init`.
- Восстанавливается спецификация **текущего** поведения по `src/`,
  `migrations/`, `CMakeLists.txt`, `Containerfile`, `.env.example`, CI,
  `openapi.yaml` и `README.md`; общие `jwt`/`jwt_claims`/`log`/`metrics` из
  `third_party/wallet-common/` — в той мере, в какой их видно снаружи.
- Клиенты и потребители токенов (wallet-gateway, wallet-api, wallet-report,
  wallet-ai, wallet-web, android-wallet, wallet-telegram) описываются только
  через то, что google-auth им отдаёт; их поведение остаётся в их спецификациях.
- Решения из README и комментариев (подтверждение регистрации вместо
  автосоздания, отзыв только внутри google-auth, связка refresh↔access,
  схлопывание по `device_id`, токен бота без `aud: google-auth`) переносятся в
  `design.md`.
- Расхождения README, `openapi.yaml`, комментариев и кода записываются в
  `design.md` как наблюдения; требованиями они не становятся и в этом
  изменении не исправляются.
- Код, конфигурация и поведение **не меняются**.

## Capabilities

### New Capabilities

- `browser-sign-in`: стартовая страница, `GET /auth/google` (PKCE + CSRF
  `state`), выбор `redirect_uri` по `Host`/`X-Forwarded-Host`, callback с
  проверкой `id_token`, подтверждение регистрации, HTML-страницы ошибок.
- `mobile-sign-in`: `POST /auth/nonce` и `POST /auth/google/mobile` —
  одноразовый nonce, обязательный `device_id`, белый список `platform`,
  регистрация без подтверждения.
- `session-tokens`: пара access/refresh, claim'ы access-JWT (`iss`, `aud`,
  `scope`, `role`, `device_id`), cookie, JWKS, `/auth/refresh`,
  `/auth/logout`, проверка токена на ручках самого сервиса, `GET`/`DELETE
  /auth/me`, роли из `ADMIN_EMAILS`/`SUPPORT_EMAILS`.
- `device-sessions`: `GET /auth/devices`, отзыв одной сессии и всех, кроме
  текущей; одна активная сессия на `(user, device_id)`.
- `telegram-linking`: код связывания и deep link, обмен кода ботом, токен бота
  на команду, список и отключение связок из веба и из бота, `X-Service-Secret`.
- `admin-users`: `GET /admin/users` и принудительный logout пользователя.
- `service-ops`: `/healthz`, `/version`, `/metrics`, `/docs`,
  `/openapi.yaml`, журнал запросов и сокрытие секретных тел, настройки
  запуска и проверки при старте, схема БД, образ и CI.

### Modified Capabilities

<!-- Нет: в openspec/specs/ пока нет ни одной спецификации. -->

## Impact

- Новые файлы только в `openspec/` и `.claude/` (от `openspec init`).
- Код, `openapi.yaml`, `README.md`, миграции, `Containerfile`, CI — без
  изменений.
- Другие репозитории не затрагиваются.
