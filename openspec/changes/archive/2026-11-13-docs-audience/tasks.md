# Tasks

## 1. Состав токена

- [x] 1.1 Добавить `wallet-docs` в `aud` и `docs:ask` в `scope` пользовательского access-токена (вход из браузера, вход Android, обмен refresh). Токены бота и обмена не менять. Проверка: юнит-тест (`ctest`) проверяет `aud`/`scope` пользовательского токена и их отсутствие у токенов бота и обмена.
- [x] 1.2 Найти потребителей `aud`: `grep -rn "aud" wallet-api wallet-report wallet-ai wallet-mcp --include=*.cpp` (без `build/`). Проверка: ни один не сравнивает `aud` на равенство целиком; список записан в заметках к выкату.
- [x] 1.3 (2026-11-13: токен с test — `aud` содержит `wallet-docs`, `scope` содержит `docs:ask`; `/auth/me`, `/api/reports/accounts`, `/api/ai/status` через гейтвей `:8091` — 200 и по Bearer, и по cookie) Проверить на живом стеке: войти в test, декодировать access-токен (без вывода подписи в логи). Проверка: в `aud` есть `wallet-docs`, в `scope` — `docs:ask`; `GET /auth/me`, `GET /api/reports/accounts` и `GET /api/ai/status` через гейтвей отвечают 200 как раньше.

## 2. Документация

- [x] 2.1 Обновить `openapi.yaml` (описание claim'ов, если есть) и `README.md` (состав токена). Проверка: README описывает `wallet-docs` и `docs:ask`; Swagger UI открывается.

## Workflow follow-up

- Выкатить первым из трёх (google-auth → wallet-docs → wallet-gateway), затем архивировать change.
