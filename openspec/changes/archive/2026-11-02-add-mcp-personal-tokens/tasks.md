# Tasks

«Изолированный стенд» в итогах ниже — образ ветки (`Containerfile`,
`BUILD_JOBS=3`), свой одноразовый Redis 7 и временная база `ga_mcp_it` на
`wallet-test-db-1` (миграции 000001–000004, тестовые пользователи). Контуры
test/prod при проверке не затронуты; curl — прямо в порт сервиса.

## 1. Клиент Redis и claims

- [x] 1.1 `redis::Client`: `set_exat(key, value, epoch)`, `set_xx_exat(key, value, epoch) -> bool` (nil-ответ на `XX` → `false`) и `ttl(key) -> optional<int64>` (`-2` → nullopt). Проверка: на живом стеке `docker exec` `redis-cli` — `SET … XX EXAT` на несуществующий ключ не создаёт его, `ctest` собирается
  Итог: вместо `ttl()` сделан `expiretime(key) -> optional<int64>` (`EXPIRETIME`, Redis ≥ 7.0; `-2` → nullopt): `expires_at` = абсолютный момент ключа, не «дрожит» на секунду между просмотрами, как `now + TTL` (сценарий «Просмотр не продлевает MCP-токен»). На стенде `SET it:xx v XX EXAT …` → nil, `EXISTS` = 0; `ctest` зелёный.
- [x] 1.2 `token_claims.hpp`: `kScopeMcp`, `mcp_audience()`, `kMcpTokenTtlSecs = 300`, `add_mcp_claims()` (D4). Юнит-тест в `tests/test_token_claims.cpp`: `aud == ["wallet-report"]`, `scope == "reports:read"`, нет `role`/`email`/`name`. Проверка: `ctest` зелёный
  Итог: `add_mcp_claims` к тому же стирает `role`/`email`/`name`, если их положили по ошибке; два теста, `ctest` зелёный.

## 2. Хранилище MCP-токенов (repo)

- [x] 2.1 `repo`: `store_mcp_token`, `find_mcp_token`, `touch_mcp_token` (SET XX EXAT `min(now+30д, cap_at)`, `last_used_at=now`), индекс `user_mcp_tokens:<id>` с `EXPIRE 90д` (D1, D2). Чистые функции расчёта срока (`next_expiry(now, cap_at)`) — в `detail::`, юнит-тест на скольжение, потолок и `now ≥ cap_at`. Проверка: `ctest`
  Итог: `repo::detail::next_mcp_expiry`, `mcp_record_to_json/from_json`, плюс `revoke_mcp_token`; тесты в `tests/test_mcp_tokens.cpp` (10-й день → 40-й, 70-й → потолок, `now ≥ cap_at` → nullopt), `ctest` зелёный.
- [x] 2.2 `SessionSummary`: `kind`, `last_used_at`, `expires_at`. `list_user_sessions` читает оба индекса, `expires_at` берёт из `TTL`. `store_refresh_token` пишет `issued_at` (D5). Проверка: curl `GET /auth/devices` на живом стеке — у новой браузерной сессии заполнены `last_used_at`/`expires_at`, у старой `last_used_at: null`
  Итог: `expires_at` — из `EXPIRETIME` (см. 1.1). Изолированный стенд: новая сессия — `last_used_at` ≈ сейчас, `expires_at` ≈ +30 дней; запись старого формата — `last_used_at: null`, `expires_at` из остатка срока.
- [x] 2.3 `revoke_user_sessions_if` удаляет MCP-ключи по `kind`, `revoke_all_user_tokens` чистит `user_mcp_tokens:<id>` (D5). Проверка покрывается в 3.4 и 4.3
  Итог: проверено в 4.3. Схлопывание по `device_id` в `auth::issue_tokens` ограничено `kind == Refresh` (device_id мобильного входа задаёт клиент).

## 3. Выпуск: `POST /auth/mcp-tokens`

- [x] 3.1 Модуль `mcp_tokens.cpp/.hpp`: `detail::normalize_name` (обрезка, 1..64 символа) и `detail::is_well_formed_token` (префикс `wmcp_` и 43 символа base64url) с юнит-тестами `tests/test_mcp_tokens.cpp`. Проверка: `ctest`
  Итог: длина считается в символах UTF-8 (64 «ж» — можно, 65 — нет); `ctest` зелёный (106 тестов).
- [x] 3.2 Ручка выпуска: `auth::authenticate`, разбор тела, лимит 10 → `409` с текстом из спеки, `uuidgen::v4()` для `device_id`, `201 {"token","device_id","name","expires_at"}`, метрика `mcp_tokens_issued_total`, журнал `mcp_token_issued`. Проверка: curl с cookie `session` — `201`. Без токена — `401 {"error":"unauthenticated"}`. С токеном бота — `401`. `{"name":"  "}` — `400` с текстом из спеки
  Итог: изолированный стенд — все пункты проверки, плюс не JSON / нет `name` / 65 символов → `400`. Метрика с лейблом: `mcp_tokens_issued_total{result="ok"}` (`metrics::inc_counter` в wallet-common без лейбла не умеет). Тело ответа добавлено в `secret_body` (не пишется в debug-журнал).
- [x] 3.3 Лимит: curl-скрипт выпускает 10 токенов, 11-й получает `409`, после отзыва одного — `201`
  Итог: изолированный стенд — 10 активных, 11-й `409` с текстом спеки, после отзыва — `201`.
- [x] 3.4 `GET /auth/devices` показывает MCP-сессию (`platform: "mcp"`, имя, `is_current: false`, `last_used_at: null`), а значения `wmcp_` в ответе нет. Проверка: curl
  Итог: изолированный стенд — всё так; `token_hash` = base64url(sha256) токена, `device_id` — из ответа выпуска.
- [x] 3.5 `openapi.yaml`: `POST /auth/mcp-tokens`, новые поля `GET /auth/devices`. `README.md`: раздел «Устройства» и новый раздел «MCP-токены» (срок 30/90, лимит, отзыв). Проверка: `/docs` открывается, схема валидна
  Итог: `issueMcpToken`, схемы `McpTokenIssued`, `DeviceSession.last_used_at/expires_at`; `openapi-spec-validator` — OK, `/docs` на стенде — `200`.

## 4. Обмен: `POST /internal/mcp/token`

- [x] 4.1 Ручка обмена: проверка формата, затем `find_mcp_token`, проверка `now < cap_at`, `find_user_by_id` (нет — удалить ключ, D3), `touch_mcp_token` (`false` → отказ), подпись JWT с `add_mcp_claims`, `200 {"access_token","expires_in":300,"user_id","device_id"}`. Любой отказ — `401 {"error":"invalid_token"}`. Метрика `mcp_token_exchanges_total{result}`, журнал по D8. Проверка: curl изнутри сети контура (`docker exec` в контейнер google-auth или wallet-report) — `200`, декодированный JWT без `role`
  Итог: изолированный стенд (curl в порт сервиса) — `200`, JWT: `aud ["wallet-report"]`, `scope reports:read`, `platform mcp`, `exp-iat = 300`, нет `role/email/name`; этим JWT `GET /auth/me` и `POST /auth/mcp-tokens` → `401`. D3 (пользователя нет) и потолок при живом ключе → `401`, ключ удалён. В контуре не проверялось.
- [x] 4.2 Отказы: curl `{"token":"abc"}`, не JSON, действующий refresh-токен вместо MCP-токена — всё `401 {"error":"invalid_token"}`. Refresh после этого по-прежнему обменивается на `/auth/refresh`
  Итог: изолированный стенд — всё так, плюс `{}` и неизвестный `wmcp_…` → `401`.
- [x] 4.3 Отзыв: `POST /auth/devices/revoke` по `token_hash` MCP-сессии, затем обмен — `401`. `revoke-others` из браузера отзывает и MCP (`revoked` учитывает его). `POST /admin/users/{id}/logout` и `DELETE /auth/me` гасят MCP-токены. Проверка: curl на живом стеке
  Итог: изолированный стенд — всё так (`revoked` = все сессии, кроме текущей, включая 10 MCP; после удаления аккаунта оба MCP-токена → `401`).
- [x] 4.4 MCP-токен на `/auth/refresh` (`{"refresh_token":"wmcp_…"}`) — `401` с текстом refresh, и после этого MCP-токен обменивается как прежде. Проверка: curl
  Итог: изолированный стенд — так.
- [x] 4.5 Сквозная проверка с wallet-report: JWT обмена → `GET /api/reports/accounts` напрямую в wallet-report — `200`. С `as_user_id` чужого пользователя при MCP-токене администратора чужие данные не отдаются. Проверка: curl
  Итог 2026-11-02, в сети контура test: обмен wmcp_ → JWT (expires_in 300); GET wallet-report /api/reports/accounts с ним — 200; с as_user_id второго пользователя при токене администратора — 403 «as_user_id: доступно только роли admin» (в JWT обмена нет role).
  Открыто: нужен выкат в test-контур (wallet-report проверяет подпись по JWKS google-auth контура).
- [x] 4.6 Скольжение на живом стеке: после обмена `TTL mcp_token:<hash>` ≈ 30 дней, в `GET /auth/devices` растёт `expires_at` и появляется `last_used_at`. Потолок — юнит-тестом из 2.1 (ждать 90 дней на стенде нельзя). Проверка: `redis-cli TTL` и curl
  Итог: изолированный стенд — `TTL` 2591999, `expires_at` вырос на время между выпуском и обменом, `last_used_at` заполнен; два просмотра подряд дают одинаковый `expires_at`.
- [x] 4.7 `openapi.yaml` (`/internal/mcp/token` с пометкой «не проксируется гейтвеем») и `README.md` (обмен, claims, потребители). Проверка: `/docs`
  Итог: `exchangeMcpToken`, схема `McpExchangeResult`; валидатор — OK, `/docs` — `200`.

## 5. Метрики и выкат

- [x] 5.1 `/metrics` содержит `mcp_tokens_issued_total` и `mcp_token_exchanges_total{result}`. В журнале нет ни `wmcp_`, ни JWT обмена (поиск по логам контейнера после прогона групп 3–4). Проверка: curl `/metrics`, `docker logs … | grep -c wmcp_` = 0
  Итог: изолированный стенд с `LOG_LEVEL=debug` — оба счётчика есть (`ok` и `invalid`), `grep -c wmcp_` = 0, JWT обмена в журнале нет, в `mcp_token_rejected` нет хэша (есть `reason`). `token_hash` встречается в debug-теле ответа `GET /auth/devices` — как и у refresh-сессий до изменения, это публичный id сессии.
- [x] 5.2 Выкат в test-контур первым из всей фичи: старый wallet-web продолжает показывать устройства (новые поля игнорирует). Проверка: ручной заход в «Настройки» на test — Тест: [google-auth#3](https://github.com/WalletTransactions/google-auth/issues/3) — не требуется: обратная совместимость со старыми клиентами сейчас не нужна (решение 2026-11-02)
  Открыто: выкат делает пользователь.

## Workflow follow-up

- После выката: wallet-mcp (`add-mcp-read-tools`) и wallet-web (`add-mcp-tokens-ui`) опираются на эти ручки.
- Архив change — после проверки в prod.
