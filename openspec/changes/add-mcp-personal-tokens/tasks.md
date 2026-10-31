# Tasks

## 1. Клиент Redis и claims

- [ ] 1.1 `redis::Client`: `set_exat(key, value, epoch)`, `set_xx_exat(key, value, epoch) -> bool` (nil-ответ на `XX` → `false`) и `ttl(key) -> optional<int64>` (`-2` → nullopt). Проверка: на живом стеке `docker exec` `redis-cli` — `SET … XX EXAT` на несуществующий ключ не создаёт его, `ctest` собирается
- [ ] 1.2 `token_claims.hpp`: `kScopeMcp`, `mcp_audience()`, `kMcpTokenTtlSecs = 300`, `add_mcp_claims()` (D4). Юнит-тест в `tests/test_token_claims.cpp`: `aud == ["wallet-report"]`, `scope == "reports:read"`, нет `role`/`email`/`name`. Проверка: `ctest` зелёный

## 2. Хранилище MCP-токенов (repo)

- [ ] 2.1 `repo`: `store_mcp_token`, `find_mcp_token`, `touch_mcp_token` (SET XX EXAT `min(now+30д, cap_at)`, `last_used_at=now`), индекс `user_mcp_tokens:<id>` с `EXPIRE 90д` (D1, D2). Чистые функции расчёта срока (`next_expiry(now, cap_at)`) — в `detail::`, юнит-тест на скольжение, потолок и `now ≥ cap_at`. Проверка: `ctest`
- [ ] 2.2 `SessionSummary`: `kind`, `last_used_at`, `expires_at`. `list_user_sessions` читает оба индекса, `expires_at` берёт из `TTL`. `store_refresh_token` пишет `issued_at` (D5). Проверка: curl `GET /auth/devices` на живом стеке — у новой браузерной сессии заполнены `last_used_at`/`expires_at`, у старой `last_used_at: null`
- [ ] 2.3 `revoke_user_sessions_if` удаляет MCP-ключи по `kind`, `revoke_all_user_tokens` чистит `user_mcp_tokens:<id>` (D5). Проверка покрывается в 3.4 и 4.3

## 3. Выпуск: `POST /auth/mcp-tokens`

- [ ] 3.1 Модуль `mcp_tokens.cpp/.hpp`: `detail::normalize_name` (обрезка, 1..64 символа) и `detail::is_well_formed_token` (префикс `wmcp_` и 43 символа base64url) с юнит-тестами `tests/test_mcp_tokens.cpp`. Проверка: `ctest`
- [ ] 3.2 Ручка выпуска: `auth::authenticate`, разбор тела, лимит 10 → `409` с текстом из спеки, `uuidgen::v4()` для `device_id`, `201 {"token","device_id","name","expires_at"}`, метрика `mcp_tokens_issued_total`, журнал `mcp_token_issued`. Проверка: curl с cookie `session` — `201`. Без токена — `401 {"error":"unauthenticated"}`. С токеном бота — `401`. `{"name":"  "}` — `400` с текстом из спеки
- [ ] 3.3 Лимит: curl-скрипт выпускает 10 токенов, 11-й получает `409`, после отзыва одного — `201`
- [ ] 3.4 `GET /auth/devices` показывает MCP-сессию (`platform: "mcp"`, имя, `is_current: false`, `last_used_at: null`), а значения `wmcp_` в ответе нет. Проверка: curl
- [ ] 3.5 `openapi.yaml`: `POST /auth/mcp-tokens`, новые поля `GET /auth/devices`. `README.md`: раздел «Устройства» и новый раздел «MCP-токены» (срок 30/90, лимит, отзыв). Проверка: `/docs` открывается, схема валидна

## 4. Обмен: `POST /internal/mcp/token`

- [ ] 4.1 Ручка обмена: проверка формата, затем `find_mcp_token`, проверка `now < cap_at`, `find_user_by_id` (нет — удалить ключ, D3), `touch_mcp_token` (`false` → отказ), подпись JWT с `add_mcp_claims`, `200 {"access_token","expires_in":300,"user_id","device_id"}`. Любой отказ — `401 {"error":"invalid_token"}`. Метрика `mcp_token_exchanges_total{result}`, журнал по D8. Проверка: curl изнутри сети контура (`docker exec` в контейнер google-auth или wallet-report) — `200`, декодированный JWT без `role`
- [ ] 4.2 Отказы: curl `{"token":"abc"}`, не JSON, действующий refresh-токен вместо MCP-токена — всё `401 {"error":"invalid_token"}`. Refresh после этого по-прежнему обменивается на `/auth/refresh`
- [ ] 4.3 Отзыв: `POST /auth/devices/revoke` по `token_hash` MCP-сессии, затем обмен — `401`. `revoke-others` из браузера отзывает и MCP (`revoked` учитывает его). `POST /admin/users/{id}/logout` и `DELETE /auth/me` гасят MCP-токены. Проверка: curl на живом стеке
- [ ] 4.4 MCP-токен на `/auth/refresh` (`{"refresh_token":"wmcp_…"}`) — `401` с текстом refresh, и после этого MCP-токен обменивается как прежде. Проверка: curl
- [ ] 4.5 Сквозная проверка с wallet-report: JWT обмена → `GET /api/reports/accounts` напрямую в wallet-report — `200`. С `as_user_id` чужого пользователя при MCP-токене администратора чужие данные не отдаются. Проверка: curl
- [ ] 4.6 Скольжение на живом стеке: после обмена `TTL mcp_token:<hash>` ≈ 30 дней, в `GET /auth/devices` растёт `expires_at` и появляется `last_used_at`. Потолок — юнит-тестом из 2.1 (ждать 90 дней на стенде нельзя). Проверка: `redis-cli TTL` и curl
- [ ] 4.7 `openapi.yaml` (`/internal/mcp/token` с пометкой «не проксируется гейтвеем») и `README.md` (обмен, claims, потребители). Проверка: `/docs`

## 5. Метрики и выкат

- [ ] 5.1 `/metrics` содержит `mcp_tokens_issued_total` и `mcp_token_exchanges_total{result}`. В журнале нет ни `wmcp_`, ни JWT обмена (поиск по логам контейнера после прогона групп 3–4). Проверка: curl `/metrics`, `docker logs … | grep -c wmcp_` = 0
- [ ] 5.2 Выкат в test-контур первым из всей фичи: старый wallet-web продолжает показывать устройства (новые поля игнорирует). Проверка: ручной заход в «Настройки» на test

## Workflow follow-up

- После выката: wallet-mcp (`add-mcp-read-tools`) и wallet-web (`add-mcp-tokens-ui`) опираются на эти ручки.
- Архив change — после проверки в prod.
