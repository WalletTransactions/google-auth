# Design

## Context

Мотивация — в `proposal.md`. Требования — в `specs/mcp-tokens` и
`specs/device-sessions`. Что сейчас в коде и что определяет подход:

- **Сессии в Redis.** Ключ `refresh_token:<hash>` с JSON `{user_id,
  device_id, device_name, platform, access_token_hash}` и TTL
  `REFRESH_TOKEN_TTL_SECS`, плюс индекс `user_refresh_tokens:<user_id>`
  (SET). `hash` — `base64(sha256(token))` (`auth::hash_token`). Список
  устройств (`repo::list_user_sessions`) и все отзывы
  (`repo::revoke_user_sessions_if`, `repo::revoke_all_user_tokens`) построены
  поверх этого индекса.
- **Короткий токен «за пользователя» уже есть:** `/internal/telegram/token`
  (`telegram.cpp`). Это JWT на 300 с с урезанными `aud`/`scope`, без `role`,
  не регистрируется в Redis. Claims собраны в `token_claims.hpp`.
- **`redis::Client`** умеет `SET EX`, `GET`, `GETDEL`, `DEL`,
  `SADD/SMEMBERS/SREM`, `EXPIRE`, но не умеет `SET … XX EXAT` и `TTL`.
- **Потребитель JWT — wallet-report** (`session.cpp`): обязательны только
  подпись, `exp`, `iss`, `aud` `wallet-report` и scope `reports:read`. `email`
  и `name` читаются через `value(…, "")`, `role` — через `value(…, "user")`.
  Значит, токен без `email`, `name` и `role` он принимает как обычного
  пользователя.
- Redis персистентный (AOF и том в `wallet-infra/compose.yaml`), версия 7:
  `GETDEL` и `SET … EXAT` доступны.

## Goals / Non-Goals

**Goals:**
- Отдельное от refresh-токенов хранилище MCP-токенов, которое нельзя спутать
  с refresh ни при обмене, ни при `/auth/refresh`.
- Скользящий срок и потолок выражены TTL ключа Redis, без фоновой чистки.
- MCP-сессии встраиваются в существующие список и отзывы, а не дублируют их.

**Non-Goals:**
- OAuth 2.1 (authorization server, PKCE, DCR) — отдельный change.
- MCP-токены с правом записи. Сейчас JWT обмена не адресован wallet-api,
  поэтому `device` в wallet-api для MCP не заводится, и CHECK `platform`
  там (`000023`) расширять не нужно.
- Ограничение частоты обменов. Энтропия токена — 256 бит, перебор
  бессмыслен, а `/internal/*` не виден снаружи.

## Decisions

### D1. Отдельные ключи `mcp_token:<hash>` и индекс `user_mcp_tokens:<user_id>`

Значение — JSON `{user_id, device_id, name, created_at, cap_at,
last_used_at}` (epoch-секунды, `last_used_at` = 0 до первого обмена).

*Почему не `refresh_token:` с пометкой типа:* `POST /auth/refresh` ищет
ключ по хэшу предъявленной строки. Если MCP-токен лежит под тем же префиксом,
`{"refresh_token":"wmcp_…"}` обменялся бы на полную сессию со scope
`wallet:write` и `account`. Отдельный префикс закрывает это без проверок в
коде refresh: такого ключа там просто нет (требование «MCP-токен не
обменивается как refresh»). И наоборот: обмен смотрит только
`mcp_token:`, поэтому refresh-токен на `/internal/mcp/token` не найдётся и не
потратится.

### D2. Скольжение и потолок — TTL ключа

- Выпуск: `SET mcp_token:<hash> <json> EXAT (now + 30 д)`, `cap_at = now + 90 д`.
- Обмен: `GET`, затем проверка пользователя, затем
  `SET mcp_token:<hash> <json с last_used_at=now> XX EXAT min(now + 30 д, cap_at)`.
  `XX` не воскрешает ключ, удалённый отзывом между `GET` и `SET`: в этом
  случае `SET` возвращает nil, и ответ — `401 invalid_token`.
- Если `now ≥ cap_at`, ключ уже истёк сам. Защитная проверка в коде всё равно
  нужна на случай, если часы хоста сдвинулись.
- Индекс `user_mcp_tokens:<user_id>` при каждом выпуске получает
  `EXPIRE 90 д`. Последний выпущенный токен — самый долгоживущий, поэтому
  индекс его переживёт, а висячие хэши вычищает листинг (как у refresh).

*Альтернатива — хранить `expires_at` в значении и проверять в коде.*
Отклонена: просроченные записи копились бы, и понадобилась бы чистка. TTL
решает это даром.

Клиенту Redis добавляются `set_xx_exat(key, value, epoch) -> bool`,
`set_exat(key, value, epoch)` и `ttl(key) -> optional<int64>`.

### D3. Обмен проверяет, что пользователь существует

На обмене выполняется один `repo::find_user_by_id`. Нет записи —
`401 invalid_token`, ключ удаляется. Это страховка, а не основной механизм:
`DELETE /auth/me` и админский выход и так отзывают MCP-токены (D5). Цена —
один запрос в Postgres на обмен. wallet-mcp кеширует JWT до `exp`, поэтому
обменов не больше одного на токен за ~5 минут.

### D4. Claims JWT обмена — в `token_claims.hpp`

`kScopeMcp = "reports:read"`, `mcp_audience() = ["wallet-report"]`,
`kMcpTokenTtlSecs = 300`, `add_mcp_claims(payload)` — по образцу
`add_telegram_bot_claims`. Payload: `sub`, `iat`, `exp`, `device_id`,
`platform: "mcp"`. **Без `role`, `email`, `name`.** Отсутствие `role`
закрывает админский `as_user_id` в wallet-report, а `email`/`name`
потребителю не нужны. Как и у бота, JWT не кладётся в Redis: google-auth его
и так не примет, потому что в `aud` нет `google-auth`.

Юнит-тест в `test_token_claims.cpp` фиксирует, что `role` в MCP-токен не
попадает. Регрессия здесь была бы тихой.

### D5. Встраивание в сессии

- `repo::SessionSummary` получает `kind` (`refresh` | `mcp`), `last_used_at`
  и `expires_at` (optional).
- `list_user_sessions` читает оба индекса. Для MCP: `device_name` = `name`,
  `platform` = `mcp`. `expires_at` = `now + TTL(ключа)` для обоих видов:
  TTL — единственный источник правды, он работает и для refresh-записей
  старого формата. Для refresh `last_used_at` — новое поле `issued_at` в
  значении, у старых записей его нет, и тогда это `null`.
- `revoke_user_sessions_if` удаляет ключ по `kind`. Парного access у MCP нет.
- `revoke_all_user_tokens` (админский выход, `DELETE /auth/me`) удаляет и
  `user_mcp_tokens:<id>` со всеми ключами.
- `is_current` для `kind == mcp` всегда `false`. Браузер не может прийти с
  MCP-токеном на `/auth/devices`, потому что `authenticate` требует
  `aud` `google-auth`.
- Админская колонка `active_sessions` начинает учитывать MCP-сессии. Это
  ожидаемо: это тоже активный доступ пользователя.

### D6. Где живёт код

Новый модуль `mcp_tokens.cpp/.hpp`: две ручки, `register_routes`,
`detail::` для разбора имени и формата токена (юнит-тестируемо, как
`telegram::detail`). Хранилище — в `repo.cpp` рядом с refresh. `devices.cpp`
меняется только в `session_to_json`. Токен: `"wmcp_" + b64url(random_bytes(32))`.
Проверка формата до похода в Redis: префикс и длина 5 + 43 символа
base64url без `=`.

### D7. Ответы и коды

Тексты ошибок — дословно из спеки. `401 invalid_token` на обмене один для
всех причин: отказы не различаются, чтобы не подсказывать, существовал ли
токен.

### D8. Метрики и журнал

- `mcp_tokens_issued_total`, `mcp_token_exchanges_total{result="ok|invalid"}`
  через `util/metrics`.
- Журнал: `mcp_token_issued` (`user_id`, `device_id`), `mcp_token_exchanged`
  (`user_id`, `device_id`), `mcp_token_rejected` (без хэша). Токен и JWT в
  журнал не пишутся никогда.

## Потребители claim'ов и порядок выката

| Потребитель | Что видит | Правка |
| --- | --- | --- |
| wallet-report | JWT `aud` `["wallet-report"]`, `reports:read`, без `role` | нет (проверено по `session.cpp`) |
| wallet-gateway | MCP-JWT через гейтвей не ходит: wallet-mcp зовёт wallet-report напрямую. Сам `wmcp_` на `/api/mcp/` гейт не проверяет | `add-mcp-route` |
| wallet-api, wallet-ai | не адресаты, отклоняют по `aud` | нет |
| wallet-mcp | клиент `/internal/mcp/token` | `add-mcp-read-tools` |
| wallet-web | `POST /auth/mcp-tokens`, новые поля `GET /auth/devices` | `add-mcp-tokens-ui` |

Порядок: **google-auth первым.** Новые поля в `/auth/devices` аддитивны, и
старый веб их игнорирует. Затем wallet-mcp и гейтвей, затем веб. Откат
google-auth безопасен: MCP-ключи остаются в Redis, но их никто не читает,
и они истекают сами.

## Risks / Trade-offs

- [`/internal/mcp/token` защищён только сетью контура] → Не страшнее
  `/internal/telegram/token`, к тому же без токена ручка ничего не выдаёт.
  Сетевые политики — п. 3 `org/docs/TODO_service_auth_tls.md`.
- [Потеря тома Redis] → Все MCP-токены пропадают вместе с сессиями. Отказ в
  закрытую сторону, пользователь выпускает токены заново.
- [Отзыв действует с задержкой до 300 с на стороне wallet-report] → Это
  свойство JWT по JWKS, как у бота. Предел — `exp` JWT обмена.
- [Гонка двух выпусков у лимита] → Возможно 11 токенов вместо 10. Это не
  нарушение безопасности, атомарная проверка не нужна.
- [Сдвиг часов хоста] → Потолок дублируется проверкой `now < cap_at` в коде.

## Migration Plan

Миграций Postgres нет. В Redis только новые префиксы, а у refresh-записей
появляется необязательное поле `issued_at`: старые читаются как раньше.
Выкат — обычный образ google-auth. Откат — предыдущий образ: новые ключи
просто перестают читаться.
