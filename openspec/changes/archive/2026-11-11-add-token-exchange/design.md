# Design

## Context

- google-auth подписывает access-JWT одним RS256-ключом (`state.jwt_signing_key`)
  и публикует его в `/.well-known/jwks.json`. Другие сервисы проверяют JWT
  сами по JWKS. Отзыв в Redis (`is_access_token_active`) действует только
  внутри google-auth.
- Уже есть два служебных обмена:
  - `/internal/telegram/token`: бот по общему секрету `TELEGRAM_SERVICE_SECRET`
    получает урезанный JWT пользователя (aud `wallet-report`, `wallet-api`,
    `wallet-ai`; scope `reports:read expense:write ai:use`);
  - `/internal/mcp/token`: `wmcp_…` → JWT `wallet-report`/`reports:read` без
    `role` (`token_claims::add_mcp_claims`).
- Субъектами обмена будут два вида JWT: токен бота (через wallet-ai) и токен
  веб-сессии (когда появится веб-чат). У обоих в `aud` есть `wallet-ai`, в
  `scope` — `ai:use`.
- Мотивация — в proposal.md, требования — в `specs/token-exchange/spec.md`.

## Goals / Non-Goals

**Goals:**
- Один обобщённый эндпоинт обмена в форме RFC 8693 вместо ещё одного
  «`/internal/<сервис>/token`» на каждую пару сервисов.
- Права только сужаются: адресат один, scope фиксирован политикой, срок не
  длиннее subject, `role` срезается.
- В выданном токене видно, кто действует от имени пользователя (`act`).

**Non-Goals:**
- Обмен refresh-токенов, `wmcp_…` и других непрозрачных токенов (это
  `/internal/mcp/token`).
- `actor_token` из RFC 8693: actor удостоверяется общим секретом, как бот.
- Проверка отзыва subject-токена в Redis (см. Risks).
- Перевод `/internal/mcp/token` и `/internal/telegram/token` на новый
  эндпоинт.

## Decisions

### D1. Форма RFC 8693, а не свой JSON
Тело `application/x-www-form-urlencoded` с именами полей RFC 8693, ошибки в
форме RFC 6749 §5.2 (`invalid_request`, `invalid_client`, `invalid_grant`,
`unsupported_grant_type`, `invalid_scope`) плюс `invalid_target` из RFC 8707.
Когда google-auth станет OAuth-сервером для внешних MCP-клиентов, этот же
grant появится на публичном `/auth/oauth/token` без новой семантики.
Альтернатива — JSON, как у `/internal/mcp/token`. Отклонена: пришлось бы
придумывать свои имена ошибок, а потом всё равно переводить их на стандарт.

### D2. `audience` — имя сервиса, не URL
`audience=wallet-mcp`, а не `resource=https://…/api/mcp/`. Внутри контура
сервисы адресуются именами (`token_claims::kAud*`), адреса в compose и k8s
разные. Параметр `resource` (RFC 8707) не принимается: он понадобится
внешнему OAuth, где адресат — канонический URL MCP-сервера, и там будет
своё сопоставление URL → имя.

### D3. Actor — по секрету из `TOKEN_EXCHANGE_SECRETS`
Формат: `wallet-ai=<секрет>,wallet-mcp=<секрет>`. Сравнение секретов —
`telegram::detail::secret_matches` (за постоянное время). Его стоит
перенести в общий `util/crypto` вместе с этим change, если правка в
wallet-common приемлема; иначе вызывается как есть. У каждого сервиса свой
секрет, поэтому утечка секрета wallet-mcp не даёт получать токены для
wallet-mcp (это может только actor `wallet-ai`).
Альтернативы:
- mTLS — в LAN-MVP нет TLS;
- `actor_token` (JWT сервиса, client credentials) — нужен выпуск сервисных
  токенов, которого нет.

### D4. Политика — таблица в коде
```
actor       subject: aud ∋ / scope ∋     -> audience        scope
wallet-ai   wallet-ai / ai:use           -> wallet-mcp      mcp:read
wallet-mcp  wallet-mcp / mcp:read        -> wallet-report   reports:read
```
Таблица — `constexpr` массив в `token_exchange.hpp` рядом с
`token_claims`. В env её не выносим: изменение политики — это изменение
поведения безопасности, оно должно проходить через ревью и тесты, а не через
`.env`. Порядок проверок: секрет (actor) → `grant_type` →
`subject_token_type` → подпись/iss/exp subject → строка таблицы для actor и
`audience` (`invalid_target`) → требования к subject (`invalid_grant`) →
`scope` (`invalid_scope`).

### D5. Claims и срок
`exp = min(subject.exp, now + 300)`: обмен не продлевает жизнь токена. Иначе
wallet-mcp, меняя токены по кругу, держал бы пользователя бесконечно. `act`
вкладывается по RFC 8693 §4.1: `{"sub":"wallet-mcp","act":{"sub":"wallet-ai"}}`.
`device_id` и `platform` копируются, чтобы журналы потребителей привязывали
вызов к устройству (боту, браузеру). Функция `token_claims::add_exchange_claims`
по образцу `add_mcp_claims`: сначала стирает `role`/`email`/`name`/`act`,
потом пишет новые. Тест — в `tests/test_token_claims.cpp`.

### D6. Выданный токен не регистрируется
Как у `/internal/mcp/token`: токен не кладётся в Redis активных, поэтому
`authenticate()` google-auth его не примет (к тому же `google-auth` нет в его
`aud`). Logout его не отзывает, его срок — не больше 300 с.

### D7. Новые адресат и scope
`kAudWalletMcp = "wallet-mcp"` и `kScopeMcpRead = "mcp:read"` в
`token_claims.hpp`. В пользовательский набор (`user_audience`, `kScopeUser`)
они **не** добавляются: веб-сессия не должна напрямую ходить в wallet-mcp.
Попасть в wallet-mcp можно только обменом.

### Правки в других сервисах
- **wallet-gateway:** нет, `/internal/*` не маршрутизируется.
- **wallet-common:** по желанию — перенос `secret_matches` в `util/crypto`
  (D3). Без этого change работает.
- **wallet-infra:** `TOKEN_EXCHANGE_SECRETS` в `.env` google-auth для обоих
  контуров. Те же секреты — в `.env` wallet-ai (`AUTH_EXCHANGE_SECRET`) и
  wallet-mcp (`AUTH_EXCHANGE_SECRET`). Это задачи соответствующих changes.
- **Потребители нового `aud`/`scope`:** wallet-mcp (проверяет `aud` ∋
  `wallet-mcp`, `scope` ∋ `mcp:read`), wallet-report (принимает токен от
  wallet-mcp как обычный `reports:read` без `role`, без правок).

## Risks / Trade-offs

- [Subject мог быть отозван (logout), но ещё не истёк] → обмен его примет, как
  его принимают wallet-report и wallet-api по JWKS. Выданный токен живёт не
  дольше subject. Проверка `is_access_token_active` не подходит: токены бота
  и обмена в Redis активных не регистрируются.
- [Утечка `X-Service-Secret` wallet-ai] → злоумышленник с этим секретом и
  чужим действующим JWT (aud `wallet-ai`) получит read-only токен для
  wallet-mcp. Это не шире того, что уже даёт сам JWT (`reports:read` у
  wallet-report). Секрет живёт только в сети контура.
- [Перебор секретов на прямом порту] → ответ `invalid_client` одинаковый,
  сравнение за постоянное время. Порт google-auth снаружи закрыт (как для
  `/internal/telegram/*`).
- [Политика в коде] → новая пара сервисов требует релиза google-auth. Это
  осознанная цена (D4).

## Migration Plan

1. Выкатить google-auth с пустым `TOKEN_EXCHANGE_SECRETS`: эндпоинт отвечает
   `503`, поведение остальных ручек не меняется.
2. Задать секреты в wallet-infra для test-контура, проверить обмен `curl`.
3. Выкатить wallet-mcp (`add-jwt-access`), затем wallet-ai (`add-chat-agent`).
4. Откат: очистить `TOKEN_EXCHANGE_SECRETS`. Чат перестанет работать, MCP по
   `wmcp_…` продолжит.
