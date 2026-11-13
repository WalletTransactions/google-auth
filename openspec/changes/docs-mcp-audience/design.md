# Design

## Context

wallet-mcp получает у google-auth короткие JWT для wallet-report двумя путями: по
персональному `wmcp_…` (`POST /internal/mcp/token`, JWT с `platform` = `mcp`) и по JWT
пользователя из чата wallet-ai (`POST /internal/token/exchange`, actor `wallet-mcp`,
JWT наследует `platform` и `device_id` исходной сессии, роль стирается). Чтобы wallet-mcp
мог задать вопрос wallet-docs, оба пути должны уметь выдавать JWT с `aud` =
`wallet-docs` и `scope` = `docs:ask`. См. proposal.md и `wallet-mcp/docs-tool`.

## Goals / Non-Goals

**Goals:**
- Второй адресат для обоих путей wallet-mcp, без изменения существующих ответов.
- Права не растут: JWT справки не принимают wallet-report, wallet-api, wallet-gateway,
  а JWT для wallet-report не принимает wallet-docs.

**Non-Goals:**
- Новые actor'ы, новые claim'ы, роль в JWT обмена.
- Выдача `wallet-docs` боту Telegram и actor'у `wallet-ai` (решение `docs-audience`).

## Decisions

**D1. `audience` в теле `/internal/mcp/token`, а не новая ручка.** Поле необязательное,
белый список из двух значений, по умолчанию `wallet-report` — все существующие
вызовы wallet-mcp остаются прежними. Новая ручка отвергнута: она дублировала бы проверку
токена, продление и `last_used_at` и расширила бы openapi без выгоды.

**D2. Проверка `audience` до проверки токена.** Мусорное значение — `400 invalid_audience`,
токен не проверяется и не продлевается. Это не раскрывает действительность токена
(ответ не зависит от него) и не даёт продлевать токен запросами с неверным адресатом.

**D3. Scope — из таблицы, не от клиента.** `wallet-docs` → `docs:ask`, `wallet-report` →
`reports:read`; `/internal/mcp/token` `scope` вообще не принимает. В обмене RFC 8693 правило
«Scope не расширяется» работает как есть: чужой `scope` для пары — `400 invalid_scope`.

**D4. `platform` не придумывается.** JWT по `wmcp_…` несёт `platform` = `mcp` (как сейчас);
JWT обмена наследует `platform` исходной сессии. Поэтому wallet-docs видит `mcp` только
у клиентов с персональным токеном, а у чата wallet-ai — `android`/`web` пользователя; роль
не несёт ни один, админом через MCP не стать.

**D5. Продление MCP-токена при обмене для справки сохраняется.** Обмен для wallet-docs
тоже «использование» токена: продлевает срок и обновляет `last_used_at`, как обмен для
отчётов. Альтернатива «не продлевать» отвергнута: токен, которым пользуются только для
справки, не должен неожиданно истекать, а расходится с поведением того же эндпоинта.

**D6. Метрика с лейблом.** `mcp_token_exchanges_total{result}` получает `audience`
(`wallet-report`/`wallet-docs`); лейбл только из белого списка, кардинальность мала.

**Потребители и порядок выкатки.** Читают токен wallet-docs (проверяет `aud`, `scope`,
выбирает область по `platform`) и wallet-mcp (получает его). Правок в wallet-gateway,
wallet-api, wallet-report, wallet-ai, wallet-web нет. Порядок: google-auth → wallet-docs
(`mcp-scope`) → wallet-mcp (`docs-tool`) → `WALLET_DOCS_URL` в окружении. Пока wallet-mcp
не обновлён, новые значения никто не запрашивает.

## Risks / Trade-offs

- **Лишний обмен на первый вопрос.** Один обмен на сессию на адресата; кеш — на стороне
  wallet-mcp (300 с).
- **Раскрытие адресата.** `audience` — поле из белого списка двух имён; новая поверхность
  атаки — только служебная ручка в сети контура, гейтвей её не проксирует.
- **Ослабление изоляции токенов.** JWT справки с `platform` = `mcp` не подходит ни для
  чего, кроме wallet-docs: гейтвей отвечает `401` без `wallet-api` в `aud`.
