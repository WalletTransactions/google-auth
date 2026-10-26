# service-ops Specification

## Purpose

Всё, что нужно, чтобы сервис запустить, наблюдать и выкатить: настройки и
проверки при старте, служебные ручки, журнал, схема БД, образ и CI.

## Requirements

### Requirement: Обязательные настройки
Сервис SHALL читать настройки из окружения, предварительно подгрузив `.env`
из рабочего каталога. Без `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
`JWT_RSA_PRIVATE_KEY_PATH` или `DATABASE_URL` он SHALL писать в журнал
`<ИМЯ> must be set — <подсказка> (см. README.md)` и завершаться с кодом 1.
Адрес по умолчанию — `127.0.0.1:8080` (`HOST`, `PORT`).

#### Scenario: Нет client secret
- **WHEN** `GOOGLE_CLIENT_SECRET` не задан
- **THEN** процесс завершается с кодом 1 и строкой `GOOGLE_CLIENT_SECRET must be set — …`

### Requirement: Проверки при старте
Сервис SHALL завершаться с кодом 1, если ключ подписи не читается,
`CA_BUNDLE_PATH` указывает на несуществующий файл, `DATABASE_POOL_SIZE` < 1,
Postgres или Redis недоступны, в базе нет таблиц `roles` или `users` или порт
не удалось занять.

#### Scenario: Схема не накачена
- **WHEN** сервис стартует на пустой базе
- **THEN** он завершается с кодом 1 и сообщением «таблица 'roles' не найдена — схема ещё не накачена…»

#### Scenario: Бот не настроен
- **WHEN** не заданы `TELEGRAM_BOT_USERNAME` и `TELEGRAM_SERVICE_SECRET`
- **THEN** сервис стартует, ручки связывания отвечают `503`

### Requirement: Схема БД
Схема SHALL накатываться миграциями `migrations/` отдельной ролью-мигратором,
не самим сервисом: справочник `roles` (1 `user`, 2 `support`, 3 `admin`),
`users` (`google_sub` уникален, `last_login_at` может быть NULL),
`telegram_links` (ключ `tg_user_id` > 0, `user_id` с `ON DELETE CASCADE`).
Образ SHALL содержать миграции в `/migrations/`.

#### Scenario: Удаление пользователя
- **WHEN** удаляется строка `users`
- **THEN** его строки `telegram_links` удаляются вместе с ней

### Requirement: Живость, версия и метрики
Без аутентификации сервис SHALL отдавать `GET /healthz` — `200`
`{"status":"ok"}` без проверки Postgres и Redis; `GET /version` —
`{"service", "version", "git_commit"}`; `GET /metrics` — метрики Prometheus
(запросы по методу, маршруту и статусу, длительность, `build_info`,
`jwt_claims_total`).

#### Scenario: Healthcheck при упавшем Redis
- **WHEN** Redis недоступен, а процесс жив
- **THEN** `/healthz` отвечает `200`, контейнер не перезапускается

### Requirement: Документация API
Без аутентификации сервис SHALL отдавать `GET /openapi.yaml` — `openapi.yaml`
из рабочего каталога (`application/yaml; charset=utf-8`) и `GET /docs` —
Swagger UI на вендоренной статике `/vendor/swagger-ui/*`, без внешних ресурсов.

#### Scenario: Файл спеки не скопирован
- **WHEN** `openapi.yaml` нет рядом с исполняемым файлом
- **THEN** `GET /openapi.yaml` отвечает `500` с текстом «openapi.yaml не найден рядом с исполняемым файлом…»

### Requirement: Журнал запросов
На каждый запрос, кроме `/healthz` и `/metrics`, сервис SHALL писать строку
`event=request_finished` с методом, путём, статусом и `duration_ms`.
Пришедший `X-Trace-Id` SHALL попадать во все строки запроса и возвращаться в
ответе; свой сервис не порождает.

#### Scenario: Запрос через гейтвей
- **WHEN** гейтвей прислал `X-Trace-Id: abc`
- **THEN** строки журнала этого запроса несут `trace_id` `abc`, ответ — заголовок `X-Trace-Id: abc`

### Requirement: Секреты вне журнала
На уровне debug сервис SHALL писать строку `event=request_body` с телами
запроса и ответа, обрезанными до 1024 байт; для `/internal/*`,
`/auth/telegram/link-code`, `/auth/refresh`, `/auth/logout` и
`/auth/google/mobile` тела SHALL заменяться на `(скрыто: секреты)`. Параметры
SQL SHALL NOT попадать в журнал, пока не включён `LOG_SQL_PARAMS`.

#### Scenario: Обмен refresh на стенде с debug
- **WHEN** `POST /auth/refresh` при `LOG_LEVEL=debug`
- **THEN** в журнале нет ни старого, ни нового refresh-токена

### Requirement: Образ и CI
Образ SHALL собираться `Containerfile` в два этапа на `debian:bookworm-slim`
(`BUILD_JOBS` по умолчанию 3, `GIT_COMMIT` попадает в `/version`) и запускать
сервис от `appuser` на порту 8080 с `curl` для healthcheck. CI SHALL на push в
`main` и на PR собирать и прогонять юнит-тесты (`ctest`) и собирать образ.

#### Scenario: Сборка с хэшем
- **WHEN** образ собран с `--build-arg GIT_COMMIT=<хэш>`
- **THEN** `GET /version` отдаёт этот хэш в `git_commit`
