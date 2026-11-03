# Spec Delta

## MODIFIED Requirements

### Requirement: Живость, версия и метрики
Без аутентификации сервис SHALL отдавать `GET /healthz` — `200`
`{"status":"ok"}` без проверки Postgres и Redis; `GET /version` —
`{"service", "version", "build", "git_commit", "started_at"}`, где `build` — тег
образа из `APP_BUILD` (без него `<VERSION>-dev`), а `started_at` — время запуска
процесса в ISO-8601 UTC; `GET /metrics` — метрики Prometheus (запросы по методу,
маршруту и статусу, длительность, `build_info` с меткой `build`,
`process_start_time_seconds`, `jwt_claims_total`).

#### Scenario: Healthcheck при упавшем Redis
- **WHEN** Redis недоступен, а процесс жив
- **THEN** `/healthz` отвечает `200`, контейнер не перезапускается

#### Scenario: Версия rc-сборки
- **WHEN** образ собран Release-workflow по тегу `v0.1.1-rc.3`
- **THEN** `/version` отдаёт `"version":"0.1.1"`, `"build":"0.1.1-rc.3"` и `started_at` запуска контейнера, а после перезапуска — новый `started_at`
