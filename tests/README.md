# Юнит-тесты google-auth

Своя минимальная тестовая обвязка (`test_framework.hpp` — `TEST`/`CHECK`/
`CHECK_EQ`/`CHECK_THROWS`/`REQUIRE`), без Catch2/GoogleTest — в том же духе,
что и весь остальной код сервиса (см. корневой `README.md`, "Минимум внешних
зависимостей"): пакетный менеджер и внешняя тестовая библиотека ради
нескольких десятков тестов не нужны.

## Сборка и запуск

```bash
cmake -B build
cmake --build build --target google_auth_tests
./build/google_auth_tests        # или build/Debug/... на Windows/MSVC
# либо через CTest:
ctest --test-dir build --output-on-failure
```

Если библиотеки OpenSSL/PostgreSQL не установлены (см. корневой README,
"Зависимости") — можно временно исключить тесты из сборки:
`cmake -B build -DGOOGLE_AUTH_BUILD_TESTS=OFF`.

## Что покрыто

Только то, что реально юнит-тестируемо без живых Postgres/Redis/сети:

| Файл | Что проверяет |
|---|---|
| `test_base64.cpp` | `util/base64` — кодирование/декодирование base64url, известные векторы, отказ на битом вводе |
| `test_crypto.cpp` | `util/crypto` — sha256, `random_bytes`, `constant_time_equal`, `RsaSigningKey` (подпись/`kid`) + `rsa_sha256_verify` (в т.ч. отказ на чужом ключе/подменённых данных) |
| `test_jwt.cpp` | `util/jwt` — `sign_rs256`/`verify_rs256`/`peek_kid`: корректный roundtrip, отказ на подменённом payload/подписи/чужом ключе/битом формате; явно фиксирует, что `verify_rs256` НЕ проверяет `exp` (это ответственность вызывающего кода) |
| `test_time.cpp` | `util/time` — `now_epoch()` даёт правдоподобное и монотонное значение |
| `test_url.cpp` | `util/url` — percent-encoding, сборка query-строки |
| `test_uuid.cpp` | `util/uuid` — формат UUID v4 (версия/вариант), уникальность, `looks_valid` |
| `test_dotenv.cpp` | `util/dotenv` — парсинг `KEY=VALUE`, комментарии/пустые строки, кавычки, приоритет реального окружения над `.env` |
| `test_types.cpp` | `types.hpp` — `Role` ⇄ строка/id, дефолт "user" на неизвестном значении |
| `test_token_claims.cpp` | `token_claims.hpp` — iss/aud/scope пользовательского токена; JWT обмена MCP-токена: `aud` только `wallet-report`, scope `reports:read`, нет `role`/`email`/`name` |
| `test_mcp_tokens.cpp` | `mcp_tokens::detail` — обрезка и длина имени (в символах UTF-8), формат `wmcp_` + 43 символа base64url; `repo::detail` — скользящий срок 30 дней, потолок 90 дней (в т.ч. `now ≥ cap_at`), формат записи `mcp_token:` в Redis |
| `test_auth.cpp` | `auth::authenticate()` — все reject-пути (нет токена, битый/чужой/просроченный токен, токен без `exp`, токен из cookie `session`), `auth::set_session_cookies`/`clear_session_cookies` — состав и атрибуты `Set-Cookie` |

## Что сознательно НЕ покрыто юнит-тестами (нужны живые Postgres/Redis)

`AppState::db`/`AppState::redis` — конкретные RAII-обёртки над реальным
подключением (`db::Database`/`redis::Client` бросают исключение уже в
конструкторе, если подключиться не удалось, см. `db.hpp`/`redis_client.hpp`)
— интерфейсов для подмены фейком у них нет, и заводить такие интерфейсы
только ради тестов означало бы вносить абстракцию в прод-код без другой
пользы. Значит, без реальной БД/Redis честно не протестировать:

- `auth::get_or_create_user` (`repo::upsert_user`, Postgres);
- `auth::issue_tokens`/`auth::rotate_refresh_token`/`auth::revoke_refresh_token`
  (`repo::store_*`/`take_refresh_token`/`revoke_refresh_token`, Redis);
- "счастливый" путь `auth::authenticate()` — подпись верна и токен не истёк:
  единственная ветка, которая доходит до `repo::is_access_token_active`
  (Redis) — см. код `auth.cpp`;
- сами HTTP-хендлеры в `auth::register_routes` (`/auth/refresh`,
  `/auth/logout`, `/auth/me`) — тонкие обвязки поверх перечисленного выше;
- `google.cpp` целиком (`google_auth::verify_id_token` и хендлеры
  `/auth/google*`) — реальные HTTPS-запросы к Google (обмен кода, JWKS), не
  юнит-тестируемо без мока HTTP-клиента.

Это — материал для отдельных интеграционных тестов (поднятый Postgres+Redis,
как в `docker-compose`/`k8s/`), не для юнит-тестов в этой директории.
