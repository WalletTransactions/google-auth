# Tasks

## 1. База и хэширование пароля

- [ ] 1.1 Добавить миграцию `migrations/000005_password_auth.{up,down}.sql` (таблица `user_passwords`, `users.google_sub` без NOT NULL; `down` падает с понятной ошибкой, если есть пользователи без `google_sub`) и проверить накат и откат на пустой базе через мигратор
- [ ] 1.2 Реализовать модуль паролей (`src/passwords.{hpp,cpp}`: PBKDF2-HMAC-SHA256 на OpenSSL, соль 16 байт, `CRYPTO_memcmp`, пересчёт при устаревшем числе итераций, фиктивная проверка для несуществующего email) и покрыть юнит-тестами `tests/test_passwords.cpp` (верный и неверный пароль, пересчёт, постоянное время не проверяется) — `ctest` зелёный
- [ ] 1.3 Добавить в `repo` функции работы с паролем и поиском по email (`find_user_by_email`, `create_password_user`, `set_password`, `delete_password`, `link_google_sub`) и проверить их интеграционным прогоном на тестовой БД; обновить комментарии к колонкам миграцией (`COMMENT ON`)

## 2. Лимиты и транспорт

- [ ] 2.1 Добавить в `redis_client` команды `INCR`, `EXPIRE`, `TTL` и проверить юнит-тестом на разбор ответов RESP (`tests/`, `ctest`)
- [ ] 2.2 Реализовать счётчики неудач по email и IP (`AUTH_FAIL_*`), ответ `429` с `Retry-After`, `503` при недоступном Redis; проверить юнит-тестом и `curl` на живом стеке: пять неверных паролей → шестой `429`
- [ ] 2.3 Реализовать проверку `X-Forwarded-Proto: https` и `ALLOW_INSECURE_AUTH` с предупреждением `event=insecure_auth_enabled` при запуске; проверить `curl` без заголовка (`403 insecure_transport`) и с ним

## 3. Ручки и способы входа

- [ ] 3.1 Прочитать и проверить `AUTH_METHODS`, `REGISTRATION` при запуске (`.env`, ошибка на неверном значении), `403 auth_method_disabled` для ручек пароля и `/auth/google*`, `/auth/nonce`; проверить `ctest` и запуском с `AUTH_METHODS=github`
- [ ] 3.2 Реализовать `POST /auth/register` (одинаковый `202`, роль `user`, `email_verified=false`, проверка email и пароля) и привязку Google к неподтверждённой парольной записи в браузерном и мобильном входах; проверить юнит-тестами и `curl`: занятый email не меняет запись, Google-вход забирает аккаунт и отзывает сессии
- [ ] 3.3 Реализовать `POST /auth/login` (web: cookie; Android: тело с токенами, `device_id` обязателен), единый отказ `401`, сброс счётчика при успехе; проверить `curl` для обеих платформ и совпадение `aud`, `scope`, `device_id`, `platform` в выданном токене
- [ ] 3.4 Реализовать `POST /auth/password` (установка и смена, отзыв остальных сессий) и `POST /admin/users/{id}/password`; проверить `curl`: смена отзывает вторую сессию, не админ получает `403`, несуществующий пользователь — `404`
- [ ] 3.5 Добавить журнал `event=password_*` без пароля и метрики `password_auth_total`; проверить, что в журнале и `/metrics` нет значений пароля после серии входов
- [ ] 3.6 Обновить стартовую страницу `GET /` под `AUTH_METHODS` и проверить `curl` при `both` и `password`
- [ ] 3.7 Реализовать `GET /auth/methods` и схему `redirect_uri` из `X-Forwarded-Proto`; проверить `curl` при каждом `AUTH_METHODS` и юнит-тестом на сборку `redirect_uri` с `https` и без

## 4. Документация и интеграционная проверка

- [ ] 4.1 Обновить `openapi.yaml` (новые ручки, коды `400/401/403/429/503`) и проверить, что `GET /openapi.yaml` и `/docs` отдают его без ошибок
- [ ] 4.2 Обновить `README.md` (переменные `AUTH_METHODS`, `REGISTRATION`, `ALLOW_INSECURE_AUTH`, `AUTH_FAIL_*`, `PASSWORD_PBKDF2_ITERATIONS`, раздел про TLS и риск неподтверждённого email) и `.env.example`; проверить, что все переменные из кода описаны (grep по `getenv`)
- [ ] 4.3 Сверить дельта-спеки с поведением на живом стеке (`AUTH_METHODS` во всех трёх режимах, `REGISTRATION=closed`) и выполнить `openspec validate add-password-auth --strict`

## Workflow follow-up

- Отдельные change в wallet-infra (TLS, `COOKIE_SECURE`), wallet-gateway (пути, `X-Forwarded-*`, маскирование журнала), wallet-web и android-wallet (формы, `network_security_config`) — выкатываются по порядку из `design.md`.
- Отдельный change с SMTP: подтверждение email, «забыл пароль», показ статуса подтверждения участников кошелька.
- Архивировать change после выкатки и проверки на test-контуре.
