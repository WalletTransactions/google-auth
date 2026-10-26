# admin-users Specification

## Purpose

Инструменты администратора: список пользователей с активностью и
принудительный выход пользователя. Таблицу рисует wallet-web, сервис отдаёт
JSON.

## Requirements

### Requirement: Доступ только для admin
Ручки `/admin/*` SHALL требовать принятый токен (см. `session-tokens`) — иначе
`401` `{"error":"unauthenticated"}` — и роль `admin` в нём — иначе `403`
`{"error":"forbidden"}`.

#### Scenario: Обычный пользователь
- **WHEN** пользователь с ролью `user` вызывает `GET /admin/users`
- **THEN** ответ `403` `{"error":"forbidden"}`

### Requirement: Список пользователей
`GET /admin/users` SHALL отвечать `200` `{"users": [{"id", "email",
"email_verified", "name", "role", "created_at", "last_login_at",
"active_sessions"}]}` по всем пользователям, отсортированным по email.
`last_login_at` — пустая строка, если время входа неизвестно;
`active_sessions` — число активных сессий пользователя.

#### Scenario: Пользователь вошёл с двух устройств
- **WHEN** у пользователя активны сессии браузера и телефона
- **THEN** его `active_sessions` = 2

### Requirement: Принудительный выход
`POST /admin/users/{id}/logout` SHALL отзывать все access- и refresh-токены
пользователя и отвечать `204`; неизвестный `id` — `404` `{"error":"user not
found"}`. Отзыв SHALL действовать на ручки google-auth и на обмен refresh
сразу, а на сервисы, проверяющие токен по JWKS, — по истечении `exp`.

#### Scenario: Выкинуть пользователя
- **WHEN** администратор разлогинивает пользователя
- **THEN** ответ `204`, его следующий `/auth/refresh` — `401`, `active_sessions` = 0
