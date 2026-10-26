# device-sessions Specification

## Purpose

Экран «Мои устройства»: пользователь видит свои активные сессии и отзывает
их сам. Сессия — это непотраченный refresh-токен и устройство, которому он
выдан.

## Requirements

### Requirement: Одна сессия на устройство
При выпуске сессии с непустым `device_id` сервис SHALL отзывать прежние
сессии того же пользователя с тем же `device_id` (refresh и парный access),
так что у пары (пользователь, `device_id`) активна не больше одной сессии.
Браузерный вход получает новый `device_id` на каждый вход, поэтому разные
входы из браузера остаются разными сессиями.

#### Scenario: Переустановка приложения
- **WHEN** телефон снова входит через Google с тем же `device_id`
- **THEN** в `GET /auth/devices` остаётся одна сессия этого устройства

### Requirement: Определение текущей сессии
Текущей SHALL считаться сессия, чей refresh-токен пришёл с запросом (cookie
`refresh_token` или JSON-поле `refresh_token`). Если refresh-токена нет, а в
access-токене есть `device_id`, текущей SHALL считаться сессия с этим
`device_id`. Иначе текущая сессия не определена.

#### Scenario: Браузер
- **WHEN** браузер вызывает `GET /auth/devices` (cookie `refresh_token` уходит на `/auth/*`)
- **THEN** ровно его сессия помечена `is_current: true`

### Requirement: Список сессий
`GET /auth/devices` SHALL для принятого токена (см. `session-tokens`)
отвечать `200` `{"devices": [{"token_hash", "device_id", "device_name",
"platform", "is_current"}]}` по всем активным сессиям пользователя. Просмотр
SHALL NOT тратить ни одного refresh-токена.

#### Scenario: Без токена
- **WHEN** `GET /auth/devices` без токена
- **THEN** ответ `401` `{"error":"unauthenticated"}`

### Requirement: Отзыв одной сессии
`POST /auth/devices/revoke` `{"token_hash"}` SHALL отзывать сессию с этим
хэшем (refresh и парный access) и отвечать `204`, только если она есть в
списке сессий вызывающего. Ответы: не JSON — `400` `invalid JSON body`; пустой
`token_hash` — `400` `token_hash отсутствует`; сессии нет среди своих — `404`
`session not found`; это текущая сессия — `400` `нельзя отозвать текущую
сессию — используйте POST /auth/logout`.

#### Scenario: Чужой хэш
- **WHEN** пользователь A присылает `token_hash` сессии пользователя B
- **THEN** ответ `404`, сессия B не тронута

#### Scenario: Потерянный телефон
- **WHEN** пользователь из браузера отзывает сессию телефона
- **THEN** ответ `204`, следующий `/auth/refresh` телефона — `401`

### Requirement: Отзыв всех, кроме текущей
`POST /auth/devices/revoke-others` SHALL отзывать все сессии пользователя,
кроме текущей, и отвечать `200` `{"revoked": <число>}`. Если текущую сессию
определить нельзя — `400` `не удалось определить текущую сессию —
refresh-токен не передан`, ничего не отзывая.

#### Scenario: Bearer без refresh и без device_id
- **WHEN** запрос несёт только access-токен без `device_id`, без refresh-токена
- **THEN** ответ `400`, ни одна сессия не отозвана
