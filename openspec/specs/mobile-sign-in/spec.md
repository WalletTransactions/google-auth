# mobile-sign-in Specification

## Purpose

Вход с Android через Credential Manager: приложение само получает `id_token`
у Google и обменивает его на пару токенов сервиса. Повтор перехваченного
`id_token` закрывает одноразовый nonce, выданный сервисом.

## Requirements

### Requirement: Выдача nonce
`POST /auth/nonce` SHALL без аутентификации отвечать `200`
`{"nonce": "<32 символа [A-Za-z0-9]>"}` и запоминать nonce в памяти процесса
как выданный. Срока жизни у nonce нет; после рестарта сервиса выданные nonce
теряются.

#### Scenario: Приложение начинает вход
- **WHEN** приложение вызывает `POST /auth/nonce`
- **THEN** получает новый nonce, который затем передаёт Google в запросе id_token

### Requirement: Проверка тела запроса
`POST /auth/google/mobile` SHALL принимать JSON `{"id_token", "device_id",
"device_name"?, "platform"?}`. `platform` по умолчанию — `android`. Ошибки
тела SHALL отдаваться `400` с JSON `{"error": ...}` в таком порядке проверки:
не JSON — `invalid JSON body`; пустой `id_token` — `id_token отсутствует`;
пустой `device_id` — `device_id отсутствует`; `platform` не из `android`,
`ios`, `web`, `other` — `недопустимый platform (android/ios/web/other)`.

#### Scenario: Без device_id
- **WHEN** тело `{"id_token": "..."}` без `device_id`
- **THEN** ответ `400` `{"error":"device_id отсутствует"}`

#### Scenario: Платформа telegram
- **WHEN** тело содержит `"platform": "telegram"`
- **THEN** ответ `400`: такую сессию выдаёт только связывание бота

### Requirement: Проверка id_token и nonce
`id_token` SHALL проверяться так же, как в браузерном входе (JWKS Google,
RS256, `exp`, `iss`, `aud` = `GOOGLE_CLIENT_ID`, непустой `sub`); при отказе —
`401` `{"error": "<причина>"}`. Затем claim `nonce` SHALL совпасть с ранее
выданным и ещё не предъявленным nonce, который при этом гасится; иначе —
`401` `{"error":"nonce отсутствует, неизвестен или уже использован — запросите новый через POST /auth/nonce"}`.

#### Scenario: Повтор того же id_token
- **WHEN** тот же `id_token` предъявлен второй раз
- **THEN** ответ `401` про nonce, сессия не выпускается

#### Scenario: id_token без nonce
- **WHEN** Google выдал `id_token` без `nonce`
- **THEN** ответ `401` про nonce

### Requirement: Выпуск сессии без подтверждения регистрации
При успешной проверке сервис SHALL создать пользователя, если его ещё нет
(без страницы подтверждения), или обновить его профиль, выпустить сессию для
устройства из тела и ответить `200` `{"access_token", "refresh_token",
"expires_in"}`. Cookie SHALL NOT выставляться.

#### Scenario: Первый вход с телефона
- **WHEN** новый пользователь входит с валидными `id_token` и nonce
- **THEN** учётная запись создаётся сразу, в ответе пара токенов и `expires_in` = TTL access-токена в секундах

#### Scenario: Повторный вход с того же устройства
- **WHEN** пользователь снова входит с тем же `device_id`, пока прежняя сессия этого устройства жива
- **THEN** прежняя сессия отзывается, активной остаётся одна новая (см. `device-sessions`)
