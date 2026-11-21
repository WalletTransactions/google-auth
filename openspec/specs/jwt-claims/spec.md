# jwt-claims Specification

## Purpose

Справочник claim'ов JWT, которые выпускает google-auth: какие поля лежат в токене каждого вида, за что отвечает каждое поле и какой сервис что проверяет. Подпись RS256 и `kid` описаны в `session-tokens`; обмен токенов — в `token-exchange`; здесь — смысл полей и различия между видами токенов.

## Requirements

### Requirement: Служебные claim'ы времени и подписи
Каждый JWT SHALL нести `iat` (время выпуска, секунды Unix) и `exp` (время окончания). Сервис-потребитель SHALL отклонять токен с истёкшим `exp` или неверной подписью до проверки остальных claim'ов. Подпись проверяется по открытому ключу из JWKS google-auth, выбранному по `kid` заголовка.

#### Scenario: Токен истёк
- **WHEN** сервис получает токен с `exp` в прошлом
- **THEN** он отвечает `401` и не смотрит `aud` и `scope`

### Requirement: iss — кто выпустил
Каждый JWT SHALL нести `iss` = `google-auth`. Сервис-потребитель SHALL отклонять токен с другим или отсутствующим `iss` (результат `wrong_issuer`).

#### Scenario: Чужой издатель
- **WHEN** сервис получает токен с `iss`, отличным от `google-auth`
- **THEN** токен отклоняется как `wrong_issuer`

### Requirement: aud — кому адресован токен
`aud` SHALL быть массивом имён сервисов (не URL), которым токен разрешено предъявлять. Сервис SHALL принимать токен, только если `aud` содержит его имя (строка или массив, RFC 7519 §4.1.3), иначе отклонять как `wrong_audience`. Токен без `aud` SHALL отклоняться как `legacy`.

#### Scenario: Пользовательский токен
- **WHEN** выпущен токен для браузера или телефона
- **THEN** `aud` = `wallet-api`, `wallet-report`, `google-auth`, `wallet-ai`, `wallet-docs`, без `wallet-mcp`

#### Scenario: Токен Telegram-бота
- **WHEN** выпущен токен для бота
- **THEN** `aud` = `wallet-report`, `wallet-api`, `wallet-ai`, без `google-auth`

#### Scenario: Токены MCP и обмена
- **WHEN** выпущен токен обменом MCP-токена или `/internal/token/exchange`
- **THEN** `aud` содержит ровно одного адресата: `wallet-report`, `wallet-docs` или (только при обмене) `wallet-mcp`

#### Scenario: Токен бота на ручках аккаунта
- **WHEN** токен бота предъявлен google-auth на `GET /auth/me`
- **THEN** он отклоняется как `wrong_audience`

#### Scenario: Пользовательский токен у wallet-mcp
- **WHEN** пользовательский токен предъявлен wallet-mcp
- **THEN** он отклоняется как `wrong_audience`: веб-сессия в wallet-mcp напрямую не ходит

### Requirement: scope — что по токену можно
`scope` SHALL быть строкой слов через пробел; сервис проверяет наличие нужного слова. Отсутствие `scope` MUST NOT трактоваться как «можно всё»; недостающий scope — отказ `insufficient_scope`.

#### Scenario: Значения данных
- **WHEN** сервис проверяет доступ к данным
- **THEN** `wallet:read` и `wallet:write` — чтение и запись в wallet-api, `expense:write` — только создание новой операции, `reports:read` — отчёты wallet-report

#### Scenario: Значения функций
- **WHEN** сервис проверяет доступ к функции
- **THEN** `account` — ручки аккаунта google-auth, `ai:use` — wallet-ai (не выдать — выключить ИИ), `docs:ask` — вопросы к wallet-docs, `mcp:read` — инструменты wallet-mcp (только в токене обмена)

#### Scenario: Набор пользователя
- **WHEN** выпущен пользовательский токен
- **THEN** `scope` = `wallet:read wallet:write reports:read account ai:use docs:ask`

#### Scenario: Набор бота и MCP
- **WHEN** выпущен токен бота или MCP
- **THEN** у бота `scope` = `reports:read expense:write ai:use`, у MCP — `reports:read` (адресат wallet-report) или `docs:ask` (адресат wallet-docs)

#### Scenario: Урезанный токен бота
- **WHEN** бот с токеном без `wallet:write` вызывает запись, требующую `wallet:write`
- **THEN** сервис отвечает отказом `insufficient_scope`

#### Scenario: Только создание операции
- **WHEN** токен несёт `expense:write` без `wallet:write` и вызывает `POST /sync/push`
- **THEN** wallet-api разрешает только создание новой операции

### Requirement: sub — чей токен
`sub` SHALL содержать идентификатор пользователя, от имени которого выполняется запрос. Сервисы SHALL определять пользователя только по `sub` проверенного токена, а не по параметрам запроса. В токене обмена `sub` копируется из subject-токена без изменений.

#### Scenario: Данные чужого пользователя
- **WHEN** запрос несёт токен пользователя A и параметр с идентификатором пользователя B
- **THEN** сервис работает с данными A, кроме разрешённого администратору `as_user_id` в wallet-report

### Requirement: role — права пользователя
Пользовательский токен SHALL нести `role` (`user`, `support` или `admin`), назначенную при создании учётной записи. Отсутствие `role` трактуется как `user`. Токены бота, MCP и обмена SHALL NOT нести `role`, `email` и `name`; google-auth стирает их, даже если вызывающий положил их по ошибке.

#### Scenario: Где роль что даёт
- **WHEN** сервис проверяет `role`
- **THEN** `admin` даёт `as_user_id` в wallet-report, `GET /api/versions` в гейтвее и полную область документации wallet-docs

#### Scenario: Сводка версий не админу
- **WHEN** пользователь с `role: user` запрашивает `GET /api/versions`
- **THEN** гейтвей отвечает `403`

#### Scenario: Токен обмена
- **WHEN** выдан токен обмена для subject с ролью `admin`
- **THEN** в нём нет `role`, и wallet-report видит обычного пользователя без `as_user_id`

### Requirement: email и name — отображение
`email` и `name` SHALL попадать только в пользовательский токен, служить для отображения (`/auth/me`) и MUST NOT быть признаком прав. Аватар в токен SHALL NOT попадать.

#### Scenario: Бот не знает email
- **WHEN** выпускается токен Telegram-бота
- **THEN** в нём нет `email` и `name`

### Requirement: device_id и platform — откуда пришла сессия
`device_id` SHALL идентифицировать устройство или вход, `platform` — тип клиента: `web`, `android`, `telegram`, `mcp`. Пользовательский токен несёт их, если у сессии есть `device_id`; токен обмена наследует их у исходной сессии.

#### Scenario: Платформа бота и MCP
- **WHEN** выпущен токен бота или MCP
- **THEN** `platform` равен `telegram` или `mcp` соответственно

#### Scenario: Область документации по платформе
- **WHEN** wallet-docs получает проверенный токен
- **THEN** область выбирается по `role` и `platform`: `admin` — всё, `android` — Android-приложение, `web` — веб-клиент, `mcp` — веб и wallet-mcp, `telegram` — продуктовые репозитории, иначе пусто

### Requirement: act — цепочка делегирования
Токен обмена SHALL нести `act` = `{"sub": "<сервис, запросивший обмен>"}` (RFC 8693 §4.1); `act` subject-токена вкладывается внутрь нового. Пользовательские токены и токены бота SHALL NOT нести `act`. `act` показывает, кто действовал от имени пользователя, и прав не расширяет.

#### Scenario: Цепочка wallet-ai → wallet-mcp
- **WHEN** wallet-mcp меняет токен, полученный от wallet-ai
- **THEN** выданный токен несёт `act` = `{"sub":"wallet-mcp","act":{"sub":"wallet-ai"}}`

### Requirement: Сроки жизни токенов
Срок `exp` SHALL зависеть от вида токена: пользовательский — `ACCESS_TOKEN_TTL_SECS` (по умолчанию 900 с); Telegram-бот и MCP — 300 с; обмен — не больше 300 с и не позже `exp` subject-токена.

#### Scenario: Обмен не продлевает срок
- **WHEN** у subject-токена до `exp` осталось 60 секунд
- **THEN** выданный токен обмена живёт не дольше этих 60 секунд
