# password-auth Specification

## Purpose
Вход и регистрация по email и паролю, которые хранятся и проверяются в
google-auth, как способ входа наряду с Google. Какие способы включены и открыта
ли регистрация, задаёт конфигурация сервиса.

## Requirements

### Requirement: Режим способов входа
Переменная `AUTH_METHODS` SHALL принимать `password`, `google` или `both` (по
умолчанию `both`); другое значение SHALL останавливать запуск сервиса с
ошибкой.

#### Scenario: Неверное значение
- **WHEN** сервис запускается с `AUTH_METHODS=github`
- **THEN** запуск завершается ошибкой с указанием допустимых значений

### Requirement: Отключённые способы входа
При `AUTH_METHODS=google` ручки `POST /auth/register`, `POST /auth/login`,
`POST /auth/password` SHALL отвечать `403` `{"error":"auth_method_disabled"}`.
При `password` то же `403` SHALL отдавать `GET /auth/google`,
`POST /auth/google/mobile` и `POST /auth/nonce`. Остальные ручки (обмен refresh,
`GET /auth/me`, выход) SHALL работать при любом значении.

#### Scenario: Только Google
- **WHEN** `AUTH_METHODS=google` и приходит `POST /auth/login`
- **THEN** ответ `403` `{"error":"auth_method_disabled"}`, пароль не проверяется

#### Scenario: Только пароль
- **WHEN** `AUTH_METHODS=password` и браузер открывает `GET /auth/google`
- **THEN** ответ `403` `{"error":"auth_method_disabled"}`, на Google редиректа нет

### Requirement: Список способов входа
`GET /auth/methods` SHALL без аутентификации и при любом `AUTH_METHODS` отвечать
`200` `{"methods": [...], "registration": <bool>}`: `methods` — включённые
способы из `password`, `google` (порядок: `password`, `google`), `registration`
— `true`, если включён `password` и `REGISTRATION=open`. Клиенты SHALL по нему
решать, какие кнопки показывать.

#### Scenario: Оба способа
- **WHEN** `AUTH_METHODS=both`, `REGISTRATION=open` и приходит `GET /auth/methods`
- **THEN** ответ `200` `{"methods":["password","google"],"registration":true}`

#### Scenario: Только Google
- **WHEN** `AUTH_METHODS=google`
- **THEN** ответ `200` `{"methods":["google"],"registration":false}`

### Requirement: Режим регистрации
Переменная `REGISTRATION` SHALL принимать `open` или `closed` (по умолчанию
`open`). При `closed` `POST /auth/register` SHALL отвечать `403`
`{"error":"registration_closed"}`; вход существующих пользователей это не
затрагивает. Регистрация через Google в этот режим не входит.

#### Scenario: Регистрация закрыта
- **WHEN** `REGISTRATION=closed` и приходит `POST /auth/register` с корректным телом
- **THEN** ответ `403` `{"error":"registration_closed"}`, учётная запись не создаётся

### Requirement: Регистрация по паролю
`POST /auth/register` SHALL принимать JSON `{"email", "password", "name"?}` и
при допустимых email и пароле создавать пользователя с `email_verified=false`,
ролью `user` и именем из тела (если пусто — часть email до `@`). Сессию
регистрация SHALL NOT выпускать. Ответ SHALL быть одинаковым независимо от того,
свободен ли email: `202` `{"status":"accepted"}`, и при занятом email учётная
запись и пароль SHALL NOT меняться.

#### Scenario: Новый email
- **WHEN** приходит `POST /auth/register` со свободным email и допустимым паролем
- **THEN** ответ `202` `{"status":"accepted"}`, учётная запись создана с `email_verified=false`

#### Scenario: Занятый email
- **WHEN** email уже есть у любого пользователя (в том числе заведённого через Google)
- **THEN** ответ тот же `202` `{"status":"accepted"}`, существующая учётная запись и пароль не меняются

#### Scenario: Роль из ADMIN_EMAILS
- **WHEN** регистрируется email из `ADMIN_EMAILS`
- **THEN** роль учётной записи `user`, потому что email не подтверждён

### Requirement: Проверка email и пароля
Email SHALL приводиться к нижнему регистру и обрезаться по краям; допустимым
SHALL быть адрес вида `local@domain` длиной не более 254 символов. Пароль SHALL
быть длиной от 10 до 128 символов, других требований к составу нет. Нарушения
SHALL отдаваться `400` с JSON `{"error": ...}` в таком порядке проверки: не
JSON — `invalid JSON body`; недопустимый email — `недопустимый email`; пароль
короче 10 или длиннее 128 — `пароль должен быть от 10 до 128 символов`.

#### Scenario: Короткий пароль
- **WHEN** в `POST /auth/register` пароль из 9 символов
- **THEN** ответ `400` `{"error":"пароль должен быть от 10 до 128 символов"}`

#### Scenario: Email в другом регистре
- **WHEN** регистрируется `User@Mail.COM`, а потом входит `user@mail.com`
- **THEN** вход идёт в ту же учётную запись

### Requirement: Хранение пароля
Пароль SHALL храниться только как PBKDF2-HMAC-SHA256 от пароля с солью из 16
случайных байт и числом итераций не меньше 600 000; соль, число итераций и
хэш SHALL храниться вместе, чтобы число итераций можно было повысить, не ломая
старые записи. Сам пароль SHALL NOT записываться ни в БД, ни в журнал, ни в
метрики. Сравнение хэшей SHALL быть за постоянное время.

#### Scenario: Дамп базы
- **WHEN** кто-то читает таблицу учётных данных
- **THEN** там только соль, число итераций и хэш, пароля нет

#### Scenario: Вход после повышения числа итераций
- **WHEN** в записи старое число итераций, а конфигурация требует большее, и пароль верный
- **THEN** вход проходит, хэш пересчитывается с новым числом итераций

### Requirement: Вход по паролю
`POST /auth/login` SHALL принимать JSON `{"email", "password", "device_id"?,
"device_name"?, "platform"?}`. Если `platform` не указан или `web`, вход SHALL
выпускать сессию `platform=web` (новый `device_id` на каждый вход, `device_name`
— `User-Agent`), выставлять cookie сессии и отвечать `200` `{"id", "email",
"name", "picture", "role"}`. Ошибки тела — как в «Проверка email и пароля».

#### Scenario: Вход из браузера
- **WHEN** `POST /auth/login` с верным email и паролем, без `platform`
- **THEN** ответ `200` с профилем и двумя `Set-Cookie` (`session`, `refresh_token`)

### Requirement: Вход по паролю с телефона
Если в `POST /auth/login` `platform` указан и не `web`, `device_id` SHALL быть
обязателен, а ответ — `200` `{"access_token", "refresh_token", "expires_in"}`
без cookie. Допустимые значения и сообщения об ошибке `platform` — как в
`mobile-sign-in`.

#### Scenario: Вход с телефона
- **WHEN** `POST /auth/login` с верными данными, `device_id` и `platform: "android"`
- **THEN** ответ `200` с `access_token`, `refresh_token`, `expires_in`, cookie нет

#### Scenario: Телефон без device_id
- **WHEN** `platform: "android"`, `device_id` не передан
- **THEN** ответ `400` `{"error":"device_id отсутствует"}`

### Requirement: Единый отказ входа
При любом неудачном входе (нет такого email, неверный пароль, у учётной записи
нет пароля, учётная запись только Google) `POST /auth/login` SHALL отвечать
`401` `{"error":"неверный email или пароль"}`, а время ответа SHALL NOT
различаться между «нет такого email» и «неверный пароль» (для несуществующего
email проверка пароля SHALL выполняться на фиктивной записи).

#### Scenario: Неверный пароль
- **WHEN** email существует, пароль не подходит
- **THEN** ответ `401` `{"error":"неверный email или пароль"}`

#### Scenario: Несуществующий email
- **WHEN** такого email нет
- **THEN** ответ тот же `401` с тем же текстом

### Requirement: Защита от перебора
Сервис SHALL считать неудачные входы в Redis по email и по IP клиента (первый адрес в
`X-Forwarded-For`, если заголовок есть, иначе адрес соединения) в фиксированном окне
`AUTH_FAIL_WINDOW_SECS` (по умолчанию 900). Успешный вход SHALL сбрасывать
счётчик по email.

#### Scenario: Успешный вход
- **WHEN** после двух неудач введён верный пароль
- **THEN** вход проходит, счётчик неудач по этому email обнуляется

### Requirement: Что считается попыткой
Каждая попытка регистрации SHALL считаться только по IP, не по email: иначе
чужой адрес можно было бы заблокировать, «регистрируя» его. Неверный
`current_password` в `POST /auth/password` SHALL считаться неудачей по email
учётной записи и по IP, как неверный пароль при входе.

#### Scenario: Регистрация чужого адреса
- **WHEN** с одного IP много раз регистрируют `victim@mail.com`
- **THEN** счётчик по email этого адреса не растёт, и владелец может войти

#### Scenario: Подбор текущего пароля
- **WHEN** в `POST /auth/password` пять раз передан неверный `current_password`
- **THEN** шестая попытка отвечает `429`, пароль не проверяется

### Requirement: Отказ при превышении лимита
Если неудач по email не меньше `AUTH_FAIL_MAX_PER_EMAIL` (по умолчанию 5) или
по IP не меньше `AUTH_FAIL_MAX_PER_IP` (по умолчанию 30), вход и регистрация
SHALL отвечать `429` `{"error":"слишком много попыток — повторите позже"}` с
заголовком `Retry-After` в секундах, а пароль SHALL NOT проверяться.

#### Scenario: Пять неудач подряд
- **WHEN** по одному email пять раз подряд введён неверный пароль
- **THEN** шестая попытка, даже с верным паролем, получает `429` с `Retry-After`

### Requirement: Отказ при недоступном хранилище счётчиков
Недоступность Redis SHALL приводить к ответу `503` на вход и регистрацию, а не к
проверке пароля без лимитов.

#### Scenario: Redis недоступен
- **WHEN** Redis не отвечает
- **THEN** `POST /auth/login` отвечает `503`, пароль не проверяется

### Requirement: Пароль только по защищённому соединению
`POST /auth/register`, `POST /auth/login`, `POST /auth/password` и
`POST /admin/users/{id}/password` SHALL принимать пароль, только если запрос
пришёл с `X-Forwarded-Proto: https`.
Иначе SHALL отвечать `403` `{"error":"insecure_transport"}` без чтения тела,
если не включено `ALLOW_INSECURE_AUTH=true`. При включённом
`ALLOW_INSECURE_AUTH` сервис SHALL при запуске писать в журнал предупреждение
`event=insecure_auth_enabled`.

#### Scenario: Запрос без TLS
- **WHEN** `POST /auth/login` приходит без `X-Forwarded-Proto: https`, `ALLOW_INSECURE_AUTH` не задан
- **THEN** ответ `403` `{"error":"insecure_transport"}`

#### Scenario: Осознанно небезопасный режим
- **WHEN** `ALLOW_INSECURE_AUTH=true`
- **THEN** вход по HTTP принимается, а в журнале при запуске есть `event=insecure_auth_enabled`

### Requirement: Установка и смена пароля
`POST /auth/password` SHALL для принятого токена принимать JSON
`{"password", "current_password"?}`. Если у пользователя пароль уже есть,
`current_password` SHALL быть обязателен и верен, иначе `401`
`{"error":"неверный текущий пароль"}`. Новый пароль SHALL проходить ту же
проверку, что при регистрации. После успеха SHALL отзываться все сессии
пользователя, кроме текущей, и ответ — `204`.

#### Scenario: Смена пароля
- **WHEN** пользователь с паролем вызывает `POST /auth/password` с верным `current_password`
- **THEN** ответ `204`, остальные его сессии больше не обмениваются, текущая жива

### Requirement: Пароль для Google-аккаунта
Для учётной записи, заведённой через Google и не имевшей пароля, вызов
`POST /auth/password` SHALL добавлять пароль, не меняя `google_sub`, email и
`email_verified`.

#### Scenario: Пароль для Google-аккаунта
- **WHEN** пользователь, вошедший через Google, вызывает `POST /auth/password` без `current_password`
- **THEN** ответ `204`, в учётной записи появляется пароль, `email_verified` не меняется

### Requirement: Сброс пароля админом
`POST /admin/users/{id}/password` SHALL быть доступна только роли `admin` (как
остальные `/admin/*`), принимать `{"password"}` и устанавливать пароль
пользователя, отзывая все его сессии, с ответом `204`. Несуществующий
пользователь SHALL давать `404`.

#### Scenario: Админ задаёт новый пароль
- **WHEN** админ вызывает `POST /admin/users/<id>/password`
- **THEN** ответ `204`, все сессии этого пользователя отозваны

#### Scenario: Не админ
- **WHEN** тот же вызов делает пользователь с ролью `user`
- **THEN** ответ `403`

### Requirement: Google забирает неподтверждённый парольный аккаунт
Если вход через Google (браузер или `POST /auth/google/mobile`) приходит с
`email_verified=true` и email совпадает с email учётной записи, у которой
`email_verified=false` и нет `google_sub`, сервис SHALL привязать к ней
`google_sub`, выставить `email_verified=true`, удалить её пароль, отозвать все её
сессии и выпустить новую; страницы подтверждения регистрации в этом случае не
будет. Если у такой учётной записи `email_verified=true`, привязка SHALL NOT
происходить автоматически.

#### Scenario: Предварительная регистрация чужого email
- **WHEN** злоумышленник зарегистрировал `victim@mail.com` с паролем, а владелец почты входит через Google
- **THEN** учётная запись переходит к владельцу, пароль удалён, сессии злоумышленника отозваны

#### Scenario: Google с неподтверждённым email
- **WHEN** `id_token` содержит `email_verified=false`
- **THEN** привязки к парольному аккаунту нет, вход идёт по обычным правилам Google

### Requirement: Журнал и метрики
Каждый вход, регистрация, смена пароля и отказ SHALL писаться одной строкой
журнала с `event=password_login|password_register|password_change|password_reset`,
результатом и причиной, без пароля и без хэша. Сервис SHALL вести счётчики
`password_auth_total` по событию и результату.

#### Scenario: Неверный пароль
- **WHEN** вход отклонён
- **THEN** в журнале строка `event=password_login` с `result=denied`, пароля в строке нет
