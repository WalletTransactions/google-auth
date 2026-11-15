# Spec Delta

## MODIFIED Requirements

### Requirement: Начало входа
`GET /auth/google` SHALL при `AUTH_METHODS` `google` или `both` отвечать редиректом на
`https://accounts.google.com/o/oauth2/v2/auth` с параметрами `client_id`,
`redirect_uri`, `response_type=code`, `scope=openid email profile`, `state`,
`code_challenge` (S256 от одноразового `code_verifier`),
`code_challenge_method=S256`, `access_type=online`, `prompt=select_account`.
Пара `state` → (`code_verifier`, `redirect_uri`) SHALL храниться в памяти
процесса до callback; после рестарта сервиса незавершённые входы теряются.
При `AUTH_METHODS=password` ручка SHALL отвечать `403`
`{"error":"auth_method_disabled"}` (см. `password-auth`).

#### Scenario: Пользователь жмёт «Войти через Google»
- **WHEN** браузер открывает `GET /auth/google`
- **THEN** ответ — редирект на Google с новым `state` и `code_challenge`, и `state` запомнен на сервере

#### Scenario: Google отключён настройкой
- **WHEN** `AUTH_METHODS=password` и браузер открывает `GET /auth/google`
- **THEN** ответ `403` `{"error":"auth_method_disabled"}`, на Google редиректа нет

### Requirement: Выбор redirect_uri
`redirect_uri` SHALL строиться как `<схема>://<хост>/auth/google/callback`, где
хост — `X-Forwarded-Host`, а если его нет — `Host`, а схема — `https`, если
пришёл `X-Forwarded-Proto: https`, иначе `http`. Хост вида `192.168.x.y[:порт]`
(голый IP) SHALL сначала переписываться в `192.168.x.y.nip.io[:порт]`.
Получившийся адрес SHALL использоваться, только если он есть в
`ALLOWED_REDIRECT_URIS` или совпадает с `REDIRECT_URL`; иначе SHALL
использоваться `REDIRECT_URL` (по умолчанию
`http://localhost:8080/auth/google/callback`).

#### Scenario: Вход с телефона в LAN
- **WHEN** запрос пришёл через гейтвей с `X-Forwarded-Host: 192.168.1.105:8090`, а `http://192.168.1.105.nip.io:8090/auth/google/callback` есть в `ALLOWED_REDIRECT_URIS`
- **THEN** Google получает этот nip.io-адрес как `redirect_uri`

#### Scenario: Уже nip.io-хост
- **WHEN** `Host: 192.168.1.105.nip.io:8090`
- **THEN** хост не переписывается повторно и сверяется со списком как есть

#### Scenario: Незнакомый хост
- **WHEN** `Host` не даёт адреса из списка
- **THEN** используется `REDIRECT_URL`

#### Scenario: Вход через TLS
- **WHEN** запрос пришёл с `X-Forwarded-Host: wallet.example.com` и `X-Forwarded-Proto: https`, а `https://wallet.example.com/auth/google/callback` есть в `ALLOWED_REDIRECT_URIS`
- **THEN** Google получает этот https-адрес как `redirect_uri`

### Requirement: Отложенная регистрация
Если `sub` ещё не известен, сервис SHALL NOT создавать пользователя сразу: он
SHALL показать страницу «Аккаунт не найден» с именем, email и аватаром (все
значения HTML-экранированы) и формой `POST /auth/google/confirm-signup` со
скрытым одноразовым `token`. Проверенные claim'ы SHALL храниться в памяти до
подтверждения. Исключение: если `email_verified=true` и email совпадает с
неподтверждённой парольной учётной записью без `google_sub`, сервис SHALL
привязать её (см. `password-auth`), выпустить сессию `platform=web` и
ответить редиректом на `/`, не показывая эту страницу.

#### Scenario: Имя с разметкой
- **WHEN** имя в Google-профиле содержит `<script>`
- **THEN** на странице оно выводится текстом, а не разметкой

#### Scenario: Email занят неподтверждённым парольным аккаунтом
- **WHEN** новый для Google `sub` приходит с `email_verified=true`, а такой email есть у парольной учётной записи с `email_verified=false`
- **THEN** ответ — `302` на `/` с cookie сессии, страницы «Аккаунт не найден» нет, пароль той записи удалён

### Requirement: Стартовая страница
`GET /` SHALL отдавать HTML-страницу со ссылками на доступные способы входа:
кнопка «Войти через Google» (ссылка на `/auth/google`) при `AUTH_METHODS`
`google` или `both`; при `password` или `both` — подсказка, что вход по паролю
выполняется через `POST /auth/login`. Через гейтвей `/` обслуживает wallet-web, поэтому
страница видна только при прямом обращении к сервису.

#### Scenario: Прямой заход
- **WHEN** `GET /` на порт сервиса при `AUTH_METHODS=both`
- **THEN** ответ `200`, `text/html; charset=utf-8`, в теле ссылка `/auth/google`

#### Scenario: Только пароль
- **WHEN** `GET /` при `AUTH_METHODS=password`
- **THEN** в теле нет ссылки `/auth/google`
