# Spec Delta

## Purpose

Вход через Google из браузера: OAuth 2.0 Authorization Code + PKCE, проверка
`id_token` Google и выпуск своей сессии в cookie. Новый Google-аккаунт
получает учётную запись только после явного подтверждения.

## ADDED Requirements

### Requirement: Начало входа
`GET /auth/google` SHALL отвечать редиректом на
`https://accounts.google.com/o/oauth2/v2/auth` с параметрами `client_id`,
`redirect_uri`, `response_type=code`, `scope=openid email profile`, `state`,
`code_challenge` (S256 от одноразового `code_verifier`),
`code_challenge_method=S256`, `access_type=online`, `prompt=select_account`.
Пара `state` → (`code_verifier`, `redirect_uri`) SHALL храниться в памяти
процесса до callback; после рестарта сервиса незавершённые входы теряются.

#### Scenario: Пользователь жмёт «Войти через Google»
- **WHEN** браузер открывает `GET /auth/google`
- **THEN** ответ — редирект на Google с новым `state` и `code_challenge`, и `state` запомнен на сервере

### Requirement: Выбор redirect_uri
`redirect_uri` SHALL строиться как `http://<хост>/auth/google/callback`, где
хост — `X-Forwarded-Host`, а если его нет — `Host`. Хост вида `192.168.x.y[:порт]`
(голый IP) SHALL сначала переписываться в `192.168.x.y.nip.io[:порт]`.
Получившийся адрес SHALL использоваться, только если он есть в
`ALLOWED_REDIRECT_URIS` или совпадает с `REDIRECT_URL`; иначе SHALL
использоваться `REDIRECT_URL` (по умолчанию
`http://localhost:8080/auth/google/callback`). Схема всегда `http`.

#### Scenario: Вход с телефона в LAN
- **WHEN** запрос пришёл через гейтвей с `X-Forwarded-Host: 192.168.1.105:8090`, а `http://192.168.1.105.nip.io:8090/auth/google/callback` есть в `ALLOWED_REDIRECT_URIS`
- **THEN** Google получает этот nip.io-адрес как `redirect_uri`

#### Scenario: Уже nip.io-хост
- **WHEN** `Host: 192.168.1.105.nip.io:8090`
- **THEN** хост не переписывается повторно и сверяется со списком как есть

#### Scenario: Незнакомый хост
- **WHEN** `Host` не даёт адреса из списка
- **THEN** используется `REDIRECT_URL`

### Requirement: Обмен кода в callback
`GET /auth/google/callback` SHALL принимать `code` и `state`, однократно
забирать сохранённую по `state` запись и обменивать `code` на токены в
`https://oauth2.googleapis.com/token` с тем же `redirect_uri` и
`code_verifier`, что ушли в Google при начале входа.

#### Scenario: Повтор старой ссылки
- **WHEN** callback приходит с `state`, который уже использован или неизвестен
- **THEN** ответ — HTML-страница ошибки с текстом «Неизвестный или уже использованный state — возможная CSRF-атака либо повторный переход по старой ссылке. Начните вход заново.»

#### Scenario: Google вернул ошибку
- **WHEN** callback пришёл с параметром `error=access_denied`
- **THEN** ответ — страница ошибки «Google вернул ошибку авторизации: access_denied»

### Requirement: Проверка id_token Google
`id_token` SHALL приниматься, только если его `kid` есть в JWKS Google
(`https://www.googleapis.com/oauth2/v3/certs`), подпись RS256 верна, `exp` не
истёк, `iss` — `https://accounts.google.com` или `accounts.google.com`, `aud`
равен `GOOGLE_CLIENT_ID` и `sub` не пуст.

#### Scenario: Токен для другого клиента
- **WHEN** `id_token` выпущен для чужого `client_id`
- **THEN** вход отклоняется с причиной «неверный audience в id_token»

### Requirement: Запросы к Google
Запросы к Google SHALL идти только по IPv4, с проверкой сертификата
(системное хранилище или `CA_BUNDLE_PATH`) и таймаутами соединения и чтения по
10 с.

#### Scenario: Сеть без исходящего IPv6
- **WHEN** у хоста нет маршрута в интернет по IPv6
- **THEN** обмен кода и загрузка JWKS идут по IPv4 без зависания

### Requirement: Ошибки входа — HTML со статусом 200
Все отказы браузерного входа (ошибка Google, нет `code`/`state`, неизвестный
`state`, сбой обмена, неверный `id_token`, неизвестный confirm-токен) SHALL
отдаваться HTML-страницей «Не удалось войти» с текстом причины и ссылкой
«Попробовать снова» на `/`, со статусом `200`.

#### Scenario: Подпись id_token не прошла
- **WHEN** `id_token` подписан неизвестным ключом
- **THEN** страница содержит «Не удалось верифицировать учётную запись: …», статус `200`

### Requirement: Вход существующего пользователя
Если `sub` из `id_token` уже есть среди пользователей, сервис SHALL обновить
email, `email_verified`, имя, аватар и время последнего входа, выпустить новую
сессию для устройства `platform=web` (новый `device_id` на каждый вход,
`device_name` — `User-Agent`), выставить cookie сессии и ответить редиректом
на `/`.

#### Scenario: Повторный вход
- **WHEN** пользователь с уже заведённым Google-аккаунтом завершает вход
- **THEN** ответ — `302` на `/` с двумя `Set-Cookie` (`session` и `refresh_token`)

### Requirement: Отложенная регистрация
Если `sub` ещё не известен, сервис SHALL NOT создавать пользователя сразу: он
SHALL показать страницу «Аккаунт не найден» с именем, email и аватаром (все
значения HTML-экранированы) и формой `POST /auth/google/confirm-signup` со
скрытым одноразовым `token`. Проверенные claim'ы SHALL храниться в памяти до
подтверждения.

#### Scenario: Имя с разметкой
- **WHEN** имя в Google-профиле содержит `<script>`
- **THEN** на странице оно выводится текстом, а не разметкой

### Requirement: Подтверждение регистрации
`POST /auth/google/confirm-signup` с известным `token` SHALL однократно
создать пользователя, выпустить сессию `platform=web` и ответить редиректом
на `/`.

#### Scenario: Повтор подтверждения
- **WHEN** тот же `token` отправлен второй раз
- **THEN** ответ — страница ошибки «Заявка на регистрацию не найдена или уже обработана — начните вход заново.»

#### Scenario: Новый пользователь подтверждает
- **WHEN** новый пользователь жмёт «Создать аккаунт»
- **THEN** появляется учётная запись, ответ — `302` на `/` с cookie сессии

#### Scenario: Новый пользователь отказывается
- **WHEN** новый пользователь жмёт «Отмена»
- **THEN** учётная запись не создаётся

### Requirement: Стартовая страница
`GET /` SHALL отдавать HTML-страницу с кнопкой «Войти через Google»
(ссылка на `/auth/google`). Через гейтвей `/` обслуживает wallet-web, поэтому
страница видна только при прямом обращении к сервису.

#### Scenario: Прямой заход
- **WHEN** `GET /` на порт сервиса
- **THEN** ответ `200`, `text/html; charset=utf-8`, в теле ссылка `/auth/google`
