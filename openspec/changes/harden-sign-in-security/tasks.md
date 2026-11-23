# Tasks

## 1. Страница ошибки

- [x] 1.1 `pages::error` экранирует текст причины, `html_escape` — ещё и `'`; проверить юнит-тестом `tests/test_pages.cpp` (`ctest`)

## 2. Связки Telegram

- [x] 2.1 `repo::delete_all_telegram_links`; вызвать из `auth::claim_password_account` и `POST /admin/users/{id}/password`; проверить интеграционным `it_claim_takes_squatted_account_and_revokes_sessions` на временных Postgres+Redis
- [ ] 2.2 На test: `curl '…/auth/google/callback?error=%3Cb%3Ex'` — на странице `&lt;b&gt;x`, не жирный текст; сброс пароля админом пользователю с привязанным ботом — бот просит привязать заново

## 3. Спеки

- [x] 3.1 `openspec validate harden-sign-in-security --strict`
- [ ] 3.2 Архивировать change после проверки на test
