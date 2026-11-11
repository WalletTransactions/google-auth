# Proposal

## Why

Новый необязательный сервис `wallet-docs` отвечает на вопросы о системе по OpenSpec-спекам.
Гейтвей пускает на `/api/docs/*` только токены с `aud` ∋ `wallet-docs`, а сам сервис решает,
что показать: по `role` (админ видит всё) и `platform` (`android` или `web`). Сейчас в
access-токен адресат `wallet-docs` не попадает, и вход клиентов к сервису закрыт.

## What Changes

- В `aud` access-токена, выдаваемого пользователю (Google-вход в браузере и на Android,
  обмен refresh), добавляется `wallet-docs`; в `scope` — `docs:ask`.
- Токены бота Telegram и токены, полученные обменом (wallet-ai, wallet-mcp), **не**
  получают ни адресата, ни scope.
- Существующие claim'ы (`role`, `platform`, `device_id`) не меняются: wallet-docs берёт
  из них роль и клиент.
- Изменения аддитивны: потребители, которые проверяют свой адресат (`wallet-api`,
  `wallet-report`, `wallet-ai`), лишний элемент `aud` игнорируют.

## Capabilities

### New Capabilities

### Modified Capabilities
- `session-tokens`: состав `aud` и `scope` пользовательского access-токена.

## Impact

- **google-auth**: выпуск access-JWT, тест состава claim'ов, `openapi.yaml` (если описывает `aud`/`scope`), README.
- **Потребители токена**: wallet-gateway (change `docs-route`), wallet-docs — выкатываются позже.
- Уже выданные токены живут до 15 минут без нового адресата; после обновления токена
  клиент получает доступ к docs.
