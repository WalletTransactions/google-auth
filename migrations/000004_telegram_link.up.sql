-- Связка Telegram-пользователя с пользователем кошелька — в google-auth, а
-- не в базе бота (servers/TODO_telegram_tokens.md, шаг 4). Бот по ней
-- получает короткий токен на команду (POST /internal/telegram/token
-- {tg_user_id}) вместо хранения refresh-токена каждого пользователя.
-- Бот, даже скомпрометированный, получает токены только для тех, кто сам
-- связал чат из веба.
--
-- Создаётся обменом одноразового кода (POST /internal/telegram/exchange),
-- удаляется из веба (DELETE /auth/telegram/links/:tg_user_id), /unlink в
-- боте или вместе с пользователем (ON DELETE CASCADE).
CREATE TABLE telegram_links (
    -- id Telegram-пользователя (from.id апдейта) — ключ: один Telegram-аккаунт
    -- связан ровно с одним пользователем. Повторное связывание с другим
    -- пользователем заменяет строку.
    tg_user_id  BIGINT      PRIMARY KEY CHECK (tg_user_id > 0),
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Устройство бота в wallet-api (device.platform = telegram): от его имени
    -- записываются операции (updated_by). Детерминирован от (user_id,
    -- tg_user_id), см. google-auth/src/telegram.cpp, device_id_for.
    device_id   UUID        NOT NULL,
    -- Только для показа в вебе («Telegram @username»), не для идентификации.
    tg_username TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- «Какие Telegram-аккаунты связаны со мной» — список в вебе.
CREATE INDEX telegram_links_user_id_idx ON telegram_links (user_id);

COMMENT ON TABLE telegram_links IS
    'Связка Telegram-пользователя с пользователем кошелька: по ней бот получает короткий токен со scope reports:read expense:write.';
COMMENT ON COLUMN telegram_links.tg_user_id IS 'from.id Telegram — проставляют серверы Telegram, при long polling не подделывается.';
COMMENT ON COLUMN telegram_links.device_id IS 'Устройство бота в wallet-api (device.platform = telegram), попадает в claim device_id токена бота.';
