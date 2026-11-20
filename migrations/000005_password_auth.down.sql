-- Откат возможен, только пока нет пользователей без google_sub: вернуть
-- NOT NULL при таких строках нельзя, а удалять чужие учётные записи откат не
-- должен. Сначала такие пользователи удаляются осознанно вручную.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE google_sub IS NULL) THEN
        RAISE EXCEPTION
            'откат 000005 невозможен: есть пользователи без google_sub (вход только по паролю) — удалите их или привяжите Google, затем повторите';
    END IF;
END
$$;

DROP INDEX IF EXISTS users_password_email_uniq;
DROP INDEX IF EXISTS users_email_lower_idx;
ALTER TABLE users ALTER COLUMN google_sub SET NOT NULL;
COMMENT ON COLUMN users.google_sub IS
    '"sub" из Google ID-токена — уникальный, неизменный идентификатор Google-аккаунта; ключ поиска пользователя при входе.';
COMMENT ON COLUMN users.email IS 'Email из Google-профиля — кэш на момент последнего входа, может устаревать.';
COMMENT ON COLUMN users.email_verified IS
    'Подтверждён ли email в Google-аккаунте (claim email_verified самого Google ID-токена на момент входа).';
DROP TABLE IF EXISTS user_passwords;
