-- Вход по email и паролю (change add-password-auth): учётные данные — в
-- отдельной таблице, а не колонкой в users. Хэш так не попадает в выборки
-- users (список админа, /auth/me) по недосмотру, а при Google-захвате
-- парольного аккаунта и при удалении пользователя строка уходит целиком
-- (DELETE / ON DELETE CASCADE).
--
-- algo — идентификатор алгоритма, чтобы позже перейти (например, на argon2id)
-- без поломки существующих записей; пока единственное значение — pbkdf2-sha256.
CREATE TABLE user_passwords (
    user_id    UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    algo       TEXT        NOT NULL DEFAULT 'pbkdf2-sha256',
    salt       BYTEA       NOT NULL,
    iterations INTEGER     NOT NULL CHECK (iterations > 0),
    hash       BYTEA       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Пользователь без Google (только пароль) не имеет google_sub. UNIQUE остаётся:
-- в Postgres несколько NULL в UNIQUE допустимы.
ALTER TABLE users ALTER COLUMN google_sub DROP NOT NULL;

-- Поиск по email при входе, регистрации и привязке Google. Не UNIQUE: у уже
-- заведённых пользователей email мог повториться (разные google_sub), а
-- уникальность новых проверяется кодом (create_password_user).
CREATE INDEX users_email_lower_idx ON users (lower(email));

-- Среди пользователей без Google (только пароль) email уникален без учёта
-- регистра: две одновременные регистрации одного адреса не создадут дубль.
-- Частичный индекс не мешает уже существующим Google-пользователям с общим
-- email; пересечение «парольный ↔ Google» проверяет код (create_password_user).
CREATE UNIQUE INDEX users_password_email_uniq ON users (lower(email)) WHERE google_sub IS NULL;

COMMENT ON TABLE user_passwords IS
    'Учётные данные входа по паролю: только соль, число итераций и хэш PBKDF2 — сам пароль не хранится. Строка удаляется при Google-захвате аккаунта и вместе с пользователем.';
COMMENT ON COLUMN user_passwords.algo IS 'Алгоритм хэширования; пока только pbkdf2-sha256 (PBKDF2-HMAC-SHA256).';
COMMENT ON COLUMN user_passwords.salt IS 'Случайная соль, 16 байт.';
COMMENT ON COLUMN user_passwords.iterations IS 'Число итераций PBKDF2 при создании хэша; при входе устаревшее число пересчитывается.';
COMMENT ON COLUMN user_passwords.hash IS 'PBKDF2-HMAC-SHA256(пароль, соль, iterations), 32 байта.';
COMMENT ON COLUMN user_passwords.updated_at IS 'Момент установки или последней смены пароля.';
COMMENT ON COLUMN users.google_sub IS
    'Идентификатор Google (sub). NULL у пользователей, заведённых только по паролю; привязывается при входе через Google с тем же подтверждённым email.';
COMMENT ON COLUMN users.email IS
    'Email пользователя: из Google-профиля (кэш на момент последнего входа) либо введённый при регистрации по паролю; хранится в нижнем регистре у парольных учётных записей.';
COMMENT ON COLUMN users.email_verified IS
    'Подтверждён ли email: true — подтвердил Google (claim email_verified); false — введён при регистрации по паролю без проверки, такая учётная запись всегда получает роль user.';
