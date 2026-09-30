-- Откат 000002_comments.up.sql — снимает все COMMENT ON (единственный способ
-- убрать комментарий в Postgres, DROP COMMENT не существует), не трогая
-- таблицы/данные.

COMMENT ON TABLE roles IS NULL;
COMMENT ON COLUMN roles.id IS NULL;
COMMENT ON COLUMN roles.code IS NULL;
COMMENT ON COLUMN roles.description IS NULL;

COMMENT ON TABLE users IS NULL;
COMMENT ON COLUMN users.id IS NULL;
COMMENT ON COLUMN users.google_sub IS NULL;
COMMENT ON COLUMN users.email IS NULL;
COMMENT ON COLUMN users.email_verified IS NULL;
COMMENT ON COLUMN users.name IS NULL;
COMMENT ON COLUMN users.picture IS NULL;
COMMENT ON COLUMN users.role_id IS NULL;
COMMENT ON COLUMN users.created_at IS NULL;
