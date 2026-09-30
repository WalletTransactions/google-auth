-- Перенесено из infra/db/init-db.sh (там раньше была вся схема — теперь тот
-- скрипт только заводит роли/базы и права, см. его шапку и infra/db/README.md,
-- "Схема / миграции"). Права DML для AUTH_POSTGRES_USER на будущие таблицы
-- этой схемы уже выданы в init-db.sh (ALTER DEFAULT PRIVILEGES) ДО того, как
-- этот файл вообще накатывается — накатывает его та же роль-мигратор,
-- поэтому порядок этот важен и уже соблюдён (см. infra/db/README.md).

-- Справочник ролей — id зафиксированы и совпадают с
-- google-auth/src/types.hpp::to_role_id()/role_from_id(). Менять их можно
-- только синхронно в обоих местах.
CREATE TABLE roles (
    id SMALLINT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);
INSERT INTO roles (id, code, description) VALUES
    (1, 'user', 'видит и правит только свои кошельки'),
    (2, 'support', 'read-only доступ к кошелькам всех пользователей'),
    (3, 'admin', 'полный доступ ко всем кошелькам, включая удаление');

CREATE TABLE users (
    id UUID PRIMARY KEY,
    google_sub TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    name TEXT NOT NULL,
    picture TEXT NOT NULL DEFAULT '',
    role_id SMALLINT NOT NULL DEFAULT 1 REFERENCES roles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- refresh_tokens сюда сознательно не перенесены — они переехали в Redis
-- (см. google-auth/README.md, "Персистентность"), в Postgres для этого
-- сервиса больше не нужны.
