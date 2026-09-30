-- Обратный порядок относительно up: users ссылается на roles (FK role_id),
-- удалять нужно сначала зависимую таблицу.
DROP TABLE users;
DROP TABLE roles;
