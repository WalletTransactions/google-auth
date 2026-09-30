-- Описания таблиц и колонок как настоящие Postgres-комментарии (COMMENT ON)
-- — та же правка, что и wallet/000003_comments.up.sql, см. её шапку почему
-- отдельной миграцией, а не правкой уже накаченной 000001.

COMMENT ON TABLE roles IS
    'Справочник ролей доступа. id зафиксированы и совпадают с google-auth/src/types.hpp::to_role_id()/role_from_id() — менять можно только синхронно в обоих местах.';
COMMENT ON COLUMN roles.id IS
    'Числовой id роли, ровно тот же, что кладётся в claim "role_id" внутреннего представления и что возвращает to_role_id() (1=user, 2=support, 3=admin).';
COMMENT ON COLUMN roles.code IS
    'Короткий код роли (''user''/''support''/''admin'') — именно он попадает в claim "role" выпускаемого access-JWT.';
COMMENT ON COLUMN roles.description IS 'Человекочитаемое описание прав роли — для админки и логов, не читается кодом.';

COMMENT ON TABLE users IS
    'Пользователь, вошедший через Google. Пароля нет и не предполагается — google-auth проверяет Google ID-токен и выдаёт свой JWT.';
COMMENT ON COLUMN users.id IS
    'Внутренний идентификатор пользователя (UserRecord.id) — именно он попадает в claim "sub" access-JWT и используется как app_user.id/device.user_id в wallet-api.';
COMMENT ON COLUMN users.google_sub IS
    '"sub" из Google ID-токена — уникальный, неизменный идентификатор Google-аккаунта; ключ поиска пользователя при входе.';
COMMENT ON COLUMN users.email IS 'Email из Google-профиля — кэш на момент последнего входа, может устаревать.';
COMMENT ON COLUMN users.email_verified IS
    'Подтверждён ли email в Google-аккаунте (claim email_verified самого Google ID-токена на момент входа).';
COMMENT ON COLUMN users.name IS 'Отображаемое имя пользователя из Google-профиля.';
COMMENT ON COLUMN users.picture IS 'URL аватара из Google-профиля; пустая строка, если Google его не прислал.';
COMMENT ON COLUMN users.role_id IS 'Ссылка на roles.id — уровень доступа пользователя, по умолчанию 1 (user).';
COMMENT ON COLUMN users.created_at IS 'Момент первого входа (создания записи пользователя).';
