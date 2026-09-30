#include "repo.hpp"

#include "nlohmann/json.hpp"
#include "util/uuid.hpp"

using nlohmann::json;

namespace repo {

namespace {

UserRecord row_to_user(const db::Row& row) {
    UserRecord u;
    u.id = row.fields.at(0);
    u.google_sub = row.fields.at(1);
    u.email = row.fields.at(2);
    u.email_verified = row.fields.at(3) == "t" || row.fields.at(3) == "true";
    u.name = row.fields.at(4);
    u.picture = row.fields.at(5);
    u.role = role_from_id(static_cast<int16_t>(std::stoi(row.fields.at(6))));
    u.created_at = row.fields.at(7);
    u.last_login_at = row.fields.at(8); // "" — ни разу не логинился после появления этой колонки
    return u;
}

} // namespace

UserRecord upsert_user(db::Database& db, const std::string& google_sub, const std::string& email,
                        bool email_verified, const std::string& name, const std::string& picture,
                        Role role) {
    // role_id НЕ входит в SET при конфликте — намеренно. email/name/picture
    // легитимно устаревают (человек сменил аватар/имя в Google) и их стоит
    // подтягивать на каждый вход. Роль — другое: это авторизационное
    // решение, а не профильные данные, и его не должен молча переписывать
    // каждый логин. role передаётся сюда только на случай INSERT (первый
    // логин этого google_sub) — вычисляется из ADMIN_EMAILS/SUPPORT_EMAILS
    // (см. auth::compute_role) как роль по умолчанию для НОВОГО
    // пользователя. Если строка уже существует — ON CONFLICT её просто не
    // трогает, role_id сохраняет то значение, что реально лежит в БД (в
    // т.ч. если его правили руками) — см. README, "Роли".
    // last_login_at = now() — и на INSERT (первый логин — created_at И
    // last_login_at совпадают), и на ON CONFLICT UPDATE (каждый повторный
    // логин). В отличие от role_id (авторизационное решение, ON CONFLICT
    // его не трогает — см. комментарий выше), last_login_at — обычные
    // профильные данные "когда видели в последний раз", обновлять их на
    // каждый вход и правильно, и безопасно.
    auto res = db.exec(
        "INSERT INTO users (id, google_sub, email, email_verified, name, picture, role_id, last_login_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7, now()) "
        "ON CONFLICT (google_sub) DO UPDATE SET "
        "  email = EXCLUDED.email, email_verified = EXCLUDED.email_verified, "
        "  name = EXCLUDED.name, picture = EXCLUDED.picture, last_login_at = now() "
        "RETURNING id, google_sub, email, email_verified, name, picture, role_id, created_at, last_login_at",
        {uuidgen::v4(), google_sub, email, email_verified ? "true" : "false", name, picture,
         std::to_string(to_role_id(role))});
    return row_to_user(res.rows.at(0));
}

std::optional<UserRecord> find_user_by_id(db::Database& db, const std::string& id) {
    auto res = db.exec(
        "SELECT id, google_sub, email, email_verified, name, picture, role_id, created_at, last_login_at "
        "FROM users WHERE id = $1",
        {id});
    if (res.rows.empty()) return std::nullopt;
    return row_to_user(res.rows[0]);
}

std::optional<UserRecord> find_user_by_google_sub(db::Database& db, const std::string& google_sub) {
    auto res = db.exec(
        "SELECT id, google_sub, email, email_verified, name, picture, role_id, created_at, last_login_at "
        "FROM users WHERE google_sub = $1",
        {google_sub});
    if (res.rows.empty()) return std::nullopt;
    return row_to_user(res.rows[0]);
}

void delete_user(db::Database& db, const std::string& id) {
    db.exec("DELETE FROM users WHERE id = $1", {id});
}

namespace {

TelegramLink row_to_telegram_link(const db::Row& row) {
    TelegramLink l;
    l.tg_user_id = row.fields.at(0);
    l.user_id = row.fields.at(1);
    l.device_id = row.fields.at(2);
    l.tg_username = row.fields.at(3);
    l.created_at = row.fields.at(4);
    return l;
}

constexpr const char* kTelegramLinkColumns =
    "tg_user_id::text, user_id::text, device_id::text, tg_username, "
    "to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

} // namespace

void upsert_telegram_link(db::Database& db, const TelegramLink& link) {
    db.exec(
        "INSERT INTO telegram_links (tg_user_id, user_id, device_id, tg_username) VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (tg_user_id) DO UPDATE SET user_id = EXCLUDED.user_id, device_id = EXCLUDED.device_id, "
        "tg_username = EXCLUDED.tg_username, created_at = now()",
        {link.tg_user_id, link.user_id, link.device_id, link.tg_username});
}

std::optional<TelegramLink> find_telegram_link(db::Database& db, const std::string& tg_user_id) {
    auto res = db.exec(std::string("SELECT ") + kTelegramLinkColumns + " FROM telegram_links WHERE tg_user_id = $1",
                       {tg_user_id});
    if (res.rows.empty()) return std::nullopt;
    return row_to_telegram_link(res.rows[0]);
}

std::vector<TelegramLink> list_telegram_links(db::Database& db, const std::string& user_id) {
    auto res = db.exec(std::string("SELECT ") + kTelegramLinkColumns +
                           " FROM telegram_links WHERE user_id = $1 ORDER BY created_at",
                       {user_id});
    std::vector<TelegramLink> out;
    for (const auto& row : res.rows) out.push_back(row_to_telegram_link(row));
    return out;
}

bool delete_telegram_link(db::Database& db, const std::string& user_id, const std::string& tg_user_id) {
    auto res = db.exec("DELETE FROM telegram_links WHERE user_id = $1 AND tg_user_id = $2 RETURNING tg_user_id",
                       {user_id, tg_user_id});
    return !res.rows.empty();
}

std::optional<TelegramLink> delete_telegram_link_by_tg(db::Database& db, const std::string& tg_user_id) {
    auto res = db.exec(std::string("DELETE FROM telegram_links WHERE tg_user_id = $1 RETURNING ") +
                           kTelegramLinkColumns,
                       {tg_user_id});
    if (res.rows.empty()) return std::nullopt;
    return row_to_telegram_link(res.rows[0]);
}

std::vector<UserRecord> list_users(db::Database& db) {
    auto res = db.exec(
        "SELECT id, google_sub, email, email_verified, name, picture, role_id, created_at, last_login_at "
        "FROM users ORDER BY email");
    std::vector<UserRecord> out;
    out.reserve(res.rows.size());
    for (auto& row : res.rows) out.push_back(row_to_user(row));
    return out;
}

namespace {
// Разные префиксы — чтобы access- и refresh-токены не путались, живя в
// одном и том же Redis под разными ключами.
std::string refresh_token_key(const std::string& token_hash) {
    return "refresh_token:" + token_hash;
}
std::string access_token_key(const std::string& token_hash) {
    return "access_token:" + token_hash;
}
// Обратные индексы для revoke_all_user_tokens() — множества хэшей токенов
// конкретного user_id (см. её комментарий в repo.hpp).
std::string user_refresh_index_key(const std::string& user_id) {
    return "user_refresh_tokens:" + user_id;
}
std::string user_access_index_key(const std::string& user_id) {
    return "user_access_tokens:" + user_id;
}

// Общий разбор JSON-значения ключа refresh_token:<hash> — тот же формат,
// что кладёт store_refresh_token, и та же терпимость к дотиконовому/
// доpairing-у форматам (голый user_id без JSON вовсе, либо JSON без
// access_token_hash — сессии, выпущенные до появления этого поля), что и в
// take_refresh_token: списку устройств не нужен user_id (он и так известен
// вызывающей стороне), поэтому здесь заполняются только device и
// access_token_hash — отсутствие любого из них молча даёт пустую строку,
// а не бросает исключение.
void fill_session_fields(const std::string& raw, DeviceInfo& device, std::string& access_token_hash) {
    try {
        json value = json::parse(raw);
        device.device_id = value.value("device_id", std::string{});
        device.device_name = value.value("device_name", std::string{});
        device.platform = value.value("platform", std::string{});
        access_token_hash = value.value("access_token_hash", std::string{});
    } catch (const std::exception&) {
        // старый формат (голый user_id) — устройство и связка неизвестны, не ошибка
    }
}
} // namespace

void store_refresh_token(redis::Client& redis, const std::string& token_hash,
                          const std::string& user_id, const DeviceInfo& device,
                          const std::string& access_token_hash, uint64_t ttl_secs) {
    // JSON, а не голый user_id — см. комментарий в repo.hpp. Пустые поля
    // DeviceInfo просто лягут в JSON пустыми строками, take_refresh_token их
    // так и вернёт (браузерный вход отличим от мобильного по пустому
    // device_id).
    json value = {
        {"user_id", user_id},
        {"device_id", device.device_id},
        {"device_name", device.device_name},
        {"platform", device.platform},
        {"access_token_hash", access_token_hash},
    };
    redis.set_ex(refresh_token_key(token_hash), value.dump(), ttl_secs);
    // Индекс живёт не дольше самого долгоживущего токена, который в нём
    // мог бы упомянуться — EXPIRE тут выставляется заново на каждый выпуск,
    // поэтому только продлевается, никогда не укорачивается досрочно.
    std::string index_key = user_refresh_index_key(user_id);
    redis.sadd(index_key, token_hash);
    redis.expire(index_key, ttl_secs);
}

std::optional<RefreshTokenOwner> take_refresh_token(redis::Client& redis, db::Database& db,
                                                     const std::string& token_hash) {
    // GETDEL — атомарно и читает, и удаляет; Redis сам не отдаст то, что уже
    // истекло по TTL (в отличие от прежней Postgres-реализации, там
    // приходилось вручную сверять expires_at после DELETE). Хэш при этом
    // остаётся висеть в user_refresh_tokens:<id> — не страшно, см.
    // revoke_all_user_tokens() в repo.hpp.
    auto raw = redis.getdel(refresh_token_key(token_hash));
    if (!raw) return std::nullopt;

    // Инстансы, поднятые до появления DeviceInfo/access_token_hash, могли
    // оставить в Redis более старый формат — переживших свой TTL (максимум
    // REFRESH_TOKEN_TTL_SECS с прошлого релиза) уже не осталось бы, но на
    // всякий случай не падаем, а трактуем как "устройство/связка неизвестны".
    // user_id разбирается отдельно (fill_session_fields его не трогает — он
    // не нужен списку устройств, см. её комментарий), с тем же фоллбэком на
    // "голая строка — это и есть user_id" для самого древнего формата.
    std::string user_id;
    DeviceInfo device;
    std::string access_token_hash;
    try {
        json value = json::parse(*raw);
        user_id = value.value("user_id", std::string{});
    } catch (const std::exception&) {
        user_id = *raw;
    }
    fill_session_fields(*raw, device, access_token_hash);
    if (user_id.empty()) return std::nullopt;

    auto user = find_user_by_id(db, user_id);
    if (!user) return std::nullopt;
    return RefreshTokenOwner{*user, device};
}

void revoke_refresh_token(redis::Client& redis, const std::string& token_hash) {
    redis.del(refresh_token_key(token_hash));
}

void store_access_token(redis::Client& redis, const std::string& token_hash,
                         const std::string& user_id, uint64_t ttl_secs) {
    redis.set_ex(access_token_key(token_hash), user_id, ttl_secs);
    std::string index_key = user_access_index_key(user_id);
    redis.sadd(index_key, token_hash);
    redis.expire(index_key, ttl_secs);
}

bool is_access_token_active(redis::Client& redis, const std::string& token_hash) {
    return redis.exists(access_token_key(token_hash));
}

void revoke_access_token(redis::Client& redis, const std::string& token_hash) {
    redis.del(access_token_key(token_hash));
}

std::vector<SessionSummary> list_user_sessions(redis::Client& redis, const std::string& user_id) {
    std::string index_key = user_refresh_index_key(user_id);
    std::vector<SessionSummary> out;
    for (const auto& hash : redis.smembers(index_key)) {
        auto raw = redis.get(refresh_token_key(hash));
        if (!raw) {
            // Ключ истёк по TTL сам — висячая ссылка в индексе, подчищаем
            // заодно (см. комментарий в repo.hpp).
            redis.srem(index_key, hash);
            continue;
        }
        SessionSummary session;
        session.token_hash = hash;
        fill_session_fields(*raw, session.device, session.access_token_hash);
        out.push_back(std::move(session));
    }
    return out;
}

int revoke_user_sessions_if(redis::Client& redis, const std::string& user_id,
                             const std::function<bool(const SessionSummary&)>& predicate) {
    std::string index_key = user_refresh_index_key(user_id);
    int revoked = 0;
    for (const auto& hash : redis.smembers(index_key)) {
        auto raw = redis.get(refresh_token_key(hash));
        if (!raw) {
            redis.srem(index_key, hash); // тот же попутный уход за индексом, что и в list_user_sessions
            continue;
        }
        SessionSummary session;
        session.token_hash = hash;
        fill_session_fields(*raw, session.device, session.access_token_hash);
        if (!predicate(session)) continue;

        redis.del(refresh_token_key(hash));
        redis.srem(index_key, hash);
        // Парный access-токен — см. комментарий в repo.hpp: без этого отзыв
        // сессии оставлял бы её access-токен рабочим (в этом сервисе, см.
        // is_access_token_active) до его собственного TTL, хотя refresh уже
        // мёртв. Пусто — сессия старого формата (до этого поля), просто
        // нечего гасить адресно, не ошибка.
        if (!session.access_token_hash.empty()) {
            redis.del(access_token_key(session.access_token_hash));
            redis.srem(user_access_index_key(user_id), session.access_token_hash);
        }
        ++revoked;
    }
    return revoked;
}

void revoke_all_user_tokens(redis::Client& redis, const std::string& user_id) {
    std::string access_index = user_access_index_key(user_id);
    std::string refresh_index = user_refresh_index_key(user_id);

    for (const auto& hash : redis.smembers(access_index)) {
        redis.del(access_token_key(hash));
    }
    for (const auto& hash : redis.smembers(refresh_index)) {
        redis.del(refresh_token_key(hash));
    }
    redis.del(access_index);
    redis.del(refresh_index);
}

} // namespace repo
