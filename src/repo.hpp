// Типизированный слой поверх db::Database (users) и redis::Client
// (access/refresh-токены) — auth.cpp/admin.cpp работают с UserRecord, а не с
// сырыми Row/SQL/RESP. Отдельный файл специально: если бэкенд любого из них
// снова сменится, меняются только реализации нужных функций здесь —
// auth.cpp это не заметит.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "db.hpp"
#include "redis_client.hpp"
#include "types.hpp"

namespace repo {

// Заводит пользователя, если его ещё нет (по google_sub), либо обновляет
// изменившиеся поля у существующего — атомарно, одним UPSERT. `id`
// назначается один раз при первом появлении и дальше никогда не меняется
// (ON CONFLICT не трогает существующий id).
UserRecord upsert_user(db::Database& db, const std::string& google_sub, const std::string& email,
                        bool email_verified, const std::string& name, const std::string& picture,
                        Role role);

std::optional<UserRecord> find_user_by_id(db::Database& db, const std::string& id);
std::optional<UserRecord> find_user_by_google_sub(db::Database& db, const std::string& google_sub);

// Жёсткое удаление — самообслуживание (см. DELETE /auth/me, auth.cpp) и,
// возможно позже, админ-инструмент. На users ссылается только
// telegram_links.user_id (ON DELETE CASCADE, миграция auth/000004) — связки
// Telegram пользователя удаляются вместе с ним.
// Токены пользователя (Redis) сюда не входят — их отзывает
// repo::revoke_all_user_tokens ДО этого вызова (см. auth.cpp): иначе между
// удалением строки и отзывом токенов остаётся окно, где ещё не истёкший
// access-токен продолжает проходить authenticate() для уже не существующего
// пользователя. Не бросает, если id уже не существует (DELETE ... WHERE
// не находит строк — это не ошибка, а idempotent-повтор).
void delete_user(db::Database& db, const std::string& id);

// Все пользователи — для админ-страницы (см. admin.cpp/pages::admin_users).
// Сортировка по email тут чисто для детерминированности ответа; итоговую
// сортировку по любому столбцу делает браузер кликом по заголовку.
std::vector<UserRecord> list_users(db::Database& db);

// Связки Telegram ↔ пользователь (таблица telegram_links, миграция
// auth/000004; org/docs/TODO_telegram_tokens.md, шаг 4). tg_user_id — строка
// из цифр (см. telegram::detail::normalize_tg_user_id).
struct TelegramLink {
    std::string tg_user_id;
    std::string user_id;
    std::string device_id;
    std::string tg_username;
    std::string created_at;
};

// Вставка или замена: повторное связывание того же Telegram-аккаунта (в т.ч.
// с другим пользователем) перезаписывает строку.
void upsert_telegram_link(db::Database& db, const TelegramLink& link);
std::optional<TelegramLink> find_telegram_link(db::Database& db, const std::string& tg_user_id);
std::vector<TelegramLink> list_telegram_links(db::Database& db, const std::string& user_id);
// Удаляет, только если связка принадлежит user_id: чужой tg_user_id — false.
bool delete_telegram_link(db::Database& db, const std::string& user_id, const std::string& tg_user_id);
// Удаляет по одному tg_user_id (/unlink из самого Telegram — там владелец
// связки и есть этот Telegram-аккаунт). Возвращает удалённую строку.
std::optional<TelegramLink> delete_telegram_link_by_tg(db::Database& db, const std::string& tg_user_id);

// Refresh-токены — в Redis, не в Postgres (переехали вместе с
// access-токенами — см. README google-auth, "Персистентность"): та же пара
// причин, что и у access-токенов, только острее — здесь TTL не 15 минут, а
// REFRESH_TOKEN_TTL_SECS (30 дней по умолчанию), и Redis-EXPIRE избавляет от
// накопления просроченного мусора, которым раньше (в Postgres) обрастала
// таблица refresh_tokens между использованиями токена. Персистентность
// Redis обязательна именно для этих ключей (AOF + volume, см.
// compose.yaml) — в отличие от access-токенов, потеря refresh-токенов при
// пересоздании контейнера разлогинила бы ВСЕХ пользователей на 30 дней
// вперёд, а не даёт самоисправиться за 15 минут.
// device — см. DeviceInfo (types.hpp): значение в Redis теперь не голый
// user_id, а JSON {"user_id","device_id","device_name","platform",
// "access_token_hash"} — так take_refresh_token ниже может вернуть
// устройство обратно и передать его в новую пару при ротации (см.
// auth::rotate_refresh_token), иначе "какое это устройство" терялось бы уже
// на первом /auth/refresh. access_token_hash — хэш access-токена, выпущенного
// В ЭТОЙ ЖЕ паре (см. auth::issue_tokens) — единственная надёжная связка
// "эта refresh-сессия ↔ её access-токен": device_id её не заменяет (у
// браузерных сессий он всегда пуст, и без этой связки нечем отличить ОДИН
// конкретный браузерный access-токен от access-токенов других сессий того
// же пользователя). Только благодаря этому полю revoke_user_sessions_if
// ниже может погасить не только refresh-, но и парный access-токен именно
// ЭТОЙ сессии, а не только "по совпадению device_id".
void store_refresh_token(redis::Client& redis, const std::string& token_hash,
                          const std::string& user_id, const DeviceInfo& device,
                          const std::string& access_token_hash, uint64_t ttl_secs);

// GETDEL — атомарно читает И удаляет запись ОДНОЙ командой (взамен
// "DELETE ... RETURNING" в прежней Postgres-реализации): токен одноразовый,
// повторное предъявление уже не найдёт ничего. nullopt от Redis (ключа
// нет — не существовал или истёк по TTL) -> сразу nullopt, до Postgres не
// доходим. Если токен был — value это user_id, но САМ UserRecord (email,
// role и т.п.) по-прежнему живёт в Postgres (см. find_user_by_id выше),
// поэтому нужен ещё один поход туда — этим отличается от access-токенов,
// которым отдельный UserRecord не требуется (там валидность и так уже
// подтверждена подписью JWT).
// Пара "пользователь + устройство, которому был выпущен этот refresh-токен"
// — см. DeviceInfo (types.hpp) и комментарий у store_refresh_token выше.
struct RefreshTokenOwner {
    UserRecord user;
    DeviceInfo device;
};

std::optional<RefreshTokenOwner> take_refresh_token(redis::Client& redis, db::Database& db,
                                                     const std::string& token_hash);

void revoke_refresh_token(redis::Client& redis, const std::string& token_hash);

// Активные access-токены — тоже в Redis (см. AppState::redis, README
// "Персистентность"): естественный TTL (Redis EXPIRE сам удаляет запись) и
// самый высокий churn — новая запись на каждый логин/рефреш. Ключом и здесь
// служит хэш токена (не сам JWT), тем же приёмом, что и у refresh-токенов
// выше (см. hash_token() в auth.cpp); значение — user_id, оно не участвует в
// проверке (проверяется только сам факт наличия ключа), но пригодится на
// будущее (например, "показать активные сессии пользователя"). В отличие от
// refresh-токенов, потеря этих записей не критична (см. комментарий выше) —
// поэтому им хватает и обычного TTL без пристального внимания к
// персистентности самого Redis.
//
// TTL передаётся явно (а не берётся из payload access-токена) — это разные
// вещи: TTL самого JWT (claim "exp") наружу этот код не смотрит вообще,
// вызывающая сторона (auth::issue_tokens) передаёт то же значение
// (state.access_token_ttl_secs), которым подписан токен, но могла бы в
// принципе передать и другое.
void store_access_token(redis::Client& redis, const std::string& token_hash,
                         const std::string& user_id, uint64_t ttl_secs);

// true — токен выпущен и ещё не отозван logout'ом и не истёк по TTL в Redis.
// Используется в auth::authenticate() ДОПОЛНИТЕЛЬНО к проверке подписи/exp
// самого JWT — это и даёт мгновенный отзыв, а не только естественное
// истечение (см. revoke_access_token ниже).
bool is_access_token_active(redis::Client& redis, const std::string& token_hash);

// Отзывает access-токен раньше его естественного истечения (logout).
// Мгновенно — но ТОЛЬКО для этого сервиса: auth::authenticate() здесь, в
// google-auth, проверяет Redis (см. выше), а wallet-api/wallet-gateway
// проверяют токен по JWKS локально (см. их util/jwks.hpp) и про это
// отозвание не узнают — их access-токен продолжит "работать" до истечения
// exp. См. README, "Мгновенный logout — только в auth-сервисе".
void revoke_access_token(redis::Client& redis, const std::string& token_hash);

// Отзывает ВСЕ активные access- и refresh-токены пользователя разом —
// принудительный logout ("выкинуть" конкретного user_id, а не себя самого
// через /auth/logout). Используется только из /admin/users, только
// Role::Admin (см. admin.cpp) — та же оговорка про "только для этого
// сервиса", что и у revoke_access_token выше, действует и здесь.
//
// По самому token_hash узнать user_id можно (это и есть значение ключа), а
// вот обратное — "все token_hash этого user_id" — Redis не умеет "найти все
// ключи по значению", поэтому store_access_token/store_refresh_token
// ДОПОЛНИТЕЛЬНО кладут хэш в множество-индекс (см. repo.cpp) на каждый
// выпуск; здесь оно вычитывается и оба множества-индекса тоже удаляются.
// Не абсолютно точно: если токен уже истёк сам (TTL) или был отозван
// поштучно (обычный /auth/logout), его хэш может остаться в индексе как
// "висячая" ссылка — DEL на уже отсутствующий ключ у Redis не ошибка, просто
// no-op, так что это не баг, а осознанный компромисс ради простоты (индекс
// не обязан быть идеально синхронизирован, только не терять реальные
// активные токены).
void revoke_all_user_tokens(redis::Client& redis, const std::string& user_id);

// Одна активная (непросроченная) сессия пользователя = один непотраченный
// refresh-токен + устройство, которому он выдан (см. DeviceInfo, types.hpp).
// Экран "Устройства" (org/docs/TODO_mobile_sync.md, "Открытые вопросы", "Показ/
// отзыв одного конкретного устройства") строится из списка таких сессий, не
// из access-токенов — у access-токена нет собственного индекса "по
// устройству" (см. store_access_token выше), и он и так короткоживущий.
struct SessionSummary {
    std::string token_hash;
    DeviceInfo device;
    // Хэш access-токена, выпущенного в паре с этим refresh-токеном (см.
    // store_refresh_token выше) — пусто только для сессий, переживших
    // формат до появления этого поля (тот же принцип терпимости к старому
    // формату, что и у device). Наружу (devices.cpp/JSON-ответ) не
    // отдаётся — чисто внутренняя связка для revoke_user_sessions_if.
    std::string access_token_hash;
};

// Все активные сессии пользователя — GET (не GETDEL, см. redis::Client::get):
// список не должен тратить чужой refresh-токен самим фактом показа. Заодно
// подчищает user_refresh_tokens:<user_id> (SREM) от хэшей, чьи ключи уже
// истекли по TTL — та же "не абсолютно точный, но самоисправляющийся индекс"
// логика, что у revoke_all_user_tokens (см. её комментарий), просто чистка
// происходит здесь, на чтении, а не только там, на удалении.
std::vector<SessionSummary> list_user_sessions(redis::Client& redis, const std::string& user_id);

// Отзывает refresh-токены сессий пользователя, для которых predicate(session)
// вернул true — общий примитив для трёх сценариев экрана "Устройства":
// "отозвать вот эту сессию" (predicate по token_hash), "закрыть все, кроме
// текущей" (predicate — НЕ текущая) и авто-схлопывание при новом мобильном
// входе (predicate — тот же device_id, см. auth::issue_tokens). Возвращает
// число реально отозванных refresh-сессий.
//
// Заодно гасит и ПАРНЫЙ access-токен каждой отозванной сессии
// (session.access_token_hash, см. SessionSummary) — благодаря этой связке
// (а не совпадению device_id, которое для браузерных сессий всегда пустое и
// потому неразличимо) отзыв бьёт точно по одной сессии, не по всем
// access-токенам пользователя разом, как это делает revoke_all_user_tokens.
// Действует та же оговорка, что и у него: мгновенно — но ТОЛЬКО для проверок
// внутри ЭТОГО сервиса (`auth::authenticate()` здесь смотрит в Redis, см.
// repo::is_access_token_active) — wallet-api/wallet-gateway проверяют
// access-токен по JWKS локально, в Redis не заглядывают вообще и про этот
// отзыв никогда не узнают: тот же самый access-токен у них "работает" до
// истечения `exp` (обычно 15 минут), сколько бы записей о нём ни удалили
// здесь. См. README, "Мгновенный logout — только в auth-сервисе".
int revoke_user_sessions_if(redis::Client& redis, const std::string& user_id,
                             const std::function<bool(const SessionSummary&)>& predicate);

} // namespace repo
