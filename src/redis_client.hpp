// Минимальный клиент Redis поверх RESP (REdis Serialization Protocol) через
// голый TCP-сокет — тем же приёмом, что util/jwt.hpp поверх OpenSSL (см. его
// шапку): нужен ровно тот набор команд, что использует repo.hpp — не повод
// тащить hiredis/redis-plus-plus отдельной зависимостью (апт-пакет в
// Containerfile, и без внятного пути установки под Windows-сборку вне
// Docker, см. README "Зависимости"). Одно постоянное соединение + мьютекс —
// тот же паттерн, что db::Database поверх libpq (см. db.hpp): для масштаба
// этого сервиса достаточно, настоящая нагрузка потребует пул соединений.
//
// Используется для активных access- и refresh-токенов и обратного индекса
// "все токены этого user_id" (см. repo.hpp) — не общий Redis-клиент "на все
// случаи", а ровно то подмножество команд, что для этого нужно.
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace redis {

class Client {
public:
    // host/port — адрес Redis. password — пусто, если AUTH не требуется
    // (см. REDIS_PASSWORD в .env.example — обычная ситуация для локальной
    // разработки и для контейнера в приватной docker-сети). Бросает
    // std::runtime_error, если не удалось подключиться или (при заданном
    // пароле) AUTH не прошёл.
    Client(const std::string& host, int port, const std::string& password);
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // SET key value EX ttl_secs — Redis сам удаляет запись по истечении TTL,
    // отдельный "сборщик мусора" не нужен (в отличие от просроченных строк
    // refresh_tokens в старой, Postgres-based реализации).
    void set_ex(const std::string& key, const std::string& value, uint64_t ttl_secs);

    // true, если ключ есть (и не истёк — Redis сам не отдаст истёкший ключ).
    bool exists(const std::string& key);

    // Не ошибка, если ключа и так нет.
    void del(const std::string& key);

    // GETDEL key (Redis >= 6.2) — атомарно читает значение И удаляет ключ
    // ОДНОЙ командой. Ровно то, что нужно для одноразового refresh-токена
    // (см. repo::take_refresh_token): раньше эквивалент на Postgres был
    // "DELETE ... RETURNING" одним SQL-запросом — здесь тот же принцип
    // (predostavit-and-remove без гонки между отдельными "прочитать" и
    // "удалить"), но средствами Redis. nullopt — ключа не было (никогда не
    // существовал или уже истёк по TTL).
    std::optional<std::string> getdel(const std::string& key);

    // SADD key member — добавляет member в множество (не ошибка, если он
    // там уже есть). Используется для обратного индекса "все хэши токенов
    // этого user_id" (см. repo.hpp) — по значению самого token-ключа узнать
    // user_id можно и без индекса, а вот наоборот, "все ключи с таким
    // значением", Redis сам не умеет.
    void sadd(const std::string& key, const std::string& member);

    // EXPIRE key ttl_secs — выставляет/обновляет TTL уже существующему
    // ключу (в отличие от SET..EX, который сам создаёт ключ; SADD такого
    // параметра не имеет — TTL множеству ставится отдельной командой).
    void expire(const std::string& key, uint64_t ttl_secs);

    // SMEMBERS key — все элементы множества, в любом порядке. Пустой
    // вектор — ключа нет или множество пустое (Redis не различает эти два
    // случая для SMEMBERS, и для наших целей разница не нужна).
    std::vector<std::string> smembers(const std::string& key);

    // GET key — читает значение, НЕ удаляя ключ (в отличие от getdel выше).
    // Нужен для того, что должно остаться пригодным для повторного
    // использования после чтения — список активных устройств пользователя
    // (см. repo::list_user_sessions) не должен тратить чужой refresh-токен
    // самим фактом показа списка. nullopt — ключа нет (никогда не
    // существовал или истёк по TTL), тот же смысл, что и у getdel.
    std::optional<std::string> get(const std::string& key);

    // SREM key member — убирает member из множества (не ошибка, если его
    // там и не было). Пара к sadd() выше — нужна, чтобы вычищать из
    // обратного индекса хэши токенов, чьи ключи уже истекли по TTL
    // (см. repo::list_user_sessions) или были отозваны явно
    // (см. repo::revoke_user_sessions_if), а не оставлять индекс расти
    // висячими ссылками быстрее, чем это допустимо для revoke_all_user_tokens.
    void srem(const std::string& key, const std::string& member);

    // SET key value EXAT epoch_secs — то же, что set_ex, но срок задан
    // моментом (unix-секунды), а не длительностью. Нужен MCP-токенам (см.
    // repo::store_mcp_token): их срок — min(сейчас + 30 дней, потолок), и
    // потолок — абсолютный момент, который удобнее не пересчитывать в TTL.
    void set_exat(const std::string& key, const std::string& value, uint64_t epoch_secs);

    // SET key value XX EXAT epoch_secs — перезаписывает ТОЛЬКО существующий
    // ключ. false — ключа не было (nil-ответ на XX): запись не создана. Так
    // продление MCP-токена (repo::touch_mcp_token) не воскрешает ключ,
    // удалённый отзывом между чтением и записью.
    bool set_xx_exat(const std::string& key, const std::string& value, uint64_t epoch_secs);

    // EXPIRETIME key (Redis >= 7.0) — момент истечения ключа, unix-секунды.
    // nullopt — ключа нет (-2); -1 — ключ есть, но без срока (у наших
    // ключей так не бывает, значение отдаётся как есть). Абсолютный момент,
    // а не TTL: срок сессии в GET /auth/devices не «дрожит» на секунду
    // между двумя просмотрами (now + TTL округлялся бы по-разному).
    std::optional<int64_t> expiretime(const std::string& key);

private:
    // nullopt — только для null-bulk-ответа ($-1, "ключа нет"), отличать от
    // пустой строки-значения. SET/EXISTS/DEL никогда не возвращают null-bulk
    // (simple string/integer оборачиваются в optional тривиально) — только
    // GETDEL реально может.
    std::optional<std::string> send_command(const std::vector<std::string>& args);

    // Хранится как intptr_t, а не как платформенный SOCKET/int — чтобы этот
    // заголовок не тянул <winsock2.h>/<sys/socket.h> во все .cpp, которые
    // просто хотят тип redis::Client (тот же приём, что db.hpp с
    // форвард-декларацией PGconn). Оба реальных типа (SOCKET на Windows, int
    // на POSIX) без потерь помещаются в intptr_t.
    std::intptr_t fd_ = -1;
    std::mutex mutex_;
};

} // namespace redis
