// Минимальный клиент Redis поверх RESP (REdis Serialization Protocol) через
// голый TCP-сокет — тем же приёмом, что util/jwt.hpp поверх OpenSSL (см. его
// шапку): нужен ровно тот набор команд, что использует repo.hpp — не повод
// тащить hiredis/redis-plus-plus отдельной зависимостью (апт-пакет в
// Containerfile, и без внятного пути установки под Windows-сборку вне
// Docker, см. README "Зависимости").
//
// Пул постоянных соединений (REDIS_POOL_SIZE, по умолчанию 8): команды разных
// потоков идут параллельно, каждая на своём соединении, а не по очереди под
// одним мьютексом. Соединение не живёт «навсегда»: ошибка ввода-вывода
// (рестарт Redis, обрыв сети, таймаут) закрывает его, следующая команда
// открывает новое (с AUTH). Если сбой случился на соединении, взятом из пула
// (оно могло протухнуть, например после рестарта Redis), команда один раз
// повторяется на свежем — рестарт Redis проходит для вызывающих незаметно.
// Повтор допустим для всех команд этого клиента: SET/DEL/SADD/SREM/EXPIRE/GET/
// EXISTS/TTL идемпотентны; INCR при потерянном ответе мог бы засчитаться
// дважды (счётчик неудачных входов — лишняя попытка, не проблема), GETDEL —
// вернуть «ключа нет» (токен уже потрачен, пользователь просто войдёт заново).
// На connect/send/recv стоят таймауты (REDIS_TIMEOUT_MS): зависший Redis не
// блокирует потоки сервиса навсегда.
//
// Используется для активных access- и refresh-токенов и обратного индекса
// "все токены этого user_id" (см. repo.hpp) — не общий Redis-клиент "на все
// случаи", а ровно то подмножество команд, что для этого нужно.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace redis {

struct Conn; // одно соединение с буфером чтения (redis_client.cpp)

// Настройки пула и таймаутов (REDIS_POOL_SIZE, REDIS_TIMEOUT_MS в main.cpp).
struct Options {
    std::size_t pool_size = 8;       // максимум одновременных соединений (>= 1)
    int connect_timeout_ms = 2000;   // подключение + AUTH
    int io_timeout_ms = 5000;        // отправка и чтение ответа одной команды
    int wait_timeout_ms = 5000;      // ожидание свободного соединения при исчерпанном пуле
};

class Client {
public:
    // host/port — адрес Redis. password — пусто, если AUTH не требуется
    // (см. REDIS_PASSWORD в .env.example — обычная ситуация для локальной
    // разработки и для контейнера в приватной docker-сети). Бросает
    // std::runtime_error, если не удалось подключиться или (при заданном
    // пароле) AUTH не прошёл.
    // username — необязательный ACL-пользователь Redis 6+ (REDIS_USERNAME, change add-redis-auth):
    // пусто — прежнее `AUTH <пароль>` (пользователь default).
    // Первое соединение открывается сразу (ошибка настройки/пароля видна на старте), остальные — по мере
    // надобности.
    Client(const std::string& host, int port, const std::string& password, const std::string& username = "",
           Options options = {});
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

    // INCR key — атомарно увеличивает целое (ключа нет — считает с 0) и
    // возвращает новое значение. Срок ключу INCR не ставит — это делает
    // вызывающий через expire() (см. auth_limits, счётчики неудачных входов).
    int64_t incr(const std::string& key);

    // TTL key — сколько секунд осталось до истечения. nullopt — ключа нет
    // (-2); -1 — ключ есть, но без срока (вызывающий должен поставить срок
    // сам, иначе счётчик не сбросится никогда).
    std::optional<int64_t> ttl(const std::string& key);

    struct Stats {
        std::size_t connects = 0;   // открытых соединений за всё время (включая переподключения)
        std::size_t retried = 0;    // команд, повторённых на свежем соединении после сбоя «протухшего»
        std::size_t io_errors = 0;  // закрытых из-за ошибки ввода-вывода или таймаута
        std::size_t waited = 0;     // команд, ждавших свободного соединения
        std::size_t open = 0;       // соединений сейчас (в работе + в простое)
    };
    Stats stats() const;

private:
    // nullopt — только для null-bulk-ответа ($-1, "ключа нет"), отличать от
    // пустой строки-значения. SET/EXISTS/DEL никогда не возвращают null-bulk
    // (simple string/integer оборачиваются в optional тривиально) — только
    // GETDEL реально может.
    std::optional<std::string> send_command(const std::vector<std::string>& args);

    // Выполняет io на соединении из пула: берёт (или открывает) соединение, при сбое на «протухшем» повторяет
    // один раз на свежем, возвращает исправное соединение в пул. io делает запись команды и чтение ответа.
    void run(const std::function<void(Conn&)>& io);
    // force_fresh — не брать соединение из простоя (повтор после сбоя «протухшего»): простаивающие закрываются.
    std::unique_ptr<Conn> acquire(bool& reused, bool force_fresh = false);
    std::unique_ptr<Conn> open_connection(); // connect + AUTH; слот под pool_size уже занят вызывающим
    void release(std::unique_ptr<Conn> conn);
    void discard();     // соединение закрыто: освободить слот
    void flush_idle();  // закрыть простаивающие (после рестарта Redis все протухли)

    std::string host_;
    int port_;
    std::string password_;
    std::string username_;
    Options options_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::unique_ptr<Conn>> idle_;
    std::size_t open_ = 0; // в работе + в простое
    Stats stats_;
};

// Разбор уже прочитанного скалярного ответа — отдельно от сокета, чтобы его
// можно было проверить юнит-тестом (tests/test_redis_replies.cpp).
namespace detail {

// Ответ-целое (":42" приходит сюда как "42"). Бросает std::runtime_error на
// null-bulk и на не-число — INCR/TTL/EXPIRETIME так не отвечают, значит
// что-то не так с самим ответом.
int64_t parse_integer(const std::optional<std::string>& reply);

// Ответ TTL/EXPIRETIME: -2 — ключа нет (nullopt), -1 и больше отдаются как есть.
std::optional<int64_t> parse_ttl(const std::optional<std::string>& reply);

// Команда аутентификации: `AUTH <пароль>` без пользователя, `AUTH <пользователь> <пароль>` с ним.
std::vector<std::string> auth_command(const std::string& username, const std::string& password);

} // namespace detail

} // namespace redis
