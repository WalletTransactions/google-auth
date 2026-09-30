// Тонкая обёртка над libpq (C API Postgres) — без vcpkg/libpqxx, в том же
// стиле, что и util/crypto.hpp поверх OpenSSL: прямой вызов C-библиотеки без
// лишней прослойки. Database сама по себе — по-прежнему одно постоянное
// соединение + мьютекс, как и была; пул из НЕСКОЛЬКИХ таких Database — это
// Pool ниже (по прямому запросу, 2026-09-17 — та же правка, что уже стоит в
// wallet-api/wallet-report, см. их db.hpp: у google-auth была ровно та же
// архитектурная дыра, просто ни разу не проявившаяся на практике — ни одного
// db_query_failed в логах на момент правки).
#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

// Форвард-декларация вместо #include <libpq-fe.h> здесь — чтобы этот
// заголовок (а с ним и libpq-fe.h) не тянулся во все .cpp, которые просто
// хотят типы db::Database/Result. Полный <libpq-fe.h> нужен только db.cpp.
// Typedef ровно повторяет объявление в libpq-fe.h, поэтому конфликта нет.
extern "C" {
typedef struct pg_conn PGconn;
}

namespace db {

struct Row {
    // SQL NULL -> "" — наша схема их не производит (везде NOT NULL/DEFAULT),
    // поэтому различать NULL и пустую строку здесь не нужно.
    std::vector<std::string> fields;
};

struct Result {
    std::vector<Row> rows;
};

class Database {
public:
    // log_params — писать ли значения параметров запроса ($1, $2, ...) в
    // structured-лог (см. exec() ниже). По умолчанию false: параметры — это
    // произвольные данные приложения (email, суммы кошельков и т.п.), и
    // логировать их вслепую значило бы решать за вызывающий код, что можно
    // писать в лог, а что нет (см. README, "Логирование" — включается через
    // LOG_SQL_PARAMS, только для локальной отладки). Сам SQL-текст логируется
    // всегда — он безопасен по построению: это plain PQexecParams с $N
    // плейсхолдерами, литеральных значений в нём нет независимо от флага.
    //
    // mask_param_names — доп. имена параметров (сверх встроенного набора
    // password/token/secret/... — см. builtin_mask_param_names() в db.cpp),
    // чьё значение exec() заменит на "***" в логе, если вызывающий код указал
    // это имя для параметра через param_names (см. exec() ниже) — расширяет
    // встроенный набор, а не заменяет (см. LOG_SQL_MASK_PARAMS в README.md/
    // .env.example). Работает независимо от log_params_: секрет не должен
    // осесть в логе в открытом виде, даже когда параметры логируются
    // намеренно для отладки.
    explicit Database(const std::string& conninfo, bool log_params = false,
                       const std::unordered_set<std::string>& mask_param_names = {});
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // НЕ создаёт схему (в отличие от прежнего migrate()) — роль, которой
    // подключается сервис, лишена DDL (см. infra/db/README.md в корне репозитория,
    // "Три роли"): CREATE TABLE ей запрещён, даже IF NOT EXISTS, даже если
    // таблица уже есть (Postgres проверяет право CREATE на схему раньше,
    // чем факт существования объекта — не короткое замыкание). Схему
    // накатывает отдельная роль-мигратор — см. infra/db/init-db.sh. Здесь —
    // быстрая проверка "а она вообще накачена", чтобы упасть сразу с
    // понятной ошибкой при старте, а не на первом реальном запросе.
    // Бросает std::runtime_error, если чего-то не хватает.
    void verify_schema();

    // params — текстовые значения; libpq сам кастует их к типу колонки по
    // контексту запроса ($1, $2, ... без явных типов). Бросает
    // std::runtime_error при ошибке SQL.
    //
    // param_names — имена параметров ИЗ params, в том же порядке; можно
    // короче params или вовсе пусто — недостающие позиции просто не участвуют
    // в маскировке. Нужны, только если среди params есть значение, которое
    // нельзя писать в лог в открытом виде (см. mask_param_names у
    // конструктора выше) — тогда exec() заменит его на "***" при
    // log_params_ == true. Сейчас ни один вызывающий код не передаёт сюда
    // секретов: в Postgres хранятся только roles/users (google_sub, email,
    // ...), а токены — в Redis (см. AppState::redis, repo.hpp), поэтому везде
    // пусто; передавайте явно, как только появится такая колонка.
    Result exec(const std::string& sql, const std::vector<std::string>& params = {},
                const std::vector<std::string>& param_names = {});

private:
    PGconn* conn_;
    std::mutex mutex_;
    bool log_params_;
    std::unordered_set<std::string> mask_param_names_;
};

// Пул из N постоянных соединений — вместо ЕДИНСТВЕННОЙ Database на весь
// процесс (см. AppState::db_pool). google-auth — общая точка входа для JWKS/
// логина/refresh для ВСЕХ остальных сервисов: на одном соединении все его
// запросы сериализовались бы через mutex_ целиком, а если бы это единственное
// соединение оборвалось (сеть/рестарт соседнего контейнера) — Database не
// восстанавливается сама (см. exec() в db.cpp), и сервис отдавал бы 500 на
// КАЖДЫЙ следующий запрос, пока его не перезапустят руками, — то есть один
// обрыв TCP кладёт логин/обновление токенов для всех пользователей сразу.
//
// Pool не меняет саму Database (по-прежнему одно соединение + мьютекс
// внутри каждого экземпляра, с автопереподключением в exec(), см. db.cpp) —
// просто держит N её экземпляров и раздаёт их запросам по одному через
// acquire(): конкуренция теперь упирается в N, а не в 1.
class Pool {
public:
    // conninfo/log_params/mask_param_names — те же смыслы, что у конструктора
    // Database выше: ВСЕ size соединений пула открываются с ОДИНАКОВЫМИ
    // параметрами. Бросает то же std::runtime_error, что и Database, если
    // хотя бы одно из size соединений не открылось — падаем при старте
    // процесса, а не на первом реальном запросе.
    Pool(const std::string& conninfo, std::size_t size, bool log_params = false,
         const std::unordered_set<std::string>& mask_param_names = {});
    ~Pool() = default;
    Pool(const Pool&) = delete;
    Pool& operator=(const Pool&) = delete;

    // Схема одна на все size соединений (та же Postgres-база) — проверяем
    // один раз, на первом же соединении пула, а не на каждом.
    void verify_schema();

    // RAII-обёртка вокруг ОДНОГО соединения "на время одного вызова" —
    // получена из acquire(), возвращается в пул автоматически в деструкторе
    // (в т.ч. если вызывающий код кинул исключение). Некопируема (владение
    // одним соединением должно быть ровно у одного Lease одновременно), но
    // перемещаема — только так acquire() может вернуть её по значению.
    class Lease {
    public:
        Lease(Lease&& other) noexcept;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease& operator=(Lease&&) = delete;
        ~Lease();

        Database& operator*() const { return *conn_; }
        Database* operator->() const { return conn_; }

    private:
        friend class Pool;
        Lease(Pool* pool, Database* conn) : pool_(pool), conn_(conn) {}

        Pool* pool_;
        Database* conn_;
    };

    // Блокирует вызывающий поток, если все size соединений заняты — до тех
    // пор, пока какой-нибудь Lease не разрушится и не вернёт своё соединение.
    // httplib сам ограничивает число потоков, обрабатывающих запросы, так
    // что это не бесконечная очередь, а обычное ожидание своей очереди за
    // общим ресурсом.
    Lease acquire();

private:
    void release(Database* conn);

    // conns_ — владение: N экземпляров Database, живут всё время жизни
    // пула. idle_ — подмножество СВОБОДНЫХ СЕЙЧАС из них, сырыми указателями
    // (не владение — оно у conns_).
    std::vector<std::unique_ptr<Database>> conns_;
    std::vector<Database*> idle_;
    std::mutex mutex_;
    std::condition_variable cv_;

    friend class Lease;
};

} // namespace db
