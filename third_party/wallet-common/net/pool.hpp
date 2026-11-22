// Пул постоянных клиентов к одному апстриму (change add-internal-mtls, design D6).
//
// Зачем: при mTLS каждое новое соединение — рукопожатие. На горячих связях (гейтвей → api,
// report, ai, mcp, web) клиенты держатся в пуле с keep-alive, и рукопожатие делается не на
// каждый запрос. httplib::Client не потокобезопасен, поэтому клиента берёт один поток на время
// запроса, потом возвращает.
//
// Сервер закрывает простаивающее соединение (keep-alive около 5 с). Запрос на «протухшем»
// клиенте падает на чтении/записи — пул один раз повторяет его на свежем соединении.
// Ограничение одновременных соединений (max_total): без него при сотнях параллельных запросов пул
// открывает сотни свежих клиентов (каждый — своё TLS-рукопожатие и SSL_CTX), а возвращает в простой
// только max_idle — остальные закрываются. На стороне сервера при потоке-на-соединение закреплённые
// keep-alive-соединения занимают потоки и обслуживаются сразу, а свежие стоят в очереди за потоком и
// падают на рукопожатии по таймауту (замер add-internal-mtls, 10.2: p50 300 мс при p95 4–7 с и 2–3 %
// ошибок). С max_total число соединений к апстриму не больше заданного (берите меньше числа потоков
// сервера), все они постоянные, а лишние запросы ждут свободного клиента в самом пуле — по очереди и не
// дольше wait_timeout_sec.
//
// Редкие вызовы (JWKS, /internal/*, справочник счетов) пул не используют: рукопожатие ECDSA
// стоит долей миллисекунды. SSE-потоки (чат) — отдельный клиент мимо пула.
#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "net/tls.hpp"

namespace nettls {

class ClientPool {
public:
    // base_url — http://host:port или https://…; при включённой cfg схема приводится к https
    // (как у make_client). max_idle — сколько простаивающих клиентов держать.
    // max_total — предел одновременных клиентов (в работе + в простое); 0 — без предела (как раньше).
    // wait_timeout_sec — сколько запрос ждёт свободного клиента при исчерпанном max_total; по
    // истечении call() возвращает ошибку ConnectionTimeout, не открывая соединения сверх предела.
    ClientPool(std::string base_url, Config cfg, int connect_timeout_sec = 3, int read_timeout_sec = 30,
               std::size_t max_idle = 16, std::size_t max_total = 0, int wait_timeout_sec = 30);

    // fn получает клиента и возвращает результат запроса. Клиент — эксклюзивно на время вызова.
    // Сбой на переиспользованном клиенте (Read, Write, Connection) — один повтор на свежем.
    httplib::Result call(const std::function<httplib::Result(httplib::Client&)>& fn);

    struct Stats {
        std::size_t created = 0; // новых клиентов (≈ новых соединений)
        std::size_t reused = 0;  // запросов на уже открытом клиенте
        std::size_t retried = 0; // повторов после сбоя переиспользованного клиента
        std::size_t waited = 0;    // запросов, которым пришлось ждать свободного клиента (max_total)
        std::size_t timed_out = 0; // запросов, не дождавшихся клиента за wait_timeout_sec
    };
    Stats stats() const;

    // Ошибка создания клиента (TLS включён, но файлы/ключ неверны) — пусто, если всё хорошо.
    std::string error() const;

private:
    std::unique_ptr<httplib::Client> make_fresh();
    std::unique_ptr<httplib::Client> acquire(bool& fresh, bool& timed_out);
    void release(std::unique_ptr<httplib::Client> client);
    void discard(); // клиент не возвращается в пул: освобождает место под max_total

    std::string base_url_;
    Config cfg_;
    int connect_timeout_sec_;
    int read_timeout_sec_;
    std::size_t max_idle_;
    std::size_t max_total_;
    int wait_timeout_sec_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::size_t in_use_ = 0; // клиентов, выданных вызывающим (в простое — idle_)
    std::vector<std::unique_ptr<httplib::Client>> idle_;
    Stats stats_;
    std::string error_;
};

} // namespace nettls
