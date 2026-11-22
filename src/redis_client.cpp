#include "redis_client.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace redis {

namespace {

// Ошибка ввода-вывода (соединение закрыто/сброшено, таймаут): соединение после неё непригодно, его
// закрывают и, если оно было взято из пула, команду повторяют на свежем. Отличается от ответа-ошибки Redis
// ("-ERR…", просто std::runtime_error): тогда ответ прочитан целиком и соединение остаётся годным.
struct IoError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Платформенные различия спрятаны здесь же (в одном .cpp) — тем же приёмом,
// что уже применён в CMakeLists.txt для этого проекта (WIN32-ветка линкует
// ws2_32, POSIX-ветка — нет): заголовок redis_client.hpp платформенно
// нейтрален, socket-специфика не выходит за пределы этого файла.
#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;

// WSAStartup один раз на процесс — второй и последующие вызовы Client(...)
// (если их несколько) просто увеличивают внутренний счётчик ссылок Winsock,
// WSACleanup() не вызываем: процесс завершится — ОС сама всё освободит (то
// же решение, что и с закрытием db-соединения при неожиданном завершении).
void ensure_platform_ready() {
    static bool done = [] {
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
        return true;
    }();
    (void)done;
}

void close_socket(socket_t s) { closesocket(s); }
int send_bytes(socket_t s, const char* data, std::size_t len) {
    return send(s, data, static_cast<int>(len), 0);
}
int recv_bytes(socket_t s, char* buf, std::size_t len) {
    return recv(s, buf, static_cast<int>(len), 0);
}
void set_timeouts(socket_t s, int ms) {
    DWORD v = static_cast<DWORD>(ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&v), sizeof(v));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&v), sizeof(v));
}
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;

void ensure_platform_ready() {}
void close_socket(socket_t s) { ::close(s); }
int send_bytes(socket_t s, const char* data, std::size_t len) {
    return static_cast<int>(::send(s, data, len, MSG_NOSIGNAL));
}
int recv_bytes(socket_t s, char* buf, std::size_t len) {
    return static_cast<int>(::recv(s, buf, len, 0));
}
void set_timeouts(socket_t s, int ms) {
    struct timeval tv {};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)); // на Linux ограничивает и connect()
}
#endif

#ifdef _WIN32
bool is_timeout() { return WSAGetLastError() == WSAETIMEDOUT; }
#else
bool is_timeout() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

void tune_socket(socket_t s) {
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&one), sizeof(one));
}

socket_t connect_to(const std::string& host, int port, int connect_timeout_ms) {
    ensure_platform_ready();

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* candidates = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &candidates) != 0 ||
        candidates == nullptr) {
        throw IoError("Redis: не удалось разрешить адрес " + host + ":" + port_str);
    }

    socket_t sock = kInvalidSocket;
    for (auto* rp = candidates; rp != nullptr; rp = rp->ai_next) {
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == kInvalidSocket) continue;
        set_timeouts(sock, connect_timeout_ms);
        if (::connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) break;
        close_socket(sock);
        sock = kInvalidSocket;
    }
    freeaddrinfo(candidates);

    if (sock == kInvalidSocket) {
        throw IoError("Redis: не удалось подключиться к " + host + ":" + port_str);
    }
    tune_socket(sock);
    return sock;
}

} // namespace

// Одно соединение с буфером чтения. Читаем кусками, а не байт за раз: ответ обычно приходит одним
// сегментом, и системный вызов нужен один, а не по одному на каждый байт ответа.
struct Conn {
    socket_t sock = kInvalidSocket;
    std::string rbuf;
    std::size_t rpos = 0;

    explicit Conn(socket_t s) : sock(s) {}
    ~Conn() {
        if (sock != kInvalidSocket) close_socket(sock);
    }
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;

    // Есть ли непрочитанные байты после полного ответа: так не бывает (запрос-ответ по одному), значит поток
    // рассинхронизирован и соединение использовать нельзя.
    bool clean() const { return rpos >= rbuf.size(); }

    void fill() {
        if (rpos > 0 && rpos == rbuf.size()) {
            rbuf.clear();
            rpos = 0;
        }
        char chunk[4096];
        int n = recv_bytes(sock, chunk, sizeof(chunk));
        if (n <= 0) {
            const bool timed_out = n < 0 && is_timeout();
            throw IoError(timed_out ? "Redis: таймаут чтения ответа" : "Redis: соединение закрыто при чтении ответа");
        }
        rbuf.append(chunk, static_cast<std::size_t>(n));
    }
};

namespace {

std::string build_command(const std::vector<std::string>& args) {
    // RESP-массив bulk-строк — формат, который понимает redis-server для
    // любой команды (в т.ч. с бинарными значениями, здесь не нужно, но
    // именно поэтому длина указывается явно, а не через разделители).
    std::string cmd = "*" + std::to_string(args.size()) + "\r\n";
    for (const auto& a : args) {
        cmd += "$" + std::to_string(a.size()) + "\r\n" + a + "\r\n";
    }
    return cmd;
}

void write_all(Conn& c, const std::string& data) {
    std::size_t sent_total = 0;
    while (sent_total < data.size()) {
        int sent = send_bytes(c.sock, data.data() + sent_total, data.size() - sent_total);
        if (sent <= 0) throw IoError("Redis: соединение закрыто при отправке команды");
        sent_total += static_cast<std::size_t>(sent);
    }
}

// Одна строка RESP, оканчивающаяся "\r\n" (без них в результате) — заголовки
// simple string/error/integer/bulk-length.
std::string read_line(Conn& c) {
    for (;;) {
        auto nl = c.rbuf.find('\n', c.rpos);
        if (nl != std::string::npos) {
            std::string line = c.rbuf.substr(c.rpos, nl - c.rpos);
            c.rpos = nl + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return line;
        }
        c.fill();
    }
}

std::string read_exact(Conn& c, std::size_t len) {
    while (c.rbuf.size() - c.rpos < len) c.fill();
    std::string data = c.rbuf.substr(c.rpos, len);
    c.rpos += len;
    return data;
}

// Тело bulk string ПОСЛЕ заголовка "$<len>\r\n" — общая часть между
// read_reply() (одиночный bulk string) и read_array_reply() (SMEMBERS —
// массив bulk string'ов). len < 0 (null bulk, "$-1") сюда не передают —
// вызывающая сторона проверяет это до вызова.
std::string read_bulk_body(Conn& c, int len) {
    std::string data = read_exact(c, static_cast<std::size_t>(len));
    read_exact(c, 2); // завершающее "\r\n" после данных
    return data;
}

// Разбирает один RESP-ответ. Поддержаны только типы, которые реально
// возвращают используемые здесь скалярные команды (AUTH/SET/EXISTS/DEL/
// GETDEL/SADD/EXPIRE): simple string (+), error (-), integer (:), bulk
// string ($, включая null-bulk "$-1"). Массивы (*) сюда не попадают — их
// разбирает отдельно read_array_reply() (см. ниже, только для SMEMBERS).
//
// nullopt — ТОЛЬКО для null-bulk ("$-1", ключа нет/GETDEL промахнулся) —
// сознательно отличаем от пустой строки-значения (её тут никто не кладёт, но
// если бы положили, отличие имело бы значение).
std::optional<std::string> read_reply(Conn& c) {
    std::string header = read_line(c);
    if (header.empty()) throw IoError("Redis: пустой ответ сервера");

    char type = header.front();
    std::string rest = header.substr(1);

    switch (type) {
        case '+': // simple string, напр. "+OK"
        case ':': // integer, напр. ":1"
            return rest;
        case '-': // error, напр. "-ERR ..." — ответ прочитан целиком, соединение остаётся годным
            throw std::runtime_error("Redis: " + rest);
        case '$': { // bulk string
            int len = std::stoi(rest);
            if (len < 0) return std::nullopt; // null bulk — ключа нет
            return read_bulk_body(c, len);
        }
        default:
            throw IoError("Redis: неожиданный тип ответа '" + std::string(1, type) + "'");
    }
}

// Единственный потребитель — SMEMBERS: RESP-массив bulk string'ов
// ("*N\r\n" + N раз "$len\r\n<данные>\r\n"). Null-массив ("*-1", ключа нет
// вообще) и пустой массив ("*0", ключ есть, но пуст) намеренно не
// различаем — для repo::revoke_all_user_tokens разницы нет, в обоих
// случаях просто нечего отзывать.
std::vector<std::string> read_array_reply(Conn& c) {
    std::string header = read_line(c);
    if (!header.empty() && header.front() == '-') throw std::runtime_error("Redis: " + header.substr(1));
    if (header.empty() || header.front() != '*') {
        throw IoError("Redis: ожидался массив (*), получено: " + header);
    }
    int count = std::stoi(header.substr(1));
    std::vector<std::string> out;
    if (count <= 0) return out;
    out.reserve(static_cast<std::size_t>(count));

    for (int i = 0; i < count; ++i) {
        std::string elem_header = read_line(c);
        if (elem_header.empty() || elem_header.front() != '$') {
            throw IoError("Redis: ожидался bulk string внутри массива");
        }
        int len = std::stoi(elem_header.substr(1));
        out.push_back(len < 0 ? std::string{} : read_bulk_body(c, len));
    }
    return out;
}

} // namespace

Client::Client(const std::string& host, int port, const std::string& password, const std::string& username,
               Options options)
    : host_(host), port_(port), password_(password), username_(username), options_(options) {
    if (options_.pool_size < 1) options_.pool_size = 1;
    // Первое соединение — сразу: неверный адрес или пароль виден на старте, а не на первом запросе.
    ++open_;
    try {
        idle_.push_back(open_connection());
    } catch (...) {
        --open_;
        throw;
    }
}

Client::~Client() = default;

std::unique_ptr<Conn> Client::open_connection() {
    auto conn = std::make_unique<Conn>(connect_to(host_, port_, options_.connect_timeout_ms));
    if (!password_.empty()) {
        try {
            write_all(*conn, build_command(detail::auth_command(username_, password_)));
            read_reply(*conn);
        } catch (const std::exception& ex) {
            throw std::runtime_error(std::string("Redis: AUTH не прошёл: ") + ex.what());
        }
    }
    set_timeouts(conn->sock, options_.io_timeout_ms);
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.connects;
    return conn;
}

std::unique_ptr<Conn> Client::acquire(bool& reused, bool force_fresh) {
    std::vector<std::unique_ptr<Conn>> dead; // закрываются после отпускания мьютекса
    std::unique_lock<std::mutex> lock(mutex_);
    if (force_fresh && !idle_.empty()) {
        dead.swap(idle_);
        open_ -= std::min(open_, dead.size());
    }
    if (idle_.empty() && open_ >= options_.pool_size) {
        // Пул исчерпан: ждём, пока кто-то вернёт соединение (не дольше wait_timeout_ms).
        ++stats_.waited;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(options_.wait_timeout_ms);
        while (idle_.empty() && open_ >= options_.pool_size) {
            if (cv_.wait_until(lock, deadline) == std::cv_status::timeout && idle_.empty() &&
                open_ >= options_.pool_size) {
                throw IoError("Redis: нет свободного соединения (пул исчерпан)");
            }
        }
    }
    if (!idle_.empty()) {
        auto conn = std::move(idle_.back());
        idle_.pop_back();
        reused = true;
        return conn;
    }
    ++open_; // слот под новое соединение
    lock.unlock();
    reused = false;
    try {
        return open_connection();
    } catch (...) {
        discard();
        throw;
    }
}

void Client::release(std::unique_ptr<Conn> conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    idle_.push_back(std::move(conn));
    cv_.notify_one();
}

void Client::discard() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (open_ > 0) --open_;
    cv_.notify_one();
}

void Client::flush_idle() {
    std::vector<std::unique_ptr<Conn>> dead;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dead.swap(idle_);
        open_ -= std::min(open_, dead.size());
        cv_.notify_all();
    }
    // закрываются вне мьютекса, в деструкторах
}

void Client::run(const std::function<void(Conn&)>& io) {
    bool reused = false;
    auto conn = acquire(reused);
    try {
        io(*conn);
        if (!conn->clean()) throw IoError("Redis: рассинхронизация потока ответов");
        release(std::move(conn));
        return;
    } catch (const IoError&) {
        conn.reset();
        discard();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++stats_.io_errors;
        }
        if (!reused) throw; // свежее соединение тоже не сработало — это не «протухшее», повтор не поможет
        // Соединение из пула, скорее всего, протухло (рестарт Redis, обрыв): остальные простаивающие — тоже.
        flush_idle();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++stats_.retried;
        }
    } catch (const std::runtime_error&) {
        // Ответ-ошибка Redis (-ERR…, -NOAUTH…): ответ прочитан целиком, соединение годно.
        if (conn->clean()) {
            release(std::move(conn));
        } else {
            conn.reset();
            discard();
        }
        throw;
    } catch (...) {
        conn.reset();
        discard();
        throw;
    }

    // Повтор один раз на свежем соединении.
    bool unused = false;
    auto fresh = acquire(unused, /*force_fresh=*/true);
    try {
        io(*fresh);
        if (!fresh->clean()) throw IoError("Redis: рассинхронизация потока ответов");
        release(std::move(fresh));
    } catch (const IoError&) {
        fresh.reset();
        discard();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++stats_.io_errors;
        }
        throw;
    } catch (const std::runtime_error&) {
        if (fresh->clean()) {
            release(std::move(fresh));
        } else {
            fresh.reset();
            discard();
        }
        throw;
    } catch (...) {
        fresh.reset();
        discard();
        throw;
    }
}

Client::Stats Client::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats s = stats_;
    s.open = open_;
    return s;
}

std::optional<std::string> Client::send_command(const std::vector<std::string>& args) {
    const std::string wire = build_command(args);
    std::optional<std::string> reply;
    run([&](Conn& c) {
        write_all(c, wire);
        reply = read_reply(c);
    });
    return reply;
}

void Client::set_ex(const std::string& key, const std::string& value, uint64_t ttl_secs) {
    send_command({"SET", key, value, "EX", std::to_string(ttl_secs)});
}

bool Client::exists(const std::string& key) {
    // EXISTS всегда отвечает integer (":0"/":1"...), никогда null-bulk —
    // value_or("0") тут просто разворачивает optional, не скрывает реальный
    // "ключа нет" случай (того от EXISTS и не бывает).
    return send_command({"EXISTS", key}).value_or("0") != "0";
}

void Client::del(const std::string& key) {
    send_command({"DEL", key});
}

std::optional<std::string> Client::getdel(const std::string& key) {
    return send_command({"GETDEL", key});
}

void Client::sadd(const std::string& key, const std::string& member) {
    send_command({"SADD", key, member});
}

void Client::expire(const std::string& key, uint64_t ttl_secs) {
    send_command({"EXPIRE", key, std::to_string(ttl_secs)});
}

std::vector<std::string> Client::smembers(const std::string& key) {
    // Не через send_command() — та ждёт скалярный ответ (read_reply()),
    // SMEMBERS всегда отвечает массивом (см. read_array_reply()).
    const std::string wire = build_command({"SMEMBERS", key});
    std::vector<std::string> members;
    run([&](Conn& c) {
        write_all(c, wire);
        members = read_array_reply(c);
    });
    return members;
}

std::optional<std::string> Client::get(const std::string& key) {
    return send_command({"GET", key});
}

void Client::srem(const std::string& key, const std::string& member) {
    send_command({"SREM", key, member});
}

void Client::set_exat(const std::string& key, const std::string& value, uint64_t epoch_secs) {
    send_command({"SET", key, value, "EXAT", std::to_string(epoch_secs)});
}

bool Client::set_xx_exat(const std::string& key, const std::string& value, uint64_t epoch_secs) {
    // "+OK" — записано; null bulk ("$-1") — условие XX не выполнено, ключа нет.
    return send_command({"SET", key, value, "XX", "EXAT", std::to_string(epoch_secs)}).has_value();
}

std::optional<int64_t> Client::expiretime(const std::string& key) {
    // EXPIRETIME всегда отвечает integer: -2 — ключа нет, -1 — без срока,
    // иначе unix-секунды.
    auto reply = send_command({"EXPIRETIME", key});
    if (!reply) return std::nullopt;
    int64_t secs = std::stoll(*reply);
    if (secs == -2) return std::nullopt;
    return secs;
}

int64_t Client::incr(const std::string& key) {
    return detail::parse_integer(send_command({"INCR", key}));
}

std::optional<int64_t> Client::ttl(const std::string& key) {
    return detail::parse_ttl(send_command({"TTL", key}));
}

namespace detail {

std::vector<std::string> auth_command(const std::string& username, const std::string& password) {
    if (username.empty()) return {"AUTH", password};
    return {"AUTH", username, password};
}

int64_t parse_integer(const std::optional<std::string>& reply) {
    if (!reply || reply->empty()) throw std::runtime_error("Redis: ожидался integer-ответ");
    std::size_t used = 0;
    int64_t value = 0;
    try {
        value = std::stoll(*reply, &used);
    } catch (const std::exception&) {
        throw std::runtime_error("Redis: ожидался integer-ответ, получено: " + *reply);
    }
    if (used != reply->size()) throw std::runtime_error("Redis: ожидался integer-ответ, получено: " + *reply);
    return value;
}

std::optional<int64_t> parse_ttl(const std::optional<std::string>& reply) {
    int64_t secs = parse_integer(reply);
    if (secs == -2) return std::nullopt;
    return secs;
}

} // namespace detail

} // namespace redis
