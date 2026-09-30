#include "redis_client.hpp"

#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace redis {

namespace {

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
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;

void ensure_platform_ready() {}
void close_socket(socket_t s) { ::close(s); }
int send_bytes(socket_t s, const char* data, std::size_t len) {
    return static_cast<int>(::send(s, data, len, 0));
}
int recv_bytes(socket_t s, char* buf, std::size_t len) {
    return static_cast<int>(::recv(s, buf, len, 0));
}
#endif

socket_t connect_to(const std::string& host, int port) {
    ensure_platform_ready();

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* candidates = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &candidates) != 0 ||
        candidates == nullptr) {
        throw std::runtime_error("Redis: не удалось разрешить адрес " + host + ":" + port_str);
    }

    socket_t sock = kInvalidSocket;
    for (auto* rp = candidates; rp != nullptr; rp = rp->ai_next) {
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == kInvalidSocket) continue;
        if (::connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) break;
        close_socket(sock);
        sock = kInvalidSocket;
    }
    freeaddrinfo(candidates);

    if (sock == kInvalidSocket) {
        throw std::runtime_error("Redis: не удалось подключиться к " + host + ":" + port_str);
    }
    return sock;
}

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

void write_all(socket_t sock, const std::string& data) {
    std::size_t sent_total = 0;
    while (sent_total < data.size()) {
        int sent = send_bytes(sock, data.data() + sent_total, data.size() - sent_total);
        if (sent <= 0) throw std::runtime_error("Redis: соединение закрыто при отправке команды");
        sent_total += static_cast<std::size_t>(sent);
    }
}

// Одна строка RESP, оканчивающаяся "\r\n" (без них в результате) — заголовки
// simple string/error/integer/bulk-length. Байт за раз ценой лишних
// сисколлов, зато без буферизации и без риска утащить кусок следующего
// ответа — для scale этого сервиса (несколько команд в секунду) достаточно.
std::string read_line(socket_t sock) {
    std::string line;
    char c;
    for (;;) {
        int n = recv_bytes(sock, &c, 1);
        if (n <= 0) throw std::runtime_error("Redis: соединение закрыто при чтении ответа");
        if (c == '\n') {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            return line;
        }
        line.push_back(c);
    }
}

std::string read_exact(socket_t sock, std::size_t len) {
    std::string data;
    data.resize(len);
    std::size_t got = 0;
    while (got < len) {
        int n = recv_bytes(sock, data.data() + got, len - got);
        if (n <= 0) throw std::runtime_error("Redis: соединение закрыто при чтении данных");
        got += static_cast<std::size_t>(n);
    }
    return data;
}

// Тело bulk string ПОСЛЕ заголовка "$<len>\r\n" — общая часть между
// read_reply() (одиночный bulk string) и read_array_reply() (SMEMBERS —
// массив bulk string'ов). len < 0 (null bulk, "$-1") сюда не передают —
// вызывающая сторона проверяет это до вызова.
std::string read_bulk_body(socket_t sock, int len) {
    std::string data = read_exact(sock, static_cast<std::size_t>(len));
    read_exact(sock, 2); // завершающее "\r\n" после данных
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
std::optional<std::string> read_reply(socket_t sock) {
    std::string header = read_line(sock);
    if (header.empty()) throw std::runtime_error("Redis: пустой ответ сервера");

    char type = header.front();
    std::string rest = header.substr(1);

    switch (type) {
        case '+': // simple string, напр. "+OK"
        case ':': // integer, напр. ":1"
            return rest;
        case '-': // error, напр. "-ERR ..."
            throw std::runtime_error("Redis: " + rest);
        case '$': { // bulk string
            int len = std::stoi(rest);
            if (len < 0) return std::nullopt; // null bulk — ключа нет
            return read_bulk_body(sock, len);
        }
        default:
            throw std::runtime_error("Redis: неожиданный тип ответа '" + std::string(1, type) + "'");
    }
}

// Единственный потребитель — SMEMBERS: RESP-массив bulk string'ов
// ("*N\r\n" + N раз "$len\r\n<данные>\r\n"). Null-массив ("*-1", ключа нет
// вообще) и пустой массив ("*0", ключ есть, но пуст) намеренно не
// различаем — для repo::revoke_all_user_tokens разницы нет, в обоих
// случаях просто нечего отзывать.
std::vector<std::string> read_array_reply(socket_t sock) {
    std::string header = read_line(sock);
    if (header.empty() || header.front() != '*') {
        throw std::runtime_error("Redis: ожидался массив (*), получено: " + header);
    }
    int count = std::stoi(header.substr(1));
    std::vector<std::string> out;
    if (count <= 0) return out;
    out.reserve(static_cast<std::size_t>(count));

    for (int i = 0; i < count; ++i) {
        std::string elem_header = read_line(sock);
        if (elem_header.empty() || elem_header.front() != '$') {
            throw std::runtime_error("Redis: ожидался bulk string внутри массива");
        }
        int len = std::stoi(elem_header.substr(1));
        out.push_back(len < 0 ? std::string{} : read_bulk_body(sock, len));
    }
    return out;
}

} // namespace

Client::Client(const std::string& host, int port, const std::string& password) {
    socket_t sock = connect_to(host, port);
    fd_ = static_cast<std::intptr_t>(sock);

    if (!password.empty()) {
        try {
            send_command({"AUTH", password});
        } catch (const std::exception& ex) {
            close_socket(sock);
            fd_ = -1;
            throw std::runtime_error(std::string("Redis: AUTH не прошёл: ") + ex.what());
        }
    }
}

Client::~Client() {
    if (fd_ != -1) close_socket(static_cast<socket_t>(fd_));
}

std::optional<std::string> Client::send_command(const std::vector<std::string>& args) {
    // Одно соединение на процесс (см. hpp) — сериализуем запрос-ответ, чтобы
    // параллельные запросы (httplib гоняет обработчики в пуле потоков) не
    // перемешали команды и ответы на одном сокете. Тот же приём, что
    // db::Database::exec() с своим мьютексом (см. db.cpp).
    std::lock_guard<std::mutex> lock(mutex_);
    socket_t sock = static_cast<socket_t>(fd_);
    write_all(sock, build_command(args));
    return read_reply(sock);
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
    // SMEMBERS всегда отвечает массивом (см. read_array_reply()). Лок и
    // запись команды — тот же приём, что в send_command.
    std::lock_guard<std::mutex> lock(mutex_);
    socket_t sock = static_cast<socket_t>(fd_);
    write_all(sock, build_command({"SMEMBERS", key}));
    return read_array_reply(sock);
}

std::optional<std::string> Client::get(const std::string& key) {
    return send_command({"GET", key});
}

void Client::srem(const std::string& key, const std::string& member) {
    send_command({"SREM", key, member});
}

} // namespace redis
