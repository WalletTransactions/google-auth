#include "request_info.hpp"

#include <algorithm>
#include <cctype>

namespace request_info {

namespace {

std::string trim(const std::string& s) {
    std::size_t begin = 0;
    std::size_t end = s.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(s[begin])) != 0) ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) --end;
    return s.substr(begin, end - begin);
}

// Первый элемент списка через запятую ("a, b" -> "a"), обрезанный.
std::string first_list_item(const std::string& header) {
    return trim(header.substr(0, header.find(',')));
}

} // namespace

std::string client_ip(const httplib::Request& req) {
    std::string forwarded = first_list_item(req.get_header_value("X-Forwarded-For"));
    if (!forwarded.empty()) return forwarded;
    if (!req.remote_addr.empty()) return req.remote_addr;
    return "unknown";
}

bool is_https(const httplib::Request& req) {
    std::string proto = first_list_item(req.get_header_value("X-Forwarded-Proto"));
    std::transform(proto.begin(), proto.end(), proto.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return proto == "https";
}

std::string rewrite_lan_ip_to_nip_io(const std::string& host) {
    if (host.rfind("192.168.", 0) != 0) return host;
    std::string::size_type colon = host.find(':');
    std::string ip = colon == std::string::npos ? host : host.substr(0, colon);
    std::string rest = colon == std::string::npos ? std::string() : host.substr(colon);
    // Только голый IP: "192.168.1.105.nip.io" тоже начинается с "192.168.",
    // и без этой проверки превращался в "...nip.io.nip.io" и падал в фолбэк.
    if (ip.find_first_not_of("0123456789.") != std::string::npos) return host;
    return ip + ".nip.io" + rest;
}

std::string resolve_redirect_uri(const AppState& state, const httplib::Request& req) {
    // X-Forwarded-Host приоритетнее Host: браузер ходит через wallet-gateway,
    // а тот не форвардит сырой Host и кладёт исходный сюда. Прямые запросы мимо
    // гейтвея заголовка не несут — тогда обычный Host. Хост — это заголовок,
    // который шлёт сам клиент, поэтому слепо ему доверять нельзя: результат
    // берётся, только если он есть в зарегистрированном у Google списке.
    std::string host = req.get_header_value("X-Forwarded-Host");
    if (host.empty()) host = req.get_header_value("Host");
    if (host.empty()) return state.redirect_url;

    host = rewrite_lan_ip_to_nip_io(host);

    // Схему даёт reverse proxy, перед которым стоит TLS (X-Forwarded-Proto);
    // без заголовка — http, как в LAN без TLS.
    std::string candidate = std::string(is_https(req) ? "https" : "http") + "://" + host + "/auth/google/callback";
    if (state.allowed_redirect_uris.count(candidate) > 0) return candidate;
    return state.redirect_url;
}

} // namespace request_info
