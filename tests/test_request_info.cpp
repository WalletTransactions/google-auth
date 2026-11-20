// request_info (change add-password-auth, 2.3/3.7): IP клиента, признак HTTPS и
// сборка redirect_uri со схемой из X-Forwarded-Proto.
#include "request_info.hpp"

#include "test_framework.hpp"

namespace {

httplib::Request make_request(std::initializer_list<std::pair<const char*, const char*>> headers) {
    httplib::Request req;
    for (const auto& [k, v] : headers) req.set_header(k, v);
    return req;
}

// AppState не копируется (мьютексы, unique_ptr) — заполняем по ссылке.
void fill_state(AppState& state) {
    state.redirect_url = "http://localhost:8080/auth/google/callback";
    state.allowed_redirect_uris = {
        "http://localhost:8080/auth/google/callback",
        "http://192.168.1.105.nip.io:8090/auth/google/callback",
        "https://wallet.example.com/auth/google/callback",
    };
}

} // namespace

TEST(request_info_client_ip_prefers_first_forwarded_for) {
    auto req = make_request({{"X-Forwarded-For", "203.0.113.7, 10.0.0.2"}});
    req.remote_addr = "172.18.0.5";
    CHECK_EQ(request_info::client_ip(req), std::string("203.0.113.7"));
}

TEST(request_info_client_ip_trims_and_falls_back_to_connection) {
    // Пробелы по краям значения срезает сам парсер HTTP, а вот перед запятой в списке остаются.
    auto spaced = make_request({{"X-Forwarded-For", "198.51.100.4 , 10.0.0.2"}});
    CHECK_EQ(request_info::client_ip(spaced), std::string("198.51.100.4"));

    auto none = make_request({});
    none.remote_addr = "172.18.0.5";
    CHECK_EQ(request_info::client_ip(none), std::string("172.18.0.5"));

    auto nothing = make_request({});
    CHECK_EQ(request_info::client_ip(nothing), std::string("unknown")); // ключ счётчика не бывает пустым
}

TEST(request_info_is_https_by_forwarded_proto) {
    CHECK(request_info::is_https(make_request({{"X-Forwarded-Proto", "https"}})));
    CHECK(request_info::is_https(make_request({{"X-Forwarded-Proto", "HTTPS"}})));
    CHECK(request_info::is_https(make_request({{"X-Forwarded-Proto", "https, http"}}))); // первый прокси
    CHECK(!request_info::is_https(make_request({{"X-Forwarded-Proto", "http"}})));
    CHECK(!request_info::is_https(make_request({{"X-Forwarded-Proto", "http, https"}})));
    CHECK(!request_info::is_https(make_request({})));
}

TEST(request_info_redirect_uri_https_behind_tls) {
    AppState state;
    fill_state(state);
    auto req = make_request({{"X-Forwarded-Host", "wallet.example.com"}, {"X-Forwarded-Proto", "https"}});
    CHECK_EQ(request_info::resolve_redirect_uri(state, req),
             std::string("https://wallet.example.com/auth/google/callback"));
}

TEST(request_info_redirect_uri_http_without_proto) {
    AppState state;
    fill_state(state);
    // Тот же хост без заголовка схемы — http://wallet.example.com/... нет в списке -> запасной.
    auto req = make_request({{"X-Forwarded-Host", "wallet.example.com"}});
    CHECK_EQ(request_info::resolve_redirect_uri(state, req), state.redirect_url);

    // LAN: схема по умолчанию http, голый IP переписывается в nip.io.
    auto lan = make_request({{"X-Forwarded-Host", "192.168.1.105:8090"}});
    CHECK_EQ(request_info::resolve_redirect_uri(state, lan),
             std::string("http://192.168.1.105.nip.io:8090/auth/google/callback"));
}

TEST(request_info_redirect_uri_not_in_allowlist_falls_back) {
    AppState state;
    fill_state(state);
    // https-адрес, которого нет в зарегистрированных у Google, не принимается на слово.
    auto req = make_request({{"X-Forwarded-Host", "evil.example.org"}, {"X-Forwarded-Proto", "https"}});
    CHECK_EQ(request_info::resolve_redirect_uri(state, req), state.redirect_url);
}

TEST(request_info_redirect_uri_host_header_and_empty) {
    AppState state;
    fill_state(state);
    auto direct = make_request({{"Host", "localhost:8080"}});
    CHECK_EQ(request_info::resolve_redirect_uri(state, direct),
             std::string("http://localhost:8080/auth/google/callback"));
    auto empty = make_request({});
    CHECK_EQ(request_info::resolve_redirect_uri(state, empty), state.redirect_url);
}

TEST(request_info_rewrite_lan_ip) {
    CHECK_EQ(request_info::rewrite_lan_ip_to_nip_io("192.168.1.105:8090"), std::string("192.168.1.105.nip.io:8090"));
    CHECK_EQ(request_info::rewrite_lan_ip_to_nip_io("192.168.1.105"), std::string("192.168.1.105.nip.io"));
    // Уже nip.io, другие подсети и домены не трогаем.
    CHECK_EQ(request_info::rewrite_lan_ip_to_nip_io("192.168.1.105.nip.io:8090"), std::string("192.168.1.105.nip.io:8090"));
    CHECK_EQ(request_info::rewrite_lan_ip_to_nip_io("10.0.0.5:80"), std::string("10.0.0.5:80"));
    CHECK_EQ(request_info::rewrite_lan_ip_to_nip_io("localhost:8080"), std::string("localhost:8080"));
}
