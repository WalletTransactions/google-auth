// Тесты net/tls из wallet-common (change add-internal-mtls, задача 3.2): рукопожатие
// проходит с верным сертификатом и не проходит без сертификата, с чужим CA, с чужим
// именем сервера, по обычному HTTP; peer_service() возвращает CN клиента.
// Сертификаты (ECDSA P-256) тест выпускает сам через OpenSSL API — CLI не нужен.
#include "net/tls.hpp"

#include "test_framework.hpp"
#include "tls_test_util.hpp"

using namespace tlstest;

TEST(nettls_config_all_empty_is_disabled) {
    auto r = nettls::config_from("", "", "");
    CHECK(r.error.empty());
    CHECK(!r.config.enabled());
}

TEST(nettls_config_partial_is_error_naming_missing) {
    auto r = nettls::config_from("/c", "", "");
    CHECK(!r.error.empty());
    CHECK(r.error.find("TLS_KEY") != std::string::npos);
    CHECK(r.error.find("TLS_CA") != std::string::npos);
    CHECK(r.error.find("TLS_CERT") == std::string::npos);
    CHECK(!r.config.enabled());
}

TEST(nettls_config_all_set_is_enabled) {
    auto r = nettls::config_from("/c", "/k", "/ca");
    CHECK(r.error.empty());
    CHECK(r.config.enabled());
    CHECK_EQ(r.config.ca, std::string("/ca"));
}

TEST(nettls_to_https_rewrites_only_http_scheme) {
    CHECK_EQ(nettls::to_https("http://google-auth:8080"), std::string("https://google-auth:8080"));
    CHECK_EQ(nettls::to_https("https://x:1"), std::string("https://x:1"));
    CHECK_EQ(nettls::to_https("x:1"), std::string("x:1"));
}

TEST(nettls_disabled_gives_plain_server_and_client_and_empty_peer) {
    nettls::Config off;
    Running run(nettls::make_server(off));
    auto cli = nettls::make_client(url(run.port()), off);
    REQUIRE(cli != nullptr);
    auto res = cli->Get("/who");
    REQUIRE(static_cast<bool>(res));
    CHECK_EQ(res->status, 200);
    CHECK_EQ(res->body, std::string("cn="));
}

TEST(nettls_handshake_ok_and_peer_service_is_client_cn) {
    Dir d;
    auto ca = issue("wallet-test-ca", "", nullptr);
    auto srv = issue("google-auth", "IP:127.0.0.1,DNS:google-auth", ca.get());
    auto cl = issue("wallet-telegram", "DNS:wallet-telegram", ca.get());
    std::string err;
    auto server = nettls::make_server(files(d, "srv", *srv, *ca), &err);
    REQUIRE(server != nullptr);
    Running run(std::move(server));

    auto cli = nettls::make_client(url(run.port()), files(d, "cl", *cl, *ca), &err);
    REQUIRE(cli != nullptr);
    auto res = cli->Get("/who");
    REQUIRE(static_cast<bool>(res));
    CHECK_EQ(res->status, 200);
    CHECK_EQ(res->body, std::string("cn=wallet-telegram"));
}

TEST(nettls_client_without_certificate_is_rejected) {
    Dir d;
    auto ca = issue("ca", "", nullptr);
    auto srv = issue("google-auth", "IP:127.0.0.1", ca.get());
    Running run(nettls::make_server(files(d, "srv", *srv, *ca)));

    httplib::Client cli("https://127.0.0.1:" + std::to_string(run.port()));
    cli.set_ca_cert_path(d.write("only-ca.pem", ca->cert));
    cli.enable_server_certificate_verification(true);
    auto res = cli.Get("/who");
    CHECK(!res || res->status != 200); // сервер требует клиентский сертификат
    CHECK(!(res && res->status == 200));
}

TEST(nettls_client_from_other_ca_is_rejected) {
    Dir d;
    auto ca = issue("ca-a", "", nullptr);
    auto other = issue("ca-b", "", nullptr);
    auto srv = issue("google-auth", "IP:127.0.0.1", ca.get());
    auto stranger = issue("wallet-telegram", "DNS:wallet-telegram", other.get());
    Running run(nettls::make_server(files(d, "srv", *srv, *ca)));

    // Сертификат клиента — от чужого CA; корень у клиента свой, сервер проверяет по ca-a.
    nettls::Config cfg = files(d, "cl", *stranger, *ca); // корень ca-a, чтобы сервер был признан
    auto cli = nettls::make_client(url(run.port()), cfg);
    REQUIRE(cli != nullptr);
    auto res = cli->Get("/who");
    CHECK(!(res && res->status == 200));
}

TEST(nettls_server_with_foreign_name_is_rejected_by_client) {
    Dir d;
    auto ca = issue("ca", "", nullptr);
    // SAN сервера не содержит ни 127.0.0.1, ни имени из URL.
    auto srv = issue("other-service", "DNS:other-service", ca.get());
    auto cl = issue("wallet-telegram", "DNS:wallet-telegram", ca.get());
    Running run(nettls::make_server(files(d, "srv", *srv, *ca)));

    auto cli = nettls::make_client(url(run.port()), files(d, "cl", *cl, *ca));
    REQUIRE(cli != nullptr);
    auto res = cli->Get("/who");
    CHECK(!(res && res->status == 200));
}

TEST(nettls_plain_http_to_tls_server_fails) {
    Dir d;
    auto ca = issue("ca", "", nullptr);
    auto srv = issue("google-auth", "IP:127.0.0.1", ca.get());
    Running run(nettls::make_server(files(d, "srv", *srv, *ca)));

    httplib::Client cli(url(run.port()));
    cli.set_connection_timeout(2);
    cli.set_read_timeout(2);
    auto res = cli.Get("/who");
    CHECK(!(res && res->status == 200));
}

TEST(nettls_server_with_unreadable_files_reports_error) {
    nettls::Config bad{"/nonexistent/c.pem", "/nonexistent/k.pem", "/nonexistent/ca.pem"};
    std::string err;
    auto s = nettls::make_server(bad, &err);
    CHECK(s == nullptr);
    CHECK(err.find("TLS_CERT") != std::string::npos);
}

TEST(nettls_expired_server_certificate_is_rejected) {
    Dir d;
    auto ca = issue("ca", "", nullptr);
    auto srv = issue("google-auth", "IP:127.0.0.1", ca.get(), -1); // уже истёк
    auto cl = issue("wallet-telegram", "DNS:wallet-telegram", ca.get());
    Running run(nettls::make_server(files(d, "srv", *srv, *ca)));

    auto cli = nettls::make_client(url(run.port()), files(d, "cl", *cl, *ca));
    REQUIRE(cli != nullptr);
    auto res = cli->Get("/who");
    CHECK(!(res && res->status == 200));
}
