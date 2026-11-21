// Тесты net/tls из wallet-common (change add-internal-mtls, задача 3.2): рукопожатие
// проходит с верным сертификатом и не проходит без сертификата, с чужим CA, с чужим
// именем сервера, по обычному HTTP; peer_service() возвращает CN клиента.
// Сертификаты (ECDSA P-256) тест выпускает сам через OpenSSL API — CLI не нужен.
#include "net/tls.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <thread>

#include "test_framework.hpp"

namespace {

struct Pem {
    std::string cert;
    std::string key;
    X509* x509 = nullptr; // владеет
    EVP_PKEY* pkey = nullptr; // владеет
    ~Pem() {
        if (x509) X509_free(x509);
        if (pkey) EVP_PKEY_free(pkey);
    }
    Pem() = default;
    Pem(const Pem&) = delete;
    Pem& operator=(const Pem&) = delete;
};

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    long n = BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<size_t>(n));
}

void add_ext(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
}

// ca == nullptr — самоподписанный корень. san пуст — без SAN.
std::unique_ptr<Pem> issue(const std::string& cn, const std::string& san, Pem* ca, long days = 30) {
    auto out = std::make_unique<Pem>();
    out->pkey = EVP_EC_gen("P-256");
    out->x509 = X509_new();
    X509* c = out->x509;
    X509_set_version(c, 2);
    static std::atomic<long> serial{1};
    ASN1_INTEGER_set(X509_get_serialNumber(c), serial++);
    X509_gmtime_adj(X509_getm_notBefore(c), -60);
    X509_gmtime_adj(X509_getm_notAfter(c), days * 24 * 3600);
    X509_set_pubkey(c, out->pkey);
    X509_NAME* name = X509_get_subject_name(c);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509* issuer = ca ? ca->x509 : c;
    X509_set_issuer_name(c, X509_get_subject_name(issuer));
    if (!ca) {
        add_ext(c, issuer, NID_basic_constraints, "critical,CA:TRUE");
        add_ext(c, issuer, NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add_ext(c, issuer, NID_basic_constraints, "CA:FALSE");
        add_ext(c, issuer, NID_ext_key_usage, "serverAuth,clientAuth");
        if (!san.empty()) add_ext(c, issuer, NID_subject_alt_name, san.c_str());
    }
    X509_sign(c, ca ? ca->pkey : out->pkey, EVP_sha256());

    BIO* b1 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b1, c);
    out->cert = bio_to_string(b1);
    BIO_free(b1);
    BIO* b2 = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b2, out->pkey, nullptr, nullptr, 0, nullptr, nullptr);
    out->key = bio_to_string(b2);
    BIO_free(b2);
    return out;
}

// Временный каталог с PEM-файлами; удаляется в деструкторе.
class Dir {
public:
    Dir() {
        static std::atomic<int> n{0};
        path_ = std::filesystem::temp_directory_path() /
                ("nettls-" + std::to_string(std::random_device{}()) + "-" + std::to_string(n++));
        std::filesystem::create_directories(path_);
    }
    ~Dir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    std::string write(const std::string& name, const std::string& content) {
        auto p = path_ / name;
        std::ofstream(p, std::ios::binary) << content;
        return p.string();
    }

private:
    std::filesystem::path path_;
};

nettls::Config files(Dir& d, const std::string& tag, const Pem& leaf, const Pem& ca) {
    return nettls::Config{d.write(tag + ".crt", leaf.cert), d.write(tag + ".key", leaf.key),
                          d.write(tag + "-ca.pem", ca.cert)};
}

// Сервер на свободном порту 127.0.0.1; GET /who отвечает CN клиента.
class Running {
public:
    explicit Running(std::unique_ptr<httplib::Server> s) : svr_(std::move(s)) {
        svr_->Get("/who", [](const httplib::Request& req, httplib::Response& res) {
            res.set_content("cn=" + nettls::peer_service(req), "text/plain");
        });
        port_ = svr_->bind_to_any_port("127.0.0.1");
        thread_ = std::thread([this] { svr_->listen_after_bind(); });
        svr_->wait_until_ready();
    }
    ~Running() {
        svr_->stop();
        if (thread_.joinable()) thread_.join();
    }
    int port() const { return port_; }

private:
    std::unique_ptr<httplib::Server> svr_;
    std::thread thread_;
    int port_ = 0;
};

std::string url(int port) { return "http://127.0.0.1:" + std::to_string(port); }

} // namespace

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
