// Общие помощники тестов с TLS: выпуск ECDSA-сертификатов через OpenSSL API (CLI не
// нужен), временный каталог с PEM-файлами, сервер на свободном порту.
#pragma once

#include "net/tls.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <thread>

namespace tlstest {

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

inline std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    long n = BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<size_t>(n));
}

inline void add_ext(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
}

// ca == nullptr — самоподписанный корень. san пуст — без SAN.
inline std::unique_ptr<Pem> issue(const std::string& cn, const std::string& san, Pem* ca, long days = 30) {
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

inline nettls::Config files(Dir& d, const std::string& tag, const Pem& leaf, const Pem& ca) {
    return nettls::Config{d.write(tag + ".crt", leaf.cert), d.write(tag + ".key", leaf.key),
                          d.write(tag + "-ca.pem", ca.cert)};
}

// Сервер на свободном порту 127.0.0.1. По умолчанию GET /who отвечает CN клиента;
// setup позволяет зарегистрировать свои маршруты вместо него.
class Running {
public:
    explicit Running(std::unique_ptr<httplib::Server> s,
                     std::function<void(httplib::Server&)> setup = nullptr)
        : svr_(std::move(s)) {
        if (setup) {
            setup(*svr_);
        } else {
            svr_->Get("/who", [](const httplib::Request& req, httplib::Response& res) {
                res.set_content("cn=" + nettls::peer_service(req), "text/plain");
            });
        }
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

inline std::string url(int port) { return "http://127.0.0.1:" + std::to_string(port); }


} // namespace tlstest
