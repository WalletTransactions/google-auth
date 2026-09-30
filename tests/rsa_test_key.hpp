// Одноразовый RSA-ключ на диске — только для тестов. crypto::RsaSigningKey
// умеет грузить ключ только из файла (нет конструктора "из памяти"), а
// jwt.hpp/auth.cpp тестируются именно через неё — поэтому здесь честно
// генерируем ключ и кладём его во временный файл вместо того, чтобы хранить
// в репозитории готовый PEM (даже тестовый приватный ключ в git — плохая
// практика и повод для лишних вопросов при аудите).
#pragma once

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

class TempRsaKeyFile {
public:
    TempRsaKeyFile() {
        path_ = (std::filesystem::temp_directory_path() /
                 ("google_auth_test_key_" + std::to_string(reinterpret_cast<std::uintptr_t>(this)) +
                  "_" + std::to_string(std::rand()) + ".pem"))
                    .string();

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (ctx == nullptr || EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("TempRsaKeyFile: не удалось инициализировать генерацию RSA-ключа");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("TempRsaKeyFile: не удалось сгенерировать RSA-ключ");
        }
        EVP_PKEY_CTX_free(ctx);

        BIO* bio = BIO_new_file(path_.c_str(), "wb");
        if (bio == nullptr ||
            PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            if (bio != nullptr) BIO_free(bio);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("TempRsaKeyFile: не удалось записать тестовый ключ на диск: " +
                                      path_);
        }
        BIO_free(bio);
        EVP_PKEY_free(pkey);
    }

    ~TempRsaKeyFile() { std::remove(path_.c_str()); }

    TempRsaKeyFile(const TempRsaKeyFile&) = delete;
    TempRsaKeyFile& operator=(const TempRsaKeyFile&) = delete;

    const std::string& path() const { return path_; }

private:
    std::string path_;
};
