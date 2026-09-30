// Разовый CLI для нагрузочного контура wallet-report
// (wallet-report/loadtest/README.md) — печатает в stdout валидный
// RS256 access-токен, подписанный ТЕМ ЖЕ кодом, что реально выпускает
// google-auth (auth.cpp::issue_access_token), просто без похода через
// настоящий OAuth Google: никакого тестового/обходного эндпоинта в проде
// нет и не должно быть (см. tests/README.md, "google.cpp не покрыт юнит-
// тестами"), а ручной base64url-JWT в bash легко собрать неправильно
// (padding, алфавит). Здесь используется тот же jwt::sign_rs256 +
// crypto::RsaSigningKey, что и в самом сервисе — kid() детерминированно
// выводится из публичной части ключа (см. util/crypto.cpp), поэтому токен
// автоматически совпадает с тем, что реально отдаёт GET
// /.well-known/jwks.json того же ключа.
//
// ДЛЯ ЛОКАЛЬНОЙ РАЗРАБОТКИ. Инструмент требует путь к приватному ключу
// (jwt_signing_key.pem) — не гонять против чего-либо с боевым ключом.
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unordered_map>

#include "nlohmann/json.hpp"
#include "token_claims.hpp"
#include "util/crypto.hpp"
#include "util/jwt.hpp"
#include "util/time.hpp"

using nlohmann::json;

namespace {

void print_usage() {
    std::cerr
        << "Использование: mint_loadtest_token --pem <path> --sub <user_id> --email <email>\n"
           "  [--name <name>] [--role <user|admin>] [--ttl-secs <n>]\n"
           "  [--device-id <id>] [--platform <platform>]\n\n"
           "Печатает готовый RS256 JWT в stdout. Для локальной разработки\n"
           "(нагрузочный контур wallet-report) — см. wallet-report/loadtest/README.md.\n";
}

std::unordered_map<std::string, std::string> parse_args(int argc, char** argv) {
    std::unordered_map<std::string, std::string> out;
    for (int i = 1; i < argc; ++i) {
        std::string key = argv[i];
        if (key.rfind("--", 0) != 0 || i + 1 >= argc) continue;
        out[key.substr(2)] = argv[++i];
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    auto args = parse_args(argc, argv);

    auto require = [&](const char* name) -> std::string {
        auto it = args.find(name);
        if (it == args.end() || it->second.empty()) {
            std::cerr << "--" << name << " обязателен\n\n";
            print_usage();
            std::exit(1);
        }
        return it->second;
    };

    std::string pem_path = require("pem");
    std::string sub = require("sub");
    std::string email = require("email");
    std::string name = args.count("name") ? args["name"] : email;
    std::string role = args.count("role") ? args["role"] : "user";
    uint64_t ttl_secs = args.count("ttl-secs") ? std::stoull(args["ttl-secs"]) : 3600;

    try {
        crypto::RsaSigningKey key(pem_path);

        uint64_t now = timeutil::now_epoch();
        json payload = {
            {"sub", sub}, {"email", email}, {"name", name}, {"role", role},
            {"iat", now}, {"exp", now + ttl_secs},
        };
        // device_id/platform — те же два необязательных claim'а, что
        // добавляет issue_access_token() только при мобильном входе (см.
        // auth.cpp) — здесь тоже опциональны.
        if (args.count("device-id") && !args["device-id"].empty()) {
            payload["device_id"] = args["device-id"];
            payload["platform"] = args.count("platform") ? args["platform"] : "other";
        }
        // iss/aud/scope — те же, что у настоящих токенов (token_claims.hpp):
        // когда сервисы начнут отклонять токены без aud, нагрузочный контур
        // не должен сломаться.
        token_claims::add_user_claims(payload);

        std::cout << jwt::sign_rs256(payload, key) << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
