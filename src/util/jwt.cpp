#include "util/jwt.hpp"

#include "util/base64.hpp"
#include "util/crypto.hpp"

using nlohmann::json;

namespace jwt {

namespace {

std::vector<std::string> split_token(const std::string& token) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (size_t i = 0; i <= token.size(); ++i) {
        if (i == token.size() || token[i] == '.') {
            parts.push_back(token.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}

std::optional<json> parse_json_part(const std::string& b64_part) {
    try {
        auto bytes = b64::decode(b64_part);
        std::string text(bytes.begin(), bytes.end());
        return json::parse(text);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace

std::string sign_rs256(const json& payload, const crypto::RsaSigningKey& key) {
    json header = {{"alg", "RS256"}, {"typ", "JWT"}, {"kid", key.kid()}};
    std::string h = b64::encode(header.dump());
    std::string p = b64::encode(payload.dump());
    std::string signing_input = h + "." + p;
    auto sig = key.sign(signing_input);
    return signing_input + "." + b64::encode(sig);
}

// Намеренно НЕ проверяет exp (и остальные claims) — эта функция общая для
// двух разных контекстов (id_token Google в google.cpp и наши собственные
// access-токены в auth.cpp), а допустимая обработка "просрочен" в них разная
// (google.cpp хочет отдельное сообщение "id_token истёк", auth.cpp — просто
// отказ). Проверку exp делает вызывающий код, см. auth::authenticate().
std::optional<json> verify_rs256(const std::string& token, const std::vector<unsigned char>& n,
                                  const std::vector<unsigned char>& e) {
    auto parts = split_token(token);
    if (parts.size() != 3) return std::nullopt;

    std::string signing_input = parts[0] + "." + parts[1];
    std::vector<unsigned char> sig;
    try {
        sig = b64::decode(parts[2]);
    } catch (const std::exception&) {
        return std::nullopt;
    }

    if (!crypto::rsa_sha256_verify(n, e, signing_input, sig)) return std::nullopt;

    return parse_json_part(parts[1]);
}

std::optional<std::string> peek_kid(const std::string& token) {
    auto parts = split_token(token);
    if (parts.empty()) return std::nullopt;

    auto header = parse_json_part(parts[0]);
    if (!header || !header->contains("kid")) return std::nullopt;

    try {
        return header->at("kid").get<std::string>();
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace jwt
