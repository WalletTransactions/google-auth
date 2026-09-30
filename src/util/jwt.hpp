// Минимальная реализация JWT (JWS Compact Serialization) поверх
// util/crypto.hpp + nlohmann::json — без внешней JWT-библиотеки, чтобы не
// тащить лишнюю зависимость ради десятка строк кодирования/проверки.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "util/crypto.hpp"

namespace jwt {

// Подписывает payload как RS256 JWT (для СВОИХ access-токенов) — заголовок
// получает "kid" из key.kid(), верифицирующая сторона (wallet-api/
// wallet-gateway) использует его, чтобы выбрать нужный публичный ключ из
// JWKS (см. auth.cpp: GET /.well-known/jwks.json).
std::string sign_rs256(const nlohmann::json& payload, const crypto::RsaSigningKey& key);

// Проверяет подпись RS256 по сырым модулю/экспоненте RSA-ключа (как их
// отдаёт JWKS) и срок действия (exp, если есть). НЕ проверяет остальные
// claims (iss/aud) — это ответственность вызывающего кода, т.к. допустимые
// значения зависят от контекста (например, google.cpp для id_token Google —
// свои iss/aud, наши собственные access-токены их не используют вовсе).
std::optional<nlohmann::json> verify_rs256(const std::string& token,
                                            const std::vector<unsigned char>& n,
                                            const std::vector<unsigned char>& e);

// Читает `kid` из заголовка БЕЗ проверки подписи — нужен только чтобы понять,
// каким ключом из JWKS проверять токен дальше.
std::optional<std::string> peek_kid(const std::string& token);

} // namespace jwt
