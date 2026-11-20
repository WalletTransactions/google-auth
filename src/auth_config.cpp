#include "auth_config.hpp"

std::optional<AuthMethods> parse_auth_methods(const std::string& value) {
    if (value == "password") return AuthMethods::Password;
    if (value == "google") return AuthMethods::Google;
    if (value == "both") return AuthMethods::Both;
    return std::nullopt;
}

std::optional<bool> parse_registration_open(const std::string& value) {
    if (value == "open") return true;
    if (value == "closed") return false;
    return std::nullopt;
}

std::vector<std::string> enabled_method_names(const AuthConfig& config) {
    std::vector<std::string> out;
    if (config.password_enabled()) out.push_back("password");
    if (config.google_enabled()) out.push_back("google");
    return out;
}
