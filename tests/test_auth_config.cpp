// auth_config (change add-password-auth, 3.1): разбор AUTH_METHODS и
// REGISTRATION, какие способы включены.
#include "auth_config.hpp"

#include "test_framework.hpp"

TEST(auth_methods_valid_values) {
    CHECK(*parse_auth_methods("password") == AuthMethods::Password);
    CHECK(*parse_auth_methods("google") == AuthMethods::Google);
    CHECK(*parse_auth_methods("both") == AuthMethods::Both);
}

TEST(auth_methods_rejects_anything_else) {
    CHECK(!parse_auth_methods("github").has_value()); // спека: запуск с AUTH_METHODS=github падает
    CHECK(!parse_auth_methods("").has_value());
    CHECK(!parse_auth_methods("Both").has_value());   // регистр значим: опечатка не должна работать молча
    CHECK(!parse_auth_methods("password,google").has_value());
}

TEST(auth_registration_values) {
    CHECK(*parse_registration_open("open") == true);
    CHECK(*parse_registration_open("closed") == false);
    CHECK(!parse_registration_open("true").has_value());
    CHECK(!parse_registration_open("").has_value());
}

TEST(auth_config_defaults_are_both_and_open) {
    AuthConfig c;
    CHECK(c.methods == AuthMethods::Both);
    CHECK(c.registration_open);
    CHECK(!c.allow_insecure); // по умолчанию пароль по HTTP не принимается
    CHECK_EQ(c.pbkdf2_iterations, 600000);
    CHECK_EQ(c.fail_max_per_email, static_cast<int64_t>(5));
    CHECK_EQ(c.fail_max_per_ip, static_cast<int64_t>(30));
    CHECK_EQ(c.fail_window_secs, static_cast<uint64_t>(900));
}

TEST(auth_config_enabled_methods_per_mode) {
    AuthConfig c;
    c.methods = AuthMethods::Both;
    CHECK(c.password_enabled() && c.google_enabled());
    c.methods = AuthMethods::Password;
    CHECK(c.password_enabled() && !c.google_enabled());
    c.methods = AuthMethods::Google;
    CHECK(!c.password_enabled() && c.google_enabled());
}

TEST(auth_config_method_names_order_password_first) {
    AuthConfig c;
    c.methods = AuthMethods::Both;
    auto both = enabled_method_names(c);
    REQUIRE(both.size() == 2);
    CHECK_EQ(both[0], std::string("password"));
    CHECK_EQ(both[1], std::string("google"));

    c.methods = AuthMethods::Google;
    auto google = enabled_method_names(c);
    REQUIRE(google.size() == 1);
    CHECK_EQ(google[0], std::string("google"));

    c.methods = AuthMethods::Password;
    auto pw = enabled_method_names(c);
    REQUIRE(pw.size() == 1);
    CHECK_EQ(pw[0], std::string("password"));
}

TEST(auth_config_registration_available_needs_password_and_open) {
    AuthConfig c;
    c.methods = AuthMethods::Both;
    c.registration_open = true;
    CHECK(c.registration_available()); // спека: both + open -> true

    c.registration_open = false;
    CHECK(!c.registration_available());

    c.methods = AuthMethods::Google; // спека: только Google -> registration false
    c.registration_open = true;
    CHECK(!c.registration_available());

    c.methods = AuthMethods::Password;
    CHECK(c.registration_available());
}
