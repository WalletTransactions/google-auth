#include "types.hpp"

#include "test_framework.hpp"

TEST(types_to_string_matches_role) {
    CHECK_EQ(std::string(to_string(Role::Admin)), std::string("admin"));
    CHECK_EQ(std::string(to_string(Role::Support)), std::string("support"));
    CHECK_EQ(std::string(to_string(Role::User)), std::string("user"));
}

TEST(types_role_from_string_roundtrip) {
    CHECK(role_from_string("admin") == Role::Admin);
    CHECK(role_from_string("support") == Role::Support);
    CHECK(role_from_string("user") == Role::User);
}

TEST(types_role_from_string_unknown_defaults_to_user) {
    // Минимум привилегий по умолчанию — см. комментарий в types.hpp.
    CHECK(role_from_string("") == Role::User);
    CHECK(role_from_string("superadmin") == Role::User);
    CHECK(role_from_string("Admin") == Role::User); // регистрозависимо, намеренно
}

TEST(types_role_id_roundtrip) {
    CHECK(role_from_id(to_role_id(Role::User)) == Role::User);
    CHECK(role_from_id(to_role_id(Role::Support)) == Role::Support);
    CHECK(role_from_id(to_role_id(Role::Admin)) == Role::Admin);
}

TEST(types_role_from_id_unknown_defaults_to_user) {
    CHECK(role_from_id(0) == Role::User);
    CHECK(role_from_id(99) == Role::User);
}

TEST(types_role_ids_are_fixed_values) {
    // Значения зашиты синхронно с seed-данными таблицы roles (см.
    // infra/db/init-db.sh в корне репозитория) — если кто-то поменяет их здесь, не
    // тронув seed, этот тест должен упасть первым.
    CHECK_EQ(to_role_id(Role::User), static_cast<std::int16_t>(1));
    CHECK_EQ(to_role_id(Role::Support), static_cast<std::int16_t>(2));
    CHECK_EQ(to_role_id(Role::Admin), static_cast<std::int16_t>(3));
}
