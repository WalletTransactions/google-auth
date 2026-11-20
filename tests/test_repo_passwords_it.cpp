// Интеграционный прогон repo::*password* на живой БД (change add-password-auth,
// задача 1.3). Без TEST_DATABASE_URL тесты молча пропускаются — обычный ctest
// не требует Postgres. Нужна база с накаченной схемой (миграции 000001–000005);
// тесты сами заводят пользователей с уникальными email и убирают за собой.
//
//   TEST_DATABASE_URL="host=127.0.0.1 dbname=auth user=postgres password=pw" \
//       ./google_auth_tests
#include <cstdlib>
#include <iostream>

#include "db.hpp"
#include "passwords.hpp"
#include "repo.hpp"
#include "test_framework.hpp"
#include "util/uuid.hpp"

namespace {

// nullptr — переменная не задана, тест пропускается.
db::Database* test_db() {
    static std::unique_ptr<db::Database> database;
    static bool tried = false;
    if (!tried) {
        tried = true;
        const char* url = std::getenv("TEST_DATABASE_URL");
        if (url != nullptr && *url != '\0') database = std::make_unique<db::Database>(url);
    }
    return database.get();
}

std::string unique_email(const char* tag) {
    return std::string(tag) + "-" + uuidgen::v4().substr(0, 8) + "@it.example.com";
}

constexpr int kIter = 1000;

} // namespace

#define REQUIRE_DB(var)                                                              \
    db::Database* var = test_db();                                                   \
    if (var == nullptr) {                                                            \
        std::cerr << "  [SKIP] " << ::testing::current_test_name() << ": нет TEST_DATABASE_URL\n"; \
        return;                                                                      \
    }

TEST(it_create_password_user_and_find) {
    REQUIRE_DB(db);
    std::string email = unique_email("create");
    auto rec = passwords::make_record("correct horse battery", kIter);

    auto user = repo::create_password_user(*db, email, "Тест", rec);
    REQUIRE(user.has_value());
    CHECK_EQ(user->email, email);
    CHECK(!user->email_verified);
    CHECK(user->role == Role::User);
    CHECK_EQ(user->google_sub, std::string(""));
    CHECK_EQ(user->name, std::string("Тест"));
    CHECK_EQ(user->last_login_at, std::string(""));

    // Поиск без учёта регистра.
    std::string shouting = email;
    for (char& c : shouting) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    auto found = repo::find_user_by_email(*db, shouting);
    REQUIRE(found.has_value());
    CHECK_EQ(found->id, user->id);

    // Пароль читается обратно и проверяется.
    auto stored = repo::find_password(*db, user->id);
    REQUIRE(stored.has_value());
    CHECK_EQ(stored->iterations, kIter);
    CHECK_EQ(stored->salt, rec.salt);
    CHECK_EQ(stored->hash, rec.hash);
    CHECK(passwords::verify("correct horse battery", *stored));
    CHECK(!passwords::verify("wrong password!!", *stored));

    repo::delete_user(*db, user->id);
    CHECK(!repo::find_password(*db, user->id).has_value()); // каскад
}

TEST(it_create_password_user_taken_email_changes_nothing) {
    REQUIRE_DB(db);
    std::string email = unique_email("taken");
    auto first_rec = passwords::make_record("first password!!", kIter);
    auto first = repo::create_password_user(*db, email, "Первый", first_rec);
    REQUIRE(first.has_value());

    auto second = repo::create_password_user(*db, email, "Второй", passwords::make_record("second password", kIter));
    CHECK(!second.has_value());

    // Регистр не обходит занятость.
    auto third = repo::create_password_user(*db, "X" + email, "Третий", first_rec);
    CHECK(third.has_value()); // другой адрес — свободен
    auto fourth = repo::create_password_user(*db, "x" + email, "Четвёртый", first_rec);
    CHECK(!fourth.has_value()); // тот же адрес в другом регистре — занят

    // Первая запись не тронута.
    auto stored = repo::find_password(*db, first->id);
    REQUIRE(stored.has_value());
    CHECK_EQ(stored->hash, first_rec.hash);
    CHECK_EQ(repo::find_user_by_id(*db, first->id)->name, std::string("Первый"));

    repo::delete_user(*db, first->id);
    if (third) repo::delete_user(*db, third->id);
}

TEST(it_create_password_user_blocked_by_google_user) {
    REQUIRE_DB(db);
    std::string email = unique_email("googleowner");
    auto g = repo::upsert_user(*db, "it-sub-" + uuidgen::v4(), email, true, "Google", "", Role::User);

    auto attempt = repo::create_password_user(*db, email, "Захват", passwords::make_record("attacker password", kIter));
    CHECK(!attempt.has_value());
    CHECK(!repo::find_password(*db, g.id).has_value());

    repo::delete_user(*db, g.id);
}

TEST(it_set_and_delete_password) {
    REQUIRE_DB(db);
    // Google-пользователь без пароля получает его через set_password.
    std::string email = unique_email("setpw");
    auto g = repo::upsert_user(*db, "it-sub-" + uuidgen::v4(), email, true, "Google", "", Role::User);
    CHECK(!repo::find_password(*db, g.id).has_value());

    repo::set_password(*db, g.id, passwords::make_record("first password!!", kIter));
    auto first = repo::find_password(*db, g.id);
    REQUIRE(first.has_value());
    CHECK(passwords::verify("first password!!", *first));

    // Повторный вызов заменяет, а не дублирует.
    repo::set_password(*db, g.id, passwords::make_record("second password", kIter * 2));
    auto second = repo::find_password(*db, g.id);
    REQUIRE(second.has_value());
    CHECK_EQ(second->iterations, kIter * 2);
    CHECK(passwords::verify("second password", *second));
    CHECK(!passwords::verify("first password!!", *second));

    // google_sub и email_verified не затронуты.
    auto after = repo::find_user_by_id(*db, g.id);
    REQUIRE(after.has_value());
    CHECK_EQ(after->google_sub, g.google_sub);
    CHECK(after->email_verified);

    repo::delete_password(*db, g.id);
    CHECK(!repo::find_password(*db, g.id).has_value());
    repo::delete_password(*db, g.id); // повтор — не ошибка

    repo::delete_user(*db, g.id);
}

TEST(it_find_user_by_email_prefers_account_with_password) {
    REQUIRE_DB(db);
    std::string email = unique_email("dup");
    // Исторически допустимо: два Google-пользователя с одним email.
    auto a = repo::upsert_user(*db, "it-sub-" + uuidgen::v4(), email, true, "A", "", Role::User);
    auto b = repo::upsert_user(*db, "it-sub-" + uuidgen::v4(), email, true, "B", "", Role::User);
    repo::set_password(*db, b.id, passwords::make_record("b password!!!", kIter));

    auto found = repo::find_user_by_email(*db, email);
    REQUIRE(found.has_value());
    CHECK_EQ(found->id, b.id); // тот, у кого есть пароль, даже если он новее

    repo::delete_user(*db, a.id);
    repo::delete_user(*db, b.id);
}

TEST(it_find_user_by_email_free_address) {
    REQUIRE_DB(db);
    CHECK(!repo::find_user_by_email(*db, unique_email("nobody")).has_value());
}

TEST(it_link_google_takes_unverified_password_account) {
    REQUIRE_DB(db);
    std::string email = unique_email("victim");
    auto rec = passwords::make_record("attacker password", kIter);
    auto squatter = repo::create_password_user(*db, email, "Атакующий", rec);
    REQUIRE(squatter.has_value());

    auto candidate = repo::find_unverified_password_user(*db, email);
    REQUIRE(candidate.has_value());
    CHECK_EQ(candidate->id, squatter->id);

    std::string sub = "it-sub-" + uuidgen::v4();
    auto linked = repo::link_google_sub(*db, candidate->id, sub, "Владелец", "https://pic/x");
    REQUIRE(linked.has_value());
    CHECK_EQ(linked->id, squatter->id); // тот же users.id — данные кошелька остаются
    CHECK_EQ(linked->google_sub, sub);
    CHECK(linked->email_verified);
    CHECK_EQ(linked->name, std::string("Владелец"));
    CHECK_EQ(linked->picture, std::string("https://pic/x"));
    CHECK(linked->last_login_at != std::string(""));
    CHECK(linked->role == Role::User); // привязка роль не меняет

    // Пароль злоумышленника удалён.
    CHECK(!repo::find_password(*db, squatter->id).has_value());
    // Второй раз привязать нельзя, и кандидатом аккаунт больше не является.
    CHECK(!repo::link_google_sub(*db, squatter->id, "it-sub-" + uuidgen::v4(), "Ещё", "").has_value());
    CHECK(!repo::find_unverified_password_user(*db, email).has_value());
    // Привязка видна и поиском по google_sub.
    auto by_sub = repo::find_user_by_google_sub(*db, sub);
    REQUIRE(by_sub.has_value());
    CHECK_EQ(by_sub->id, squatter->id);

    repo::delete_user(*db, squatter->id);
}

TEST(it_link_google_skips_verified_and_google_accounts) {
    REQUIRE_DB(db);
    std::string email = unique_email("verified");
    auto g = repo::upsert_user(*db, "it-sub-" + uuidgen::v4(), email, true, "G", "", Role::User);
    // У Google-пользователя google_sub уже есть: кандидатом он не является.
    CHECK(!repo::find_unverified_password_user(*db, email).has_value());
    CHECK(!repo::link_google_sub(*db, g.id, "it-sub-" + uuidgen::v4(), "X", "").has_value());
    CHECK_EQ(repo::find_user_by_id(*db, g.id)->google_sub, g.google_sub);
    repo::delete_user(*db, g.id);
}

TEST(it_touch_last_login) {
    REQUIRE_DB(db);
    auto user = repo::create_password_user(*db, unique_email("login"), "T", passwords::make_record("correct horse battery", kIter));
    REQUIRE(user.has_value());
    CHECK_EQ(user->last_login_at, std::string(""));
    repo::touch_last_login(*db, user->id);
    CHECK(repo::find_user_by_id(*db, user->id)->last_login_at != std::string(""));
    repo::delete_user(*db, user->id);
}
