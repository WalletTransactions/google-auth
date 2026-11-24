// auth::claim_password_account (change add-password-auth, 3.2): «Google
// забирает неподтверждённый парольный аккаунт» на живых Postgres и Redis.
// Без TEST_DATABASE_URL и TEST_REDIS_HOST тесты пропускаются.
#include <cstdlib>
#include <iostream>
#include <memory>

#include "auth.hpp"
#include "passwords.hpp"
#include "repo.hpp"
#include "rsa_test_key.hpp"
#include "test_framework.hpp"
#include "util/uuid.hpp"

namespace {

constexpr int kIter = 1000;

struct ItEnv {
    TempRsaKeyFile key;
    AppState state;
};

// nullptr — окружения для интеграционных тестов нет.
ItEnv* it_env() {
    static std::unique_ptr<ItEnv> env;
    static bool tried = false;
    if (!tried) {
        tried = true;
        const char* url = std::getenv("TEST_DATABASE_URL");
        const char* redis_addr = std::getenv("TEST_REDIS_HOST");
        if (url != nullptr && *url != '\0' && redis_addr != nullptr && *redis_addr != '\0') {
            env = std::make_unique<ItEnv>();
            env->state.jwt_signing_key = std::make_unique<crypto::RsaSigningKey>(env->key.path());
            env->state.db_pool = std::make_unique<db::Pool>(url, 2);
            std::string host = redis_addr;
            int port = 6379;
            auto colon = host.find(':');
            if (colon != std::string::npos) {
                port = std::stoi(host.substr(colon + 1));
                host = host.substr(0, colon);
            }
            env->state.redis = std::make_unique<redis::Client>(host, port, "");
        }
    }
    return env.get();
}

std::string unique_email(const char* tag) {
    return std::string(tag) + "-" + uuidgen::v4().substr(0, 8) + "@claim.example.com";
}

std::string new_sub() { return "claim-sub-" + uuidgen::v4(); }

DeviceInfo web_device() {
    DeviceInfo d;
    d.platform = "web";
    d.device_name = "test";
    auth::ensure_browser_device_id(d);
    return d;
}

} // namespace

#define REQUIRE_ENV(var)                                                                        \
    ItEnv* var = it_env();                                                                      \
    if (var == nullptr) {                                                                       \
        std::cerr << "  [SKIP] " << ::testing::current_test_name() << ": нет TEST_DATABASE_URL/TEST_REDIS_HOST\n"; \
        return;                                                                                 \
    }

TEST(it_claim_takes_squatted_account_and_revokes_sessions) {
    REQUIRE_ENV(env);
    AppState& state = env->state;
    std::string email = unique_email("victim");
    state.admin_emails = {email}; // владелец адреса в ADMIN_EMAILS — роль при привязке всё равно не меняется

    auto squatter = repo::create_password_user(*state.db_pool->acquire(), email, "Атакующий",
                                               passwords::make_record("attacker password", kIter));
    REQUIRE(squatter.has_value());
    CHECK(squatter->role == Role::User); // email не подтверждён — админом не стать
    // Сессия захватчика живёт.
    auth::TokenPair stolen = auth::issue_tokens(state, *squatter, web_device());
    // И Telegram-чат захватчика привязан к записи (связка — в Postgres).
    repo::TelegramLink tg;
    tg.tg_user_id = std::to_string(100000000 + std::rand() % 900000000);
    tg.user_id = squatter->id;
    tg.device_id = uuidgen::v4();
    tg.tg_username = "squatter";
    repo::upsert_telegram_link(*state.db_pool->acquire(), tg);

    std::string sub = new_sub();
    auto claimed = auth::claim_password_account(state, sub, email, true, "Владелец", "https://pic/o");
    REQUIRE(claimed.has_value());
    CHECK_EQ(claimed->id, squatter->id); // та же идентичность — данные кошелька остаются на месте
    CHECK_EQ(claimed->google_sub, sub);
    CHECK(claimed->email_verified);
    CHECK_EQ(claimed->name, std::string("Владелец"));
    // Спека: привязка Google к парольной записи роль не меняет и автоматически не повышает.
    CHECK(claimed->role == Role::User);

    // Пароль захватчика удалён, его сессия отозвана.
    CHECK(!repo::find_password(*state.db_pool->acquire(), squatter->id).has_value());
    CHECK(!auth::rotate_refresh_token(state, stolen.refresh_token).has_value());
    // Связка Telegram захватчика удалена — бот больше не получит токены владельца.
    CHECK(repo::list_telegram_links(*state.db_pool->acquire(), squatter->id).empty());
    CHECK(!repo::find_telegram_link(*state.db_pool->acquire(), tg.tg_user_id).has_value());

    // После привязки вход идёт обычным путём по google_sub; второй раз забирать нечего.
    CHECK(repo::find_user_by_google_sub(*state.db_pool->acquire(), sub).has_value());
    CHECK(!auth::claim_password_account(state, new_sub(), email, true, "Другой", "").has_value());

    repo::delete_user(*state.db_pool->acquire(), squatter->id);
    state.admin_emails.clear();
}

TEST(it_claim_requires_google_to_confirm_email) {
    REQUIRE_ENV(env);
    AppState& state = env->state;
    std::string email = unique_email("unverified");
    auto squatter = repo::create_password_user(*state.db_pool->acquire(), email, "Аккаунт",
                                               passwords::make_record("attacker password", kIter));
    REQUIRE(squatter.has_value());
    auth::TokenPair session = auth::issue_tokens(state, *squatter, web_device());

    // id_token с email_verified=false привязки не даёт: аккаунт остаётся как был.
    CHECK(!auth::claim_password_account(state, new_sub(), email, false, "Кто-то", "").has_value());
    CHECK(repo::find_password(*state.db_pool->acquire(), squatter->id).has_value());
    CHECK(repo::find_user_by_id(*state.db_pool->acquire(), squatter->id)->google_sub.empty());
    CHECK(auth::rotate_refresh_token(state, session.refresh_token).has_value()); // сессия жива

    repo::delete_user(*state.db_pool->acquire(), squatter->id);
}

TEST(it_claim_skips_when_sub_already_belongs_to_another_user) {
    REQUIRE_ENV(env);
    AppState& state = env->state;
    std::string email = unique_email("occupied");
    std::string sub = new_sub();
    // Этот Google-аккаунт уже заведён под другим email.
    auto owner = repo::upsert_user(*state.db_pool->acquire(), sub, unique_email("other"), true, "Владелец sub", "",
                                   Role::User);
    auto squatter = repo::create_password_user(*state.db_pool->acquire(), email, "Аккаунт",
                                               passwords::make_record("attacker password", kIter));
    REQUIRE(squatter.has_value());

    CHECK(!auth::claim_password_account(state, sub, email, true, "Владелец sub", "").has_value());
    CHECK(repo::find_password(*state.db_pool->acquire(), squatter->id).has_value()); // не тронут
    CHECK_EQ(repo::find_user_by_google_sub(*state.db_pool->acquire(), sub)->id, owner.id);

    repo::delete_user(*state.db_pool->acquire(), squatter->id);
    repo::delete_user(*state.db_pool->acquire(), owner.id);
}

TEST(it_claim_nothing_to_take_for_unknown_or_google_only_email) {
    REQUIRE_ENV(env);
    AppState& state = env->state;
    // Адреса нет вовсе.
    CHECK(!auth::claim_password_account(state, new_sub(), unique_email("nobody"), true, "Никто", "").has_value());

    // Адрес принадлежит Google-пользователю (подтверждённому) — автоматической привязки нет.
    std::string email = unique_email("googleuser");
    auto g = repo::upsert_user(*state.db_pool->acquire(), new_sub(), email, true, "Google", "", Role::User);
    CHECK(!auth::claim_password_account(state, new_sub(), email, true, "Второй Google", "").has_value());
    CHECK(repo::find_user_by_id(*state.db_pool->acquire(), g.id).has_value());
    repo::delete_user(*state.db_pool->acquire(), g.id);
}
