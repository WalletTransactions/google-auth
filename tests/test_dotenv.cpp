#include "util/dotenv.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "test_framework.hpp"

namespace {

std::string write_temp_env(const std::string& content) {
    std::string path = (std::filesystem::temp_directory_path() / "google_auth_test.env").string();
    std::ofstream f(path, std::ios::trunc | std::ios::binary);
    f << content;
    f.close();
    return path;
}

#ifdef _WIN32
void unset_env(const char* key) { _putenv_s(key, ""); }
void set_env(const char* key, const char* value) { _putenv_s(key, value); }
#else
void unset_env(const char* key) { unsetenv(key); }
void set_env(const char* key, const char* value) { setenv(key, value, 1); }
#endif

std::string get_env(const char* key) {
    const char* v = std::getenv(key);
    return v != nullptr ? std::string(v) : std::string();
}

} // namespace

TEST(dotenv_loads_simple_key_value) {
    unset_env("GA_TEST_SIMPLE");
    dotenv::load(write_temp_env("GA_TEST_SIMPLE=hello\n"));
    CHECK_EQ(get_env("GA_TEST_SIMPLE"), std::string("hello"));
}

TEST(dotenv_does_not_overwrite_existing_env_var) {
    // Как и обычные dotenv-библиотеки: реальное окружение — приоритетнее
    // (см. комментарий в dotenv.hpp).
    set_env("GA_TEST_EXISTING", "from_real_env");
    dotenv::load(write_temp_env("GA_TEST_EXISTING=from_dotenv\n"));
    CHECK_EQ(get_env("GA_TEST_EXISTING"), std::string("from_real_env"));
}

TEST(dotenv_skips_comments_and_blank_lines) {
    unset_env("GA_TEST_AFTER_COMMENT");
    dotenv::load(write_temp_env("# комментарий\n\n   \nGA_TEST_AFTER_COMMENT=ok\n"));
    CHECK_EQ(get_env("GA_TEST_AFTER_COMMENT"), std::string("ok"));
}

TEST(dotenv_strips_surrounding_quotes) {
    unset_env("GA_TEST_QUOTED_D");
    unset_env("GA_TEST_QUOTED_S");
    dotenv::load(write_temp_env(
        "GA_TEST_QUOTED_D=\"double quoted value\"\n"
        "GA_TEST_QUOTED_S='single quoted value'\n"));
    CHECK_EQ(get_env("GA_TEST_QUOTED_D"), std::string("double quoted value"));
    CHECK_EQ(get_env("GA_TEST_QUOTED_S"), std::string("single quoted value"));
}

TEST(dotenv_trims_whitespace_around_key_and_value) {
    unset_env("GA_TEST_TRIM");
    dotenv::load(write_temp_env("  GA_TEST_TRIM   =   spaced value  \n"));
    CHECK_EQ(get_env("GA_TEST_TRIM"), std::string("spaced value"));
}

TEST(dotenv_ignores_lines_without_equals_sign) {
    unset_env("GA_TEST_NOEQ");
    dotenv::load(write_temp_env("this line has no equals sign\n"));
    CHECK_EQ(get_env("GA_TEST_NOEQ"), std::string());
}

TEST(dotenv_missing_file_is_not_an_error) {
    dotenv::load("/this/path/definitely/does/not/exist.env");
    // Дошли сюда, не поймав исключение и не упав — это и есть проверка (см.
    // dotenv.hpp: отсутствие файла — не ошибка).
    CHECK(true);
}
