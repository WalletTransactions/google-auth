#include "util/time.hpp"

#include "test_framework.hpp"

TEST(time_now_epoch_is_plausible) {
    // Нижняя граница — заведомо в прошлом (2023 год), верхняя — щедрый
    // запас на будущее. Ловит регрессию вида "функция всегда возвращает 0"
    // или "возвращает миллисекунды, а не секунды".
    std::uint64_t now = timeutil::now_epoch();
    CHECK(now > 1700000000ULL);
    CHECK(now < 4000000000ULL);
}

TEST(time_iso8601_utc_known_values) {
    CHECK_EQ(timeutil::iso8601_utc(0), std::string("1970-01-01T00:00:00Z"));
    CHECK_EQ(timeutil::iso8601_utc(951782400), std::string("2000-02-29T00:00:00Z")); // високосный
    CHECK_EQ(timeutil::iso8601_utc(1798761599), std::string("2026-12-31T23:59:59Z"));
    CHECK_EQ(timeutil::iso8601_utc(1709251199), std::string("2024-02-29T23:59:59Z"));
}

TEST(time_now_epoch_does_not_go_backwards) {
    std::uint64_t a = timeutil::now_epoch();
    std::uint64_t b = timeutil::now_epoch();
    CHECK(b >= a);
}
