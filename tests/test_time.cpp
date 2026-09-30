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

TEST(time_now_epoch_does_not_go_backwards) {
    std::uint64_t a = timeutil::now_epoch();
    std::uint64_t b = timeutil::now_epoch();
    CHECK(b >= a);
}
