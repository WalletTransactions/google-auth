#include "util/time.hpp"

#include <chrono>
#include <cstdio>

namespace timeutil {

uint64_t now_epoch() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count());
}

std::string iso8601_utc(uint64_t epoch_secs) {
    // Гражданская дата из числа дней (Howard Hinnant, days_from_civil
    // наоборот) — без gmtime_r/gmtime_s: те различаются между POSIX и MSVC,
    // а здесь нужна только UTC-арифметика.
    int64_t days = static_cast<int64_t>(epoch_secs / 86400);
    uint64_t rem = epoch_secs % 86400;
    days += 719468;
    int64_t era = days / 146097;
    unsigned doe = static_cast<unsigned>(days - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t year = static_cast<int64_t>(yoe) + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned day = doy - (153 * mp + 2) / 5 + 1;
    unsigned month = mp < 10 ? mp + 3 : mp - 9;
    if (month <= 2) ++year;

    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02u:%02u:%02uZ", static_cast<long long>(year), month, day,
                  static_cast<unsigned>(rem / 3600), static_cast<unsigned>((rem % 3600) / 60),
                  static_cast<unsigned>(rem % 60));
    return std::string(buf);
}

} // namespace timeutil
