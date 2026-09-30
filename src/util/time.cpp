#include "util/time.hpp"

#include <chrono>

namespace timeutil {

uint64_t now_epoch() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count());
}

} // namespace timeutil
