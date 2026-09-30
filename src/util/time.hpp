// Общая точка правды для "сейчас в unix-секундах" — раньше эта функция была
// продублирована в auth.cpp и google.cpp по отдельности.
#pragma once

#include <cstdint>

namespace timeutil {

uint64_t now_epoch();

} // namespace timeutil
