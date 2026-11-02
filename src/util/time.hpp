// Общая точка правды для "сейчас в unix-секундах" — раньше эта функция была
// продублирована в auth.cpp и google.cpp по отдельности.
#pragma once

#include <cstdint>
#include <string>

namespace timeutil {

uint64_t now_epoch();

// "2026-11-02T10:15:30Z" — ISO 8601 UTC с точностью до секунды (поля
// last_used_at/expires_at в GET /auth/devices, expires_at выпуска MCP-токена).
std::string iso8601_utc(uint64_t epoch_secs);

} // namespace timeutil
