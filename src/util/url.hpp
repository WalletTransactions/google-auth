// Percent-encoding для сборки строки запроса ссылки авторизации Google.
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace urlutil {

std::string encode_component(const std::string& value);

std::string build_query(const std::vector<std::pair<std::string, std::string>>& params);

} // namespace urlutil
