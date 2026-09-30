#include "util/url.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>

namespace urlutil {

std::string encode_component(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        if (std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.' || c == '~') {
            out << static_cast<char>(c);
        } else {
            out << '%' << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                << static_cast<int>(c) << std::nouppercase << std::dec;
        }
    }
    return out.str();
}

std::string build_query(const std::vector<std::pair<std::string, std::string>>& params) {
    std::string out;
    for (size_t i = 0; i < params.size(); ++i) {
        if (i != 0) out += '&';
        out += encode_component(params[i].first);
        out += '=';
        out += encode_component(params[i].second);
    }
    return out;
}

} // namespace urlutil
