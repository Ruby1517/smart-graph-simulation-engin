
#pragma once

#include <algorithm>
#include <cctype>
#include <string>

inline std::string normalizeProtocol(std::string protocol) {
    std::transform(
        protocol.begin(),
        protocol.end(),
        protocol.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::toupper(c));
        }
    );

    return protocol;
}
