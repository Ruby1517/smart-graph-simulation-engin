
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

struct GeoTrafficSummary {
    std::string sourceIP;
    std::string destinationIP;

    std::size_t connectionCount = 0;
    std::uint64_t totalBytes = 0;
};
