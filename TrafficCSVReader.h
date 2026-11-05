
#pragma once

#include "NetworkConnection.h"

#include <string>
#include <vector>

class TrafficCSVReader {
public:
    std::vector<NetworkConnection> readFile(
        const std::string& filename
    ) const;
};
