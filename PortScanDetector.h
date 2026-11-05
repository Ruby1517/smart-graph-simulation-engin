
#pragma once

#include "NetworkConnection.h"

#include <cstddef>
#include <string>
#include <vector>

struct PortScanAlert {
    std::string sourceIP;
    std::string destinationIP;
    std::size_t uniquePorts;
    std::string firstSeen;
    std::string lastSeen;
};

class PortScanDetector {
private:
    std::size_t portThreshold;
    int windowSeconds;

public:
    explicit PortScanDetector(
        std::size_t threshold,
        int window = 60
    );

    std::vector<PortScanAlert> detect(
        const std::vector<NetworkConnection>& connections
    ) const;
};
