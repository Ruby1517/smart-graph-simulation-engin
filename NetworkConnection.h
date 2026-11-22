
#pragma once

#include <string>
#include <cstdint>

struct NetworkConnection {
    std::string timestamp;

    std::string sourceIP;
    std::string destinationIP;

    std::uint16_t sourcePort;
    std::uint16_t destinationPort;

    std::string protocol;
    std::uint64_t bytesTransferred;

    // Additional Zeek metadata
    std::uint64_t originatorBytes = 0;
    std::uint64_t responderBytes = 0;
    std::string connectionState;
};
