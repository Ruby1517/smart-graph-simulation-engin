
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
};
