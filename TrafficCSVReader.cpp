
#include "TrafficCSVReader.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <limits>

std::vector<NetworkConnection>
TrafficCSVReader::readFile(
    const std::string& filename
) const {
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw std::runtime_error(
            "Unable to open traffic file: " + filename
        );
    }

    std::vector<NetworkConnection> records;
    std::string line;

    // Skip CSV header
    std::getline(file, line);

    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        std::stringstream stream(line);
        NetworkConnection connection{};

        std::string sourcePort;
        std::string destinationPort;
        std::string bytes;

        std::getline(stream, connection.timestamp, ',');
        std::getline(stream, connection.sourceIP, ',');
        std::getline(stream, connection.destinationIP, ',');
        std::getline(stream, sourcePort, ',');
        std::getline(stream, destinationPort, ',');
        std::getline(stream, connection.protocol, ',');
        std::getline(stream, bytes, ',');

        auto src = std::stoul(sourcePort);
        auto dst = std::stoul(destinationPort);
        auto count = std::stoull(bytes);

        if (src > std::numeric_limits<std::uint16_t>::max() ||
            dst > std::numeric_limits<std::uint16_t>::max()) {
            throw std::out_of_range("Invalid network port");
        }

        connection.sourcePort =
            static_cast<std::uint16_t>(src);

        connection.destinationPort =
            static_cast<std::uint16_t>(dst);

        connection.bytesTransferred =
            static_cast<std::uint64_t>(count);

        records.push_back(connection);
    }

    return records;
}
