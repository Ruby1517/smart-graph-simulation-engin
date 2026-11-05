
#include "TrafficCSVReader.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// Validate and convert an unsigned numeric field
std::uint64_t parseUnsigned(
    const std::string& text,
    const std::string& fieldName
) {
    if (text.empty() ||
        !std::all_of(
            text.begin(),
            text.end(),
            [](unsigned char c) {
                return c >= '0' && c <= '9';
            }
        )) {
        throw std::invalid_argument(
            "Invalid numeric field: " + fieldName +
            " (value: " + text + ")"
        );
    }

    std::size_t position = 0;
    auto value = std::stoull(text, &position);

    if (position != text.size()) {
        throw std::invalid_argument(
            "Unexpected characters in: " + fieldName
        );
    }

    return static_cast<std::uint64_t>(value);
}

// Split a simple CSV row into fields
std::vector<std::string> splitCSV(
    const std::string& line
) {
    std::vector<std::string> fields;
    std::stringstream stream(line);
    std::string field;

    while (std::getline(stream, field, ',')) {
        fields.push_back(field);
    }

    // Preserve an empty final column
    if (!line.empty() && line.back() == ',') {
        fields.push_back("");
    }

    return fields;
}

// Check that required text fields are present
void validateRequiredFields(
    const std::vector<std::string>& fields
) {
    if (fields[0].empty()) {
        throw std::invalid_argument(
            "Timestamp cannot be empty"
        );
    }

    if (fields[1].empty()) {
        throw std::invalid_argument(
            "Source IP cannot be empty"
        );
    }

    if (fields[2].empty()) {
        throw std::invalid_argument(
            "Destination IP cannot be empty"
        );
    }

    if (fields[5].empty()) {
        throw std::invalid_argument(
            "Protocol cannot be empty"
        );
    }
}

} // namespace

std::vector<NetworkConnection>
TrafficCSVReader::readFile(
    const std::string& filename
) const {

    // Open the CSV file
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw std::runtime_error(
            "Unable to open traffic file: " + filename
        );
    }

    std::vector<NetworkConnection> records;
    std::string line;
    std::size_t lineNumber = 0;

    // Read and validate the CSV header
    if (!std::getline(file, line)) {
        throw std::runtime_error(
            "CSV file is empty: " + filename
        );
    }

    ++lineNumber;

    const std::string expectedHeader =
        "timestamp,sourceIP,destinationIP,"
        "sourcePort,destinationPort,protocol,"
        "bytesTransferred";

    if (line == expectedHeader + "\r") {
        line.pop_back();
    }

    if (line != expectedHeader) {
        throw std::runtime_error(
            "Invalid CSV header in: " + filename
        );
    }

    // Read each traffic record
    while (std::getline(file, line)) {
        ++lineNumber;

        // Support Windows CRLF line endings
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        // Skip completely empty lines
        if (line.empty()) {
            continue;
        }

        try {
            // Split the row into columns
            auto fields = splitCSV(line);

            if (fields.size() != 7) {
                throw std::runtime_error(
                    "Expected exactly 7 CSV columns, found " +
                    std::to_string(fields.size())
                );
            }

            // Validate required text fields
            validateRequiredFields(fields);

            // Parse numeric values
            auto sourcePort = parseUnsigned(
                fields[3],
                "sourcePort"
            );

            auto destinationPort = parseUnsigned(
                fields[4],
                "destinationPort"
            );

            auto bytes = parseUnsigned(
                fields[6],
                "bytesTransferred"
            );

            // Validate network port range
            constexpr auto maxPort =
                std::numeric_limits<std::uint16_t>::max();

            if (sourcePort > maxPort ||
                destinationPort > maxPort) {
                throw std::out_of_range(
                    "Network port must be between 0 and 65535"
                );
            }

            // Construct a validated traffic record
            NetworkConnection connection{};

            connection.timestamp = fields[0];
            connection.sourceIP = fields[1];
            connection.destinationIP = fields[2];

            connection.sourcePort =
                static_cast<std::uint16_t>(sourcePort);

            connection.destinationPort =
                static_cast<std::uint16_t>(destinationPort);

            connection.protocol = fields[5];

            connection.bytesTransferred = bytes;

            records.push_back(std::move(connection));

        } catch (const std::exception& e) {
            throw std::runtime_error(
                "CSV error at line " +
                std::to_string(lineNumber) +
                " in " + filename +
                ": " + e.what()
            );
        }
    }

    if (file.bad()) {
        throw std::runtime_error(
            "Error while reading CSV file: " + filename
        );
    }

    return records;
}
