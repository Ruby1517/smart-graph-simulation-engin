
#include "ZeekLogReader.h"
#include "EvidenceSnapshot.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::vector<std::string> split(
    const std::string& line,
    char delimiter
) {
    std::vector<std::string> fields;
    std::stringstream stream(line);
    std::string field;

    while (std::getline(stream, field, delimiter)) {
        fields.push_back(field);
    }

    if (!line.empty() && line.back() == delimiter) {
        fields.emplace_back();
    }

    return fields;
}

std::uint64_t parseUnsigned(
    const std::string& value
) {
    if (value.empty() ||
        !std::all_of(value.begin(), value.end(),
            [](unsigned char c) {
                return c >= '0' && c <= '9';
            })) {
        throw std::invalid_argument(
            "Invalid unsigned number: " + value
        );
    }

    return std::stoull(value);
}

std::uint64_t parseBytes(const std::string& value) {
    if (value == "-" || value.empty()) {
        return 0;
    }

    return parseUnsigned(value);
}

std::uint16_t parsePort(const std::string& value) {
    auto port = parseUnsigned(value);

    if (port > 65535) {
        throw std::out_of_range(
            "Port exceeds 65535"
        );
    }

    return static_cast<std::uint16_t>(port);
}

std::string formatTimestamp(const std::string& value) {
    std::size_t consumed = 0;
    double seconds = std::stod(value, &consumed);

    if (consumed != value.size() ||
        !std::isfinite(seconds) ||
        seconds < 0 ||
        seconds > static_cast<double>(
            std::numeric_limits<std::time_t>::max())) {
        throw std::invalid_argument(
            "Invalid Zeek timestamp"
        );
    }

    std::time_t timestamp =
        static_cast<std::time_t>(seconds);

    std::tm utc{};

#if defined(_WIN32)
    if (gmtime_s(&utc, &timestamp) != 0) {
        throw std::runtime_error("UTC conversion failed");
    }
#else
    if (gmtime_r(&timestamp, &utc) == nullptr) {
        throw std::runtime_error("UTC conversion failed");
    }
#endif

    std::ostringstream output;
    output << std::put_time(
        &utc, "%Y-%m-%d %H:%M:%S"
    );

    return output.str();
}

} // namespace

std::vector<NetworkConnection>
ZeekLogReader::readFile(
    const std::string& filename
) const {
    std::ifstream file(filename);

    if (!file) {
        throw std::runtime_error(
            "Cannot open Zeek log: " + filename
        );
    }

    return readStream(file);
}

std::vector<NetworkConnection>
ZeekLogReader::readSnapshot(const EvidenceSnapshot& snapshot) const {
    auto file = snapshot.open();
    auto records = readStream(file);
    snapshot.verifyConsumed(file);
    return records;
}

std::vector<NetworkConnection>
ZeekLogReader::readStream(std::istream& file) {
    std::vector<NetworkConnection> records;
    std::map<std::string, std::size_t> columns;

    std::string line;
    std::size_t lineNumber = 0;

    // Standard Zeek ASCII logs use tab-separated fields.
    char separator = '\t';

    while (std::getline(file, line)) {
        ++lineNumber;

        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            continue;
        }

        // Read Zeek separator metadata
        if (line.rfind("#separator ", 0) == 0) {
            const auto value =
                line.substr(std::string("#separator ").size());

            if (value == "\\x09") {
                separator = '\t';
            } else {
                throw std::runtime_error(
                    "Unsupported Zeek separator"
                );
            }
            continue;
        }

        // Discover column names dynamically
        if (line.rfind("#fields", 0) == 0) {
            auto fields = split(line, separator);

            columns.clear();

            for (std::size_t i = 1; i < fields.size(); ++i) {
                columns[fields[i]] = i - 1;
            }

            continue;
        }

        // Skip other Zeek metadata lines
        if (line[0] == '#') {
            continue;
        }

        try {
            if (columns.empty()) {
                throw std::runtime_error(
                    "Missing #fields header"
                );
            }

            auto fields = split(line, separator);

            auto get = [&](const std::string& name)
                -> const std::string& {

                auto it = columns.find(name);

                if (it == columns.end() ||
                    it->second >= fields.size()) {
                    throw std::runtime_error(
                        "Missing Zeek field: " + name
                    );
                }

                return fields[it->second];
            };

            NetworkConnection connection{};

            connection.timestamp =
                formatTimestamp(get("ts"));

            connection.sourceIP = get("id.orig_h");
            connection.destinationIP = get("id.resp_h");

            connection.sourcePort =
                parsePort(get("id.orig_p"));

            connection.destinationPort =
                parsePort(get("id.resp_p"));

            connection.protocol = get("proto");

            connection.originatorBytes =
                parseBytes(get("orig_bytes"));

            connection.responderBytes =
                parseBytes(get("resp_bytes"));

            if (connection.originatorBytes >
                std::numeric_limits<std::uint64_t>::max() -
                connection.responderBytes) {
                throw std::overflow_error(
                    "Byte count overflow"
                );
            }

            connection.bytesTransferred =
                connection.originatorBytes +
                connection.responderBytes;

            connection.connectionState =
                get("conn_state");

            records.push_back(std::move(connection));

        } catch (const std::exception& e) {
            throw std::runtime_error(
                "Zeek parse error at line " +
                std::to_string(lineNumber) +
                ": " + e.what()
            );
        }
    }

    if (columns.empty()) {
        throw std::runtime_error(
            "Zeek log has no #fields header"
        );
    }

    if (file.bad()) {
        throw std::runtime_error(
            "Error reading Zeek log"
        );
    }

    return records;
}
