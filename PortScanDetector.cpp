
#include "PortScanDetector.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace {

std::time_t parseTimestamp(const std::string& timestamp) {
    std::tm time{};

    std::istringstream stream(timestamp);
    stream >> std::get_time(&time, "%Y-%m-%d %H:%M:%S");

    if (stream.fail()) {
        throw std::invalid_argument(
            "Invalid timestamp: " + timestamp
        );
    }

    stream >> std::ws;
    if (!stream.eof()) {
        throw std::invalid_argument(
            "Unexpected timestamp content: " + timestamp
        );
    }

    time.tm_isdst = -1;
    return std::mktime(&time);
}

struct TimedPort {
    std::time_t timestamp;
    std::uint16_t port;
    std::string originalTimestamp;
};

} // namespace

PortScanDetector::PortScanDetector(
    std::size_t threshold,
    int window
) : portThreshold(threshold), windowSeconds(window) {

    if (threshold == 0 || window <= 0) {
        throw std::invalid_argument(
            "Threshold and time window must be positive"
        );
    }
}

std::vector<PortScanAlert> PortScanDetector::detect(
    const std::vector<NetworkConnection>& connections
) const {

    using HostPair = std::pair<std::string, std::string>;

    std::map<HostPair, std::vector<TimedPort>> groups;

    // Group traffic by source and destination
    for (const auto& connection : connections) {
        groups[{connection.sourceIP, connection.destinationIP}]
            .push_back({
                parseTimestamp(connection.timestamp),
                connection.destinationPort,
                connection.timestamp
            });
    }

    std::vector<PortScanAlert> alerts;

    for (auto& [pair, events] : groups) {

        std::sort(
            events.begin(),
            events.end(),
            [](const TimedPort& a, const TimedPort& b) {
                return a.timestamp < b.timestamp;
            }
        );

        // Check each possible starting event
        for (std::size_t i = 0; i < events.size(); ++i) {

            std::set<std::uint16_t> ports;
            std::size_t last = i;

            for (std::size_t j = i; j < events.size(); ++j) {

                double elapsed = std::difftime(
                    events[j].timestamp,
                    events[i].timestamp
                );

                if (elapsed > windowSeconds) {
                    break;
                }

                ports.insert(events[j].port);
                last = j;

                if (ports.size() >= portThreshold) {
                    alerts.push_back({
                        pair.first,
                        pair.second,
                        ports.size(),
                        events[i].originalTimestamp,
                        events[last].originalTimestamp
                    });

                    break;
                }
            }

            // One alert per source/destination pair
            if (!alerts.empty() &&
                alerts.back().sourceIP == pair.first &&
                alerts.back().destinationIP == pair.second) {
                break;
            }
        }
    }

    return alerts;
}
