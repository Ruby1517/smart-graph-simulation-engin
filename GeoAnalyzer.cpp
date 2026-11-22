
#include "GeoAnalyzer.h"
#include "NetworkConnection.h"

#include <cmath>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>
#include <limits>
#include <map>
#include <utility>

namespace {

// Escape special characters for valid JSON strings
std::string escapeJSON(const std::string& value) {
    std::string result;

    for (unsigned char c : value) {
        switch (c) {
            case '"':
                result += "\\\"";
                break;

            case '\\':
                result += "\\\\";
                break;

            case '\n':
                result += "\\n";
                break;

            case '\r':
                result += "\\r";
                break;

            case '\t':
                result += "\\t";
                break;

            default:
                if (c < 0x20) {
                    const char* hex = "0123456789abcdef";

                    result += "\\u00";
                    result += hex[c >> 4];
                    result += hex[c & 15];
                } else {
                    result += static_cast<char>(c);
                }
        }
    }

    return result;
}

} // namespace

// --------------------------------------------------
// Add or update a geographic location
// --------------------------------------------------

void GeoAnalyzer::addLocation(
    const GeoLocation& location
) {
    if (location.ipAddress.empty()) {
        throw std::invalid_argument(
            "IP address cannot be empty"
        );
    }

    if (location.located &&
        (!std::isfinite(location.latitude) ||
         !std::isfinite(location.longitude) ||
         location.latitude < -90.0 ||
         location.latitude > 90.0 ||
         location.longitude < -180.0 ||
         location.longitude > 180.0)) {

        throw std::invalid_argument(
            "Invalid geographic coordinates"
        );
    }

    locations[location.ipAddress] = location;
}

// --------------------------------------------------
// Check whether an IP has a location record
// --------------------------------------------------

bool GeoAnalyzer::hasLocation(
    const std::string& ip
) const {
    return locations.find(ip) != locations.end();
}

// --------------------------------------------------
// Retrieve a geographic location
// --------------------------------------------------

GeoLocation GeoAnalyzer::getLocation(
    const std::string& ip
) const {
    auto it = locations.find(ip);

    if (it == locations.end()) {
        throw std::invalid_argument(
            "Location not found for IP: " + ip
        );
    }

    return it->second;
}

// --------------------------------------------------
// Export geographic points to GeoJSON
// --------------------------------------------------

void GeoAnalyzer::exportGeoJSON(
    const std::string& filename
) const {
    std::ofstream file(filename);

    if (!file) {
        throw std::runtime_error(
            "Cannot create GeoJSON file: " + filename
        );
    }

    file << std::setprecision(10);

    file << "{\n"
         << "  \"type\": \"FeatureCollection\",\n"
         << "  \"features\": [\n";

    bool first = true;

    for (const auto& [ip, location] : locations) {

        // Skip locations without valid coordinates
        if (!location.located) {
            continue;
        }

        if (!first) {
            file << ",\n";
        }

        first = false;

        file << "    {\n"
             << "      \"type\": \"Feature\",\n"
             << "      \"geometry\": {\n"
             << "        \"type\": \"Point\",\n"
             << "        \"coordinates\": ["
             << location.longitude << ", "
             << location.latitude << "]\n"
             << "      },\n"
             << "      \"properties\": {\n"
             << "        \"ip\": \""
             << escapeJSON(ip) << "\",\n"
             << "        \"country\": \""
             << escapeJSON(location.country) << "\",\n"
             << "        \"city\": \""
             << escapeJSON(location.city) << "\"\n"
             << "      }\n"
             << "    }";
    }

    file << "\n  ]\n}\n";

    if (!file) {
        throw std::runtime_error(
            "Failed to write GeoJSON file"
        );
    }
}

// --------------------------------------------------
// Export network communication lines to GeoJSON
// --------------------------------------------------

void GeoAnalyzer::exportCommunicationGeoJSON(
    const std::string& filename,
    const std::vector<NetworkConnection>& connections
) const {
    std::ofstream file(filename);

    if (!file) {
        throw std::runtime_error(
            "Cannot create communication GeoJSON: " +
            filename
        );
    }

    file << std::setprecision(10);

    file << "{\n"
         << "  \"type\": \"FeatureCollection\",\n"
         << "  \"features\": [\n";

    bool first = true;

    for (const auto& connection : connections) {

        // Find source IP location
        auto source = locations.find(
            connection.sourceIP
        );

        // Find destination IP location
        auto destination = locations.find(
            connection.destinationIP
        );

        // Skip connections with missing locations
        if (source == locations.end() ||
            destination == locations.end()) {
            continue;
        }

        const auto& src = source->second;
        const auto& dst = destination->second;

        // Skip unknown geographic coordinates
        if (!src.located || !dst.located) {
            continue;
        }

        if (!first) {
            file << ",\n";
        }

        first = false;

        file << "    {\n"
             << "      \"type\": \"Feature\",\n"
             << "      \"geometry\": {\n"
             << "        \"type\": \"LineString\",\n"
             << "        \"coordinates\": [\n"
             << "          ["
             << src.longitude << ", "
             << src.latitude << "],\n"
             << "          ["
             << dst.longitude << ", "
             << dst.latitude << "]\n"
             << "        ]\n"
             << "      },\n"
             << "      \"properties\": {\n"
             << "        \"sourceIP\": \""
             << escapeJSON(connection.sourceIP)
             << "\",\n"
             << "        \"destinationIP\": \""
             << escapeJSON(connection.destinationIP)
             << "\",\n"
             << "        \"protocol\": \""
             << escapeJSON(connection.protocol)
             << "\",\n"
             << "        \"bytes\": "
             << connection.bytesTransferred
             << "\n"
             << "      }\n"
             << "    }";
    }

    file << "\n  ]\n}\n";

    if (!file) {
        throw std::runtime_error(
            "Failed to write communication GeoJSON"
        );
    }
}


// aggregate network traffic
std::vector<GeoTrafficSummary> GeoAnalyzer::aggregateTraffic(
    const std::vector<NetworkConnection>& connections
) const {
    using HostPair =
        std::pair<std::string, std::string>;

    std::map<HostPair, GeoTrafficSummary> summaries;

    for (const auto& connection : connections) {
        auto source = locations.find(connection.sourceIP);
        auto destination = locations.find(connection.destinationIP);

        // Only aggregate connections with located endpoints
        if (source == locations.end() ||
            destination == locations.end() ||
            !source->second.located ||
            !destination->second.located) {
            continue;
        }

        HostPair key{
            connection.sourceIP,
            connection.destinationIP
        };

        auto& summary = summaries[key];

        summary.sourceIP = connection.sourceIP;
        summary.destinationIP = connection.destinationIP;

        if (summary.connectionCount ==
            std::numeric_limits<std::size_t>::max() ||
            connection.bytesTransferred >
                std::numeric_limits<std::uint64_t>::max()
                - summary.totalBytes) {
            throw std::overflow_error(
                "Geographic traffic aggregation overflow"
            );
        }

        ++summary.connectionCount;
        summary.totalBytes += connection.bytesTransferred;
    }

    std::vector<GeoTrafficSummary> result;
    result.reserve(summaries.size());

    for (const auto& [key, summary] : summaries) {
        result.push_back(summary);
    }

    return result;
}

// Export aggregated GeoJSON

void GeoAnalyzer::exportAggregatedGeoJSON(
    const std::string& filename,
    const std::vector<NetworkConnection>& connections
) const {
    auto summaries = aggregateTraffic(connections);

    std::ofstream file(filename);

    if (!file) {
        throw std::runtime_error(
            "Cannot create aggregated GeoJSON: " + filename
        );
    }

    file << std::setprecision(10);

    file << "{\n"
         << "  \"type\": \"FeatureCollection\",\n"
         << "  \"features\": [\n";

    bool first = true;

    for (const auto& summary : summaries) {
        const auto& src =
            locations.at(summary.sourceIP);

        const auto& dst =
            locations.at(summary.destinationIP);

        if (!first) {
            file << ",\n";
        }

        first = false;

        file << "    {\n"
             << "      \"type\": \"Feature\",\n"
             << "      \"geometry\": {\n"
             << "        \"type\": \"LineString\",\n"
             << "        \"coordinates\": [\n"
             << "          ["
             << src.longitude << ", "
             << src.latitude << "],\n"
             << "          ["
             << dst.longitude << ", "
             << dst.latitude << "]\n"
             << "        ]\n"
             << "      },\n"
             << "      \"properties\": {\n"
             << "        \"sourceIP\": \""
             << escapeJSON(summary.sourceIP)
             << "\",\n"
             << "        \"destinationIP\": \""
             << escapeJSON(summary.destinationIP)
             << "\",\n"
             << "        \"connectionCount\": "
             << summary.connectionCount << ",\n"
             << "        \"totalBytes\": "
             << summary.totalBytes << "\n"
             << "      }\n"
             << "    }";
    }

    file << "\n  ]\n}\n";

    if (!file) {
        throw std::runtime_error(
            "Failed to write aggregated GeoJSON"
        );
    }
}

