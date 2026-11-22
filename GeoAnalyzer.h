
#pragma once

#include "GeoLocation.h"
#include "GeoTrafficSummary.h"
#include "NetworkConnection.h"

#include <map>
#include <string>
#include <vector>

class GeoAnalyzer {
private:
    std::map<std::string, GeoLocation> locations;

public:
    void addLocation(const GeoLocation& location);

    void exportGeoJSON(const std::string& filename) const;

    bool hasLocation(const std::string& ip) const;

    GeoLocation getLocation(const std::string& ip) const;

    void exportCommunicationGeoJSON(
        const std::string& filename,
        const std::vector<NetworkConnection>& connections
    ) const;

    std::vector<GeoTrafficSummary> aggregateTraffic(
        const std::vector<NetworkConnection>& connections
    ) const;

    void exportAggregatedGeoJSON(
        const std::string& filename,
        const std::vector<NetworkConnection>& connections
    ) const;

    void printLocations() const;
};
