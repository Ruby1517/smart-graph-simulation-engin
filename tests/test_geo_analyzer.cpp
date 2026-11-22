
#include "../GeoAnalyzer.h"

#include <cassert>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

int main() {
    try {
        GeoAnalyzer geo;

        geo.addLocation({
            "192.168.1.10", "United States", "Fresno",
            36.7378, -119.7871, true
        });

        geo.addLocation({
            "192.168.1.20", "United States", "San Francisco",
            37.7749, -122.4194, true
        });

        geo.addLocation({
            "192.168.1.50", "", "",
            0.0, 0.0, false
        });

        // Test 1: Location lookup
        assert(geo.hasLocation("192.168.1.10"));
        assert(!geo.hasLocation("192.168.1.99"));

        auto location = geo.getLocation("192.168.1.10");

        assert(location.city == "Fresno");
        assert(std::abs(location.latitude - 36.7378) < 0.000001);

        std::cout << "PASS: Location lookup\n";

        // Test 2: Invalid latitude
        bool rejected = false;

        try {
            geo.addLocation({
                "invalid", "Test", "Test",
                95.0, 0.0, true
            });
        } catch (const std::invalid_argument&) {
            rejected = true;
        }

        assert(rejected);
        std::cout << "PASS: Invalid latitude rejected\n";

        // Test 3: Traffic aggregation
        std::vector<NetworkConnection> traffic = {
            {
                "2026-11-04 10:30:00",
                "192.168.1.10", "192.168.1.20",
                50000, 443, "TCP", 100
            },
            {
                "2026-11-04 10:30:01",
                "192.168.1.10", "192.168.1.20",
                50001, 443, "TCP", 200
            },
            {
                "2026-11-04 10:30:02",
                "192.168.1.20", "192.168.1.10",
                443, 50000, "TCP", 300
            },
            {
                "2026-11-04 10:30:03",
                "192.168.1.50", "192.168.1.20",
                50002, 22, "TCP", 400
            }
        };

        auto summaries = geo.aggregateTraffic(traffic);

        assert(summaries.size() == 2);

        // std::map sorts source/destination pairs
        assert(summaries[0].sourceIP == "192.168.1.10");
        assert(summaries[0].connectionCount == 2);
        assert(summaries[0].totalBytes == 300);

        assert(summaries[1].sourceIP == "192.168.1.20");
        assert(summaries[1].connectionCount == 1);
        assert(summaries[1].totalBytes == 300);

        std::cout << "PASS: Directed traffic aggregation\n";

        // Test 4: GeoJSON export
        const fs::path output =
            fs::temp_directory_path() /
            "smart_graph_geo_test.geojson";

        geo.exportAggregatedGeoJSON(
            output.string(), traffic
        );

        std::ifstream file(output);
        assert(file.is_open());

        std::string content(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );

        assert(content.find("\"FeatureCollection\"")
               != std::string::npos);

        assert(content.find("\"LineString\"")
               != std::string::npos);

        assert(content.find("\"connectionCount\": 2")
               != std::string::npos);

        file.close();
        fs::remove(output);

        std::cout << "PASS: Aggregated GeoJSON export\n";

        std::cout << "\nAll GIS tests passed!\n";

    } catch (const std::exception& e) {
        std::cerr << "GIS TEST FAILED: "
                  << e.what() << '\n';
        return 1;
    }

    return 0;
}
