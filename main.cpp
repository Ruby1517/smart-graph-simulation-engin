
#include "NetworkAnalyzer.h"
#include "TrafficCSVReader.h"
#include "PortScanDetector.h"
#include "ZeekLogReader.h"
#include "GeoAnalyzer.h"
#include "InvestigationReport.h"
#include "EvidenceRecord.h"
#include "EvidenceSnapshot.h"

#include <iostream>
#include <exception>
#include <string>
#include <vector>

namespace {

template <typename Reader>
EvidenceRecord importEvidence(
    const Reader& reader, const std::string& filename, NetworkAnalyzer& analyzer
) {
    const EvidenceSnapshot snapshot(filename);
    const auto records = reader.readSnapshot(snapshot);
    for (const auto& record : records) {
        analyzer.addConnection(record);
    }
    return {snapshot.filename(), snapshot.sha256(), records.size(), snapshot.metadata()};
}

} // namespace

int main() {
    try {

        GeoAnalyzer geoAnalyzer;


        geoAnalyzer.addLocation({
            "192.168.1.10",
            "United States",
            "Fresno",
            36.7378,
            -119.7871,
            true
        });

        geoAnalyzer.addLocation({
            "192.168.1.20",
            "United States",
            "San Francisco",
            37.7749,
            -122.4194,
            true
        });

        geoAnalyzer.addLocation({
            "192.168.1.30",
            "United States",
            "Los Angeles",
            34.0522,
            -118.2437,
            true
        });

        geoAnalyzer.addLocation({
            "192.168.1.40",
            "United States",
            "Sacramento",
            38.5816,
            -121.4944,
            true
        });

        geoAnalyzer.addLocation({
            "192.168.1.50",
            "",
            "",
            0.0,
            0.0,
            false
        });

        geoAnalyzer.exportGeoJSON(
            "data/network_locations.geojson"
        );


        std::cout << "\nGIS GeoJSON export completed.\n";


        NetworkAnalyzer analyzer;
        const auto csvEvidence =
            importEvidence(TrafficCSVReader{}, "data/network_traffic.csv", analyzer);
        const auto zeekEvidence =
            importEvidence(ZeekLogReader{}, "data/sample_conn.log", analyzer);

        geoAnalyzer.exportAggregatedGeoJSON(
            "data/network_aggregated.geojson",
            analyzer.getConnections()
        );

        auto geoSummaries = geoAnalyzer.aggregateTraffic(
            analyzer.getConnections()
        );

        std::cout << "\n--- Geographic Traffic Summary ---\n";

        for (const auto& summary : geoSummaries) {
            std::cout
                << summary.sourceIP << " -> "
                << summary.destinationIP
                << " | Records: " << summary.connectionCount
                << " | Bytes: " << summary.totalBytes
                << '\n';
}

        geoAnalyzer.exportCommunicationGeoJSON(
            "data/network_communications.geojson",
            analyzer.getConnections()
        );

        std::cout << "\nGIS communication lines exported.\n";

        std::cout << "--- Import Summary ---\n";
        std::cout << "CSV records: "
                  << csvEvidence.importedRecords << '\n';

        std::cout << "Zeek records: "
                  << zeekEvidence.importedRecords << '\n';

        std::cout << "Total records: "
                  << analyzer.connectionCount() << '\n';

        // Detect possible port scans
        PortScanDetector detector(5, 60);

        auto alerts = detector.detect(
            analyzer.getConnections()
        );

        std::cout << "\n--- Port Scan Detection ---\n";

        if (alerts.empty()) {
            std::cout
                << "No suspicious port scan patterns found.\n";
        }

        for (const auto& alert : alerts) {
            std::cout
                << "\nPOSSIBLE PORT SCAN\n"
                << "Source: " << alert.sourceIP << '\n'
                << "Destination: " << alert.destinationIP << '\n'
                << "Unique ports: " << alert.uniquePorts << '\n'
                << "First seen: " << alert.firstSeen << '\n'
                << "Last seen: " << alert.lastSeen << '\n';
        }

        InvestigationReport report;

        report.exportText(
            "data/investigation_report.txt",
            analyzer,
            alerts,
            geoAnalyzer,
            {csvEvidence, zeekEvidence}
        );
        
        std::cout << "\nInvestigation report exported.\n";

        // Display communication graph
        std::cout << "\n--- Communication Graph ---\n";
        analyzer.printNetworkGraph();

        // Display traffic statistics
        std::cout << "\n--- Traffic Statistics ---\n";

        std::cout << "Total bytes: "
                  << analyzer.totalBytes() << '\n';

        std::cout << "\nProtocol counts:\n";

        for (const auto& [protocol, count] :
             analyzer.protocolCounts()) {
            std::cout << protocol
                      << ": " << count << '\n';
        }

        std::cout << "\nSource IP counts:\n";

        for (const auto& [ip, count] :
             analyzer.sourceIPCounts()) {
            std::cout << ip
                      << ": " << count << '\n';
        }

        std::cout << "\nDestination port counts:\n";

        for (const auto& [port, count] :
             analyzer.destinationPortCounts()) {
            std::cout << port
                      << ": " << count << '\n';
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: "
                  << e.what() << '\n';
        return 1;
    }

    return 0;
}
