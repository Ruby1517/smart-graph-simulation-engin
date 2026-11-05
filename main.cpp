
#include "NetworkAnalyzer.h"
#include "TrafficCSVReader.h"
#include "PortScanDetector.h"

#include <iostream>
#include <exception>

int main() {
    try {
        TrafficCSVReader reader;
        NetworkAnalyzer analyzer;

        // Step 1: Read network traffic CSV
        auto records = reader.readFile(
            "data/network_traffic.csv"
        );

        // Step 2: Populate the analyzer
        for (const auto& record : records) {
            analyzer.addConnection(record);
        }

        // Step 3: Detect possible port scanning
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

        // Step 4: Display imported connections
        std::cout << "\n--- Imported Connections ---\n";
        analyzer.printConnections();

        // Step 5: Display communication graph
        std::cout << "\n--- Communication Graph ---\n";
        analyzer.printNetworkGraph();

        std::cout << "\nTotal traffic records: "
                  << analyzer.connectionCount()
                  << '\n';

        // Step 6: Display traffic statistics
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
