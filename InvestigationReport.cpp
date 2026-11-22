
#include "InvestigationReport.h"

#include <fstream>
#include <stdexcept>

void InvestigationReport::exportText(
    const std::string& filename,
    const NetworkAnalyzer& analyzer,
    const std::vector<PortScanAlert>& alerts,
    const GeoAnalyzer& geoAnalyzer
) const {
    std::ofstream file(filename);

    if (!file) {
        throw std::runtime_error(
            "Cannot create investigation report: " + filename
        );
    }

    file << "SMART GRAPH NETWORK FORENSICS REPORT\n";
    file << "===================================\n\n";

    file << "TRAFFIC SUMMARY\n";
    file << "---------------\n";
    file << "Records: " << analyzer.connectionCount() << '\n';
    file << "Total bytes: " << analyzer.totalBytes() << "\n\n";

    file << "PROTOCOL COUNTS\n";
    file << "---------------\n";

    for (const auto& [protocol, count] :
         analyzer.protocolCounts()) {
        file << protocol << ": " << count << '\n';
    }

    file << "\nSOURCE IP COUNTS\n";
    file << "----------------\n";

    for (const auto& [ip, count] :
         analyzer.sourceIPCounts()) {
        file << ip << ": " << count << '\n';
    }

    file << "\nDESTINATION PORT COUNTS\n";
    file << "-----------------------\n";

    for (const auto& [port, count] :
         analyzer.destinationPortCounts()) {
        file << port << ": " << count << '\n';
    }

    file << "\nPOSSIBLE PORT SCAN ALERTS\n";
    file << "-------------------------\n";

    if (alerts.empty()) {
        file << "No alerts detected.\n";
    }

    for (const auto& alert : alerts) {
        file << "Source: " << alert.sourceIP << '\n';
        file << "Destination: " << alert.destinationIP << '\n';
        file << "Unique ports: " << alert.uniquePorts << '\n';
        file << "First seen: " << alert.firstSeen << '\n';
        file << "Last seen: " << alert.lastSeen << "\n\n";
    }

    file << "\nGEOGRAPHIC TRAFFIC SUMMARY\n";
    file << "--------------------------\n";

    auto summaries = geoAnalyzer.aggregateTraffic(
        analyzer.getConnections()
    );

    for (const auto& summary : summaries) {
        file << summary.sourceIP
             << " -> " << summary.destinationIP
             << " | Records: " << summary.connectionCount
             << " | Bytes: " << summary.totalBytes
             << '\n';
    }

    file << "\nANALYSIS NOTES\n";
    file << "--------------\n";
    file << "Alerts indicate patterns requiring investigation, "
         << "not confirmed malicious activity.\n";
    file << "Geographic locations in this demonstration are "
         << "synthetic and do not represent verified IP locations.\n";
    file << "CSV and Zeek observations may overlap; "
         << "duplicate evidence has not been reconciled.\n";

    if (!file) {
        throw std::runtime_error(
            "Failed to write investigation report"
        );
    }
}
