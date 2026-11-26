
#include "InvestigationReport.h"

#include <ctime>
#include <fstream>
#include <iomanip>
#include <stdexcept>

namespace {

void writeCaptureTime(
    std::ostream& output, std::chrono::system_clock::time_point time
) {
    const auto seconds = std::chrono::system_clock::to_time_t(time);
    std::tm utc{};
    if (::gmtime_r(&seconds, &utc)) {
        output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    } else {
        output << "unavailable";
    }
    output << '\n';
}

} // namespace

void InvestigationReport::exportText(
    const std::string& filename,
    const NetworkAnalyzer& analyzer,
    const std::vector<PortScanAlert>& alerts,
    const GeoAnalyzer& geoAnalyzer,
    const std::vector<EvidenceRecord>& evidence
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

    file << "\nEVIDENCE SOURCES\n";
    file << "----------------\n";

    std::size_t totalImported = 0;

    for (const auto& item : evidence) {
        file << "Filename: " << item.filename << '\n';
        file << "SHA-256: " << item.sha256 << '\n';
        file << "Imported records: "
             << item.importedRecords << '\n';

        if (item.snapshot) {
            const auto& snapshot = *item.snapshot;
            file << "Snapshot ID: " << snapshot.id << '\n';
            file << "Snapshot size (bytes): " << snapshot.sizeBytes << '\n';
            file << "Capture started (UTC): ";
            writeCaptureTime(file, snapshot.captureStarted);
            file << "Capture finished (UTC): ";
            writeCaptureTime(file, snapshot.captureFinished);
            if (snapshot.sourceChangeObserved) {
                file << "WARNING: Source changed during capture. Captured bytes "
                        "may include content from different moments.\n";
            }
            if (snapshot.sourcePathUnavailable) {
                file << "WARNING: Source path could not be checked after capture.\n";
            }
        } else {
            file << "WARNING: No snapshot metadata supplied for this evidence.\n";
        }
        file << '\n';

        totalImported += item.importedRecords;
    }

    file << "Total imported evidence records: "
         << totalImported << '\n';

    if (totalImported != analyzer.connectionCount()) {
        file << "WARNING: Evidence record counts do not match "
             << "the analyzer's record count.\n";
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
