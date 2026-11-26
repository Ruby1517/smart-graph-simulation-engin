
#include "../InvestigationReport.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

int main() {
    try {
        NetworkAnalyzer analyzer;
        GeoAnalyzer geoAnalyzer;

        analyzer.addConnection({
            "2026-11-04 10:30:00",
            "192.168.1.10",
            "192.168.1.20",
            51524,
            443,
            "TCP",
            2048
        });

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

        std::vector<PortScanAlert> alerts;
        EvidenceSnapshotMetadata snapshot;
        snapshot.id = "test-capture";
        snapshot.sizeBytes = 128;
        snapshot.sourceChangeObserved = true;
        snapshot.sourcePathUnavailable = true;
        const std::vector<EvidenceRecord> evidence = {
            {
                "test_traffic.csv",
                "4caac814883b9bacc3c783664e35d6190a9d52cb694a1e6ab3865eb5ac5a463e",
                1,
                snapshot
            }
        };

        InvestigationReport report;

        const fs::path output =
            fs::temp_directory_path() /
            "smart_graph_report_test.txt";

        report.exportText(
            output.string(),
            analyzer,
            alerts,
            geoAnalyzer,
            evidence
        );

        std::ifstream file(output);

        require(file.is_open(), "Report was not created");

        std::string content(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );

        require(
            content.find("Records: 1") != std::string::npos,
            "Incorrect record count"
        );

        require(
            content.find("Total bytes: 2048") != std::string::npos,
            "Incorrect byte count"
        );

        require(
            content.find("TCP: 1") != std::string::npos,
            "Protocol count missing"
        );

        require(
            content.find("No alerts detected.") != std::string::npos,
            "No-alert message missing"
        );

        require(
            content.find("GEOGRAPHIC TRAFFIC SUMMARY") !=
                std::string::npos,
            "GIS summary missing"
        );

        require(
            content.find(
                "Filename: " + evidence.front().filename + "\n" +
                "SHA-256: " + evidence.front().sha256 + "\n" +
                "Imported records: 1\n" +
                "Snapshot ID: test-capture\n" +
                "Snapshot size (bytes): 128\n"
            ) != std::string::npos,
            "Evidence snapshot details missing"
        );
        require(
            content.find("Capture started (UTC): 1970-01-01T00:00:00Z") !=
                std::string::npos &&
            content.find("Capture finished (UTC): 1970-01-01T00:00:00Z") !=
                std::string::npos,
            "Capture times missing"
        );
        require(
            content.find("WARNING: Source changed during capture.") !=
                std::string::npos &&
            content.find("WARNING: Source path could not be checked after capture.") !=
                std::string::npos,
            "Evidence integrity warnings missing"
        );
        require(
            content.find("Total imported evidence records: 1\n") != std::string::npos,
            "Evidence record total missing"
        );

        file.close();
        fs::remove(output);

        std::cout
            << "PASS: Investigation report generated\n"
            << "PASS: Traffic statistics verified\n"
            << "PASS: No-alert scenario verified\n"
            << "PASS: GIS section verified\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "REPORT TEST FAILED: "
                  << e.what() << '\n';
        return 1;
    }
}
