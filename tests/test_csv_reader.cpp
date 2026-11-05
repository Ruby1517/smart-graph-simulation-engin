
#include "../TrafficCSVReader.h"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

void writeCSV(
    const fs::path& path,
    const std::string& content
) {
    std::ofstream file(path);

    if (!file) {
        throw std::runtime_error("Cannot create test file");
    }

    file << content;

    if (!file) {
        throw std::runtime_error("Cannot write test file");
    }
}

bool rejectsCSV(
    const TrafficCSVReader& reader,
    const fs::path& path
) {
    try {
        reader.readFile(path.string());
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

int main() {
    TrafficCSVReader reader;

    const fs::path file =
        fs::temp_directory_path() / "graph_csv_test.csv";

    const std::string header =
        "timestamp,sourceIP,destinationIP,"
        "sourcePort,destinationPort,protocol,"
        "bytesTransferred\n";

    const std::string validRow =
        "2026-11-04 10:30:00,"
        "192.168.1.10,192.168.1.20,"
        "51524,443,TCP,2048\n";

    try {
        // Test 1: Valid CSV
        writeCSV(file, header + validRow);

        auto records = reader.readFile(file.string());

        assert(records.size() == 1);
        assert(records[0].sourcePort == 51524);
        assert(records[0].destinationPort == 443);
        assert(records[0].bytesTransferred == 2048);

        std::cout << "PASS: Valid CSV imported\n";

        // Test 2: Port exceeds 65535
        writeCSV(
            file,
            header +
            "2026-11-04 10:30:00,"
            "192.168.1.10,192.168.1.20,"
            "70000,443,TCP,2048\n"
        );

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Invalid port rejected\n";

        // Test 3: Negative destination port
        writeCSV(
            file,
            header +
            "2026-11-04 10:30:00,"
            "192.168.1.10,192.168.1.20,"
            "51524,-1,TCP,2048\n"
        );

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Negative port rejected\n";

        // Test 4: Invalid byte count
        writeCSV(
            file,
            header +
            "2026-11-04 10:30:00,"
            "192.168.1.10,192.168.1.20,"
            "51524,443,TCP,abc\n"
        );

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Invalid byte count rejected\n";

        // Test 5: Missing source IP
        writeCSV(
            file,
            header +
            "2026-11-04 10:30:00,"
            ",192.168.1.20,"
            "51524,443,TCP,2048\n"
        );

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Missing source IP rejected\n";

        // Test 6: Missing CSV column
        writeCSV(
            file,
            header +
            "2026-11-04 10:30:00,"
            "192.168.1.10,192.168.1.20,"
            "51524,443,TCP\n"
        );

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Missing column rejected\n";

        // Test 7: Extra CSV column
        writeCSV(
            file,
            header +
            "2026-11-04 10:30:00,"
            "192.168.1.10,192.168.1.20,"
            "51524,443,TCP,2048,EXTRA\n"
        );

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Extra column rejected\n";

        // Test 8: Incorrect header
        writeCSV(file, "wrong,header\n" + validRow);

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Invalid header rejected\n";

        // Test 9: Empty file
        writeCSV(file, "");

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Empty file rejected\n";

        // Test 10: Nonexistent file
        fs::remove(file);

        assert(rejectsCSV(reader, file));
        std::cout << "PASS: Missing file rejected\n";

        std::cout << "\nAll CSV reader tests passed!\n";

    } catch (const std::exception& e) {
        fs::remove(file);
        std::cerr << "TEST FAILED: " << e.what() << '\n';
        return 1;
    }

    fs::remove(file);
    return 0;
}
