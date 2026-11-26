#include "EvidenceHasher.h"
#include "EvidenceSnapshot.h"
#include "TrafficCSVReader.h"
#include "ZeekLogReader.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

class TestWorkspace {
public:
    TestWorkspace()
        : directory_((fs::temp_directory_path() / "graph-snapshot-test-XXXXXX").string()) {
        if (!::mkdtemp(directory_.data())) {
            throw std::runtime_error("Cannot create snapshot test workspace");
        }
    }

    ~TestWorkspace() {
        std::error_code error;
        fs::remove_all(directory_, error);
    }

    fs::path path() const { return directory_; }

private:
    std::string directory_;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Operation>
void requireFailure(Operation operation, std::string_view expectedMessage) {
    try {
        operation();
    } catch (const std::runtime_error& error) {
        if (std::string_view(error.what()).find(expectedMessage) != std::string_view::npos) {
            return;
        }
        throw;
    }
    throw std::runtime_error("Expected error containing: " + std::string(expectedMessage));
}

void writeFile(const fs::path& path, std::string_view contents) {
    std::ofstream file(path, std::ios::binary);
    file << contents;
    file.close();
    require(static_cast<bool>(file), "Cannot write test evidence");
}

void checkCSV(const fs::path& workspace, const fs::path& snapshots) {
    const auto source = workspace / "traffic.csv";
    const std::string header =
        "timestamp,sourceIP,destinationIP,sourcePort,destinationPort,protocol,bytesTransferred\r\n";
    const std::string captured = header +
        "2026-11-04 10:30:00,192.0.2.1,192.0.2.2,51524,443,TCP,2048\r\n";
    writeFile(source, captured);
    const auto originalDigest = EvidenceHasher::sha256(source.string());

    const EvidenceSnapshot snapshot(source.string());
    require(snapshot.filename() == source.string(), "Original filename lost");
    require(snapshot.sha256() == originalDigest, "Captured CSV digest mismatch");
    const auto& metadata = snapshot.metadata();
    require(metadata.sizeBytes == captured.size(), "Captured CSV size mismatch");
    require(!metadata.sourceChangeObserved && !metadata.sourcePathUnavailable,
            "Unexpected warning for stable source");

    const auto snapshotDirectory = snapshots / metadata.id;
    struct stat directoryInfo {};
    struct stat fileInfo {};
    require(::stat(snapshotDirectory.c_str(), &directoryInfo) == 0 &&
            (directoryInfo.st_mode & 0777) == 0700, "Snapshot directory must be private");
    require(::stat((snapshotDirectory / "contents").c_str(), &fileInfo) == 0 &&
            (fileInfo.st_mode & 0777) == 0400, "Snapshot contents must be read-only");

    writeFile(source, header + "2026-11-04 10:30:00,192.0.2.1,192.0.2.2,51524,80,TCP,17\n");
    require(EvidenceHasher::sha256(source.string()) != snapshot.sha256(),
            "Source modification should not change the snapshot digest");
    auto input = snapshot.open();
    const std::string actual((std::istreambuf_iterator<char>(input)), {});
    require(actual == captured, "Snapshot bytes changed with the source");
    const auto records = TrafficCSVReader{}.readSnapshot(snapshot);
    require(records.size() == 1 && records.front().destinationPort == 443 &&
            records.front().bytesTransferred == 2048, "CSV parser did not use captured bytes");
}

void checkZeek(const fs::path& workspace) {
    const auto source = workspace / "conn.log";
    writeFile(source,
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tid.orig_p\tid.resp_p\tproto\torig_bytes\tresp_bytes\tconn_state\n"
        "1700000000\t192.0.2.1\t192.0.2.2\t51524\t53\tudp\t28\t260\tSF");
    const auto originalDigest = EvidenceHasher::sha256(source.string());
    const EvidenceSnapshot snapshot(source.string());
    fs::remove(source);

    require(snapshot.sha256() == originalDigest, "Captured Zeek digest mismatch");
    const auto records = ZeekLogReader{}.readSnapshot(snapshot);
    require(records.size() == 1 && records.front().destinationPort == 53 &&
            records.front().bytesTransferred == 288, "Zeek parser did not use captured bytes");
}

void checkLargeFile(const fs::path& workspace) {
    const auto source = workspace / "large.bin";
    const std::string block(64 * 1024, '\0');
    constexpr int blockCount = 512;
    std::ofstream output(source, std::ios::binary);
    for (int i = 0; i < blockCount; ++i) {
        output.write(block.data(), static_cast<std::streamsize>(block.size()));
    }
    output.put('!');
    output.close();
    require(static_cast<bool>(output), "Cannot write large test evidence");

    const EvidenceSnapshot snapshot(source.string());
    require(snapshot.metadata().sizeBytes == blockCount * block.size() + 1,
            "Large evidence byte count mismatch");
    require(snapshot.sha256() == EvidenceHasher::sha256(source.string()),
            "Large evidence digest mismatch");
    auto input = snapshot.open();
    input.seekg(-1, std::ios::end);
    require(input.get() == '!', "Partial final buffer not captured");
}

} // namespace

int main() {
    try {
        const TestWorkspace workspace;
        const auto snapshots = workspace.path() / "snapshots";
        fs::create_directory(snapshots);
        require(::setenv("TMPDIR", snapshots.c_str(), 1) == 0,
                "Cannot isolate snapshot temporary files");

        checkCSV(workspace.path(), snapshots);
        require(fs::is_empty(snapshots), "CSV snapshot not removed after use");
        checkZeek(workspace.path());
        require(fs::is_empty(snapshots), "Zeek snapshot not removed after use");
        checkLargeFile(workspace.path());
        require(fs::is_empty(snapshots), "Large snapshot not removed after use");

        const auto empty = workspace.path() / "empty";
        writeFile(empty, "");
        requireFailure([&] {
            const EvidenceSnapshot snapshot(empty.string());
            require(snapshot.metadata().sizeBytes == 0 &&
                    snapshot.sha256() ==
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "Empty evidence snapshot does not match an empty file");
            TrafficCSVReader{}.readSnapshot(snapshot);
        }, "CSV file is empty");
        require(fs::is_empty(snapshots), "Snapshot not removed after parser error");

        requireFailure([&] {
            const EvidenceSnapshot snapshot((workspace.path() / "missing").string());
        }, "Cannot open evidence file");
        requireFailure([&] {
            const EvidenceSnapshot snapshot(workspace.path().string());
        }, "Cannot capture evidence as a regular file");
#if defined(__linux__)
        // Reading the regular procfs entry at offset zero fails with EIO.
        if (fs::exists("/proc/self/mem")) {
            requireFailure([] {
                const EvidenceSnapshot snapshot("/proc/self/mem");
            }, "Cannot read evidence file");
        }
#endif
        require(fs::is_empty(snapshots), "Temporary data left after failed capture");
    } catch (const std::exception& error) {
        std::cerr << "EVIDENCE SNAPSHOT TEST FAILED: " << error.what() << '\n';
        return 1;
    }
}
