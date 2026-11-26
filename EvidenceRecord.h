
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

struct EvidenceSnapshotMetadata {
    std::string id;
    std::uintmax_t sizeBytes = 0;
    std::chrono::system_clock::time_point captureStarted;
    std::chrono::system_clock::time_point captureFinished;
    bool sourceChangeObserved = false;
    bool sourcePathUnavailable = false;
};

struct EvidenceRecord {
    std::string filename;
    std::string sha256;
    std::size_t importedRecords = 0;
    std::optional<EvidenceSnapshotMetadata> snapshot = std::nullopt;
};
