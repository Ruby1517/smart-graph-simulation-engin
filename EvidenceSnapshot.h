#pragma once

#include "EvidenceRecord.h"

#include <fstream>
#include <memory>
#include <string>

class EvidenceSnapshot {
public:
    explicit EvidenceSnapshot(const std::string& filename);
    ~EvidenceSnapshot();

    EvidenceSnapshot(const EvidenceSnapshot&) = delete;
    EvidenceSnapshot& operator=(const EvidenceSnapshot&) = delete;

    const std::string& filename() const noexcept;
    const std::string& sha256() const noexcept;
    const EvidenceSnapshotMetadata& metadata() const noexcept;

    std::ifstream open() const;
    void verifyConsumed(std::ifstream& input) const;

private:
    struct Storage;
    std::string filename_;
    std::unique_ptr<Storage> storage_;
    std::string digest_;
    EvidenceSnapshotMetadata metadata_;
};
