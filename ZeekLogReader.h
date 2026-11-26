
#pragma once

#include "NetworkConnection.h"

#include <iosfwd>
#include <string>
#include <vector>

class EvidenceSnapshot;

class ZeekLogReader {
public:
    std::vector<NetworkConnection> readFile(
        const std::string& filename
    ) const;
    std::vector<NetworkConnection> readSnapshot(const EvidenceSnapshot& snapshot) const;

private:
    static std::vector<NetworkConnection> readStream(std::istream& file);
};
