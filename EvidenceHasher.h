#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

class EvidenceSnapshot;

class EvidenceHasher {
public:
    // Hash the file's raw bytes and return a lowercase hexadecimal digest.
    static std::string sha256(const std::string& filename);

private:
    friend class EvidenceSnapshot;

    struct Result {
        std::string digest;
        std::uintmax_t sizeBytes;
    };

    static Result hash(
        std::FILE* source, const std::string& filename, std::FILE* destination
    );
};
