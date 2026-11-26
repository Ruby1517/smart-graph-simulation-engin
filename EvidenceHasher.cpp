#include "EvidenceHasher.h"

#include <openssl/evp.h>

#include <array>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <utility>

std::string EvidenceHasher::sha256(const std::string& filename) {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(
        std::fopen(filename.c_str(), "rb"), std::fclose
    );
    if (!file) {
        throw std::runtime_error("Cannot open evidence file: " + filename);
    }
    return hash(file.get(), filename, nullptr).digest;
}

EvidenceHasher::Result EvidenceHasher::hash(
    std::FILE* source, const std::string& filename, std::FILE* destination
) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), EVP_MD_CTX_free
    );
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Cannot initialize SHA-256 for: " + filename);
    }

    std::array<char, 64 * 1024> buffer;
    std::uintmax_t sizeBytes = 0;
    while (true) {
        const auto bytesRead = std::fread(buffer.data(), 1, buffer.size(), source);
        if (std::ferror(source)) {
            throw std::runtime_error("Cannot read evidence file: " + filename);
        }

        if (destination && bytesRead > 0 &&
            std::fwrite(buffer.data(), 1, bytesRead, destination) != bytesRead) {
            throw std::runtime_error("Cannot write evidence snapshot for: " + filename);
        }
        if (bytesRead > 0 &&
            EVP_DigestUpdate(context.get(), buffer.data(), bytesRead) != 1) {
            throw std::runtime_error("Cannot update SHA-256 for: " + filename);
        }
        sizeBytes += bytesRead;
        if (bytesRead < buffer.size()) {
            break;
        }
    }

    constexpr unsigned int sha256Size = 32;
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest;
    unsigned int digestSize = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestSize) != 1 ||
        digestSize != sha256Size) {
        throw std::runtime_error("Cannot finalize SHA-256 for: " + filename);
    }

    constexpr char hexDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(2 * digestSize);
    for (unsigned int i = 0; i < digestSize; ++i) {
        hex.push_back(hexDigits[digest[i] >> 4]);
        hex.push_back(hexDigits[digest[i] & 0x0f]);
    }

    return {std::move(hex), sizeBytes};
}
