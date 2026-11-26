#include "EvidenceHasher.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace fs = std::filesystem;

namespace {

class TestDirectory {
public:
    TestDirectory()
        : path(fs::temp_directory_path() /
               ("smart_graph_hasher_" + std::to_string(std::random_device{}()))) {
        if (!fs::create_directory(path)) {
            throw std::runtime_error("Evidence test directory already exists");
        }
    }

    ~TestDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    TestDirectory(const TestDirectory&) = delete;
    TestDirectory& operator=(const TestDirectory&) = delete;

    const fs::path path;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::string& filename, std::string_view bytes) {
    std::ofstream file(filename, std::ios::binary);
    if (!bytes.empty()) {
        file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    file.close();
    require(static_cast<bool>(file), "Could not write evidence test fixture");
}

bool rejectsFile(const std::string& filename) {
    try {
        EvidenceHasher::sha256(filename);
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

} // namespace

int main() {
    try {
        const TestDirectory directory;
        const auto filename = (directory.path / "evidence.bin").string();
        require(rejectsFile(filename), "Missing file should throw");
        require(rejectsFile(directory.path.string()), "Directory should throw");

        writeFile(filename, "");
        require(
            EvidenceHasher::sha256(filename) ==
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "Incorrect SHA-256 for an empty file"
        );

        writeFile(filename, "abc");
        const auto abcHash = EvidenceHasher::sha256(filename);
        require(
            abcHash ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "Incorrect SHA-256 for abc"
        );
        require(EvidenceHasher::sha256(filename) == abcHash,
                "Repeated hashing should return the same digest");

        writeFile(filename, "abd");
        require(EvidenceHasher::sha256(filename) != abcHash,
                "Changing the file should change its digest");

        // Exercise multiple reads and a partial final buffer, with embedded nulls.
        std::string binary;
        for (int i = 0; i < 20000; ++i) {
            binary.append("\x00\xff\r\n", 4);
        }
        binary.push_back('\0');
        writeFile(filename, binary);
        require(
            EvidenceHasher::sha256(filename) ==
                "ce37f081db01f01b8d6e927301d478651efd4847e53ebc8699dec63cc4b39a0c",
            "Incorrect SHA-256 for binary evidence"
        );
    } catch (const std::exception& e) {
        std::cerr << "EVIDENCE HASHER TEST FAILED: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
