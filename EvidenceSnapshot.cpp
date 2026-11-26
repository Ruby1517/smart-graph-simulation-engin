#include "EvidenceSnapshot.h"
#include "EvidenceHasher.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using File = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

File openFile(const std::string& path, int flags, const char* mode) {
    const int fd = ::open(path.c_str(), flags | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return File(nullptr, std::fclose);
    }

    File file(::fdopen(fd, mode), std::fclose);
    if (!file) {
        ::close(fd);
    }
    return file;
}

bool sameTime(const timespec& first, const timespec& second) {
    return first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec;
}

bool sameSource(const struct stat& first, const struct stat& second) {
#if defined(__APPLE__)
    const bool sameTimes = sameTime(first.st_mtimespec, second.st_mtimespec) &&
                           sameTime(first.st_ctimespec, second.st_ctimespec);
#else
    const bool sameTimes = sameTime(first.st_mtim, second.st_mtim) &&
                           sameTime(first.st_ctim, second.st_ctim);
#endif
    return sameTimes && first.st_size == second.st_size &&
           first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

} // namespace

struct EvidenceSnapshot::Storage {
    Storage()
        : directory((fs::absolute(fs::temp_directory_path()) /
                     "smart-graph-evidence-XXXXXXXX").string()) {
        if (!::mkdtemp(directory.data())) {
            throw std::runtime_error("Cannot create private evidence snapshot directory");
        }
        try {
            filename = directory + "/contents";
        } catch (...) {
            ::rmdir(directory.c_str());
            throw;
        }
    }

    ~Storage() {
        ::unlink(filename.c_str());
        ::rmdir(directory.c_str());
    }

    std::string directory;
    std::string filename;
};

EvidenceSnapshot::EvidenceSnapshot(const std::string& filename)
    : filename_(filename), storage_(std::make_unique<Storage>()) {
    metadata_.id = fs::path(storage_->directory).filename().string();
    metadata_.captureStarted = std::chrono::system_clock::now();

    // Open once and reject non-regular sources without blocking on FIFOs.
    auto source = openFile(filename_, O_RDONLY | O_NONBLOCK, "rb");
    if (!source) {
        throw std::runtime_error("Cannot open evidence file: " + filename_);
    }
    const int sourceFd = ::fileno(source.get());
    struct stat before {};
    if (::fstat(sourceFd, &before) != 0 || !S_ISREG(before.st_mode)) {
        throw std::runtime_error("Cannot capture evidence as a regular file: " + filename_);
    }

    auto destination = openFile(storage_->filename, O_WRONLY | O_CREAT | O_EXCL, "wb");
    if (!destination) {
        throw std::runtime_error("Cannot create evidence snapshot for: " + filename_);
    }

    auto result = EvidenceHasher::hash(source.get(), filename_, destination.get());

    struct stat after {};
    if (::fstat(sourceFd, &after) != 0) {
        throw std::runtime_error("Cannot check evidence metadata: " + filename_);
    }
    struct stat currentPath {};
    metadata_.sourcePathUnavailable = ::stat(filename_.c_str(), &currentPath) != 0;
    metadata_.sourceChangeObserved =
        !sameSource(before, after) ||
        result.sizeBytes != static_cast<std::uintmax_t>(before.st_size) ||
        (!metadata_.sourcePathUnavailable && !sameSource(after, currentPath));

    if (std::fflush(destination.get()) != 0 ||
        ::fchmod(::fileno(destination.get()), S_IRUSR) != 0 ||
        std::fclose(destination.release()) != 0) {
        throw std::runtime_error("Cannot finalize evidence snapshot for: " + filename_);
    }

    digest_ = std::move(result.digest);
    metadata_.sizeBytes = result.sizeBytes;
    metadata_.captureFinished = std::chrono::system_clock::now();
}

EvidenceSnapshot::~EvidenceSnapshot() = default;

const std::string& EvidenceSnapshot::filename() const noexcept {
    return filename_;
}

const std::string& EvidenceSnapshot::sha256() const noexcept {
    return digest_;
}

const EvidenceSnapshotMetadata& EvidenceSnapshot::metadata() const noexcept {
    return metadata_;
}

std::ifstream EvidenceSnapshot::open() const {
    std::ifstream input(storage_->filename, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot open captured evidence for: " + filename_);
    }
    return input;
}

void EvidenceSnapshot::verifyConsumed(std::ifstream& input) const {
    if (input.eof() && !input.bad()) {
        // getline sets failbit at EOF. Clear that state to query the byte offset.
        input.clear();
        const auto position = static_cast<std::streamoff>(input.tellg());
        if (position >= 0 &&
            static_cast<std::uintmax_t>(position) == metadata_.sizeBytes) {
            return;
        }
    }
    throw std::runtime_error("Incomplete read of evidence snapshot for: " + filename_);
}
