// SPDX-License-Identifier: GPL-2.0-or-later
// psemu stand-in for shadPS4's file wrapper, used only by the shader-dump
// paths of the recompiler.
#pragma once

#include <cstdio>
#include <filesystem>
#include <string_view>
#include "common/types.h"

namespace Common::FS {

enum class FileAccessMode { Read, Write, Create, Append, ReadWrite };
enum class FileType { BinaryFile, TextFile };

class IOFile {
public:
    IOFile(const std::filesystem::path& path, FileAccessMode mode,
           FileType type = FileType::BinaryFile) {
        const bool text = type == FileType::TextFile;
        const char* m = mode == FileAccessMode::Read ? (text ? "r" : "rb")
                        : mode == FileAccessMode::Append ? (text ? "a" : "ab")
                                                         : (text ? "w" : "wb");
        f = _wfopen(path.c_str(), std::filesystem::path(m).c_str());
    }
    ~IOFile() {
        if (f) {
            std::fclose(f);
        }
    }
    IOFile(const IOFile&) = delete;
    IOFile& operator=(const IOFile&) = delete;

    size_t WriteString(std::string_view s) const {
        return f ? std::fwrite(s.data(), 1, s.size(), f) : 0;
    }
    template <typename T>
    size_t WriteRaw(const void* data, size_t count) const {
        return f ? std::fwrite(data, sizeof(T), count, f) : 0;
    }

private:
    std::FILE* f{};
};

} // namespace Common::FS
