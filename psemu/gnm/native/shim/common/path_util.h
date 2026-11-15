// SPDX-License-Identifier: GPL-2.0-or-later
// psemu stand-in: shader dumps go under ./psemu_shader_dumps.
#pragma once

#include <filesystem>

namespace Common::FS {
enum class PathType { ShaderDir };
inline std::filesystem::path GetUserPath(PathType) {
    return std::filesystem::current_path() / "psemu_shader_dumps";
}
} // namespace Common::FS
