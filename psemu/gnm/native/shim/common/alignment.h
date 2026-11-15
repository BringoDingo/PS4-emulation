// SPDX-License-Identifier: GPL-2.0-or-later
// psemu replacement for shadPS4's common/alignment.h (that file is CC0, not
// GPL-tagged, so it is not vendored). Only what the recompiler uses.
#pragma once

#include <cstddef>
#include <type_traits>

namespace Common {

template <typename T>
[[nodiscard]] constexpr T AlignUp(T value, std::size_t size) {
    static_assert(std::is_unsigned_v<T> || std::is_integral_v<T>);
    const auto mod = static_cast<T>(value % size);
    return mod == 0 ? value : static_cast<T>(value + (size - mod));
}

template <typename T>
[[nodiscard]] constexpr T AlignDown(T value, std::size_t size) {
    return static_cast<T>(value - value % size);
}

template <typename T>
[[nodiscard]] constexpr bool IsAligned(T value, std::size_t alignment) {
    return (value & (alignment - 1)) == 0;
}

} // namespace Common
