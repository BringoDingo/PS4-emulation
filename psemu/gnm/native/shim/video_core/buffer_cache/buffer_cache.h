// SPDX-License-Identifier: GPL-2.0-or-later
// psemu stand-in: the recompiler only needs these buffer-cache constants
// (values match shadPS4 at commit 4ce43a6).
#pragma once

#include "common/types.h"

namespace VideoCore {
struct BufferCache {
    static constexpr u32 CACHING_PAGEBITS = 14;
    static constexpr u64 CACHING_PAGESIZE = u64{1} << CACHING_PAGEBITS;
    static constexpr u64 CACHING_NUMPAGES = u64{1} << (40 - CACHING_PAGEBITS);
    static constexpr u64 BDA_PAGETABLE_SIZE = CACHING_NUMPAGES * sizeof(u64);
};
} // namespace VideoCore
