// SPDX-License-Identifier: GPL-2.0-or-later
// GCN (PS4 "Liverpool") surface tiling on the CPU.
//
// The address math is a C++ port of shadPS4's host_shaders/tiling.comp
// (GPL-2.0-or-later, Copyright 2025 shadPS4 Emulator Project), with the tile
// parameters taken from video_core/amdgpu/tiling.cpp (vendored). A Tiler
// precomputes the byte offset of every pixel of one surface layout once and
// then copies between the tiled guest surface and a linear staging buffer.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "common/types.h"
#include "video_core/amdgpu/tiling.h"

namespace psemu {

class Tiler {
public:
    // `pitch`/`height` in pixels as the descriptor gives them; they are
    // padded up to whole (macro) tiles internally. Returns nullptr and sets
    // `why` for layouts not modelled (multi-sample, PRT/3D modes).
    static std::shared_ptr<const Tiler> Get(AmdGpu::TileMode mode, u32 bytes_per_pixel,
                                            u32 pitch, u32 height, std::string* why);

    size_t TiledBytes() const { return tiled_bytes; }
    u32 PaddedPitch() const { return pitch; }
    u32 PaddedHeight() const { return height; }

    // linear rows are `row_pixels` apart; copies the top-left width x height
    void Detile(const u8* tiled, u8* linear, u32 width, u32 height, u32 row_pixels) const;
    void Tile(const u8* linear, u8* tiled, u32 width, u32 height, u32 row_pixels) const;

private:
    u32 bpp{};                 // bytes per pixel
    u32 pitch{}, height{};     // padded
    size_t tiled_bytes{};
    std::vector<u32> offsets;  // byte offset of pixel (x, y) at [y * pitch + x]
};

} // namespace psemu
