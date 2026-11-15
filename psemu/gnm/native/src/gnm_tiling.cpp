// SPDX-License-Identifier: GPL-2.0-or-later
// CPU port of shadPS4's host_shaders/tiling.comp (GPL-2.0-or-later,
// Copyright 2025 shadPS4 Emulator Project). See gnm_tiling.h.

#include "gnm_tiling.h"

#include <bit>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <tuple>

#include <fmt/format.h>

namespace psemu {
namespace {

using AmdGpu::ArrayMode;
using AmdGpu::MicroTileMode;
using AmdGpu::PipeConfig;

constexpr u32 kMicroW = 8, kMicroH = 8;
constexpr u32 kPipeInterleaveBits = 8;

inline u32 Bit(u32 v, u32 b) {
    return (v >> b) & 1;
}

struct Params {
    u32 bits{};            // bits per pixel
    ArrayMode array{};
    MicroTileMode micro{};
    u32 thickness{1};
    PipeConfig pipe_cfg{};
    u32 num_pipes{}, num_pipe_bits{};
    u32 bank_width{}, bank_height{}, num_banks{}, num_bank_bits{}, aspect{};
    u32 tile_split_bytes{};
    u32 bank_swizzle{};

    bool Is3D() const {
        return array == ArrayMode::Array3DTiledThin1 || array == ArrayMode::Array3DTiledThick ||
               array == ArrayMode::Array3DTiledXThick;
    }
    bool Is2DThinOr3DThin() const {
        return array == ArrayMode::Array2DTiledThin1 || array == ArrayMode::Array3DTiledThin1 ||
               array == ArrayMode::ArrayPrt2DTiledThin1 ||
               array == ArrayMode::ArrayPrt3DTiledThin1;
    }
    bool Is2D() const {
        return array == ArrayMode::Array2DTiledThin1 || array == ArrayMode::Array2DTiledThick ||
               array == ArrayMode::Array2DTiledXThick;
    }
    bool IsPrt() const {
        return AmdGpu::IsPrt(array);
    }
    u32 MicroTileBytes() const {
        return kMicroW * kMicroH * thickness * bits / 8;
    }
};

u32 PixelIndexWithinMicroTile(const Params& p, u32 x, u32 y, u32 z) {
    u32 b[9] = {};
    const u32 x0 = Bit(x, 0), x1 = Bit(x, 1), x2 = Bit(x, 2);
    const u32 y0 = Bit(y, 0), y1 = Bit(y, 1), y2 = Bit(y, 2);
    const u32 z0 = Bit(z, 0), z1 = Bit(z, 1), z2 = Bit(z, 2);
    auto set = [&](u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5) {
        b[0] = a0, b[1] = a1, b[2] = a2, b[3] = a3, b[4] = a4, b[5] = a5;
    };
    if (p.micro == MicroTileMode::Display) {
        switch (p.bits) {
        case 8: set(x0, x1, x2, y1, y0, y2); break;
        case 16: set(x0, x1, x2, y0, y1, y2); break;
        case 32: set(x0, x1, y0, x2, y1, y2); break;
        case 64: set(x0, y0, x1, x2, y1, y2); break;
        default: set(y0, x0, x1, x2, y1, y2); break; // 128
        }
    } else if (p.micro == MicroTileMode::Thin || p.micro == MicroTileMode::Depth) {
        set(x0, y0, x1, y1, x2, y2);
    } else { // rotated / thick
        if (p.bits == 8 || p.bits == 16) {
            set(x0, y0, x1, y1, z0, z1);
        } else if (p.bits == 32) {
            set(x0, y0, x1, z0, y1, z1);
        } else {
            set(x0, y0, z0, x1, y1, z1);
        }
        b[6] = x2;
        b[7] = y2;
        if (p.thickness == 8) {
            b[8] = z2;
        }
    }
    u32 n = 0;
    for (u32 i = 0; i < 9; ++i) {
        n |= b[i] << i;
    }
    return n;
}

u32 AddrMicroTiled(const Params& p, u32 x, u32 y, u32 slice, u32 pitch, u32 height) {
    const u32 micro_bytes = p.MicroTileBytes();
    const u32 slice_bytes = (pitch * height * p.thickness * p.bits + 7) / 8;
    const u32 tiles_per_row = pitch / kMicroW;
    const u32 slice_offset = (slice / p.thickness) * slice_bytes;
    const u32 tile_offset = ((y / kMicroH) * tiles_per_row + x / kMicroW) * micro_bytes;
    const u32 pixel_index = PixelIndexWithinMicroTile(p, x, y, slice);
    const u32 pixel_offset = pixel_index * p.bits; // single sample
    return slice_offset + tile_offset + pixel_offset / 8;
}

u32 PipeFromCoord(const Params& p, u32 x, u32 y, u32 slice) {
    const u32 tx = x / kMicroW, ty = y / kMicroH;
    const u32 x3 = Bit(tx, 0), x4 = Bit(tx, 1), x5 = Bit(tx, 2);
    const u32 y3 = Bit(ty, 0), y4 = Bit(ty, 1), y5 = Bit(ty, 2);
    u32 p0 = 0, p1 = 0, p2 = 0;
    switch (p.pipe_cfg) {
    case PipeConfig::P2:
        p0 = x3 ^ y3;
        break;
    case PipeConfig::P8_32x32_8x16:
        p0 = x4 ^ y3 ^ x5;
        p1 = x3 ^ y4;
        p2 = x5 ^ y5;
        break;
    default: // P8_32x32_16x16
        p0 = x3 ^ y3 ^ x4;
        p1 = x4 ^ y4;
        p2 = x5 ^ y5;
        break;
    }
    u32 pipe = p0 | (p1 << 1) | (p2 << 2);
    u32 swz = 0;
    if (p.Is3D()) {
        swz += std::max(1u, p.num_pipes / 2 - 1) * (slice / p.thickness);
    }
    swz &= p.num_pipes - 1;
    return pipe ^ swz;
}

u32 BankFromCoord(const Params& p, u32 x, u32 y, u32 slice, u32 tile_split_slice) {
    const u32 tx = x / kMicroW / (p.bank_width * p.num_pipes);
    const u32 ty = y / kMicroH / p.bank_height;
    const u32 x3 = Bit(tx, 0), x4 = Bit(tx, 1), x5 = Bit(tx, 2), x6 = Bit(tx, 3);
    const u32 y3 = Bit(ty, 0), y4 = Bit(ty, 1), y5 = Bit(ty, 2), y6 = Bit(ty, 3);
    u32 b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    switch (p.num_banks) {
    case 16:
        b0 = x3 ^ y6;
        b1 = x4 ^ y5 ^ y6;
        b2 = x5 ^ y4;
        b3 = x6 ^ y3;
        break;
    case 8:
        b0 = x3 ^ y5;
        b1 = x4 ^ y4 ^ y5;
        b2 = x5 ^ y3;
        break;
    case 4:
        b0 = x3 ^ y4;
        b1 = x4 ^ y3;
        break;
    case 2:
        b0 = x3 ^ y3;
        break;
    }
    u32 bank = b0 | (b1 << 1) | (b2 << 2) | (b3 << 3);
    u32 slice_rotation = 0;
    if (p.Is2D()) {
        slice_rotation = (p.num_banks / 2 - 1) * (slice / p.thickness);
    } else if (p.Is3D()) {
        slice_rotation = std::max(1u, p.num_pipes / 2 - 1) * (slice / p.thickness) / p.num_pipes;
    }
    u32 tile_split_rotation = 0;
    if (p.Is2DThinOr3DThin()) {
        tile_split_rotation = (p.num_banks / 2 + 1) * tile_split_slice;
    }
    bank ^= p.bank_swizzle + slice_rotation;
    bank ^= tile_split_rotation;
    return bank & (p.num_banks - 1);
}

u32 MacroTilePitch(const Params& p) {
    return kMicroW * p.bank_width * p.num_pipes * p.aspect;
}
u32 MacroTileHeight(const Params& p) {
    return kMicroH * p.bank_height * p.num_banks / p.aspect;
}

u32 AddrMacroTiled(const Params& p, u32 x, u32 y, u32 slice, u32 pitch, u32 height) {
    const u32 pixel_index = PixelIndexWithinMicroTile(p, x, y, slice);
    u32 element_offset = pixel_index * p.bits / 8; // single sample
    u32 micro_bytes = p.MicroTileBytes();
    u32 slices_per_tile = 1, tile_split_slice = 0;
    if (micro_bytes > p.tile_split_bytes && p.thickness == 1) {
        slices_per_tile = micro_bytes / p.tile_split_bytes;
        tile_split_slice = element_offset / p.tile_split_bytes;
        element_offset %= p.tile_split_bytes;
        micro_bytes = p.tile_split_bytes;
    }
    const u32 mt_pitch = MacroTilePitch(p), mt_height = MacroTileHeight(p);
    const u32 mt_bytes = micro_bytes * (mt_pitch / kMicroW) * (mt_height / kMicroH) /
                         (p.num_pipes * p.num_banks);
    const u32 mt_per_row = pitch / mt_pitch;
    const u32 mt_offset = ((y / mt_height) * mt_per_row + x / mt_pitch) * mt_bytes;
    const u32 mt_per_slice = mt_per_row * (height / mt_height);
    const u32 slice_bytes = mt_per_slice * mt_bytes;
    const u32 slice_offset =
        slice_bytes * (tile_split_slice + slices_per_tile * (slice / p.thickness));
    const u32 tile_row = (y / kMicroH) % p.bank_height;
    const u32 tile_col = ((x / kMicroW) / p.num_pipes) % p.bank_width;
    const u32 tile_offset = (tile_row * p.bank_width + tile_col) * micro_bytes;
    const u32 total = slice_offset + mt_offset + element_offset + tile_offset;
    if (p.IsPrt()) {
        x %= mt_pitch;
        y %= mt_height;
    }
    const u32 pipe = PipeFromCoord(p, x, y, slice);
    const u32 bank = BankFromCoord(p, x, y, slice, tile_split_slice);
    const u32 interleave = total & ((1u << kPipeInterleaveBits) - 1);
    const u32 offset = total >> kPipeInterleaveBits;
    return interleave | (pipe << kPipeInterleaveBits) |
           (bank << (kPipeInterleaveBits + p.num_pipe_bits)) |
           (offset << (kPipeInterleaveBits + p.num_pipe_bits + p.num_bank_bits));
}

u32 AlignUp(u32 v, u32 a) {
    return (v + a - 1) / a * a;
}

} // namespace

std::shared_ptr<const Tiler> Tiler::Get(AmdGpu::TileMode mode, u32 bytes_per_pixel, u32 pitch,
                                        u32 height, std::string* why) {
    static std::mutex mu;
    static std::map<std::tuple<u32, u32, u32, u32>, std::shared_ptr<const Tiler>> cache;
    const auto key = std::make_tuple(u32(mode), bytes_per_pixel, pitch, height);
    std::lock_guard lk{mu};
    if (auto it = cache.find(key); it != cache.end()) {
        return it->second;
    }
    auto fail = [&](std::string msg) -> std::shared_ptr<const Tiler> {
        if (why) {
            *why = std::move(msg);
        }
        return nullptr;
    };
    if (u32(mode) >= AmdGpu::NUM_TILE_MODES || bytes_per_pixel == 0 || bytes_per_pixel > 16 ||
        !std::has_single_bit(bytes_per_pixel) || pitch == 0 || height == 0 || pitch > 16384 ||
        height > 16384) {
        return fail(fmt::format("bad tiled surface: mode {} bpp {} {}x{}", u32(mode),
                                bytes_per_pixel, pitch, height));
    }
    Params p;
    p.bits = bytes_per_pixel * 8;
    p.array = AmdGpu::GetArrayMode(mode);
    p.micro = AmdGpu::GetMicroTileMode(mode);
    p.thickness = AmdGpu::GetMicroTileThickness(p.array);
    if (p.array == ArrayMode::ArrayLinearGeneral || p.array == ArrayMode::ArrayLinearAligned) {
        return fail("linear surface needs no tiler");
    }
    auto t = std::make_shared<Tiler>();
    t->bpp = bytes_per_pixel;
    const bool macro = AmdGpu::IsMacroTiled(p.array);
    if (macro) {
        p.pipe_cfg = AmdGpu::GetPipeConfig(mode);
        if (p.pipe_cfg != PipeConfig::P2 && p.pipe_cfg != PipeConfig::P8_32x32_8x16 &&
            p.pipe_cfg != PipeConfig::P8_32x32_16x16) {
            return fail(fmt::format("tile mode {}: pipe config {} not modelled", u32(mode),
                                    u32(p.pipe_cfg)));
        }
        p.num_pipes = p.pipe_cfg == PipeConfig::P2 ? 2 : 8;
        p.num_pipe_bits = p.num_pipes == 2 ? 1 : 3;
        const auto mtm = AmdGpu::CalculateMacrotileMode(mode, p.bits, 1);
        p.bank_width = AmdGpu::GetBankWidth(mtm);
        p.bank_height = AmdGpu::GetBankHeight(mtm);
        p.num_banks = AmdGpu::GetNumBanks(mtm);
        p.num_bank_bits = std::bit_width(p.num_banks) - 1;
        p.aspect = AmdGpu::GetMacrotileAspect(mtm);
        p.tile_split_bytes = AmdGpu::CalculateTileSplit(mode, p.array, p.micro, p.bits);
        t->pitch = AlignUp(pitch, MacroTilePitch(p));
        t->height = AlignUp(height, MacroTileHeight(p));
    } else {
        t->pitch = AlignUp(pitch, kMicroW);
        t->height = AlignUp(height, kMicroH);
    }
    t->offsets.resize(size_t(t->pitch) * t->height);
    u32 max_end = 0;
    for (u32 y = 0; y < t->height; ++y) {
        for (u32 x = 0; x < t->pitch; ++x) {
            const u32 off = macro ? AddrMacroTiled(p, x, y, 0, t->pitch, t->height)
                                  : AddrMicroTiled(p, x, y, 0, t->pitch, t->height);
            t->offsets[size_t(y) * t->pitch + x] = off;
            max_end = std::max(max_end, off + bytes_per_pixel);
        }
    }
    t->tiled_bytes = max_end;
    cache.emplace(key, t);
    return t;
}

void Tiler::Detile(const u8* tiled, u8* linear, u32 w, u32 h, u32 row_pixels) const {
    w = std::min(w, pitch);
    h = std::min(h, height);
    for (u32 y = 0; y < h; ++y) {
        const u32* off = &offsets[size_t(y) * pitch];
        u8* dst = linear + size_t(y) * row_pixels * bpp;
        if (bpp == 4) {
            for (u32 x = 0; x < w; ++x) {
                std::memcpy(dst + x * 4, tiled + off[x], 4);
            }
        } else {
            for (u32 x = 0; x < w; ++x) {
                std::memcpy(dst + size_t(x) * bpp, tiled + off[x], bpp);
            }
        }
    }
}

void Tiler::Tile(const u8* linear, u8* tiled, u32 w, u32 h, u32 row_pixels) const {
    w = std::min(w, pitch);
    h = std::min(h, height);
    for (u32 y = 0; y < h; ++y) {
        const u32* off = &offsets[size_t(y) * pitch];
        const u8* src = linear + size_t(y) * row_pixels * bpp;
        for (u32 x = 0; x < w; ++x) {
            std::memcpy(tiled + off[x], src + size_t(x) * bpp, bpp);
        }
    }
}

} // namespace psemu

#include "gnm_api.h"

// C API for tools/tests: tiled size, detile, tile (linear rows = pitch).
extern "C" GNM_API int gnm_tiling(uint32_t mode, uint32_t bytes_per_pixel, uint32_t pitch,
                                  uint32_t height, int direction, const void* src, void* dst,
                                  uint64_t* tiled_bytes, uint32_t* padded_pitch,
                                  uint32_t* padded_height, char* err, int errlen) {
    std::string why;
    const auto t = psemu::Tiler::Get(AmdGpu::TileMode(mode), bytes_per_pixel, pitch, height, &why);
    if (!t) {
        if (err && errlen > 0) {
            std::snprintf(err, size_t(errlen), "%s", why.c_str());
        }
        return 1;
    }
    if (tiled_bytes) {
        *tiled_bytes = t->TiledBytes();
    }
    if (padded_pitch) {
        *padded_pitch = t->PaddedPitch();
    }
    if (padded_height) {
        *padded_height = t->PaddedHeight();
    }
    if (src && dst) {
        if (direction > 0) { // linear -> tiled
            t->Tile(static_cast<const u8*>(src), static_cast<u8*>(dst), pitch, height, pitch);
        } else {
            t->Detile(static_cast<const u8*>(src), static_cast<u8*>(dst), pitch, height, pitch);
        }
    }
    return 0;
}
