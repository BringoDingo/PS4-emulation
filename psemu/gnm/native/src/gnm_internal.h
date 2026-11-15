// SPDX-License-Identifier: GPL-2.0-or-later
// psemu native GNM backend: pieces shared between translation, Vulkan
// execution and the PM4 command processor.
#pragma once

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gnm_api.h"
#include "shader_recompiler/backend/bindings.h"
#include "shader_recompiler/info.h"
#include "shader_recompiler/profile.h"
#include "shader_recompiler/runtime_info.h"
#include "video_core/amdgpu/regs_color.h"
#include "video_core/amdgpu/regs_depth.h"
#include "video_core/amdgpu/regs_shader.h"

namespace psemu {

struct TranslatedShader {
    std::array<u32, 16> user_data{};          // Info::user_data points here
    std::unique_ptr<Shader::Info> info;
    Shader::RuntimeInfo runtime{};
    std::vector<u32> spirv;
    Shader::Backend::Bindings first_binding{}; // bindings before / after this stage
    Shader::Backend::Bindings next_binding{};
};

// Per-pipeline state the recompiler needs besides the shader itself.
struct StageExtras {
    // PS: SPI_PS_INPUT_CNTL_0..31 (which VS param feeds each interpolant)
    std::optional<std::array<AmdGpu::PsInputControl, 32>> ps_inputs;
    // PS: what each MRT really is (format/swizzle), as derived from CB_COLORn_*
    std::optional<std::array<Shader::PsColorBuffer, Shader::MaxColorBuffers>> color_buffers;
    // CS: COMPUTE_NUM_THREAD_X/Y/Z
    std::array<u32, 3> cs_threads{64, 1, 1};
    // VS: clip space is [-w, w] in z: remap to Vulkan's [0, w] in the shader
    bool vs_depth_minus_one_to_one{};
};

// Translate a guest shader. `binding` carries descriptor numbering across the
// stages of one pipeline (fragment first, then vertex, as shadPS4 does).
std::unique_ptr<TranslatedShader> Translate(const GnmShaderDesc& desc,
                                            const Shader::Profile& profile,
                                            Shader::Backend::Bindings& binding,
                                            const StageExtras* extras = nullptr);

std::string Summarize(const TranslatedShader& ts);

// Profile used when no Vulkan device is open (translation-only runs):
// capabilities of a GCN-class AMD GPU with a Vulkan 1.3 driver.
Shader::Profile DefaultProfile();
// Profile of the open device (falls back to DefaultProfile before gnm_init).
const Shader::Profile& CurrentProfile();

void SetError(char* err, int errlen, const std::string& msg);

// While alive, hardware faults (e.g. the recompiler dereferencing a bad guest
// pointer from user data) are turned into C++ exceptions on this thread, so
// they are reported instead of killing the host process. Needs /EHa.
class SehGuard {
public:
    SehGuard();
    ~SehGuard();

private:
    void* prev;
};

// ------------------------------------------------------------- jobs

struct ColorTarget {
    u32 slot{};                     // MRT index the pixel shader exports to
    u64 address{};                  // guest surface (host pointer); 0 = read back to `readback`
    u32 width{}, height{}, pitch{}; // pitch in elements
    AmdGpu::DataFormat dfmt{AmdGpu::DataFormat::Format8_8_8_8};
    AmdGpu::NumberFormat nfmt{AmdGpu::NumberFormat::Unorm};
    AmdGpu::TileMode tile_mode{AmdGpu::TileMode::DisplayLinearAligned};
    AmdGpu::BlendControl blend{};
    u32 write_mask{0xF};
    bool load{};                    // keep the surface's existing contents
    std::array<float, 4> clear{0, 0, 0, 1};
    u8* readback{};                 // for address == 0: width*height*bpp bytes
};

// Depth/stencil surface and the DB state a draw uses it with.
struct DepthTarget {
    u64 z_address{};                // 0 = no depth plane
    u64 stencil_address{};          // 0 = no stencil plane
    u32 width{}, height{};          // pixels (DB_DEPTH_SIZE pitch / height)
    u32 z_bits{};                   // 16 (unorm) or 32 (float)
    AmdGpu::TileMode tile_mode{AmdGpu::TileMode::DisplayLinearAligned};
    AmdGpu::DepthControl control{};
    AmdGpu::StencilControl stencil_ops{};
    AmdGpu::StencilRefMask front{}, back{};
    bool clear_depth{}, clear_stencil{};  // DB_RENDER_CONTROL: draw writes the clear values
    float depth_clear{1.0f};
    u8 stencil_clear{};
    bool z_read_only{}, stencil_read_only{};
};

struct GraphicsJob {
    GnmShaderDesc vs{};
    GnmShaderDesc ps{};
    StageExtras ps_extras{};
    u32 prim_type{};
    u32 vertex_count{};
    u32 instance_count{1};
    u64 index_address{};            // 0 = non-indexed
    u32 index_size{};               // 2 or 4
    float vp_xscale{}, vp_xoffset{}, vp_yscale{}, vp_yoffset{};
    float vp_zscale{0.5f}, vp_zoffset{0.5f};    // PA_CL_VPORT_ZSCALE/ZOFFSET
    float vp_zmin{0.0f}, vp_zmax{1.0f};         // PA_SC_VPORT_ZMIN/ZMAX
    bool clip_minus_w_to_w{};                   // GL-style clip z in [-w, w]
    std::array<float, 4> blend_constants{};
    std::vector<ColorTarget> targets;
    std::optional<DepthTarget> depth;           // DB_* surface + state
    StageExtras vs_extras{};
};

struct ComputeJob {
    GnmShaderDesc cs{};
    std::array<u32, 3> threads{64, 1, 1};
    std::array<u32, 3> groups{1, 1, 1};
};

void ExecuteGraphics(const GraphicsJob& job);
void ExecuteCompute(const ComputeJob& job);
// Resident render targets (see gnm_vulkan.cpp): write back + drop the ones
// overlapping [lo, hi) / all of them (end of a submit). Caller holds DeviceMutex.
void FlushSurfaces(u64 lo, u64 hi);
void ReleaseSurfaces();
u32 SurfaceWriteBacks();

} // namespace psemu
