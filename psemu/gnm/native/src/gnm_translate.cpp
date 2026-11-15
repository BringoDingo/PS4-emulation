// SPDX-License-Identifier: GPL-2.0-or-later
// psemu native GNM backend: GCN shader -> SPIR-V through shadPS4's recompiler.
#include <windows.h>
#include <eh.h>

#include <cstring>
#include <stdexcept>
#include <fmt/format.h>

#include "common/logging/log.h"
#include "gnm_internal.h"
#include "shader_recompiler/backend/spirv/emit_spirv.h"
#include "shader_recompiler/recompiler.h"

namespace psemu {

void SetError(char* err, int errlen, const std::string& msg) {
    if (err && errlen > 0) {
        const size_t n = std::min<size_t>(msg.size(), size_t(errlen - 1));
        std::memcpy(err, msg.data(), n);
        err[n] = 0;
    }
}

static void TranslateSeh(unsigned int code, EXCEPTION_POINTERS* ep) {
    if (code == EXCEPTION_ACCESS_VIOLATION && ep && ep->ExceptionRecord->NumberParameters >= 2) {
        const auto* r = ep->ExceptionRecord;
        throw std::runtime_error(fmt::format(
            "access violation {} address {:#x} (a guest pointer in user data or a descriptor "
            "is not mapped host memory)",
            r->ExceptionInformation[0] ? "writing" : "reading", r->ExceptionInformation[1]));
    }
    throw std::runtime_error(fmt::format("hardware exception {:#x}", code));
}

SehGuard::SehGuard() : prev(reinterpret_cast<void*>(_set_se_translator(TranslateSeh))) {}
SehGuard::~SehGuard() {
    _set_se_translator(reinterpret_cast<_se_translator_function>(prev));
}

Shader::Profile DefaultProfile() {
    Shader::Profile p{};
    p.max_ubo_size = 64_KB;
    p.max_viewport_width = 16_KB;
    p.max_viewport_height = 16_KB;
    p.max_shared_memory_size = 32_KB;
    p.supported_spirv = 0x00010600;
    p.subgroup_size = 64;
    p.support_int8 = p.support_int16 = p.support_int64 = true;
    p.support_float16 = p.support_float64 = true;
    p.supports_denorm_behavior_independence = true;
    p.supports_rounding_mode_independence = true;
    p.support_fp32_denorm_flush = p.support_fp32_denorm_preserve = true;
    p.support_fp16_denorm_preserve = p.support_fp64_denorm_preserve = true;
    p.support_fp32_signed_zero_inf_nan_preserve = true;
    p.support_legacy_vertex_attributes = false;
    p.supports_image_load_store_lod = true;   // VK_AMD_shader_image_load_store_lod
    p.supports_native_cube_calc = true;       // VK_AMD_gcn_shader
    p.supports_trinary_minmax = true;         // VK_AMD_shader_trinary_minmax
    p.supports_amd_shader_explicit_vertex_parameter = true;
    p.needs_buffer_offsets = false;
    return p;
}

static Shader::Stage ToStage(u32 s) {
    if (s > GNM_STAGE_CS) {
        throw std::runtime_error(fmt::format("unknown shader stage {}", s));
    }
    return static_cast<Shader::Stage>(s);
}

static Shader::LogicalStage ToLogical(Shader::Stage s) {
    switch (s) {
    case Shader::Stage::Fragment:
        return Shader::LogicalStage::Fragment;
    case Shader::Stage::Vertex:
        return Shader::LogicalStage::Vertex;
    case Shader::Stage::Geometry:
        return Shader::LogicalStage::Geometry;
    case Shader::Stage::Compute:
        return Shader::LogicalStage::Compute;
    case Shader::Stage::Export:
        // An ES feeds a geometry shader; it is compiled as a vertex-like stage.
        return Shader::LogicalStage::Vertex;
    default:
        throw std::runtime_error("tessellation stages (LS/HS) need a full pipeline; "
                                 "not supported by the standalone translator yet");
    }
}

std::unique_ptr<TranslatedShader> Translate(const GnmShaderDesc& d, const Shader::Profile& profile,
                                            Shader::Backend::Bindings& binding,
                                            const StageExtras* extras) {
    if (!d.code || d.code_dwords == 0) {
        throw std::runtime_error("empty shader");
    }
    if (reinterpret_cast<uintptr_t>(d.code) & 3) {
        throw std::runtime_error("shader code must be 4-byte aligned");
    }
    auto ts = std::make_unique<TranslatedShader>();
    std::memcpy(ts->user_data.data(), d.user_data, sizeof(d.user_data));

    const Shader::Stage stage = ToStage(d.stage);
    const Shader::LogicalStage lstage = ToLogical(stage);
    Shader::ShaderParams params{
        .user_data = std::span<const u32, 16>(ts->user_data),
        .code = std::span<const u32>(d.code, d.code_dwords),
        .hash = d.hash,
    };
    ts->info = std::make_unique<Shader::Info>(stage, lstage, params);

    auto& rt = ts->runtime;
    rt.Initialize(stage);
    // SPI_SHADER_PGM_RSRC1/2 fields (same layout for every graphics stage)
    rt.num_user_data = (d.rsrc2 >> 1) & 0x1F;
    rt.num_input_vgprs = (d.rsrc1 >> 24) & 3;
    rt.num_allocated_vgprs = ((d.rsrc1 & 0x3F) + 1) * 4;
    rt.fp_round_mode32 = static_cast<AmdGpu::FpRoundMode>((d.rsrc1 >> 12) & 3);
    rt.fp_round_mode16_64 = static_cast<AmdGpu::FpRoundMode>((d.rsrc1 >> 14) & 3);
    rt.fp_denorm_mode32 = static_cast<AmdGpu::FpDenormMode>((d.rsrc1 >> 16) & 3);
    rt.fp_denorm_mode16_64 = static_cast<AmdGpu::FpDenormMode>((d.rsrc1 >> 18) & 3);

    switch (stage) {
    case Shader::Stage::Fragment: {
        auto& fs = rt.fs_info;
        static_assert(sizeof(fs.en_flags) == sizeof(u32));
        std::memcpy(&fs.en_flags, &d.ps_input_ena, sizeof(u32));
        std::memcpy(&fs.addr_flags, &d.ps_input_addr, sizeof(u32));
        fs.num_inputs = std::min<u32>(d.num_interp, 32);
        for (u32 i = 0; i < fs.num_inputs; ++i) {
            if (extras && extras->ps_inputs) {
                const auto& c = (*extras->ps_inputs)[i];
                fs.inputs[i] = {.param_index = u8(c.input_offset),
                                .is_default = bool(c.use_default),
                                .is_flat = bool(c.flat_shade),
                                .default_value = u8(c.default_value)};
            } else {
                fs.inputs[i] = {.param_index = u8(i), .is_default = false, .is_flat = false,
                                .default_value = 0};
            }
        }
        for (u32 i = 0; i < Shader::MaxColorBuffers; ++i) {
            if (extras && extras->color_buffers) {
                fs.color_buffers[i] = (*extras->color_buffers)[i];
                continue;
            }
            const u32 exp = (d.col_format >> (4 * i)) & 0xF;
            auto& cb = fs.color_buffers[i];
            cb.data_format = AmdGpu::DataFormat::Format8_8_8_8;
            cb.num_format = AmdGpu::NumberFormat::Unorm;
            cb.num_conversion = AmdGpu::NumberConversion::None;
            cb.export_format = static_cast<AmdGpu::ShaderExportFormat>(exp);
            cb.swizzle.r = AmdGpu::CompSwizzle::Red;
            cb.swizzle.g = AmdGpu::CompSwizzle::Green;
            cb.swizzle.b = AmdGpu::CompSwizzle::Blue;
            cb.swizzle.a = AmdGpu::CompSwizzle::Alpha;
        }
        fs.z_export_format = static_cast<AmdGpu::ShaderExportFormat>(d.z_format & 0xF);
        break;
    }
    case Shader::Stage::Vertex:
    case Shader::Stage::Export:
        rt.vs_info.num_outputs = 0;
        rt.vs_info.clip_disable = false;
        rt.vs_info.emulate_depth_negative_one_to_one =
            extras && extras->vs_depth_minus_one_to_one;
        break;
    case Shader::Stage::Compute:
        rt.num_allocated_vgprs = ((d.rsrc1 & 0x3F) + 1) * 4;
        rt.cs_info.workgroup_size = extras ? extras->cs_threads : std::array<u32, 3>{64, 1, 1};
        rt.cs_info.tgid_enable = {bool((d.rsrc2 >> 7) & 1), bool((d.rsrc2 >> 8) & 1),
                                  bool((d.rsrc2 >> 9) & 1)};
        rt.cs_info.shared_memory_size = ((d.rsrc2 >> 15) & 0x1FF) * 512;
        break;
    default:
        break;
    }

    thread_local Shader::Pools pools;
    const auto program = Shader::TranslateProgram(params.code, pools, *ts->info, rt, profile);
    ts->first_binding = binding;
    ts->spirv = Shader::Backend::SPIRV::EmitSPIRV(profile, rt, program, binding);
    ts->next_binding = binding;
    return ts;
}

std::string Summarize(const TranslatedShader& ts) {
    const auto& info = *ts.info;
    std::string s = fmt::format("stage={} spirv_words={} buffers={} images={} samplers={} "
                                "ud_regs={} flat_ud_dwords={} fetch_shader={} discard={}",
                                info.stage, ts.spirv.size(), info.buffers.size(),
                                info.images.size(), info.samplers.size(),
                                info.ud_mask.NumRegs(), info.flattened_ud_buf.size(),
                                info.has_fetch_shader, info.has_discard);
    for (const auto& b : info.buffers) {
        s += fmt::format(" | buf type={} inline={} written={}", u32(b.buffer_type),
                         bool(b.inline_cbuf), b.is_written);
    }
    for (const auto& im : info.images) {
        s += fmt::format(" | img sharp@{} written={} depth={}", im.sharp_idx, im.is_written,
                         im.is_depth);
    }
    return s;
}

} // namespace psemu

using namespace psemu;

extern "C" GNM_API void gnm_set_log_level(int level) {
    Common::Log::g_level = level;
}

extern "C" GNM_API int gnm_translate(const GnmShaderDesc* sh, uint32_t* spirv, uint32_t spirv_cap,
                                     uint32_t* spirv_words, char* summary, int summary_cap,
                                     char* err, int errlen) {
    SehGuard seh;
    try {
        Shader::Backend::Bindings binding{};
        const auto ts = Translate(*sh, CurrentProfile(), binding);
        if (spirv_words) {
            *spirv_words = static_cast<uint32_t>(ts->spirv.size());
        }
        if (spirv) {
            if (spirv_cap < ts->spirv.size()) {
                SetError(err, errlen, "spirv buffer too small");
                return 2;
            }
            std::memcpy(spirv, ts->spirv.data(), ts->spirv.size() * 4);
        }
        SetError(summary, summary_cap, Summarize(*ts));
        return 0;
    } catch (const std::exception& e) {
        SetError(err, errlen, e.what());
        return 1;
    } catch (...) {
        SetError(err, errlen, "unknown failure in shader recompiler");
        return 1;
    }
}
