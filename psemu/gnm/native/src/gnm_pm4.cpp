// SPDX-License-Identifier: GPL-2.0-or-later
// psemu native GNM backend: PM4 command processor.
//
// Walks a GNM command buffer (the PM4 packets libSceGnmDriver builds and the
// game/system submits), keeps the GPU register file in shadPS4's
// AmdGpu::Regs layout, and turns DRAW_* / DISPATCH_* packets into graphics and
// compute jobs on the Vulkan executor. Memory-writing packets (EOP/EOS
// fences, WRITE_DATA, DMA_DATA, RELEASE_MEM) write straight into guest memory,
// which in psemu is host memory.
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <fmt/format.h>

#include "gnm_internal.h"
#include "video_core/amdgpu/pm4_opcodes.h"
#include "video_core/amdgpu/regs.h"

namespace psemu {

std::mutex& DeviceMutex();

namespace {

using Op = AmdGpu::PM4ItOpcode;
using Regs = AmdGpu::Regs;

template <typename T>
u32 Raw(const T& v) {
    static_assert(sizeof(T) == sizeof(u32));
    u32 r;
    std::memcpy(&r, &v, sizeof(r));
    return r;
}

[[noreturn]] void Fail(const std::string& msg) {
    throw std::runtime_error(msg);
}

GnmShaderDesc ProgramDesc(const auto& prog, u32 stage) {
    GnmShaderDesc d{};
    d.stage = stage;
    const u32* code = prog.template Address<const u32*>();
    if (!code) {
        Fail(fmt::format("{} shader address is 0 (SPI_SHADER_PGM_LO/HI not set)",
                         stage == GNM_STAGE_PS   ? "pixel"
                         : stage == GNM_STAGE_CS ? "compute"
                                                 : "vertex"));
    }
    const auto& bin = AmdGpu::SearchBinaryInfo(code);
    d.code = code;
    d.code_dwords = bin.length / 4;
    d.hash = bin.shader_hash;
    u64 settings;
    static_assert(sizeof(prog.settings) == sizeof(settings));
    std::memcpy(&settings, &prog.settings, sizeof(settings));
    d.rsrc1 = u32(settings);
    d.rsrc2 = u32(settings >> 32);
    std::memcpy(d.user_data, prog.user_data.data(), sizeof(d.user_data));
    return d;
}

struct Processor {
    Regs regs{};
    std::vector<u8> gds = std::vector<u8>(64_KB);
    GnmSubmitStats stats{};
    std::string first_error;
    int depth = 0;

    Processor() {
        regs.SetDefaults();
    }

    void Error(const std::string& msg) {
        ++stats.failed;
        if (first_error.empty()) {
            first_error = msg;
        }
    }

    void Skipped(u32 opcode) {
        if (stats.skipped_packets++ == 0) {
            stats.first_skipped_opcode = opcode;
        }
    }

    // ------------------------------------------------------------ draws
    void Draw(u32 count, u64 index_addr, u32 index_size) {
        if (regs.stage_enable.raw != 0) {
            Fail(fmt::format("VGT_SHADER_STAGES_EN={:#x}: tessellation/geometry pipelines "
                             "are not supported yet",
                             u32(regs.stage_enable.raw)));
        }
        GraphicsJob job;
        job.vs = ProgramDesc(regs.vs_program, GNM_STAGE_VS);
        job.vs.vs_out_cntl = Raw(regs.vs_output_control);
        // No pixel shader (address 0) is legal for depth-only passes: the
        // executor then requires a depth target and no colour targets.
        if (regs.ps_program.template Address<const u32*>()) {
            job.ps = ProgramDesc(regs.ps_program, GNM_STAGE_PS);
        }
        job.ps.ps_input_ena = Raw(regs.ps_input_ena);
        job.ps.ps_input_addr = Raw(regs.ps_input_addr);
        job.ps.num_interp = regs.num_interp;
        job.ps.col_format = regs.color_export_format.raw;
        job.ps.z_format = u32(regs.z_export_format);
        job.ps_extras.ps_inputs.emplace();
        std::copy(regs.ps_inputs.begin(), regs.ps_inputs.end(), job.ps_extras.ps_inputs->begin());

        auto& keys = job.ps_extras.color_buffers.emplace();
        for (u32 cb = 0; cb < AmdGpu::NUM_COLOR_BUFFERS; ++cb) {
            const auto& col = regs.color_buffers[cb];
            keys[cb] = {};
            keys[cb].export_format = regs.color_export_format.GetFormat(cb);
            if (!col || !regs.color_target_mask.GetMask(cb)) {
                continue;
            }
            keys[cb].data_format = col.GetDataFmt();
            keys[cb].num_format = col.GetNumberFmt();
            keys[cb].num_conversion = col.GetNumberConversion();
            keys[cb].swizzle = col.Swizzle();

            ColorTarget t{};
            t.slot = cb;
            t.address = col.Address();
            t.pitch = col.Pitch();
            t.width = col.Pitch();
            t.height = col.Height();
            t.dfmt = col.GetDataFmt();
            t.nfmt = col.GetNumberFmt();
            t.tile_mode = col.GetTileMode();
            t.blend = regs.blend_control[cb];
            t.write_mask = regs.color_target_mask.GetMask(cb);
            t.load = true;
            job.targets.push_back(t);
        }
        // ---- depth / stencil (DB_*)
        const auto& db = regs.depth_buffer;
        const auto& dc = regs.depth_control;
        const auto& rc = regs.depth_render_control;
        const bool has_z = db.z_info.format != AmdGpu::DepthBuffer::ZFormat::Invalid &&
                           db.DepthAddress() != 0;
        const bool has_s = db.StencilValid();
        const bool uses_z = dc.depth_enable || rc.depth_clear_enable;
        const bool uses_s = dc.stencil_enable || rc.stencil_clear_enable;
        if ((has_z && uses_z) || (has_s && uses_s)) {
            if (db.z_info.num_samples != 0) {
                Fail("multisampled depth buffers are not supported yet");
            }
            if (db.DepthAddress() != db.DepthWriteAddress() ||
                db.StencilAddress() != db.StencilWriteAddress()) {
                Fail("depth buffers with separate read/write addresses are not supported yet");
            }
            auto& d = job.depth.emplace();
            d.z_address = has_z ? db.DepthAddress() : 0;
            d.stencil_address = has_s ? db.StencilAddress() : 0;
            d.width = db.Pitch();
            // DB_DEPTH_SIZE height_tile_max is not always programmed: fall back
            // to the slice size (pixels per slice / pitch)
            const u32 slice_px = (db.depth_slice.tile_max + 1) * 64;
            d.height = db.depth_size.height_tile_max ? db.Height() : slice_px / d.width;
            d.z_bits = db.NumBits();
            d.tile_mode = db.GetTileMode();
            d.control = dc;
            d.stencil_ops = regs.stencil_control;
            d.front = regs.stencil_ref_front;
            d.back = regs.stencil_ref_back;
            d.clear_depth = rc.depth_clear_enable;
            d.clear_stencil = rc.stencil_clear_enable;
            d.depth_clear = regs.depth_clear;
            d.stencil_clear = u8(regs.stencil_clear);
            d.z_read_only = regs.depth_view.z_read_only;
            d.stencil_read_only = regs.depth_view.stencil_read_only;
        }
        if (job.targets.empty() && !job.depth && regs.color_target_mask.raw == 0) {
            // CB_TARGET_MASK=0 and no depth/stencil buffer: the draw writes nothing
            // observable (a colour-masked pre-pass), so there is nothing to execute.
            Skipped(0x2D);
            return;
        }
        if (job.targets.empty() && !job.depth) {
            const auto& c0 = regs.color_buffers[0];
            Fail(fmt::format("draw with neither a colour nor a depth/stencil target bound "
                             "[target_mask={:08x} cb0.base={:08x} cb0.info={:08x} z_fmt={} z_addr={:x} "
                             "depth_en={} stencil_en={} ps={:x}]",
                             regs.color_target_mask.raw, c0.base_address,
                             u32(*reinterpret_cast<const u32*>(&c0.info)), u32(db.z_info.format),
                             u64(db.DepthAddress()), u32(dc.depth_enable), u32(dc.stencil_enable),
                             u64(uintptr_t(regs.ps_program.template Address<const u32*>()))));
        }

        job.prim_type = u32(regs.primitive_type);
        job.vertex_count = count;
        job.instance_count = regs.num_instances.NumInstances();
        job.index_address = index_addr;
        job.index_size = index_size;
        const auto& vp = regs.viewports[0];
        const auto& vc = regs.viewport_control;
        job.vp_xscale = vc.xscale_enable ? vp.xscale : 1.0f;
        job.vp_xoffset = vc.xoffset_enable ? vp.xoffset : 0.0f;
        job.vp_yscale = vc.yscale_enable ? vp.yscale : 1.0f;
        job.vp_yoffset = vc.yoffset_enable ? vp.yoffset : 0.0f;
        job.vp_zscale = vc.zscale_enable ? vp.zscale : 1.0f;
        job.vp_zoffset = vc.zoffset_enable ? vp.zoffset : 0.0f;
        job.vp_zmin = regs.viewport_depths[0].zmin;
        job.vp_zmax = regs.viewport_depths[0].zmax;
        job.clip_minus_w_to_w = regs.clipper_control.clip_space == AmdGpu::ClipSpace::MinusWToW;
        job.vs_extras.vs_depth_minus_one_to_one = job.clip_minus_w_to_w;
        std::memcpy(job.blend_constants.data(), &regs.blend_constants, sizeof(float) * 4);
        ExecuteGraphics(job);
        ++stats.draws;
    }

    void Dispatch(u32 x, u32 y, u32 z) {
        const auto& cs = regs.cs_program;
        ComputeJob job;
        job.cs = ProgramDesc(cs, GNM_STAGE_CS);
        job.threads = {std::max<u32>(1, cs.num_thread_x.full),
                       std::max<u32>(1, cs.num_thread_y.full),
                       std::max<u32>(1, cs.num_thread_z.full)};
        job.groups = {x, y, z};
        ExecuteCompute(job);
        ++stats.dispatches;
    }

    template <typename F>
    void Guarded(F&& f) {
        try {
            f();
        } catch (const std::exception& e) {
            Error(e.what());
        }
    }

    // ------------------------------------------------------------ memory
    static void Write32(u64 addr, u32 v) {
        std::memcpy(reinterpret_cast<void*>(uintptr_t(addr)), &v, 4);
    }
    static void Write64(u64 addr, u64 v) {
        std::memcpy(reinterpret_cast<void*>(uintptr_t(addr)), &v, 8);
    }
    static u32 Read32(u64 addr) {
        u32 v;
        std::memcpy(&v, reinterpret_cast<const void*>(uintptr_t(addr)), 4);
        return v;
    }

    void WriteEop(u64 addr, u32 data_sel, u32 lo, u32 hi) {
        switch (data_sel) {
        case 1: // Data32Low
            Write32(addr, lo);
            break;
        case 2: // Data64
            Write64(addr, u64(lo) | u64(hi) << 32);
            break;
        case 3: // GpuClock64
        case 4: // PerfCounter
            Write64(addr, ++clock);
            break;
        default:
            return;
        }
        ++stats.fences;
    }
    u64 clock = 0;

    void SetRegs(u32 base, std::span<const u32> body) {
        if (body.empty()) {
            return;
        }
        const u32 reg = base + (body[0] & 0xFFFF);
        const auto vals = body.subspan(1);
        if (reg + vals.size() > Regs::NumRegs) {
            Fail(fmt::format("register write out of range: {:#x} + {}", reg, vals.size()));
        }
        std::memcpy(&regs.reg_array[reg], vals.data(), vals.size_bytes());
    }

    // ------------------------------------------------------------ packets
    void Run(std::span<const u32> cb) {
        if (++depth > 8) {
            --depth;
            Fail("INDIRECT_BUFFER nesting deeper than 8");
        }
        size_t i = 0;
        while (i < cb.size()) {
            const u32 h = cb[i];
            const u32 type = h >> 30;
            ++stats.packets;
            if (type == 2) {          // filler
                ++i;
                continue;
            }
            if (type == 0) {          // write consecutive registers
                const u32 base = h & 0xFFFF;
                const u32 n = ((h >> 16) & 0x3FFF) + 1;
                if (i + 1 + n > cb.size() || base + n > Regs::NumRegs) {
                    Fail(fmt::format("bad type-0 packet at dword {}", i));
                }
                std::memcpy(&regs.reg_array[base], &cb[i + 1], n * 4);
                i += 1 + n;
                continue;
            }
            if (type != 3) {
                Fail(fmt::format("PM4 type {} packet at dword {}", type, i));
            }
            const u32 n = ((h >> 16) & 0x3FFF) + 1; // body dwords
            const u32 opcode = (h >> 8) & 0xFF;
            if (i + 1 + n > cb.size()) {
                Fail(fmt::format("packet {:#x} at dword {} runs past the buffer", opcode, i));
            }
            Packet(static_cast<Op>(opcode), std::span<const u32>(&cb[i + 1], n));
            i += 1 + n;
        }
        --depth;
    }

    void Packet(Op op, std::span<const u32> b) {
        auto at = [&](size_t k) -> u32 {
            if (k >= b.size()) {
                Fail(fmt::format("packet {:#x} is too short", u32(op)));
            }
            return b[k];
        };
        switch (op) {
        case Op::Nop:
        case Op::ContextControl:
        case Op::SetPredication:
        case Op::AcquireMem:
        case Op::SurfaceSync:
        case Op::PfpSyncMe:
        case Op::IncrementDeCounter:
        case Op::IncrementCeCounter:
        case Op::WaitOnCeCounter:
        case Op::WaitOnDeCounterDiff:
        case Op::EventWrite:
        case Op::PreambleCntl:
        case Op::Rewind:
            break;
        case Op::ClearState:
            regs.SetDefaults();
            break;
        case Op::SetConfigReg:
            SetRegs(Regs::ConfigRegWordOffset, b);
            break;
        case Op::SetContextReg:
            SetRegs(Regs::ContextRegWordOffset, b);
            break;
        case Op::SetShReg:
            SetRegs(Regs::ShRegWordOffset, b);
            break;
        case Op::SetUconfigReg:
            SetRegs(Regs::UconfigRegWordOffset, b);
            break;
        case Op::IndexType:
            regs.index_buffer_type.raw = at(0);
            break;
        case Op::IndexBase:
            regs.index_base_address.base_addr_lo = at(0);
            regs.index_base_address.base_addr_hi = at(1) & 0xFF;
            break;
        case Op::IndexBufferSize:
            regs.num_indices = at(0);
            break;
        case Op::NumInstances:
            regs.num_instances.num_instances = at(0);
            break;
        case Op::DrawIndexAuto:
            Guarded([&] { Draw(at(0), 0, 0); });
            break;
        case Op::DrawIndex2: {
            // max_size, base_lo, base_hi, index_count, draw_initiator
            const u64 base = (at(1) & ~1u) | (u64(at(2) & 0xFF) << 32);
            const u32 size =
                regs.index_buffer_type.index_type == AmdGpu::IndexType::Index32 ? 4 : 2;
            Guarded([&] { Draw(at(3), base, size); });
            break;
        }
        case Op::DrawIndexOffset2: {
            // max_size, index_offset, index_count, draw_initiator
            const u32 size =
                regs.index_buffer_type.index_type == AmdGpu::IndexType::Index32 ? 4 : 2;
            const u64 base = regs.index_base_address.Address() + u64(at(1)) * size;
            Guarded([&] { Draw(at(2), base, size); });
            break;
        }
        case Op::DispatchDirect:
            Guarded([&] { Dispatch(at(0), at(1), at(2)); });
            break;
        case Op::EventWriteEop: {
            const u64 addr = at(1) | (u64(at(2) & 0xFFFF) << 32);
            WriteEop(addr, at(2) >> 29, at(3), at(4));
            if ((at(2) >> 24) & 3) { // int_sel: interrupt the CPU when done
                ++stats.interrupts;
            }
            break;
        }
        case Op::EventWriteEos: {
            const u64 addr = at(1) | (u64(at(2) & 0xFFFF) << 32);
            if ((at(2) >> 29) == 2) { // SignalFence
                Write32(addr, at(3));
                ++stats.fences;
            }
            break;
        }
        case Op::ReleaseMem: {
            const u64 addr = at(2) | (u64(at(3)) << 32);
            WriteEop(addr, at(1) >> 29, at(4), at(5));
            if ((at(1) >> 24) & 3) { // int_sel
                ++stats.interrupts;
            }
            break;
        }
        case Op::WriteData: {
            const u32 dst_sel = (at(0) >> 8) & 0xF;
            const u64 addr = at(1) | (u64(at(2)) << 32);
            const auto data = b.subspan(3);
            if (dst_sel != 0) {
                FlushSurfaces(addr, addr + data.size_bytes());
            }
            if (dst_sel == 0) { // memory-mapped register (dword index)
                for (size_t k = 0; k < data.size(); ++k) {
                    if (at(1) + k < Regs::NumRegs) {
                        regs.reg_array[at(1) + k] = data[k];
                    }
                }
            } else {
                std::memcpy(reinterpret_cast<void*>(uintptr_t(addr)), data.data(),
                            data.size_bytes());
            }
            break;
        }
        case Op::DmaData: {
            const u32 ctl = at(0);
            const u32 src_sel = (ctl >> 29) & 3, dst_sel = (ctl >> 20) & 3;
            const u64 src = at(1) | (u64(at(2)) << 32);
            const u64 dst = at(3) | (u64(at(4)) << 32);
            const u32 bytes = at(5) & 0x1FFFFF;
            if (dst_sel == 0) {
                FlushSurfaces(dst, dst + bytes);
            }
            if (src_sel == 0) {
                FlushSurfaces(src, src + bytes);
            }
            u8* dptr = dst_sel == 1 ? gds.data() + (at(3) % gds.size())
                                    : reinterpret_cast<u8*>(uintptr_t(dst));
            if (dst_sel == 1 && (at(3) % gds.size()) + bytes > gds.size()) {
                Fail("DMA_DATA past the end of GDS");
            }
            if (src_sel == 1 && (at(1) % gds.size()) + bytes > gds.size()) {
                Fail("DMA_DATA source past the end of GDS");   // was an unchecked heap over-read
            }
            if (src_sel == 2) { // fill with a constant dword
                for (u32 k = 0; k + 4 <= bytes; k += 4) {
                    std::memcpy(dptr + k, &b[1], 4);
                }
            } else {
                const u8* sptr = src_sel == 1 ? gds.data() + (at(1) % gds.size())
                                              : reinterpret_cast<const u8*>(uintptr_t(src));
                std::memmove(dptr, sptr, bytes);
            }
            break;
        }
        case Op::WaitRegMem: {
            const u32 fn = at(0) & 7;
            const bool mem = (at(0) >> 4) & 1;
            const u32 v = mem ? Read32((at(1) & ~3u) | (u64(at(2)) << 32))
                              : regs.reg_array[at(1) & 0xFFFF];
            const u32 val = v & at(4), ref = at(3);
            const bool ok = fn == 0 || (fn == 1 && val < ref) || (fn == 2 && val <= ref) ||
                            (fn == 3 && val == ref) || (fn == 4 && val != ref) ||
                            (fn == 5 && val >= ref) || (fn == 6 && val > ref);
            if (!ok) {
                // Single submission, nothing else runs concurrently: report and go on.
                ++stats.waits_unsatisfied;
            }
            break;
        }
        case Op::IndirectBuffer:
        case Op::IndirectBufferConst: {
            if (op == Op::IndirectBufferConst) { // constant-engine stream: not modelled
                break;
            }
            // 40-bit GPU VA: only addr_hi[7:0] is meaningful. Sony's driver
            // builds the kernel submit array in place and leaves stale bits
            // above them (and above size[19:0]).
            const u64 addr = (at(0) & ~3u) | (u64(at(1) & 0xFF) << 32);
            const u32 size = at(2) & 0xFFFFF;
            Run(std::span<const u32>(reinterpret_cast<const u32*>(uintptr_t(addr)), size));
            break;
        }
        default:
            Skipped(u32(op));
            break;
        }
    }
};

std::unique_ptr<Processor> g_cp;

Processor& Cp() {
    if (!g_cp) {
        g_cp = std::make_unique<Processor>();
    }
    return *g_cp;
}

} // namespace
} // namespace psemu

using namespace psemu;

extern "C" GNM_API void gnm_pm4_reset(void) {
    std::lock_guard lk{DeviceMutex()};
    try {
        ReleaseSurfaces();
    } catch (...) {
    }
    g_cp.reset();
}

extern "C" GNM_API int gnm_submit(const uint32_t* dcb, uint32_t dwords, GnmSubmitStats* stats,
                                  char* err, int errlen) {
    std::lock_guard lk{DeviceMutex()};
    SehGuard seh;
    auto& cp = Cp();
    cp.stats = {};
    cp.first_error.clear();
    cp.depth = 0;
    int rc = 0;
    try {
        cp.Run(std::span<const u32>(dcb, dwords));
    } catch (const std::exception& e) {
        cp.Error(e.what());
        rc = 1; // malformed stream: processing stopped here
    }
    // Resident render targets go back to guest memory before the CPU runs.
    try {
        ReleaseSurfaces();
    } catch (const std::exception& e) {
        cp.Error(std::string("render target write-back failed: ") + e.what());
        rc = 1;
    }
    if (stats) {
        *stats = cp.stats;
    }
    SetError(err, errlen, cp.first_error);
    return rc;
}

extern "C" GNM_API int gnm_read_reg(uint32_t index, uint32_t* value) {
    std::lock_guard lk{DeviceMutex()};
    if (index >= AmdGpu::Regs::NumRegs || !value) {
        return 1;
    }
    *value = Cp().regs.reg_array[index];
    return 0;
}
