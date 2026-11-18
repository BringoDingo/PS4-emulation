// SPDX-License-Identifier: GPL-2.0-or-later
// psemu native GNM backend: plain C API (called from Python through ctypes).
//
// PS4 shaders are translated to SPIR-V by shadPS4's shader recompiler and run
// on the host GPU through Vulkan. All guest pointers (inside user-data SGPRs,
// V#/T#/S# descriptors and resource tables) are host pointers: the caller maps
// guest memory into this process and writes real addresses into descriptors.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GNM_API __declspec(dllexport)

// Shader stages use the PS4 hardware numbering (same as the OrbShdr footer).
enum { GNM_STAGE_PS = 0, GNM_STAGE_VS = 1, GNM_STAGE_GS = 2, GNM_STAGE_ES = 3,
       GNM_STAGE_HS = 4, GNM_STAGE_LS = 5, GNM_STAGE_CS = 6 };

typedef struct GnmShaderDesc {
    uint32_t stage;
    uint32_t code_dwords;      // shader length from the OrbShdr footer, in dwords
    const uint32_t* code;      // 4-byte aligned; starts at the s_mov_b32 vcc_hi marker.
                               // Keep the whole containing blob alive: pc-relative
                               // tables after the code are read through this pointer.
    uint64_t hash;             // any stable id (footer hash); used in logs only
    uint32_t rsrc1, rsrc2;     // SPI_SHADER_PGM_RSRC1/2
    uint32_t user_data[16];    // user SGPR values s0..s15
    // pixel shader registers
    uint32_t ps_input_ena, ps_input_addr;
    uint32_t num_interp;       // SPI_PS_IN_CONTROL.NUM_INTERP
    uint32_t col_format;       // SPI_SHADER_COL_FORMAT
    uint32_t z_format;         // SPI_SHADER_Z_FORMAT
    // vertex shader registers
    uint32_t vs_out_cntl;      // PA_CL_VS_OUT_CNTL (misc/clip outputs)
} GnmShaderDesc;

// AMD primitive types (VGT_PRIMITIVE_TYPE)
enum { GNM_PRIM_POINTLIST = 1, GNM_PRIM_LINELIST = 2, GNM_PRIM_LINESTRIP = 3,
       GNM_PRIM_TRILIST = 4, GNM_PRIM_TRIFAN = 5, GNM_PRIM_TRISTRIP = 6,
       // screen-aligned rectangles (3 corners, the 4th implied) and quads:
       // drawn as tessellation patches with recompiler-generated TCS/TES
       GNM_PRIM_RECTLIST = 0x11, GNM_PRIM_QUADLIST = 0x13 };

typedef struct GnmDrawDesc {
    GnmShaderDesc vs;
    GnmShaderDesc ps;
    uint32_t prim_type;
    uint32_t vertex_count;
    uint32_t instance_count;   // 0 means 1
    uint32_t width, height;    // render target (RGBA8 unorm) size
    // PA_CL_VPORT_* values; PS4 viewports flip Y with a negative yscale.
    float vp_xscale, vp_xoffset, vp_yscale, vp_yoffset;
    float clear_color[4];
} GnmDrawDesc;

// Returns 0 on success. Messages go to err (NUL-terminated, truncated to errlen).
GNM_API int gnm_init(char* err, int errlen);
GNM_API void gnm_shutdown(void);
GNM_API int gnm_device_name(char* out, int cap);
GNM_API void gnm_set_log_level(int level); // 0 trace .. 5 critical, default 3

// Translate one shader to SPIR-V (no GPU needed). spirv may be NULL to query
// the size. summary receives a short text report of resources the shader uses.
GNM_API int gnm_translate(const GnmShaderDesc* sh, uint32_t* spirv, uint32_t spirv_cap,
                          uint32_t* spirv_words, char* summary, int summary_cap, char* err,
                          int errlen);

// Draw once into a fresh render target and read it back as RGBA8 (width*height*4).
GNM_API int gnm_draw(const GnmDrawDesc* draw, uint8_t* rgba_out, char* err, int errlen);

// ---- PM4 command processor -------------------------------------------------
// The GPU register file persists across submissions (like a real queue) until
// gnm_pm4_reset(). Render targets, textures, buffers, fences and indirect
// buffers referenced by the stream are host pointers.

typedef struct GnmSubmitStats {
    uint32_t packets;              // PM4 packets walked (including indirect buffers)
    uint32_t draws;                // draws executed on the GPU
    uint32_t dispatches;           // compute dispatches executed
    uint32_t failed;               // draws/dispatches that could not run (see err)
    uint32_t skipped_packets;      // packets with opcodes not handled yet
    uint32_t first_skipped_opcode;
    uint32_t fences;               // EOP/EOS/RELEASE_MEM memory writes
    uint32_t waits_unsatisfied;    // WAIT_REG_MEM conditions that were false
    uint32_t interrupts;           // EOP/RELEASE_MEM packets that request a CPU interrupt
                                   //   (int_sel != 0): the kernel raises an EOP event
} GnmSubmitStats;

GNM_API void gnm_pm4_reset(void);
// Returns 0 when the whole stream was walked (individual draw failures are
// counted in stats->failed with the first message in err); 1 when the stream
// itself is malformed and processing stopped.
GNM_API int gnm_submit(const uint32_t* dcb, uint32_t dwords, GnmSubmitStats* stats, char* err,
                       int errlen);
// Read one register (dword index into the 0xD000-entry register file).
GNM_API int gnm_read_reg(uint32_t index, uint32_t* value);

// Accumulated per-phase time of graphics jobs as "draws=N translate=Xms ...";
// reset != 0 clears the counters after reading.
GNM_API int gnm_profile(char* out, int outlen, int reset);

// Lazy write-back of guest render targets: while on, a colour surface is not retiled into guest
// memory at the end of a submit; the host watches its pages (events from gnm_watch_events:
// {addr, size, op} u64 triples, op 1 = watch / 0 = unwatch) and calls gnm_flush_range when the CPU
// touches them.
GNM_API void gnm_set_lazy_writeback(int on);
GNM_API int gnm_watch_events(uint64_t* out, int cap);

// GCN surface tiling (CPU). mode = Gnm tile-mode index (CB_COLOR_ATTRIB /
// T# tiling_index), pitch/height in pixels (or 4x4 blocks). direction > 0
// tiles linear `src` (rows of `pitch` pixels) into `dst`; <= 0 detiles.
// src/dst may be null to only query the tiled size and padded extent.
GNM_API int gnm_tiling(uint32_t mode, uint32_t bytes_per_pixel, uint32_t pitch, uint32_t height,
                       int direction, const void* src, void* dst, uint64_t* tiled_bytes,
                       uint32_t* padded_pitch, uint32_t* padded_height, char* err, int errlen);

#ifdef __cplusplus
}
#endif
