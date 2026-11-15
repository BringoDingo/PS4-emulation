# psemu native GNM backend

Runs PS4 GPU shaders on a Windows GPU. GCN machine code from the firmware is
recompiled to SPIR-V by **shadPS4's shader recompiler** and executed through
**Vulkan 1.3**. Python drives it through a small C API (`gnm_native.dll`,
wrapped by `psemu/gnm/backend.py`).

## Licence

This directory links GPL-2.0-or-later code from shadPS4
(`third_party/shadps4`, see `PSEMU_NOTES.md`). `gnm_native.dll`, and anything
distributed together with it, must therefore be distributed under
GPL-2.0-or-later. psemu's own files here (`src/`, `shim/`, `build.py`) are
GPL-2.0-or-later too.

## Build

Needs Visual Studio 2022 with the C++ workload (MSVC 14.42+, Windows SDK) and
the shadPS4 checkout with its `sirit`, `ext-boost`, `fmt`, `magic_enum` and
`vulkan-headers` submodules (default location: `..\..\..\psemu_deps\shadPS4`).

```bash
python psemu/gnm/native/build.py                 # release -> build/release/gnm_native.dll
python psemu/gnm/native/build.py --debug
python psemu/gnm/native/build.py --deps D:/somewhere/shadPS4/externals
```

The first build compiles ~120 files (a few minutes); later builds only rebuild
what changed. No CMake needed.

## Use

```bash
python -m psemu.gnm translate path/to/shader.sb        # GCN -> SPIR-V, prints resources used
python -m psemu.gnm scan                                # recompile every shader in the firmware
python -m psemu.gnm yuv --out out.png                   # run NPXS20118's YUV shaders on the GPU
python -m psemu.gnm yuv --pm4 --out out.png             # same draw through a PM4 command buffer
python -m psemu.gnm cs-test                             # firmware compute shaders via DISPATCH_DIRECT
```

## PM4 command processor (`src/gnm_pm4.cpp`)

`gnm_submit(dcb, dwords, &stats, err, errlen)` walks a GNM command buffer and
keeps the GPU register file (shadPS4's `AmdGpu::Regs` layout) across calls,
like a real graphics queue; `gnm_pm4_reset()` starts over.

| Packets | Handling |
|---|---|
| `SET_SH_REG`, `SET_CONTEXT_REG`, `SET_UCONFIG_REG`, `SET_CONFIG_REG`, type-0 | register writes |
| `CLEAR_STATE`, `CONTEXT_CONTROL`, `INDEX_TYPE`, `INDEX_BASE`, `INDEX_BUFFER_SIZE`, `NUM_INSTANCES` | state |
| `DRAW_INDEX_AUTO`, `DRAW_INDEX_2`, `DRAW_INDEX_OFFSET_2` | graphics job on Vulkan (VS+PS, up to 8 colour targets, blending, indexed draws) |
| `DISPATCH_DIRECT` | compute job on Vulkan |
| `EVENT_WRITE_EOP`, `EVENT_WRITE_EOS`, `RELEASE_MEM`, `WRITE_DATA`, `DMA_DATA` | write guest memory (fences, fills, copies, GDS) |
| `WAIT_REG_MEM` | evaluated; unsatisfied waits are counted |
| `INDIRECT_BUFFER` | nested call (depth 8) |
| sync/cache packets (`ACQUIRE_MEM`, `SURFACE_SYNC`, `EVENT_WRITE`, CE counters...) | no-ops |

Colour targets live in guest memory: each draw loads the surface, renders,
and writes it back, so consecutive draws compose like on hardware. Unsupported
draws (tiled targets, RectList, fetch shaders, tessellation) are skipped and
counted in `stats.failed` with the first reason in `err`; the stream continues.

`psemu/gnm/pm4.py` builds command buffers from Python with the same register
writes the GNM driver emits (`set_vs_shader`, `set_ps_shader`, `set_user_data`,
`set_render_target`, `set_viewport`, `draw_index_auto`, `dispatch_direct`,
`event_write_eop`...), and `pm4.decode()` lists the packets of any stream.

## Layout

```
native/
  build.py                  MSVC build driver
  src/gnm_api.h             C API (stable boundary for Python / psemu)
  src/gnm_translate.cpp     GnmShaderDesc -> Shader::Info/RuntimeInfo -> SPIR-V
  src/gnm_vulkan.cpp        headless Vulkan device, resources from V#/T#/S#, graphics/compute jobs
  src/gnm_pm4.cpp           PM4 command processor (register file, draws, dispatches, fences)
  shim/                     psemu stand-ins for emulator-only shadPS4 headers
  third_party/shadps4/      vendored GPL sources (+ COPYING, PSEMU_NOTES.md)
```

## Memory model

Guest GPU addresses are host addresses. Whatever builds the descriptors
(today `backend.py`, later psemu's CPU emulator) must put real host pointers
into user-data SGPRs, V#/T#/S# and resource tables. Because PS4 GPU addresses
are 40-bit (and several registers store them shifted into 32 bits), guest
memory must sit below 1 TB: `backend.GuestArena` reserves it with
`VirtualAlloc` at 64 GB. Texture/target bases must be 256-byte aligned.
Buffers and storage images the shader writes are copied back after the job.

## Current limits

- Every draw/dispatch builds and destroys its Vulkan objects (no pipeline or
  resource caches yet), and render targets round-trip through guest memory.
- Only linear (tile mode 8) 2D textures; tiled textures need the detiler next.
- Vertex shaders that use a GNM fetch shader (vertex attributes) are not wired up.
- No depth/stencil targets; scissor registers are not applied yet.
- RectList/QuadList primitives (used by GNM for clears/blits) are not emulated yet.
- Tessellation (LS/HS) and geometry pipelines are not wired up.
