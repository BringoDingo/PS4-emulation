# psemu — roadmap to "boot into the main menu"

This is an honest assessment of what stands between where psemu is now and a
rendered PS4 home screen, written after reaching the boot chain's dynamic
boundary.

## Where we are

psemu runs **static** PS4 firmware modules end-to-end on a sandboxed Unicorn
CPU:

```
mini-syscore.elf  --launched, manu_cert, execve-->  SceSysAvControl.elf  --launched, idle in kevent loop-->
```

That covers a real CPU, an AVX software shim, FreeBSD/ORBIS syscalls, a thread
control block, libthr mutex fixups (auto-detected per module), a device/fd
model, `execve` chain-loading, and an event loop. See `README.md`.

## The wall: everything toward the menu is dynamically linked

`python -m psemu.modinfo --dir <firmware>` triages the tree. The result:

| Runnable now (static `ET_EXEC`) | Needs a dynamic loader (`SCE_DYNAMIC`) |
|---|---|
| mini-syscore, SceSysAvControl, safemode | SceSysCore, **SceShellCore**, GnmCompositor, orbis_audiod, the UI, … |

`SceShellCore.elf` (the shell backend — the menu's logic) is `SCE_DYNAMIC`,
interp `/libexec/ld-elf.so.1`, and imports **42 shared libraries**:
`libkernel.prx`, `libSceLibcInternal.prx` (libc itself), `libSceVideoOut.prx`
(display), `libScePad.prx` (controller), `libSceSystemService.prx`, networking,
PSN, codecs, … None of its own code can run until those symbols are resolved.

## What reaching the menu actually requires

Three layers psemu does not have, each a substantial project:

1. **ORBIS dynamic linker + shared libraries.**
   Implement `ld-elf.so.1`'s job: load the module at a base, parse the SCE
   dynamic tables, load each `.prx`/`.sprx`, resolve imports (SCE uses hashed
   symbol *NIDs*, not names), and apply relocations. The `.sprx` system
   libraries are mostly **encrypted (SELF)** in retail firmware, so in practice
   you **HLE** them — reimplement each library's exported functions in Python
   (hundreds of them: libc, pthread, VideoOut, Pad, SysService, …) rather than
   run Sony's code. This alone is the bulk of an "run a dynamic PS4 app" effort.

2. **GPU + display.**
   The menu is *rendered*. That means emulating the GNM graphics driver
   (`libSceGnmDriver`), the command processor, and enough of the AMD GCN GPU to
   produce frames, plus `libSceVideoOut`/GnmCompositor to present them to a
   surface. This is the single largest piece and the reason even mature PS4
   emulator projects do not show a home screen.

3. **Multi-process + IPC.**
   SceShellCore is one process among many. It talks to SceSysCore, the UI
   renderer (`UIProcess.self`, itself encrypted), audiod, etc. over Sony IPC
   (`libSceIpmi`, mailboxes, shared memory). The menu is the *emergent* result
   of that whole system running together.

Put plainly: a rendered main menu is out of reach for a CPU-only, single-process
HLE scaffold. It's a different and very large project (GPU emulation especially),
not a few more syscalls.

## Progress update

- **The `.sprx` libraries are already decrypted** in this tree (all 401 are plain
  ELF), so the HLE-every-function burden is gone — real library code can be run.
- **SCE dynamic linker built** (`psemu.dynld`): loads a module's full DT_NEEDED
  graph from the lib dirs, builds a NID->address export map, and resolves the
  RELA/JMPREL relocations by NID. On `fs_cleaner.elf`: 10 modules loaded, 5,415
  exported NIDs, **1,690/1,700 symbol relocs resolved (99.4%)** + 1,431 RELATIVE.
- **Host GPU detection** (`psemu.gpu`): reports the card + a VRAM budget
  reserving 30% for the host.
- **GCN shaders run on the host GPU** (`psemu.gnm`): shadPS4's shader
  recompiler (GPL-2.0-or-later, vendored in `gnm/native/third_party`, builds
  with MSVC) turns firmware GCN code into SPIR-V; a Vulkan runner draws with
  it. NPXS20118's YUV->RGB shaders render correctly on an RX 580, and 87.6% of
  the firmware's 1,615 unique shaders recompile.

### GPU next steps (in order)

1. ~~**PM4 command processor**~~ - done (`gnm/native/src/gnm_pm4.cpp`).
   Still to add: pipeline/resource caching, RectList, depth targets.
2. **Fetch shaders**: build the vertex-input layout so attribute-driven vertex
   shaders run (55 firmware VS need it).
3. **Tiled textures**: detile GNM tile modes on upload.
4. **Present**: show the colour target in a window (swapchain) and hook it to
   `libSceVideoOut` flips once dynamic modules execute.
5. **Hook the CPU side**: route `sceGnmSubmitCommandBuffers` (GnmCompositor,
   video players) from psemu's emulated CPU into `gnm_submit`, mapping the
   guest arena into Unicorn at the same addresses.

### Update: dynamic execution works up to the device drivers

GnmCompositor (16 modules + ~25 loaded at run time) now executes: libkernel
runs as the interpreter on psemu's dynlib syscalls, every library initialiser
runs, libSceGnmDriver opens `/dev/gc`, and the compositor's own main reaches
VideoOut, which stops at `/dev/dce` (display controller) ioctls. Next:

1. `/dev/dce`: the multiplexed ioctl `0xc0308203` ({u32 cmd, u64 arg,
   u64* out1, u64* out2}); command 9 returns an mmap offset/size, 0x1f
   configures state. Model enough of the display engine for VideoOut to open.
2. `/dev/gc`: queue setup ioctls (`0xc00c8110`, `0xc0848119`, `0xc008811b`,
   `0xc010810b`) and the submit path -> `gnm_submit` (memory is already
   shared: guest pointers are host pointers), `gc_eop` events back.

### Update: the drivers are in - GnmCompositor renders frames

`devices.py` models `/dev/gc`, `/dev/dce` and `/dev/dmemN`; kqueue now
delivers events (GPU EOP interrupts, VideoOut flip/vblank, user events);
`virtual_query`, `get_authinfo` and `MAP_FIXED` are real. GnmCompositor opens
the display, registers its scanout buffers and runs its frame loop: every frame
is a firmware command buffer executed on the host GPU, flipped and saved with
`--frames`. Bugs found on the way: int syscall arguments carried garbage in
the upper 32 bits (kqueue fds), Sony's submit array leaves stale bits above
IB `addr_hi[7:0]`, the stack guard `MAP_FIXED` landed elsewhere (libthr then
failed `pthread_create` with EAGAIN).

Tiled surfaces: done (`gnm_tiling.cpp`, CPU port of shadPS4's `tiling.comp`;
`backend.tile/detile/tiling_info` for tools). 23/24 compositor draws per frame
now run; the remaining one is a RectList.

RectList/QuadList: done (tessellation patches + recompiler aux TCS/TES).

Fetch shaders: done (vertex inputs from the parsed fetch shader). All 24
compositor draws run; its debug text overlay renders.
Caching: done where it mattered - host-cached staging, resident render targets
per submit, coalesced MAP_FIXED: 5.5 s -> 40 ms GPU time per frame.

Depth/stencil: done (`depth-test`); HTILE, depth bounds, MSAA depth still open.

Threads + blocking waits: done (`threads.py`, `sys_sync.py`; virtual clock).

Faster CPU: done (native per-instruction hook + native VEX execution,
`native/`; GnmCompositor 30 M instructions 105 s -> 32 s; deterministic runs).
Semaphores: done (549-556), plus vfork-style `rfork(RFPROC|RFMEM)` so both
sides of mini-syscore's spawn handshake run.

### Update: GPU submit profiled and the allocator fixed

`--gpu-profile` logs per-phase executor time. Profiling the compositor
(25 draws/submit, ~38 ms) overturned the assumption above: the shader
recompile (`translate` ~0.2 ms/draw) and pipeline creation (`pipeline` 1 ms)
are cheap. The cost was **per-draw Vulkan memory allocation** (`bind` 8 ms +
`targets` 8 ms of `vkAllocateMemory`/`vkFreeMemory`) and **per-draw
submit-and-wait** (each of the 25 draws submits one command buffer and blocks
on a fence - `gpu` phase).

Fixed the allocation half: `NewBuffer`/`NewImage` now bump-allocate from a few
large persistent `VkDeviceMemory` blocks (`g_pools` in `gnm_vulkan.cpp`),
bucketed by (memory type, buffer-vs-image) and reset per draw in `~Frame`.
Same buffers, same bytes, same copies - only the backing memory is pooled -
so output is byte-identical. The `bind` phase went 8 ms -> 0; submit median
38 -> 29 ms; the 30 M-instruction compositor run 32 s -> 24.7 s. Verified:
all 11 sampled frames identical to the reference, `cs-test`/`depth-test` pass.

### Update: draws are batched into one submit

The per-draw fence stall is gone. Consecutive graphics draws of one
`gnm_submit()` now record into a single command buffer and run with one queue
submit + fence wait (`Batch`/`BeginBatch`/`FlushBatch` in `gnm_vulkan.cpp`),
instead of a submit-and-wait per draw. Each draw keeps its Vulkan resources in
its own heap `Frame`, retained until the fence signals; CPU work that needs the
GPU result (guest write-backs, read-backs) is deferred to the flush. Resident
targets already persist on the GPU across a submit's draws, so nothing
round-trips through guest memory between them. The batch is flushed only when a
later step needs those results in memory: a resident surface write-back, a draw
that writes guest memory through a UAV, a compute dispatch, or submit end. For
the compositor that is **25 draws in 1 submit** (was 25), and the `gpu` phase
drops 7 ms -> 1 ms; an A/B on the same machine shows the submit median falling
~36 ms -> ~32 ms. Frames stay byte-identical and `cs-test`/`depth-test` pass.

One sharp edge: the memory pool (above) may be reset **only at a submit
boundary**, when the GPU is idle - several draws of one submit keep their pooled
scratch live at once, so recycling it per draw corrupts the batch.

Next: the largest remaining GPU cost is `targets` (~8 ms) - FlushRange/detile
data movement, which needs dirty-tracking to cut safely. Also: devices the
AV/system threads poll (`/dev/hdmi`, `/dev/mbus_av`); thread priorities; the
remaining `/dev/gc` queries (`0xc00c8110`, `0xc0848119`, `0xc010810b`).

A dump of the console's 5.05 kernel would pin down exact syscall layouts/error
codes, but every dump attempted so far is truncated (the dumper crashes the
console mid-read; see `D:\Ps4Tools\ps4kernel\analysis\FINDINGS.md`), so the
inferred `syscalls.csv` stays the source.

### Update: SceShellCore (the menu's backend) boots and initialises

`python -m psemu.run system/vsh/SceShellCore.elf` now runs the shell backend —
the process that holds the home-menu logic. The SCE dynamic linker maps all
**51 modules** of its graph, relocates them, and execution reaches the shell's
own startup: libSceGnmDriver comes up (`**** Base Mode ****`), then SceShellCore
creates an **IPMI** (Sony IPC) client for each system service it talks to.

Those services (SceNpManager, SceLncService, SceShellCoreUtil, SceVideoCoreServer,
…) are *separate processes* psemu does not run, so there is nobody to answer.
Modelling `ipmimgr_call` (syscall 622) to hand back a valid client handle on
`CreateClient` (cmd 2; args `{u64 client; u64 *service_name; u64 params}`) — and
report success for the other ops — unblocked the entire init: the run goes from
~640 to ~32k log lines. SceShellCore then runs `ShellCoreMain`, spawns a
**14-thread** pool, and brings up its subsystems (AppMgr, UserService, PafJob,
ModuleLoader, SQLite, the libc heap — `[Heap] sanity OK, free 96%`), with no
crashes, stopping only at the instruction budget mid-initialisation.

This is the multi-process/IPC frontier from the sections above, now reached in
practice. What remains toward a rendered menu, in rough order:

1. **IPMI method calls with real answers.** CreateClient succeeding is step one;
   the shell then *connects* and *invokes methods* on each service and will
   eventually block waiting for replies. Each service's responses have to be
   HLE'd (or the services themselves run as processes).
2. **The services as processes / HLE.** SceSysCore, the launch/app managers, the
   user service, NP, etc. — the state the menu reads (users, apps, settings).
3. **The UI render + present.** SceShellCore drives `libSceComposite` / the UI
   process to draw; routing those GPU submits through the working `gnm_submit`
   path and presenting is the last mile (the GPU backend already renders frames).

### Immediate next step (old)

Execute the linked image: map all loaded modules into the Unicorn CPU at their
bases, set up per-module TLS, run each library's `module_start` init in
dependency order, then the module entry — reusing psemu's syscall/AVX/HLE/TCB
layers. `fs_cleaner` (2 direct libs, no GPU) is the proof target.

## A realistic next milestone (not the menu, but real progress)

The tractable frontier that actually moves toward the shell is a **minimal SCE
dynamic loader with HLE'd core libraries**:

1. Load a `SCE_DYNAMIC` module at a base; parse its import NID tables.
2. Resolve imports against a Python **HLE library table** keyed by NID: start
   with `libkernel` + `libSceLibcInternal` (malloc, string, stdio, pthread) —
   the same services psemu already fakes as syscalls, now exposed as resolvable
   functions.
3. Apply relocations; jump to the module entry.
4. A small dynamic module (e.g. `fs_cleaner.elf`, 2 libs; `SceVencProxy`, 2
   libs) is the right first target — few imports, no GPU.

That gets psemu running *dynamically-linked* firmware code for the first time,
and each HLE'd library is reusable by every later module. The GPU and
multi-process layers remain prerequisites for the menu itself.

## Tools added for this

- `python -m psemu.modinfo <file>` — classify one module, list its libraries.
- `python -m psemu.modinfo --dir <tree>` — triage a whole firmware tree
  (RUN = static/runnable, DYN = needs the loader above).
