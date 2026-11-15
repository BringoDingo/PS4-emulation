# psemu — a PS4 (FreeBSD/ORBIS x86-64) ELF emulator scaffold

Runs a PS4 system module (e.g. `mini-syscore.elf`) in a **sandboxed Unicorn
CPU** on Windows x64. The module's own x86-64 instructions execute inside
Unicorn (isolated from the host); the FreeBSD/SCE `syscall` instructions it
makes are trapped and emulated in Python.

This is a **starting scaffold**, not a complete emulator. It gets the module
booting through its C-runtime / libc / pthread initialization and shows exactly
which kernel services it reaches for, so they can be filled in one at a time.

## Install

```bash
pip install unicorn capstone
```

## Run

```bash
python -m psemu.run path/to/mini-syscore.elf
python -m psemu.run mini-syscore.elf --max 5000000        # instruction budget
python -m psemu.run mini-syscore.elf --trace              # every insn + syscall
python -m psemu.run mini-syscore.elf --start 0x400080     # custom start address
python -m psemu.run mini-syscore.elf --fw-root DIR        # where to resolve execve() paths
python -m psemu.run mini-syscore.elf --max-modules 8      # chain-load cap
```

On `execve`, the emulator resolves the target (e.g. `/SceSysAvControl.elf`)
against `--fw-root` (default: the first module's directory, searched
recursively) and chain-loads it. Run untrusted firmware through a trusted
checkout (pass the ELF as an argument; don't run the interpreter from the
firmware's own directory).

## What works today

| Area | Status |
|------|--------|
| ELF64 parse + segment mapping (incl. SCE segment types) | ✅ |
| Stack, **FreeBSD Variant II TCB + `struct pthread` curthread**, `%fs` base | ✅ |
| `syscall` trap → FreeBSD/Sony dispatch table | ✅ |
| Real syscalls: `write`, `mmap`/`munmap`/`mprotect`, `sysctl` (`kern.usrstack`, `kern.arnd`, `hw.ncpu`…), `exit`, `clock_gettime`, `getpid` … | ✅ |
| **AVX software shim** (VEX ops the stock Unicorn wheel can't decode) | ✅ |
| **HLE function hooks** (replace *or* fix-up an internal function) | ✅ |
| **libthr mutex** — past the owned-list panic (HLE fixup at lock entry) | ✅ |
| **File-descriptor table** — `open`/`close`/`dup`/`dup2`/`rdup`, high-base device fds | ✅ |
| **Device/fd bring-up** — module reaches `launched` and runs its own logic | ✅ |
| **`execve` chain-loading** — load the next module in a fresh address space | ✅ |
| **Per-module libthr HLE auto-detection** (works on any libkernel module) | ✅ |
| AVX lane ops (`vinsertf128`/`vextractf128`/`vperm2f128`) | ✅ |
| **Event loop** — `kqueue`/`kevent`, idle-event-loop detection | ✅ |
| Sony kernel objects: `namedobj_create` (named handles), `get_authinfo` | ✅ basic |
| Fault diagnostics: register dump, stack backtrace, clean abort messages | ✅ |
| **Host-backed guest memory**: every guest page is host memory at the same address (`hostvm.py`) | ✅ |
| **Dynamically linked processes**: kernel-style loader + `dynlib_*` syscalls, libkernel runs as the interpreter (`dynproc.py`, `sys_dynlib.py`) | ✅ |
| **Runtime module loading** (`sceKernelLoadStartModule` / `dynlib_load_prx`) | ✅ |
| **VEX 3-operand SSE/AVX executed correctly** (QEMU silently mis-runs them; `avx_ops.py`) | ✅ |
| **Device drivers** (`devices.py`): `/dev/gc` submits run on the host GPU, `/dev/dce` flips + display events, `/dev/dmem` allocator, `virtual_query` | ✅ |
| **kqueue events**: registrations, GPU EOP interrupts, VideoOut flip/vblank, `EVFILT_USER` | ✅ |
| **Threads** (`threads.py`): `thr_new`/`thr_exit`/`thr_self`, preemptive time slices on the one emulated CPU (context save/restore) | ✅ |
| **Blocking waits** (`sys_sync.py`): `_umtx_op` (wait/wake, mutex, condvar, rwlock, usem), event flags 538-546, kevent and `nanosleep` sleep on a virtual clock | ✅ |
| Semaphores 549-556, thread priorities, `/dev/hdmi` & other polled devices | ⛔ next |
| Event sourcing (inject A/V events) / multi-process system | ⛔ next frontier |

The emulator now **chain-loads the PS4 boot sequence across modules**:

```
== module #0: mini-syscore.elf ==
  libthr hooks: fatal=0x42e4a0, mutex-lock entries=[0x4159e0, 0x440240, 0x440bc0, 0x440ed7]
  [SceSysCore mini] launched ; *** start manu_cert ***
  [execve] '/SceSysAvControl.elf'
== module #1: SceSysAvControl.elf ==            <- loaded into a fresh CPU
  libthr hooks: fatal=0x44c4c0, mutex-lock entries=[0x41eca0, 0x445d50, ...]
  [SceSysAvControl] launched
```

Each `execve` builds a new Unicorn address space and reloads; the kernel-side
state (fd table, handles) is inherited, exactly as real `execve` does. The
libthr HLE hooks are **re-detected per module** by scanning the code (the two
modules have them at different addresses), so the mutex fixup and clean fatal
diagnostics work without hardcoding.

### Terminal state: booted and idle

`sys_363` is `kevent`. After `launched`, SceSysAvControl enters its **main
event-dispatch loop** — `kevent(kq, NULL, 0, events, 8, NULL)` → dispatch →
repeat until a quit flag is set. In an isolated emulation no events ever
arrive (they'd come from other processes and A/V hardware), so the emulator
models `kqueue`/`kevent`, detects the stable empty-wait loop, and stops
cleanly:

```
== module #1: SceSysAvControl.elf ==
  [SceSysAvControl] launched
  [kqueue] -> fd 19
  [kevent] no events after 512 waits -> module is idle in its event loop
== stopped: module booted; idle in event loop (no events to deliver) ==
   ran 2 module(s), 89412 instructions total
```

This is the natural endpoint for a single-process emulation of a boot chain:
both modules load, initialise, launch, and reach their event loops. Going
further means **sourcing events** — a modelled A/V-control / IPC environment
that feeds `kevent` so the dispatch handlers run — or a **multi-process**
system where modules talk to each other. Both are large, separate efforts; the
CPU, syscall, device, fd, TCB, AVX and HLE layers built here all carry over.

### How the mutex panic was cleared

`pthread_mutex_lock` (guest `0x440240`) panicked because a freed mutex still
carried a stale owned-list link (`tqe_prev`, +0x48) — single-threaded `unlock`
goes through the stubbed `_umtx_op`, which skips the kernel dequeue. Rather
than reimplement libthr, a **fixup HLE hook** at the lock entry clears the
stale link and resets `curthread`'s owned-mutex TAILQs (never needed single
-threaded), then lets Sony's real lock code run. Fires ~21× on boot.

### How device/fd bring-up was solved

The module opens `/dev/console`, `dup2`s it onto 0/1/2, then expects a `rdup`
loop to return fds 3, 4, 5. That only holds if the device `open` lands at a
*high* fd (the real kernel starts the process with more than 0/1/2 open),
leaving the low fds free. Modelling `open` with a high base fd and `rdup`/`dup`
with lowest-free made the layout match, and the module launched.

### Milestones reached this session

- Garbage-pointer fault → root-caused to a missing TCB; built a real Variant II
  TCB + `curthread` with initialised mutex TAILQs (`0x44026c: mov r14, fs:[0x10]`).
- `int 0x44` after `kern.usrstack` / `kern.arnd` sysctls → served those MIBs.
- AVX wall at instruction 239 → software VEX shim (now ~1,800 ops emulated).
- Cryptic abort trap → HLE hook on the fatal sink yields the exact source line.
- libthr `'mutex is on list'` panic → fixup HLE hook (now runs all of pthread init).
- `'rdupped fd is not 3'` → real fd table + high-base device opens.
- Module reaches `launched`, runs `manu_cert`, and `execve`s the next stage.
- `execve` → chain-loaded `SceSysAvControl.elf` into a fresh address space; it
  `launched` too, with its libthr HLE hooks auto-detected at its own addresses.
- `kqueue`/`kevent` modelled; both modules reach their idle event loops — a
  clean "booted; idle" end state for the isolated boot chain.

## Architecture

```
psemu/
  loader.py     Elf64: parse header + program headers, map PT_LOAD into Unicorn
  emulator.py   Emulator: CPU setup (AVX CPU model + CR0/CR4), stack/TLS/TCB,
                mmap allocator, Unicorn hooks, per-module libthr hook detection,
                the chain-loading run loop (_build_image / exec_module)
  avx_shim.py   AvxShim: decodes VEX instrs with capstone and emulates them
                against Unicorn's YMM/XMM registers (the stock wheel's TCG
                does not decode AVX)
  hle.py        HleHooks: intercept a function at its entry, run Python, ret
  syscalls.py   SyscallDispatcher: number→name table + per-syscall handlers,
                Sony object/handle table
  modinfo.py    classify a module (static/runnable vs dynamic) + its libraries
  dynld.py      SCE dynamic linker (NID import/export, relocations)
  gpu.py        host GPU detection + VRAM budget
  run.py        CLI
  gnm/          PS4 GPU (GNM) layer - see "GPU: running firmware shaders" below
    isa.py        GCN gen2 (GFX7) decoder + disassembler (Python)
    sb.py         find/parse shaders (.sb files and OrbShdr blobs inside ELFs)
    resources.py  V#/T#/S# descriptor builders, data formats
    backend.py    ctypes wrapper for native/gnm_native.dll
    native/       C++: shadPS4 shader recompiler (GPL-2.0-or-later) + Vulkan runner
```

## Dynamic processes (GnmCompositor)

```bash
python -m psemu.run firmware/system/sys/GnmCompositor.elf --max 30000000 --frames frames
```

psemu now plays the PS4 kernel for dynamically linked executables: it maps the
executable and its 15 libraries into host-backed memory, relocates them, and
starts libkernel as the program interpreter. libkernel's own startup then runs
through psemu's `dynlib_*` syscalls (process params, module lists, module
info, init/fini, `dlsym`, runtime `load_prx`), initialises libc, libthr,
libSceGnmDriver (opens `/dev/gc`, prints `**** Base Mode ****`), and
libSceSysmodule loads ~25 more libraries at run time.

**The compositor runs its frame loop on the host GPU.** VideoOut opens the
display (`/dev/dce`), registers two 1920x1080 scanout buffers, and every frame
GnmCompositor submits a command buffer through `/dev/gc`; psemu hands the
firmware's own submission array (PM4 `INDIRECT_BUFFER` packets pointing into
guest memory) straight to the native PM4 processor, raises the end-of-pipe
interrupt as an equeue event, completes the flip and delivers flip/vblank
events back. `--frames` saves the displayed buffer (detiled) on the first and
every 60th flip.

Tiled surfaces are handled (`gnm/native/src/gnm_tiling.cpp`, a CPU port of
shadPS4's GPL `tiling.comp` address math: 1D/2D/3D/PRT thin and thick modes,
8-128 bpp): render targets are detiled on load and retiled on store, textures
detiled on upload. Every layout round-trips and is a bijection (all 10 common
modes x 5 pixel sizes). With it, 23 of the compositor's 24 draws per frame run.

RectList / QuadList draws run as 3/4-point tessellation patches through the
recompiler's auxiliary TCS (it builds the implied 4th corner and its
interpolants) and a passthrough TES; `python -m psemu.gnm yuv --pm4 --rectlist`
draws the YUV quad as a 3-vertex RectList and matches the triangle-strip render
pixel for pixel.

Fetch shaders: the recompiler parses the fetch shader the VS calls; psemu turns
its attributes into Vulkan vertex inputs (location = semantic, format from the
V#, USCALED/SSCALED kept as float formats), uploads each V# buffer and applies
the fetch shader's vertex/instance offset SGPRs. **All 24 compositor draws per
frame now run, and the frame shows the compositor's own debug text overlay**
(top-left: timing figures) - the first non-blank firmware output.

Speed (GnmCompositor, per frame): 5.5 s -> 40 ms on the GPU side.
- staging buffers use host-*cached* memory (retiling read write-combined
  memory: 5.2 s of the 5.5 s);
- render targets stay resident on the GPU for the whole submit and are
  retiled/written back once at its end (or earlier when a later draw, dispatch,
  DMA_DATA or WRITE_DATA touches that memory); frames are pixel-identical to
  the uncached path;
- `MAP_FIXED` maps whole runs instead of single pages (thousands of 4 KiB
  Unicorn regions had slowed every guest memory access).
Shader translation and pipeline creation measure 5 ms and 1 ms per frame (the
driver's pipeline cache), so they are not cached explicitly yet.
`--gpu-profile` logs per-phase executor time after each submit.

Per-draw scratch (staging/vertex/index buffers, textures) is suballocated from
a few large persistent `VkDeviceMemory` blocks (`g_pools` in `gnm_vulkan.cpp`)
instead of calling `vkAllocateMemory`/`vkFreeMemory` once per resource per draw.
Same resources, same bytes - output is byte-identical - but the per-submit
`bind` phase drops from 8 ms to 0. The pool is recycled only at a submit
boundary (when the GPU is idle), because the draws of one submit keep their
scratch live at once (next paragraph).

The draws of one `gnm_submit()` are **batched**: they record into a single
command buffer and run with one queue submit + fence wait, not one per draw
(`Batch`/`FlushBatch`). Each draw keeps its resources in its own `Frame`,
retained until the fence signals; write-backs/read-backs to guest memory are
deferred to the flush. The batch is cut only where a later step needs those
results - a resident-surface write-back, a UAV-writing draw, a dispatch, or
submit end - so for the compositor all 25 draws run in one submit. The `gpu`
phase falls 7 ms -> 1 ms and the submit median ~36 -> ~32 ms, frames identical.
The largest remaining cost is `targets` (~8 ms): FlushRange/detile data
movement.

Depth/stencil: the DB registers (Z16 / Z32F plane + optional 8-bit stencil
plane, depth tile modes 0-7, DB_DEPTH_CONTROL, DB_STENCIL_CONTROL,
DB_STENCILREFMASK(_BF), DB_RENDER_CONTROL clears, viewport z scale/offset,
GL/DX clip space) map onto a resident Vulkan depth/stencil image (D32F, D16,
D16S8 or D32FS8) that is detiled once per submit and retiled back like colour
targets; depth-only draws (no colour target, optionally no pixel shader) work.
`python -m psemu.gnm depth-test` checks clears, LESS/LEQUAL tests and writes,
stencil REPLACE/EQUAL/NOTEQUAL and a clear + draw inside one submit, in the
guest's tiled planes, for Z32F+S8, Z16+S8, Z16 and Z32F in four tile modes.
Not modelled yet: HTILE (compressed depth metadata), depth bounds, MSAA depth,
stencil ops ONES/AND/OR/XOR, ADD/SUB by op values other than 1.
Found on the way: `Frame` handed out references into `std::vector`s that later
allocations moved (intermittent garbage render targets / access violations).

## Threads and blocking waits

Every `thr_new` thread now runs. psemu has one Unicorn CPU, so threads take
turns: each keeps a saved CPU context (registers, FS base, SSE/AVX state) and
the scheduler (`threads.py`) switches on a 100k-instruction time slice or
when a syscall blocks. Waits really wait (`sys_sync.py`): `_umtx_op` (the
FreeBSD 9 primitive under libthr's mutexes, condition variables, rwlocks,
semaphores and `pthread_join`; kernel-managed locks hand ownership to the
woken thread), Sony event flags (AND/OR, clear modes, single/multi waiter,
cancel, timeouts - semantics from shadPS4's event_flag.cpp), kevent with a
NULL or positive timeout, and `nanosleep`. Time is virtual: 1 ns per executed
instruction, and when every thread sleeps the clock jumps to the next
deadline; `clock_gettime` reports it. Everything blocked with no deadline is
reported as idle-in-event-loop (someone waits in kevent) or a deadlock, with
each thread's wait.

Semaphores (`sceKernel*Sema`, syscalls 549-556) are real too: token counts
with a maximum, waiters asking for `need` tokens in arrival order, timeouts
with the remaining time written back, poll, cancel (ECANCELED, count reset)
and delete (EACCES); semantics from shadPS4's semaphore.cpp, argument layout
from libkernel's wrappers. `python -m psemu.tools_synctest` checks them.
Thread priorities are not modelled (waiters are FIFO).

`rfork(RFPROC|RFMEM)` - the vfork-style spawn mini-syscore uses - now runs
both sides: the child is another thread sharing memory (rdx=1), the parent
gets the child's pid (rdx=0). mini-syscore's parent signals
`SceMiniSysCoreProcSpawnSema`, which the child waits on before it `execve`s
SceSysAvControl; with the old stubs that wait was a no-op, with real
semaphores the child would otherwise deadlock.

One process stands in for the whole system: an event flag a process only
*opens* (e.g. `SceBootStatusFlags`, owned by SceSysCore) is assumed to have
the bits a waiter asks for, as on a booted console; this is logged once per
pattern. Flags the process creates itself keep exact semantics. A semaphore
that is only opened is treated the same way (assumed signalled).

Effects: SceSysAvControl's 5 threads run (it gets to its HDMI checks; one
thread then polls `/dev/hdmi` every 1 ms, which psemu doesn't model, so the
static boot now ends at the instruction limit instead of "idle"); before
blocking waits the same threads spun through 49k `_umtx_op` and 24k event-flag
waits per 2 M instructions. GnmCompositor's event-handler and timer threads
run and its frame loop is unchanged. The scanout buffer itself is tiled (CB tile mode
10, Display2DThin); with no application layers the compositor draws black.

| Device / call | What psemu models |
|---|---|
| `/dev/gc` `0xc0108102` / `0xc020810c` | submit (and submit+flip): IB packet array -> `gnm_submit` |
| `/dev/gc` `0xc008811b` | pointer to the driver status dword (a zeroed shared page) |
| `/dev/dce` `0xc0308203` | multiplexed control: cmd 0 open port, 9 status page offset/size, others acked |
| `/dev/dce` `0xc0308207` / `0xc0308206` | buffer attribute / register scanout buffer |
| `/dev/dce` `0xc0488204` | submit flip -> flip (type 6) + vblank (type 7) events, kevent filter -13 |
| `/dev/dmemN` `0xc0288001` | direct-memory allocator (physical offsets), `0x4008800a` size |
| `/dev/hdmi` `0xc0108d10` / `0xc0088d0c` | HdmiCheckAvailability `{u64 *txtype; u64 *devout}` and GET_HDMI_STATE `{u64 *state}`: report a connected HDMI sink (DevOut and state = 2, the values the firmware tests for), so SceSysAvControl's availability + state polls pass instead of "not available" / "GET_HDMI_STATE failed" |
| `/dev/mbus_av` `read` | AV message-bus events (0x30 bytes). SceSysAvControl waits on this for the HDMI hotplug; we deliver one connected event `{u32 type=9; u32 code=1; …}` then report no-more-events with EAGAIN. That clears "wait for hdmi event" → "hdmi not connected" and the ~1,400 "unknown sz = 0" EOF polls; the firmware then logs `hdmi event connected(1)`, negotiates the link (5.4 Gbps) and runs HdmiSetup/set_mode |
| `/dev/av_control` `0xc0109a0e` | display-clock status `{u32 freq; u32 pad; u64 *out}`: reports the clock locked at the requested frequency (`*out` nonzero), so `av_control_setup_dispclk()` stops timing out (`count=11`). Other ioctls acked |
| syscall 572 `virtual_query` | mapping start/end/phys offset/prot (incl. GPU bits)/direct flag |
| syscall 587 `get_authinfo` | SELF auth info: authority ID + capability words (all-ones caps) |
| `mmap` `MAP_FIXED` | exact placement (libthr stack guard pages) |

Debug helpers: `python -m psemu.tools_break <exe> libSceVideoOut+0x3920 --dump rbx:0x40`
(breakpoints at module offsets with backtraces) and `python -m psemu.tools_re`.

Fixed on the way: wrong SCE segment-type constants (RELRO is `0x61000010`),
a symbol-table overrun that invented 753 bogus exports, `sysarch` (FS base)
and `thr_self` ignored, sysctl lookups by name, and QEMU executing VEX
three-operand SSE as legacy two-operand forms (libc `strncpy` truncated
strings).

## CPU speed: the native hook

psemu used to run a Python callback before every guest instruction (~0.3-0.6
M instructions/s). `native/cpuhook.c` (built into `native/build/psemu_cpu.dll`
by `python psemu/native/build.py`, or automatically on first run) replaces it:
a C `UC_HOOK_CODE` callback that counts instructions (the virtual clock) and
stops the CPU only when Python has work - the instruction budget or a thread's
time slice is used up, an HLE function entry is reached, or a code page runs
for the first time (Python then marks every VEX instruction start on it).

VEX instructions run natively too (`native/vex.c`): Unicorn's QEMU 5 core
has no AVX, so it executes VEX.128 as the legacy two-operand form (ignoring
the extra source) and rejects VEX.256. vex.c decodes each trapped address
once and executes ~130 SSE/AVX/AVX2 forms directly on Unicorn's YMM registers
(moving RIP from inside the hook, so no Python round trip); forms QEMU gets
right are untrapped, the rest go to the Python shim (`avx_shim.py`/
`avx_ops.py`) as before. `rdtsc`/`rdtscp` read the virtual clock (1.6 GHz,
`machdep.tsc_freq`) instead of the host TSC, and `kern.arandom` is seeded,
so runs are deterministic: logs and frames are identical run to run
(`PSEMU_RANDOM=1` for real entropy).

| GnmCompositor, 30 M instructions | before | now |
|---|---|---|
| wall time | 105 s | 24.7 s |
| Python round trips (`emu_start`) | 710 k | 10 k |
| GPU submit median (646 submits) | ~38 ms | ~32 ms (memory pool + draw batching) |

Checks: `python -m psemu.tools_vexhw` runs ~2,000 firmware VEX instructions
on the host CPU (which has AVX2) and through vex.c from identical states -
bit-identical; `python -m psemu.tools_vextest` compares vex.c with the Python
shim. Switches: `PSEMU_PY_HOOK=1` (Python hook, as `--trace` uses),
`PSEMU_NATIVE_VEX=0` (all VEX through Python).

Bug found on the way: the old VEX classifier read VEX.vvvv=1111 as "no extra
source", but that is also how xmm0 is encoded, so e.g. `vsubss xmm2, xmm0,
xmm1` ran in QEMU as `xmm2 - xmm1`. Fixed in both paths; it changes the
compositor's debug-overlay timing readout (the old reference frame showed a
bogus 1065 ms peak). Two-operand VEX.128 moves are still left to QEMU, which
does not clear bits 128-255 of the destination YMM (as before).

## Dynamic linking (experimental)

```bash
python -m psemu.dynld system/sys/fs_cleaner.elf --fw-root path/to/firmware
python -m psemu.gpu          # detected host GPU + VRAM budget
```

`dynld` loads a dynamic module's full `.sprx` dependency graph, builds a
NID->address export map, and resolves its relocations (link stage; execution
integration is the next step). `gpu` reports the card and a 30%-host-reserve
VRAM budget. Rendering lives in `psemu.gnm` (next section).

## GPU: running firmware shaders on the PC

PS4 shaders are AMD GCN machine code. `psemu.gnm` recompiles them to SPIR-V
with shadPS4's shader recompiler (vendored C++, GPL-2.0-or-later) and runs
them through Vulkan on the host GPU. Build once, then:

```bash
python psemu/gnm/native/build.py                    # needs VS 2022 C++ tools
python -m psemu.gnm disasm path/to/shader.sb        # GCN disassembly
python -m psemu.gnm translate path/to/shader.sb     # GCN -> SPIR-V + resource summary
python -m psemu.gnm scan                            # recompile every shader in the firmware
python -m psemu.gnm yuv --out out.png               # run NPXS20118's YUV->RGB shaders on the GPU
python -m psemu.gnm yuv --pm4 --out out.png         # ...driven by a PM4 command buffer
python -m psemu.gnm cs-test                         # firmware compute shaders via DISPATCH_DIRECT
```

Status (firmware 5.05, Radeon RX 580):

- `yuv_vv.sb` + `yuv_p.sb` / `yuv_sd_p.sb` render 1280x720 on the GPU and
  match the source image to within 3/255 away from chroma-subsampling edges
  (PSNR ~37 dB overall).
- 1,415 of the 1,615 unique shaders embedded in the firmware recompile to
  SPIR-V (87.6%; pixel 694/706, compute 684/816, vertex 37/93). Failures:
  vertex shaders needing a runtime-generated fetch shader (55) and dynamic
  descriptor indexing the recompiler does not handle (~140).
- **PM4 command processor**: GNM command buffers (register writes, draws,
  dispatches, indirect buffers, EOP/EOS fences, WRITE_DATA, DMA_DATA) run on
  the GPU. The YUV draw through a command buffer into a guest render target is
  pixel-identical to the direct draw; two firmware compute shaders (bdj.elf
  buffer copy, libSceDepth row sums with a loop) produce correct results.
- Not yet: tiled textures/targets, fetch shaders, RectList, depth, caching,
  presenting to a window. See `gnm/native/README.md`.

Licence note: `gnm/native` links GPL-2.0-or-later code, so `gnm_native.dll`
and anything distributed with it must be distributed under GPL-2.0-or-later.

## Triage which modules can run

```bash
python -m psemu.modinfo path/to/module.elf          # one module + its libs
python -m psemu.modinfo --dir path/to/firmware       # whole tree
```

Static `ET_EXEC` modules (mini-syscore, SceSysAvControl, safemode) run under
psemu. Everything toward the shell/menu (`SceShellCore`, `SceSysCore`,
`GnmCompositor`, the UI) is `SCE_DYNAMIC` — dynamically linked against the PS4
shared-library ecosystem and needing a dynamic linker + GPU. See `ROADMAP.md`
for the honest path and scope.

### HLE hooks

```python
def pthread_mutex_lock(emu, uc):
    mutex = emu.hle.args(uc)[0]      # rdi
    ...                              # do it in Python
    return 0                         # becomes rax; the shim performs `ret`

emu.hle.register(0x440240, pthread_mutex_lock, name="pthread_mutex_lock")
```

Firmware-specific hook addresses live in `Emulator._register_default_hle()`.

## Extending it

- **A new syscall:** add `def sys_<name>(self, uc):` to `SyscallDispatcher`
  and (if needed) its number→name entry in `SYSCALLS`. Read args with
  `self._args(uc)`, return with `self._ret(uc, value, error=False)`.
- **A new AVX instruction:** add `def op_<mnemonic>(self, insn):` to `AvxShim`.
  Unhandled VEX ops are logged with their bytes so you know what to add.
- **Sony kernel objects:** `namedobj_create` and friends currently return 0.
  Give them a handle allocator and back them with Python state to go further.

## Safety / scope

Everything runs inside Unicorn's emulated CPU — the firmware code never runs
with real privileges on the host. This is a reverse-engineering / research
tool for firmware you own; it emulates kernel calls, it does not defeat any
protection.

## Note on file location

Keep these files under `psemu/`. Loose `.py` files dropped in the project root
of this directory get cleared by the surrounding project tooling; the package
subdirectory is stable.
