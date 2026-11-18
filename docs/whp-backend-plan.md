# Plan: a hardware-virtualized CPU backend (Windows Hypervisor Platform)

Status: IMPLEMENTED (see `psemu/whp_uc.py`, run with `--backend whp --max-seconds N`; results at the end of this file). Original design notes follow. Written while profiling the ShellUI boot showed
the CPU layer is the next big cost after the GPU path.

## Why

psemu runs guest code under Unicorn (QEMU TCG) with a native per-instruction hook. Sampling the
main thread over a 2B-instruction window (`docs/shellui-boot/tools/cpu_sampler.py`):

| where | share |
|---|---|
| Unicorn/QEMU (translator, helpers, hook dispatch) | 45 % |
| Python (syscalls, scheduler, glue) | 22 % + 2 % ctypes |
| psemu's native hook + native VEX emulation | 19 % |
| **translated guest code (the PS4 program itself)** | **7 %** |

The guest is a PS4 x86-64 program and the host is x86-64, so a hardware-virtualized guest would
run that program at native speed, with no per-instruction hook and no AVX/VEX emulation at all.
Later in the boot (after ~3B instructions, compositor looping) the GPU path takes ~55-60 % of
CPU time, so this has to be paired with GPU-path work to pay off fully.

## What you need to enable (host)

The host is Windows 10 Home 19045 on an **AMD Ryzen 5 3600** (SLAT/NPT present):

1. BIOS: enable **SVM Mode** (AMD-V; often under Advanced > CPU Configuration).
2. Windows: Turn Windows features on or off > tick **Windows Hypervisor Platform**
   (and **Virtual Machine Platform** if offered), reboot.
3. Check: `WHvGetCapability(HypervisorPresent)` must return 1 (it returns 0 today; the probe is in
   the notes below). Side effect: Windows then runs as a root partition under Hyper-V; other
   hypervisors (older VirtualBox/VMware modes) may conflict.

## Design

Guest runs in a WHP partition. psemu's Python HLE (syscalls, IPMI, devices, GPU, scheduler) stays
on the host and is entered through VM exits. The guest has no OS: psemu builds the page tables,
GDT/IDT and a tiny ring-0 stub, so the PS4 ring-3 code believes it is on a normal long-mode CPU.

* **Memory.** guest physical = host virtual (identity), mapped with `WHvMapGpaRange` straight
  from the host buffers psemu already allocates (`hostvm.py`). Guest page tables (built by psemu)
  map guest VA -> that GPA with the PS4 protections (RW/RX/NX), which also removes the
  "write-only becomes RW" hack. GPU backend code that reads guest memory by host pointer keeps working.
* **Syscalls.** `EFER.SCE` + `LSTAR` point at a stub that does `out`/`hlt` (a VM exit); the host
  reads RAX/RDI/RSI/..., runs the existing `SyscallDispatcher`, writes RAX/RFLAGS, resumes at the
  stub's `sysretq`. A WHP exit costs a few microseconds; the 3B-instruction profile has ~0.9M syscalls.
  **96 % of syscalls are uncontended `umtx` mutex lock/unlock**: those can be done entirely inside
  the guest stub (about 20 instructions, no exit) once the current thread id sits in a known guest
  memory slot (single vCPU: the host updates it on every thread switch).
* **HLE function hooks** (`hle.register(..., replace|fixup|guard)`): patch the entry with `int3`,
  take the breakpoint exit, run the Python handler; for fixup/guard restore the byte, single-step
  (TF -> #DB exit) and re-arm. Replaces the per-instruction trap table; no page scanning.
* **AVX/VEX, F16C, BMI.** native. Set CR4.OSXSAVE and XCR0 (x87|SSE|AVX) at vCPU setup.
  `native/vex.c`, `avx_ops.py`, `avx_shim.py` and the VEX page scanner become unnecessary on this backend
  (the Zen 2 host is a superset of the PS4's Jaguar ISA).
* **Faults.** exception-exit bitmap for #PF/#UD/#DB/#BP/#GP. A #PF exit is turned into the existing
  `deliver_signal` path (SIGSEGV -> Mono's NullReferenceException) by editing registers and resuming.
* **Threads / scheduler.** Phase 1: one vCPU, cooperative as today (switch on syscall/block), plus a
  host timer calling `WHvCancelRunVirtualProcessor` for preemption slices (replaces the instruction-count
  slice). Context switch = save/restore the vCPU register state. Phase 2 (optional): one vCPU per
  guest thread for real parallelism; needs a thread-safe syscall layer.
* **Time.** `rdtsc`/`rdtscp` read the hardware TSC; psemu reports the host TSC frequency through the
  `machdep.tsc_freq` sysctl. The virtual clock for sleeps/timeouts becomes wall-clock based (skipping
  ahead while every thread sleeps, as now).

## What changes for the project

* **Determinism is lost.** Today runs are byte-identical because the clock is the instruction count.
  Keep the Unicorn backend as the reference/debug backend and compare syscall traces between backends
  (differential testing). That is the main cost of this change.
* Everything the HLE layer does stays: IPMI, devices, vfs, registry, compositor, GPU backend.
* Expected effect: guest execution goes from ~35-45 % of wall time to a few percent. An 8B-instruction
  boot (20 min now) would be bounded by Python syscall handling and the GPU path, plausibly
  5-8 min before GPU work and ~2-3 min after it.

## Work that does not need virtualization (can start now)

1. **CpuBackend interface.** The Unicorn surface psemu uses is narrow: ~72 `mem_read`, ~109 `mem_write`,
   ~43 `reg_read`, ~49 `reg_write`, 7 `hook_add`, 6 `context_save`/3 `context_restore`, 2 `emu_start`.
   Introduce `CpuBackend` (mem/reg access, run-until-event, context save/restore, hook registration) with a
   `UnicornBackend` that changes nothing, so a `WhpBackend` can be dropped in later.
2. **Direct host-pointer memory access** for host-backed guest memory (it is identity-mapped), which is
   also faster under Unicorn.
3. **WHP ctypes binding + a hello-guest test** (`mov eax,1; hlt`), runnable the moment the hypervisor is up.
4. **Page-table builder, GDT/IDT and the syscall/umtx stub** as pure, offline-testable functions.
5. **GPU path** (independent of CPU backend): texture/buffer upload caching keyed by content hash, avoiding
   per-command-buffer re-upload + detile, and per-flip 8 MB copies. This is ~55-60 % of steady-state time.

## Reference

ChonkyStation4 (GPL-3.0, **reference only**, no code copied) runs PS4 games natively on the host CPU with
a code patcher for `fs:` TLS reads and host function pointers written into GOT slots. Our case differs: we run
the real libkernel and Mono, which use raw `syscall` and `fs:` everywhere, so hardware virtualization is the
safer way to get native speed.

Hypervisor probe used (read-only): `WinHvPlatform.dll` `WHvGetCapability(0 = HypervisorPresent)`.


## Results (2026-11-18, Ryzen 5 3600, Windows 10 19045)

`psemu/whp_uc.py` (`WhpUc`) is a Unicorn-compatible CPU object on a WHP partition; the Emulator
selects it with `--backend whp`. Self-test: `python -m psemu.tools_whp_uc_test` (syscall exit, HLE
replace/fixup traps, #PF -> unmapped/write-prot hooks, `int n`, TLB flush on unmap, FS base,
context save/restore, memory above 2^43).

ShellUI (NPXS20001) boot, same firmware, same command line apart from the backend:

| backend | time to the EvalBase stall state |
|---|---|
| Unicorn + native AVX hook, GPU caches | 12.9 min (8B instructions) |
| WHP | about 15 s |

"Stall state" = the BootManager waits on exactly the same flag set (0x400, 0x8000000 x2,
0x40000000000, 0x100000000000), 4 compositor flips, same IPMI services busy. At 240 s the WHP run is
still in that state (4.67M syscalls, 1.42M thread switches), i.e. the earlier finding stands: nothing
new initializes past it. WHP run created 101 threads against 117 for Unicorn (not yet explained).

Facts learned while building it (probed, not documented):
* Partition exception-exit bitmap accepts only vectors 0,1,3,4,5,6,7,8,10-14,16-19.
* XCR0 is register 0x27 (Dr0-3 = 0x21-0x24, Dr6 0x25, Dr7 0x26).
* WHP accepts GPAs anywhere (tested to 2^48), partial/overlapping unmaps and remaps.
* Do not switch threads mid single-step: TF travels with the saved context.
* Virtual time is wall-clock; runs are not deterministic. The Unicorn backend stays the reference.
