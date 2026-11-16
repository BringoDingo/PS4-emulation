# Multi-process + shared IPMI design

Status: **design + scaffold (phase 1).** psemu today runs one PS4 process at a
time (one `unicorn.Uc`, one address space, one `SyscallDispatcher`, one thread
`Scheduler`). Booting the actual system menu needs several cooperating
processes running concurrently and talking over IPMI:

```
mini-syscore -> SceSysAvControl   (AV/HDMI, already works via execve chain-load)
SceSysCore    hosts SceSysCoreApp / SceSysCoreApp2 (AppMgr) + spawns daemons
SceShellCore  its LnC/AppMgr launches apps; talks to SceSysCore over IPMI
NPXS20001     the UI app (Mono/.NET: app.exe.sprx embeds mono_jit + Sce.Vsh.*)
```

The UI only renders once the Mono runtime inside `app.exe.sprx` runs the managed
`Sce.Vsh.*` assemblies and draws through the compositor -> GPU. So multi-process
is necessary but **not sufficient**; the Mono/Paf runtime is a separate large
piece tracked elsewhere.

## Why one process isn't enough

SceSysCore and SceShellCore are separate processes that cooperate over IPMI:
SceSysCore hosts `SceSysCoreApp`(kid 0x102)/`SceSysCoreApp2`(kid 0x103); running
either one alone, the other side's IPMI endpoints are absent, so each stalls
waiting on `ipmi_receive`/`kevent` (confirmed: SceShellCore idles post-init
waiting for a launch request; SceSysCore idles serving, waiting for requests).

## Architecture

1. **Process** — encapsulate the per-process state currently spread across
   `Emulator`: its `Uc`, address space (`hostvm`/`vm`), loaded module set
   (`dynproc`), thread `Scheduler`, and the per-process part of
   `SyscallDispatcher` (fd table, local handles). Shared, cross-process state
   (below) moves to a `System` object every Process points at.

2. **ProcessManager / scheduler** — round-robins Processes, running each for a
   small instruction budget (reuse the existing per-thread time-slice). Requires
   making the `Emulator.run()` while-body *steppable*: extract one iteration
   (emu_start + native-stop + thread-switch + exec/stop handling) into
   `_run_segment() -> status`, so the manager can interleave Processes. run()
   becomes a thin loop over `_run_segment()` for the single-process case
   (behaviour-preserving; this is the first risky refactor and must keep the
   static-boot + SceShellCore regressions green).

3. **Spawn** — `sys_execve` from an rfork'd `spawn_child` currently either
   chain-loads (replace) or, with `--spawn-mode stay`, retires the child
   (threads.py `exit_current`). Add a third outcome: *create a new Process* in
   the manager for the child image and keep the parent Process running. The
   `--spawn-mode` policy selects follow (replace) / stay (retire) / spawn (new
   Process) / a path substring.

4. **Shared system state (`System`)** — the objects that are kernel-global and
   must be visible to every Process:
   - **IPMI bus** (`IpmiBus`, see `ipmibus.py`): servers register by name
     (`create server`, cmd 0x0) with the Process that hosts them; clients
     (`create client` 0x2, `connect` 0x400) resolve to that server; `invoke`
     (0x320) delivers the request to the server Process's receive queue and
     blocks the caller until the server replies; `receive` (0x201) pops the
     next packet for a server. This replaces the current single-process HLE in
     `syscalls.py sys_ipmimgr_call`, which fakes replies because no real server
     exists - with a real SceSysCore Process, SceShellCore's invokes route to it.
   - **Named objects** (semaphores, event flags, shm) are already modelled as
     process-external stand-ins in the `0x2000xxxxxxx` region; make them live on
     `System` keyed by name so two Processes share one object.
   - **Shared memory**: separate `Uc` instances have separate memory. Back
     cross-process regions (shm, IPMI transfer buffers) with a single host
     buffer mapped into every Process's `Uc` at the same guest address via
     `uc_mem_map_ptr` (hostvm already host-backs guest memory - extend it to
     hand out a shared host pointer for `System`-owned regions).

## Incremental plan

- **P1 (this commit):** this design + `ipmibus.py` scaffold (bus data model +
  routing logic, standalone, no behaviour change). Regressions unchanged.
- **P2:** extract `Emulator._run_segment()`; prove single-process run() is a
  loop over it (regressions green). Add a trivial `ProcessManager` that drives
  one Process through it (still single-process).
- **P3:** `Process` abstraction; run two Processes (SceSysCore + a stub) under
  the manager, each its own `Uc`, time-sliced. No IPMI yet.
- **P4:** shared host memory for `System` regions; move named objects to
  `System`; wire `IpmiBus` so an invoke in one Process is served by another.
- **P5:** spawn policy creates Processes; boot SceSysCore which spawns
  SceShellCore; route their IPMI so SceShellCore's LnC reaches SceSysCore AppMgr.
- **(separate track)** Mono/.NET runtime for the UI app + Paf + compositor.

## Risks / invariants

- The static boot (mini-syscore -> SceSysAvControl, `set_mode done`) and the
  SceShellCore boot-to-WORKING must stay green at every step; they exercise the
  run loop, execve chain-load, threads, and IPMI HLE that P2-P4 refactor.
- Determinism (same run twice byte-identical) must hold; the cross-Process
  scheduler must be deterministic (fixed round-robin + fixed slice sizes).
