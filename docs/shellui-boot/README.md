# ShellUI (NPXS20001) boot investigation

Notes, derived logs and analysis tools from running the PS4 5.05 system UI under psemu
(2026-11). Everything here was produced by psemu or by reading the metadata of a
firmware dump you supply yourself. **No firmware, shader binaries, command-buffer
dumps or rendered frames are included** (they derive from Sony's software).

## State at 8B emulated instructions

* The GPU path works: 22,500 compositor command buffers -> 37,379 draws, 0 failed, 7,459
  skipped (draws that write nothing). See `logs/gpu_totals_8B_run.txt`.
* The compositor only ever receives the same six shaders in a repeating 5-draw pattern
  (the home background wave mesh and a few fixed layers). 19 of 20 dumped frames are
  byte-identical (the dark-blue background). **No menu content is ever submitted.**
* The app made no `/dev/gc` submits of its own: the UI is not drawing anything yet.

## Why: the boot pipeline has not left step 1

`BootManager` (ShellUI.AppMain) evaluates 21 steps in order (`logs/boot_flags.txt`).
Background-init threads (`BackgroundInit*`, started by `ProcessBackgroundInit`) wait on
flags that the steps set:

| waiter (thread state at end of 8B run) | waits for | set by |
|---|---|---|
| `BackgroundInitDaemons` | 0x400 ("BasePlugin loaded") | callback of step 2 `EvalBase` |
| `BackgroundInitBackgroundAutoLogin` | 0x100000000000 | step 13 `EvalSystemPasscodeInput` |
| `BackgroundInitResetSurfaceRect`, `RemotePlayProhibitionController` | 0x8000000 | `BackgroundInitDaemons`, after 0x400 and 0x80000 |

Step 1, `EvalBGLayer`, loads the background layer plugin **synchronously on the main
thread**. Every main-thread stack taken (`logs/stacks_*`) is inside that load or its
theme/skin loading (`BGScene.OnLoading -> BackgroundLayer.Start -> BGLayerNative.Initialize`,
`SkinRegistory..cctor`, reflection `MakeGenericType`). The main thread is busy (35-97 %
CPU in every 250M window, `logs/cpu_per_thread_3B.txt`), so it is slow or looping rather
than blocked; the later steps (and with them the home menu) never run.

## IPMI

At the end of the 8B run 14 threads were held in IPMI (`logs/threads_at_end_of_8B_run.txt`):
5 client event-flag waits (SceVideoCoreServer - satisfied every 16.7 ms by the stand-in,
SceLncService x2 = app/controller focus threads, SceBgft, SceImeService) and 9
`ipmi_receive` waits that look like servers ShellUI hosts itself, idle because nothing
connects. 45 distinct methods across ~25 services get an "empty success" answer
(`logs/ipmi_first_200_events.txt`; only 200 events are logged, i.e. early boot only).

## Tools (`tools/`)

Run from a psemu checkout with a firmware dump at `D:\Ps4Tools\ps4kernel\firmware`
(edit the paths at the top of the scripts):

* `boot_flags.py` - decode the boot step order and flag dependencies from app.exe's CIL.
* `cil_app.py` / `cil_callers.py` / `cil_scan.py` - minimal ECMA-335 metadata reader:
  find methods, callers (also cross-assembly), call sequences.
* `shellui_stacks.py N` - run N instructions, then print every thread's managed stack.
* `thread_cpu.py`, `main_hot.py` - per-thread CPU share per 250M-instruction window.
* `survey_dcbs.py DIR`, `pm4_dump.py FILE` - summarise / decode saved PM4 command buffers.
* `aotsym.py` - resolve addresses in Mono AOT images to managed method names.

## Speed: native AVX (2026-11)

The 8B-instruction ShellUI boot spent much of its time in the Python AVX emulation:
~47M executions of `vpermilps` (34.9M), `vpermilpd` (3.1M) and `vcvtps2ph` (9.3M), mostly in
the native background-layer spline code. Those ops now run in C (`psemu/native/vex.c`;
`vcvtps2ph` uses the host F16C instruction).

| run (same 8B instructions, same code otherwise) | wall time | Python-emulated AVX |
|---|---|---|
| before | 74.9 min | ~47M executions |
| after  | 20.6 min | 168 executions (`vcvtpd2ps`, `vcvtps2pd`) |

The run is behaviourally identical: same instruction count, final rip, thread/switch counts and
GPU totals (22,500 compositor buffers, 37,379 draws, 0 failed). The 1.6B-instruction window that
contains the spline loop went 589 s -> 95 s (log byte-identical apart from the two AVX counter
lines). Correctness: bit-for-bit against the host CPU, 13,612 firmware-harvested executions
(`tools_vexhw`) plus 26,880 synthetic ones covering every vcvtps2ph form (`tools_vexhw_synth`),
0 mismatches. The "before" time comes from the old log's file timestamps and overlapped
other jobs for part of the run, so the true speedup may be slightly under 3.6x.

## Next

Find out where the main thread is at 4-8B instructions (stack dumps at 4B/6B were running
when this was written) and whether `PluginManager.Load` of the BGLayer plugin is making
progress or spinning on something psemu does not provide.


## Update 2026-11-18: WHP backend, and the stall moved

Run on the WHP backend (`--backend whp`, see `docs/whp-backend-plan.md`) the boot reaches its stall in
~15 s, so experiments are cheap. Findings:

* **A WHP-port bug had been masking the real state.** `thr_get_ucontext` read the target thread's
  registers through Unicorn's `UcContext.reg_read`; the WHP context lacked it, so Mono's stop-the-world
  saw all-zero contexts and spun on suspend/get/resume (769k `thr_resume_ucontext` in 240 s) while the
  main thread sat in a Mono sleep loop. `WhpContext` (whp_uc.py) fixed it.
* **With that fixed the main thread is no longer in EvalBGLayer or hung**: it runs
  `BootManager.Evaluate` -> EvalBase (all six `BootHelper.Boot` plugins + the Base plugin are requested),
  `BasePlugin.OnLoading/OnLoaded` run, and the main thread enters the normal frame loop
  (`Application.Run -> UISystem.Update -> FrameTask.Update`, `UIRenderer.End -> SwapBuffers`).
  Event flags set by the boot steps: 0x800000 0x400000000000 0x2000000 0x1000000 0x2000 0x200000
  0x100000 0x10000000 0x4000000 0x20 0x40 0x200 0x1000000000 ... 0x80000000000.
* **What still never happens:** `PluginManager.ProcessLoaded` runs for BGLayer + the six Boot plugins
  (7 calls) but not for the Base plugin, so its Loaded callback `BootManager.<EvalBase>b__e`
  (ClearInitialPowerLock + SetEventFlag 0x400) never fires, and `BackgroundInitDaemons` /
  `BackgroundInitResetSurfaceRect` keep waiting on 0x400 / 0x8000000. A ninth `BootHelper.Boot`
  plugin load (after Base) also never reaches ProcessLoaded. The open question is why the Base
  scene's Loaded action (`SceneManager.UpdateSceneAction`+0x26b -> `<LoadInternal>b__2`) is not
  dispatched although `BasePlugin.OnLoaded` ran.
* Exceptions seen in 40 s: ProfileCache `UnauthorizedAccessException` (FileStream, user image files),
  `KeyNotFoundException` in `QuickMenuPlugin.OnLoading -> CxmlLoader.GetResource` (resource not loaded),
  `GlsConfigFile.Parse` `ArgumentNullException`. None is inside BasePlugin.OnLoaded.

New tools (WHP backend, frame-pointer based, run in 20-60 s): `fp_stacks.py` (live stacks, `all`),
`fp_timeline.py` (sample one thread's stack over time), `trace_methods.py` (int3-trace named managed
methods with args / call chains, any assembly via `MODULE=`), `bootmgr_evf.py` (BootManager event
flag sets with time). `shellui_stacks.py` also accepts `20s` for WHP.
