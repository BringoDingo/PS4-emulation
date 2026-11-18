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


### Why Base never reports Loaded (2026-11-18, later the same day)

Chain established with the WHP tools:

1. `SceneManager.UpdateSceneAction` processes ONE queued scene action per call and retries the head of
   the queue until its `UpdateLoadAction` finishes. The head is `QuickMenuPlugin` (159 retries in 22 s,
   `stuck_scene.py`); the Base plugin's Loaded dispatch (and the ninth plugin) sit behind it.
2. QuickMenu waits in `ResourceManager.IsResourceLoaded` (`CxmlLoader.GetResource` -> KeyNotFound each
   frame) for `CxmlLoader.RegisterResourceFileAsync`. That only *enqueues* a `CxmlLoadRequestJob`;
   `JobQueue.Check()` (called from the main thread's frame loop) hands queued jobs to worker threads. 23
   Cxml requests were enqueued but only 10 ever ran (`trace_methods.py`).
3. The main frame loop crawls (17 `UpdateSceneLifeCycle` in 25 s). Time accounting (`WhpUc.t_run`, cProfile):
   of 40 s wall only ~3 s is guest execution and ~5 s syscall handlers; ~11 s per 27 s is the software
   compositor (`on_frame` -> `_run_dcb`, ~14 ms per 60 Hz frame). WHP virtual time follows wall time, so
   the guest was starved by our own renderer. Now GPU time is excluded from the WHP virtual clock
   (`Emulator._excl`); this did not by itself unblock the boot.
4. When the main thread stalls it is blocked in `_umtx_op(MUTEX_LOCK)` on a libkernel-resident umutex
   (0x1010e4630, word = owner tid | contested) whose owner is a worker running Mono managed code
   (`GlsConvertUtil..cctor` / `ThemeColorManager..cctor`): READY, not suspended, scheduled only a handful
   of times in 8 s (`stuck_lock.py`), while 1-5 other threads wait on the same lock. Not an EDEADLK, and
   every thread's curthread->tid matches its scheduler tid (TLS is consistent). Open: why the owner is so
   rarely run (it has not been reproduced on demand; roughly one run in two shows it).

Tools added: `stuck_scene.py`, `stuck_lock.py`, `rip_hist.py` (unbiased guest rip profile from the
preemption exits), `syscall_time.py`.

## Update 2026-11-18 (later): the EvalBase stall is fixed - it was a kevent bug

The Base plugin never reported Loaded because QuickMenu's load task waited on boot flag
`0x40000000000`, which only `BootManager.<StartInitializeVisionEngine>b__33` sets, after
`VisionRecognitionUtil.InitializeVisionEngine()` returns. That call never returned.

Chain (found with `vision_sys.py`, `native_trace.py`, `disasm_mem.py`):

1. `libSceVisionManager` creates two equeues (0x33, 0x34) and a worker thread
   (`libSceVisionManager+0x287c0`). It sends the worker a request with
   `sceKernelAddUserEvent(eq33, 0)` + `sceKernelTriggerUserEvent(eq33, 0, &msg)` and then waits on
   eq34 for the reply. `msg` is a request block (type 0, path `/app0/recognition/vision/dict/`).
2. On the kernel side a registration change updates the existing knote's `udata`
   (`kn->kn_kevent.udata = kev->udata`). `Syscalls.sys_kevent` stored `udata` only at `EV_ADD`, so
   the worker received `udata = NULL`, took its "no message" exit path, deleted the event and
   `thr_exit`ed without replying. The init thread then waited forever on an empty queue.
3. Fix (`syscalls.py`, `sys_kevent`): an `EVFILT_USER` change with `NOTE_TRIGGER` copies the
   change's `udata` onto the knote before the event is raised.

Result on WHP: `0x40000000000` is set at ~11.8 s and `0x400` (Base loaded) at ~13-15 s; the shell
draws a real screen ("Rebuilding database..." with a progress bar, the system software's
database-recovery UI) through the compositor. The remaining BootManager waiters are the later boot
steps (`0x80000`, `0x8000000`, `0x100000000000`).

Two measurement notes worth keeping:
* never patch an `int3` over a `call` instruction of Mono AOT code: the PLT resolver re-reads the
  call bytes (`aot-runtime.c: condition 'plt_entry' not met`); hook method entries only;
* the compositor service (`ring.service`) was 25 of 45 s of wall time (mean 37 ms/frame, 100 ms+
  once the scene is large). It is excluded from the guest clock but is the main cost of a run.

New tools: `ready_wait.py`, `frame_cost.py`, `disasm_method.py`, `disasm_mem.py`, `find_imm.py`,
`catch_hit.py`, `vision_sys.py`, `native_trace.py`, `kq_dump.py`, `main_syscalls.py`.

## Update 2026-11-18 (later): past EvalBase, the shell runs its DB-recovery path

With the kevent fix the boot now reaches `0x400` (Base loaded) and the shell loads `DbRecoveryPlugin`,
which draws the system "Rebuilding database..." screen. It never leaves that screen. Diagnosis chain
(`dbstatus.py`, `vision_sys.py HOOK=`, `disasm_mem.py`, `vfs_dump.py`, `path_watch.py`,
`missing_opens.py`):

1. Early in boot (~6 s) the app-DB layer opens `/priv/mms/app.db`, finds nothing valid, writes the
   markers `app.db-corrupt` and `/system_data/priv/mms/dbr.db-err`, and requests recovery.
2. `BootManager.EvalDBRecovery` -> `ExecDBRecovery` loads `DbRecoveryPlugin`. Its `OnLoaded` calls
   `DbPreparationWrapper.CexDbRecoveryStart` (returns 0 = ok); `OnUpdateFrame` then polls
   `CexDbRecoveryGetStatus(out finished, out error, out progress, out stage)` every frame.
3. `CexDbRecoveryGetStatus` is a P/Invoke into native code statically linked in `eboot.bin`
   (`+0x5c5390`) that reads a status structure. That structure is only advanced by the
   `SceDbPreparationServer` daemon - which psemu answers as an **empty-success IPMI stub**. So the
   status never changes: `finished=0, error=0, progress=0.0, stage=-1` for the whole run (confirmed
   stable over 110 s with `dbstatus.py`).

So the shell is not stuck on a lock or a scheduler problem here - it is correctly waiting for a
database service that does no real work. This is the concrete case of "the IPMI stubs cannot
reproduce complete service interactions": `SceDbPreparationServer` + `SceAppDbIpc` need either a real
app-database implementation (the no-tricks fix) or a modelled recovery that signals completion.

Also fixed this session (working copy, uncommitted): `sys_open` now returns ENOENT for a file that
is absent and not being created, instead of a permissive empty fd whose writes were silently
dropped. Verified it does not regress the boot (flags still reach `0x400`) nor the SceSysCore->ShellUI
`--then` chain (runs clean to budget, exit 0). It does not by itself prevent the corruption verdict,
because the fresh-DB creation path also goes through the stub app-DB service.

## Update 2026-11-18 (later): DB provisioning - voice DB fixed, app.db scoped

The "database corrupt -> rebuild" verdict comes from the content engine (statically linked in
eboot.bin) on a worker thread, purely file-side (no daemon call). Several user-data databases the
firmware does not ship are provisioned on first boot from a read-only master/template; with no
provisioning they are opened O_RDWR (no O_CREAT), fail, and are declared corrupt.

`syscalls.py` now stands in for that first-boot provisioning in `_vfile` (`_DB_SEED`):
- `/priv/nui_data/voice/voice_gnd_gametitle.db` <- firmware master `master_voice_gnd_gametitle.db`
  (and the systemcommand variant). **This clears that DB's corruption flag** - confirmed: the
  `DbCorruptionOccured ... voice_gnd_gametitle.db` line is gone.
- `/priv/mms/app.db` is the *application* database (not the photo/video content DB). Its schema is
  compiled into eboot.bin - `tbl_version`, `tbl_appinfo`, `tbl_cmdfunc` ("CREATE TABLE IF NOT
  EXISTS"), validated with `SELECT count(*) FROM sqlite_master WHERE name='tbl_version'`. psemu now
  generates a correct app.db with the host `sqlite3` from that exact DDL ("@app_db").

app.db still ends up flagged corrupt, but the cause is **not** the file: empty / full-schema /
schema-with-version-row all give the same `[AppDb] InitClient()[444]: DbAccessor::Init() :
80f50044`. So `DbAccessor::Init` fails for a reason independent of app.db's contents (an app-DB
client-init step, error family 0x80f500xx), which is the next thing to reverse. The provisioning is
kept because it is correct (the engine expects app.db to exist with this schema) and is needed once
Init is resolved.

Tools added: `appdb_init.py` (AppDb client's syscalls around DbAccessor::Init), `who_corrupt.py`
(native stack of the corruption-marker writer).

## Update 2026-11-18 (night): app.db accepted - the shell passes the DB check and draws its home screen

The whole app.db blocker was **missing `tbl_version` rows**, not the SQLite engine (so no SQLite shim
was needed). How it was found (tools `xref.py`, `sdis.py`, `sqltrace.py`, `peek.py`):

* Static analysis had been failing because of an address bug: the eboot's code/rodata LOAD segment
  maps file offset 0x4000 -> vaddr 0, so `vaddr = 0x100000000 + file_off - 0x4000`.
* The engine's SQLite wrapper (prepare 0x2d1700 / step 0x2d7800 / column 0x2d80d0) succeeded on
  every query, so `0x80f50044` was not a SQLite error. It came from the version check in
  `DbAccessor::Init` (0x23a5d0): the function `0x23b4f0` fills a version struct from `tbl_version`
  rows by category (`appver`->[0], `locale`->[4], `region`->[8], `appinfokeyver`->[0xc],
  `appinfover`->[0x10], `appbrowsever`->[0x14]); an unset category stays -1 and is rejected.
* The engine's expected versions (read at runtime) are 68 / 1 / 0 / 5 / 1 / 23. The provisioned
  app.db now carries exactly those rows (`_APP_DB_VERSIONS`), after which
  `[AppDb] DbAccessor::Init() : 0`, no corruption marker, no recovery plugin: BootManager sets
  0x80000 immediately and the flag set grows to include auto-login and all the layer scenes.

Boot now reaches the real home-screen chrome (function-area icon row, user, clock, and a genuine
"Less than 1.00 GB free in system storage" notification); the content area is empty (no installed
titles in the app DB).

New stub-service fallout, fixed: with boot further along, `SceAutoMounterIpc.method0x30023`
(out=[64,4]) is called. An empty reply zero-filled the full *declared* 64 bytes, but the client's
real buffer is smaller, so it smashed the stack canary (guest abort in the stack-check tail).
`IPMI_EMPTY_ZERO_CAP` now caps how much of a declared out buffer an empty reply may touch for that
method. (A real server writes only what it returns; the declared size is a capacity.)

## Update 2026-11-18 (night, later): ChangeRunLevel completion - boot flag 0x8000000

After the app.db fix the only boot-flag wait still unsatisfied was `0x8000000` (set by
`BackgroundInitDaemons`; `ResetSurfaceRect` and the remote-play controller wait on it).
`BackgroundInitDaemons` calls `ShellCoreUtilWrapper.ChangeRunLevel`, which blocks in
`sceSystemService` on an IPMI **event flag of SceShellCoreUtil** - ShellCore signals it when the
run-level change completes. psemu's stub never did, so the thread parked forever.
`SceShellCoreUtil` is now in `IPMI_EVF_SATISFY` (same model as SceAvSettingIpc: the service answers
the request by signalling its event flag). `0x8000000` is then set (~18.7 s), followed by
`0x20000000`; the wait fires once (no spin). Every boot flag the shell waits on is now set.

The home screen shows the function-area row, user, clock and a system notification; the content
area is empty. Next: what stubbed service / data (installed titles in tbl_appinfo, SceLncService,
SceAppContent...) populates the content row.

## Update 2026-11-18 (night, later still): the app catalogue - tbl_appinfo / tbl_appbrowse_<uid>

`psemu/appdb.py` (+ `sfo.py`, a param.sfo reader) now provisions the shell's application database
the way the app-install / DB-preparation services would: version rows, `tbl_appinfo`, and the
per-user tables from the engine's own DDL, with one entry per firmware app that has a
`sce_sys/param.sfo` (43 titles: the browser, library, TV & Video, media player, ...).

Findings that made this possible (tools `sqltrace.py`, `bindwatch.py`, `xref.py`, `sdis.py`):
* `tbl_appinfo.key` holds key **names** from the engine's pool (`_title_id`, `TITLE`, `CONTENT_ID`,
  `_metadata_path`, `PARENTAL_LEVEL`, `CATEGORY`, `#_contents_status`, ...; `#` = integer-valued),
  not numbers: SQLite's dynamic typing allows text in the declared-INT column.
* Per-user tables are named with the user id as `%010d` (`tbl_appbrowse_0268435457`,
  `tbl_addon_0268435457`, `tbl_info_0268435457`); their DDL is a string in the engine
  (49-column `tbl_appbrowse`). The engine checks the table with `sqlite_master`, then per title
  runs `SELECT count(*) FROM tbl_appinfo WHERE titleId=?` - with no appinfo rows it never reads
  the browse table at all.
* The shell asks for a fixed set of system titles by id (NPXS20102/04/05/09/10/11/17/18/32/33,
  CUSA02012) with `GetItemByTitleId`, then `SELECT key, val FROM tbl_appinfo WHERE titleId=?`.
* `/common/mms/av_content.db` (media content) was missing and flagged corrupt, which the content
  area depends on; it is now provisioned from the firmware's `template_content.db`.

State: no DB errors or corruption flags remain; the ghosting on the status bar is gone. The
ContentsList is created, creates its `AppBrowseItemIteratorFactory` item source, but
`ContentsList.OnItemSourceUpdated` never fires, so no tiles are drawn yet. Next: find what the
item source (Sce.Vsh.Lx) waits for - candidate values to check are the browse-row fields the
engine filters on (`contentType`, `contentStatus`, `dispLocation`, `folderType`), which the DB
daemon normally computes at install time (not derivable from param.sfo alone).
