# ShellUI (NPXS20001) boot investigation

## Current status (read this first; the sections below are a chronological log)

Last updated after the audio start-up fix (builds on commit 7ccee36). The log below is append-only, so earlier sections describe
problems that later sections solved: do not read an intermediate section as the current state.

* **Done:** WHP backend boot to the ShellUI home screen; DB provisioning (app.db / tbl_appinfo /
  tbl_appbrowse_<uid>); **the home-screen content row renders** (22 firmware apps from param.sfo, icons,
  focused tile, title, info panel - the `ContentsList.OnItemSourceUpdated` stall described under
  "where the home-screen content list stops" was fixed in "the home screen draws its content row":
  the list filters on `dispLocation`/`folderType`/`presentBoxStatus`); native GPU abort fixed;
  compositor ~5x faster (direct sampling, parallel tiler, lazy write-back behind a WHP page watch);
  network-listener CPU spin fixed; SceMbusIpc device list + `/dev/hid` model (a DualShock 4 registers and
  `scePadReadState` is polled).
* **Pad-attached stall: fixed** (see "audio start-up: the sched priority range" below): with a pad attached
  (`PSEMU_PAD=none|auto`) the UI keeps rendering (9000 DCBs / 60 s through the SceSysCore -> ShellUI chain,
  exit 0). Audio start-up now completes, libScePsm registers its Bgm library, `/dev/ajm` is on by default.
  `PSEMU_PAD` itself still defaults to off.
* **The home screen now has a user and reacts to the pad.** The "Unknown" name and the ignored controller had
  one cause: nothing answered `SceUserService` 0x30004 (the per-user string call), so the shell had no
  logged-in user name; with "Player1" (placeholder, `PSEMU_USER_NAME` overrides) the top bar and hint bar
  show it and scripted RIGHT/DOWN pulses move the content row. See "the user name" below.
* **CROSS on a tile reaches the launch call and stops in IPMI**: `AppLauncher.Start` -> `LncUtil.LaunchApp` ->
  `libSceSystemService` waits for a free slot of `SceLncAsyncCallSema` (2 slots) and the two async calls
  issued at boot (`SceLncService`, IPMI `cmd 0x241`) never complete, so the slot never frees. With the slot
  forced free (diagnostic only) the call proceeds and waits on the `SceLncService` event flag instead
  (`cmd 0x490`). See "CROSS on a tile" below.
* **Open, in order:** (1) IPMI **async** invoke (`cmd 0x241`) needs real completion (result delivery + the
  per-slot event-flag bit) - then the launch can continue to `SceLncService` launch handling, which
  does not exist yet (no app process is started anywhere); (2) compositor frame spikes of 400-600 ms
  (shader translation misses, texture uploads) cause the `LOST PAD DATA` lines and doubled text/icons in
  captured frames; (3) the name is a placeholder - no real account store (avatar, theme, NP ids);
  (4) no AJM decoding / no audio output; remaining stub IPC services.
* **Constraints:** only GPL-2.0-or-later code may be reused; no firmware is committed.


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

## Update 2026-11-18 (night): where the home-screen content list stops (SUPERSEDED: see "the home screen draws its content row")

Traced following the investigation plan (tools `sqltrace2.py`, `cil_calls.py`, `sqlcore.py`,
`trace_methods.py`). The first expected record is **not** lost in the database:

1. **Title lookups succeed.** `SELECT <49 cols> FROM tbl_appbrowse_<uid> WHERE titleId=?1` returns
   the row with our values for each default title the shell asks for by id. After the shell's own
   `UPDATE ... visible=?9` writes (it hides Share Play and TV & Video itself), 9 of the 11 titles
   are `visible=1`.
2. **The list pipeline runs.** `ContentsList` -> `AccessorItemSource.StartQuery` -> a `QueryJob`
   on a worker -> `AccessorIterator` -> `OnQueryFinished` all execute.
3. **The iterator reports 0 items.** `AccessorIterator.GetCount` returns 0 because
   `EnhancedAppBrowseItemAccessor.GetTotalCount -> AppBrowseItemAccessor.ExecuteCountQuery` (it
   builds a FROM/WHERE clause from the accessor's filter type) returns 0 - in the same
   millisecond, and no filtered count/list statement ever reaches the native `AppDb` SQLite
   wrapper. That query goes through the *managed* `Sce.Vsh.Db.Shared`/`Sce.Vsh.SQLite` layer
   (a separate connection, `//priv/mms/app.db` opened ReadOnly), which the wrapper-level SQL
   tools cannot see. With zero items `ContentsList.OnItemSourceUpdated` has nothing to deliver,
   which is exactly the observed symptom (plan case B: iterator produces zero items).

Note: the engine's own SQL fragment `WHERE visible <> 0 AND ((contentType & ?1) <> 0 OR
(contentType & ?2) <> 0)` ANDs `contentType` against masks, so a NULL `contentType` can never
match; the controlled experiments below vary that one field.

### Controlled experiments (plan priority 3) and result

Fresh emulator process and freshly generated app.db per run, one field changed. `contentType` set
to 0, 1, 2, 4, 8, 65535 (and NULL as the baseline): `AccessorIterator.GetCount` returned **0 in
every run**, including 65535 which satisfies any mask. So the filtered count does not depend on
`contentType` (or on the row data at all); `contentType` is ruled out as the cause. (The 16 run
did not reach the QueryJob inside its 34 s window - WHP timing varies.)

One environment fix came out of this: the engine's orbis SQLite VFS stat()s `//sqlite` for its
temp-file directory and logged `orbisTempFileDir ERROR ... returned 0x2` at every managed open.
`/sqlite` now exists in the virtual filesystem (the error is gone); it did not change the count.

State: stage identified (iterator count query returns 0 before reaching the native SQLite
wrapper, via the managed Sce.Vsh.Db.Shared / Sce.Vsh.SQLite connection). Still to establish
*why* the managed query yields 0: the managed layer reuses a cached connection (ConnectionManager
logs Open ReadOnly x2 then Close key[...app.dbReadOnly]), so a closed/invalid cached connection
is a candidate. The managed SQLite natives (Prepare2Native/StepNative in Sce.Vsh.SQLite) are not
reachable by the wrapper-level tools; hooking them is the next step.

## Update 2026-11-18 (night): the home screen draws its content row

Hooking the managed SQLite calls (`msql.py`: `Sce.Vsh.SQLite.SQLite3.Open/Prepare2/Step/Column*`
and `ConnectionManager`) showed the real list queries, which the native-wrapper tools could not
see. The home content area is fed by:

    select count(*) from tbl_appbrowse_<uid> where (visible = 1) and ((dispLocation & 1) <> 0)
                                              and (parentFolderId IS NULL)
    ... where (visible = 1) and ((dispLocation & 2) <> 0) and (folderType <> 1) order by lastAccessIndex desc
    ... where (visible = 1) and (presentBoxStatus = 0) and (category <> 'pn3' and <> 'pn4')
                                              and (folderType <> 1) order by sortPriority, lastAccessIndex desc

In SQL a comparison with NULL is never true, so rows with NULL `dispLocation`, `folderType` or
`presentBoxStatus` can never match - which is why `AccessorIterator.GetCount` was 0 (and why the
`contentType` experiments changed nothing). The apps' own `param.sfo` carries `DISP_LOCATION_1` /
`DISP_LOCATION_2` (position in the two display areas; non-zero = shown, 0xFFFFFFFF = shown without
a fixed slot) on 23 of 44 apps. `appdb.py` now carries those into `tbl_appinfo` and derives
`dispLocation` (bit n-1 set when DISP_LOCATION_n is set; the bit semantics are inferred from the
filters), and sets `folderType = 0`, `presentBoxStatus = 0` like a normal non-folder row.

Result: the home-count query matches 22 rows (What's New, TV & Video, Library, PlayStation Store,
PlayStation Video/Now/Music Unlimited, Spotify, Media Player, ... - what a PS4 home lists),
`AccessorIterator.GetCount` returns 21 instead of 0, and the shell draws its content row with the
icons loaded from each app's `sce_sys/icon0.png`, a focused tile with its "Start" button, the title
label, the info panel and the bottom hint bar.

Open issue (separate): in `--frames` runs the process aborts inside the native GPU library
(`gnm_submit` -> "Fatal Python error: Aborted") after ~1000 command buffers once these richer
frames render; a plain run without `--frames` completed cleanly (exit 0, 70 s). Not yet
diagnosed - likely a path exercised by the scanout write-back used for frame dumps.

## Update 2026-11-18 (late night): the native GPU abort is fixed

The `--frames` abort noted above was **not** the scanout write-back. A crash handler
(`gnm_crash.cpp`, installed per thread from `gnm_submit`: `std::set_terminate` + `SIGABRT`, prints the
pending exception and a symbolized stack via dbghelp) showed the stack:

    gnm_submit -> ... -> Shader::Backend::SPIRV::EmitGetAttribute -> Sirit::Module::OpLoad(null Id)

i.e. a Sirit assertion, not a Vulkan fault. The cause: the **fragment shader reads an interpolant the
vertex stage never exports**. shadPS4's `EmitContext` skips declaring SPIR-V variables for such
"default" inputs (and for params beyond what the previous stage wrote), but two paths still emitted a
load of the missing variable:

1. `V_INTERP_MOV_F32` did not handle `attr.IsDefault()` (its sibling `V_INTERP_P2_F32` does). It now
   returns the hardware default constant (`DefaultValTable`). Patch `interp-mov-default-input.patch`.
2. `EmitGetAttribute` for a param whose `num_components == 0` loaded a null id. It now yields `0.0f`.
   Patch `undeclared-input-param.patch`.

Both live as patches under `psemu/gnm/native/patches/` (applied idempotently by `build.py`).
Result: the same `--frames` scenario that aborted in ~5 of 6 runs now completes 4/4
(exit 0, 49-52 frames), and frames through 1200 render the same home screen. Regression suites
(synctest 40/0, policytest 34/0, whp_uc_test) unchanged.

## Update 2026-11-18 (late night): compositor speed - 1.6x more frames per second

`tools/ring_split.py` splits the compositor's `ring.service` time (Python side) and prints the native
per-phase profile (`gnm_profile`, now with sub-phases: `b_*` bind pieces, `flush4shader`,
`wb_surface/wb_wait/wb_tile`, `fingerprint`, and counters `wb`, `wb_shader`, `wb_MB`, `direct`).
Findings at the start (55 s run, ~17.5 ms per command buffer, 95 % of `ring.service` inside the native submit):

* The home screen is ~10 draws per command buffer, all into one 1920x1088 (8 MB) guest surface at
  `0x3020c00000`, which is then sampled by a draw that renders back into the same address.
* That surface was written back (CPU retile) **twice per frame** (once because a draw samples it,
  once at end of submit), dropped, and re-detiled + re-uploaded for the next draw: ~15 GB of tiling
  traffic in 55 s, and the retile ran at ~1 GB/s on one thread.

Changes (all in `psemu/gnm/native/src`):

1. **Tiler** (`gnm_tiling.cpp`): `Tile`/`Detile` run in row bands on up to 8 threads (bands touch
   disjoint pixels) with a 4-byte fast path. 8 MB: ~7 ms -> ~2 ms. `tests_tiling_rt.py` checks that
   tile -> detile is the identity for several modes/bpp/sizes.
2. **Direct sampling of resident render targets** (`gnm_vulkan.cpp`, `TryDirectSample`): when a draw reads
   a plain 2D texture that is exactly a colour surface an earlier draw of this submit rendered
   (same address, pitch, format, tile mode, T# no larger than the surface) the shader samples the GPU
   image instead of the surface being written back and reloaded. If the T# is smaller than the
   surface (here 1920x1080 vs 1920x1088) or the draw also renders into that surface (feedback pass),
   the region is first copied on the GPU into an image of the declared size (a snapshot, as the old
   write-back/upload path gave; normalised UVs depend on the image extent). The draw is rejected from
   this path (old behaviour) if any target/depth range overlaps the surface without being exactly
   that surface, since acquiring such a target would free the image being sampled.
   `PSEMU_GNM_NO_DIRECT=1` turns it off for A/B runs; `PSEMU_GNM_WBLOG=1` logs write-backs and
   rejected/missed direct matches.

Result (same 55 s WHP run of the home screen): mean native submit 17.5 -> 6.1 ms, command buffers
completed 2091 -> 4914, render-target cache misses 970 -> 2, forced shader write-backs 968 -> 0,
flips in 70 s 1224 -> 1908. Frame content: two runs in the same mode differ from each other about as
much as direct vs non-direct (animation phase depends on timing), and the second non-direct run was
within noise of the direct one; synctest/policytest/whp_uc_test/tiling round trip pass; 3 `--frames`
runs and a SceSysCore -> ShellUI chain run (4500 command buffers, 0 failed draws) are clean.

What is left in the GPU path (per 55 s): end-of-submit write-back of that surface ~9 s
(GPU copy wait + retile + fingerprint), GPU execution ~7 s, shader translation ~4.5 s (10k misses: the
exact cache keys on descriptor contents that change per draw), render-target setup ~3 s. Deferring the
write-back needs a way to see CPU reads of the surface (WHP page protection); not done.

## Update 2026-11-18 (late night): lazy write-back of the compositor's surfaces (page-watch)

After direct sampling the biggest remaining cost was writing the 8 MB surface back to guest memory
(GPU copy + wait + retile + fingerprint) at the end of every submit (~9 s of 55). Nobody reads it, but the
guest CPU *might*, so it cannot simply be dropped. Now it is deferred and guarded by a page trap:

* **Native** (`gnm_vulkan.cpp`): `gnm_set_lazy_writeback(1)` makes `ReleaseSurfaces` leave a dirty colour
  surface in the GPU (`gpu_newer`, as host-only surfaces already were) and queue a watch event
  `{addr, size, 1}` (`gnm_watch_events`). Every GPU-side access to that memory still goes through
  `FlushRange`, which writes it back and queues the unwatch event. Eviction/destruction unwatches too.
  A non-lazy submit writes a still-deferred surface back first.
* **WhpUc** (`whp_uc.py`): `watch_add(addr, size, cb)` clears the pages' PTEs in the guest page tables
  (we own them). The first guest access takes a #PF, the PTEs are restored, `cb(start, size)` runs and
  the instruction retries. Host `mem_read`/`mem_write` (syscall handlers) and `_pt_fill` (remap/unmap)
  on a watched range settle it the same way. Ranges are page-rounded and disjoint (an overlapping
  `watch_add` fires the old one). The WHP self-test covers guest read/write traps, host access,
  `watch_remove` and overlap (13 new checks).
* **Compositor** (`unixsock.py`): only the compositor's own submits are lazy (toggled around each
  `backend.submit`); the callback calls `backend.flush_range`. Needs the WHP backend (Unicorn has no
  page trap, so it stays eager); `PSEMU_NO_LAZY_WB=1` disables it.

Result (55 s WHP run): write-backs 1616 -> 4, mean native submit 6.1 -> 3.2 ms, command buffers
completed 2946 -> 5712; flips in 70 s 1908 -> ~3000 (originally 1224); SceSysCore -> ShellUI chain:
8500 command buffers in 70 s (was 4500), 0 failed draws. In the home screen nothing touches the surface, so
the trap never fires in normal runs; a probe in `ring_split.py` (host read of the watched surface)
shows one write-back and the watch released. Synctest/policytest/whp_uc_test pass.

Known limits: kernel-side access to guest memory that bypasses `mem_read`/`mem_write` (native code
reading guest pointers directly, other than the GPU backend itself) is not trapped; partial CPU writes
into a lazily deferred surface are merged correctly only because the trap writes the GPU contents back
first. A second `WhpUc()` in one process exits silently (pre-existing; the self-test reuses one).

## Update 2026-11-18 (night): hardening the lazy write-back (review follow-up)

An outside review of the page-watch work asked for six things to be checked; results:

* **Failure path.** A failed trap-time write-back used to be logged and the guest resumed with the
  page restored and stale memory. Now `backend.sync_watches(uc)` owns the trap callback: on any
  exception it re-arms the watch (so the pages keep trapping) and re-raises. A failed synchronisation
  is loud and the guest never silently reads stale data. Non-compositor `/dev/gc` submits also drain
  watch events now (they may flush deferred surfaces).
* **Eviction.** Verified in the code and by `python -m psemu.tools_lazywb_test` (real firmware shaders,
  one target per submit, the backend keeps 8): the two oldest surfaces are written back with their
  drawing *before* the GPU image is freed and are unwatched; the 8 held ones keep the guest memory
  untouched; `flush_range` on a held surface writes it back + unwatches; a later non-lazy submit that
  reuses a held surface writes it back + unwatches; an injected write-back failure raises and re-arms.
  (Shutdown frees deferred surfaces without write-back, which only happens at process exit.)
* **WHP page-watch tests** (`tools_whp_uc_test`, 13 watch checks in total): guest read/write
  traps, an 8-byte access straddling into a watched page, a partial guest write landing on top of the
  write-back (`0xAA` fill + 4 guest bytes), disjoint watches firing independently, overlap settling
  the old watch, host `mem_read`/`mem_write`, `watch_remove`, and a `mem_protect` remap of a watched
  range settling it first.
* **Concurrent guest threads.** The WHP partition has one vCPU; guest threads are interleaved only at
  preemption exits and the trap callback runs synchronously inside the exit handler before any thread
  resumes, so two threads cannot race the write-back.
* **GPU crash after extended rendering.** Long soak (`--frames`, 420 s, WHP, home screen): exit 0,
  **77,000 command buffers / 773,113 draws, 0 failed**, no abort or GPU message. (`--frames` also
  writes one `dcb_*.bin` per command buffer: ~21k files in 5 minutes, delete the directory after.)

## Update 2026-11-18 (night): watch events are transactional

A second review pass found that `sync_watches` drained the native event queue *before* applying the
events, so a `watch_add` that failed part-way lost the remaining events and left the Python page
watches out of step with the backend. Now a persistent per-CPU pending queue is filled from the
native queue and events are applied one at a time, leaving the queue only after they were applied: a
failure keeps the failed event and all later ones, in order, for the next sync. Re-entrant syncs
(a trap inside an event) return and let the outer loop drain. A failed trap-time re-arm is no
longer swallowed: it is attached to the original write-back error (`add_note`). `tools_lazywb_test`
has two new cases (the 2nd of 3 events fails -> 1st applied, rest retained, retry applies each once in
order; a failing re-arm is reported with the write-back failure). Lazy-writeback and WHP tests were
repeated 5x each: all pass.

## Update 2026-11-18 (night): what the pad stack needs (DualShock 4 input, first look)

The shell logs `[ScePsP:InputCtrl] LOST PAD DATA: Nmsec` repeatedly: it expects pad data and gets none.
`tools/hid_trace.py` (syscalls on /dev/hid with caller stacks) and `tools/hid_ioctls.py` (request codes
compiled into the binaries) show:

* `libScePad` (and a statically linked copy inside the ShellUI `eboot.bin`) talk to **`/dev/hid`** through
  ioctls only - no read(), no mmap, no kevent on the fd. (`/dev/ctrlp_sync` is also referenced but not
  opened in 45 s.) `/dev/hid` is not a modelled device in `psemu/devices.py`, so the open succeeds
  generically and every ioctl returns 0 with the argument untouched.
* The interface is ~45 `'H'`-group ioctls (`libScePad` 45, `libSceHidControl` 19, eboot 29), all of the
  form *small struct with an output pointer + arguments in, kernel writes through the pointer*, e.g.
  `0x80084809` `{u32 3; u32 type}` (open/version) and `0x8010480f` `{u64 *out; u32 arg}` where the
  wrapper returns the u64 the kernel wrote (called ~33 times/s from managed code via
  `platform.dll` -> `eboot.bin+0x9fa9e`, arg values 0 / 0x20 / 2 ...). The pad-state read is probably
  one of nr 0x45 (`0x80184845`, 6 call sites), 0x2e (`0x8030482e`, 4), 0x29 or 0x2a.
* So input needs a modelled `HidDevice`: decode each request, answer "one DualShock 4 connected,
  idle" with consistent structures, then feed button/stick state from the host (keyboard/XInput).
  Next step is to reverse the structures from the call sites (static: `tools/elfdis.py`, `sdis.py`;
  dynamic: `hid_trace.py` with a fake device that logs all requests the stack makes).

## Update 2026-11-18 (night): /dev/hid model and what gates pad use in the shell

**Controller on the host.** Nothing to wake: no XInput pad is connected (all four slots report
"not connected") and no Sony HID interface (VID 054C) is visible to Windows, i.e. DS4Windows is not
running, the pad is off, or HidHide is hiding it. Nothing was sent to any device.

**Model.** `devices.HidDevice` (`/dev/hid`) decodes what libScePad was reversed to send:
`0x80204829` = `scePadReadState` read `{u32 port; u32 _; void *buf; u32 count; u32 _; u32 *out_count}`
-> writes a report (`+0` u64 timestamp us, `+0x0c` u32 button word, `+0x10` lx ly rx ry l2 r2) and
returns the count; `0x80084803` = `scePadOpen` (returns a handle); `0x80084809` =
`scePadSetProcessPrivilege`; `0x8010480f` `{u64 *out; u32 arg}` writes a u64 (semantics unknown);
every other request is logged once and answered 0. `padsrc.py` supplies the state: the first XInput pad
(DS4Windows exposes the DS4 as an Xbox 360 pad: A/B/X/Y = cross/circle/square/triangle, Back = touchpad
click), else an idle controller; `PSEMU_PAD=none|xinput|script` (`PSEMU_PAD_BUTTONS=CROSS,DOWN`).
`python -m psemu.tools_hidtest` covers the layout, return values, button/axis encoding.

**The shell never reaches it yet.** `tools/pad_calls.py` (hooks every libScePad export) shows that in
60 s of boot only `scePadInit` (from `libScePsm`) and `scePadSetProcessPrivilege(1)` (from the eboot) run:
no `scePadOpen`, no `scePadReadState`, no `scePadGetControllerInformation`. From the disassembly:

* The ShellUI (a privileged system app) and `libScePsm` import only `scePadReadState` (not `scePadOpen`):
  they read by port number. `libScePsm`'s poll function (`+0x80bac`) walks up to 8 pad slots and calls
  `scePadReadState` only for slots whose active flag was set by its add-pad function (`+0x81a..`), which
  first calls `scePadGetControllerInformation` for the pad's port. That registration is driven from the
  managed side and has not happened: nothing has told the shell a controller exists.
* The `[ScePsP:InputCtrl] LOST PAD DATA` thread (`libScePsm+0x7f690`) is *not* about missing data: it
  waits on an equeue fed by a **video-out event** (kevent filter -13) and logs when two events are
  more than 100 ms apart, so it measures our vblank cadence (a pacing symptom, ~60 lines per minute).
* `tools/kev_filters.py` (kevent registrations by filter/ident), `plt_callers.py` (call sites of an
  imported function), `elfsyms.py` (export table + NIDs), `xref_mod.py` are the new helpers.

Next: find which managed/native call registers a pad (hook `libScePsm+0x81a..` and walk back), and
decide how a connected controller is announced (user-service login / pad events), then the
`scePadGetControllerInformation` ioctl; separately the 100 ms vblank gaps.

## Update 2026-11-18 (late night): the libScePsm pad trigger, a network spin, and the vblank gaps

**What was gating pad use.** The shell never called `scePadReadState` because `libScePsm` only polls
pad slots that its enumeration (`+0x7fca0`) has filled, and that enumeration got nothing from the
**SceMbusIpc** service (a stub: empty success). It asks `SceMbusIpc.0xce110028` (GetDeviceList) for
devices of the classes it can drive (2, 3, 12, 14, 13) and reads back 0x100-byte entries
(`+0x00` u64 device id, `+0x08` connection kind - 4 = remote play, 5 = share play, else local,
`+0x0c` class, `+0xc8` user id). The **method result code is the device count** (libSceMbus hands it
back as the return value; returning 0 there reads as "no devices"). `mbus.py` + `Syscalls._ipmi_mbus_device_list`
now answer with one DualShock 4 (class 2, local, assigned to the logged-in user) when `PSEMU_PAD` is not
`off`. After that the shell registers it exactly like a console: `scePadOpenByMbusDevice`,
`scePadGetControllerInformation`, `scePadGetCapability`, then `scePadReadState` ~30x/s, a "user logged
in" toast ("Unknown": the open username item) and `ConnectedDeviceStatus: [DUALSHOCK4][user]`.
Corrections to the first `/dev/hid` model found on the way: **open is `0x800c4802`** (`{i32 id, i32 type,
i32 0}`, returns the handle, which must be 1..3 because the read takes a port <= 3) and `0x80084803` is the
close; `0x8010480e` fills the controller-information block (a 0x48-byte buffer: writing 0x60 smashed the
canary and aborted the guest), `0x80104801` the capability block.

**The new problem (why the pad is opt-in).** With a pad registered the home screen renders ~15x less
(400-700 command buffers per 50 s vs ~7200). The main thread ends up parked in a Mono semaphore wait
(`libmonosgen` called from `libScePsm+0x1d8a94`, a `sem_wait` on a `libScePsm` data address) that
nothing posts, all threads are blocked, and the scheduler skips virtual time (95 s in 30 s of wall) while
timers churn (141k thread switches). Not the report stream (constant timestamps made no difference), not
the idle clock skipping (a real-time idle wait gave the same), not the model string. Still to find: who
should post that semaphore (a Mono stop-the-world handshake with the pad thread is the leading guess).
`PSEMU_PAD` therefore defaults to `off` (no controller attached); `auto|none|xinput|script` attach it.

**A network spin, fixed.** In every run (pad or not) one managed network listener (System.dll ->
libSceNet) spun on `setsockopt` / `netcontrol` / `recvfrom(0, buf, 0x300, 0x40000000)` ~6000 times a second
and took 45-75 % of all guest CPU: `socket()` returns a stub fd and `recvfrom` "succeeded" with 0 bytes
at once. `sys_recvfrom` now behaves like a console with no network: a blocking receive on an unmodelled
socket parks the thread, a MSG_DONTWAIT poll gets EAGAIN after 5 ms of virtual time. Default boots went
from 403-5400 (very noisy) to a steady ~7200 command buffers per 50 s, the chain run from 4500-7500 to 9000
per 60 s.

**The vblank gaps.** `[ScePsP:InputCtrl] LOST PAD DATA: N msec` is not about pad data: the thread
(`libScePsm+0x7f690`) waits on an equeue fed by a VideoOut event and prints when two events are more than
100 ms apart. It appears ~5x/s (250 per 50 s). The vblank/flip events come from the compositor stand-in,
so a gap is a slow compositor frame: `ring_split.py` shows 40-60 ms mean per ring service and spikes of
400-600 ms (new shader translation - ~10k translate-cache misses - and texture uploads). The netctl spin
made it worse by starving threads; what is left are those frame spikes.

New helpers (`docs/shellui-boot/tools/`): `mod_hooks.py` (hook module-relative function entries, GOT target
of PLT thunks), `plt_targets.py` / `plt_callers.py` / `elfsyms.py` / `xref_mod.py` (imports, NIDs, call sites,
string xrefs in any module), `kev_filters.py`, `thread_syscalls.py` (per-thread syscall histogram),
`spin_who.py`, `addr_sync.py` (who waits/wakes an address), `rip_sample.py`, `pad_calls.py`.
`python -m psemu.tools_hidtest` covers the Mbus list, filters, open/close/info/capability and the buffer sizes.

## Update 2026-11-18 (late night): the pad-attached stall - root cause chain

The main thread's Mono semaphore wait was a symptom. Following it down (tools: `sem_trace.py`,
`stw_trace.py`, `main_tail.py`, `all_stacks.py`, `wait_stack.py`, `mdbg_trace.py`, `exc_catch.py`,
`open_who.py`, `data_watch.py`, `mod_hooks.py`, `plt_targets.py`):

1. **What the wait is.** The main thread (`tid 0x10001`) is inside the managed `Exception.ToString` called from
   the UI task framework's `FilterTasksFromWorkItems`; building the exception text allocates a string, the GC
   runs and the thread parks on a Mono `libmonosgen` global semaphore (`+0x4e78d0`, a thread-state job
   handshake nobody completes: the UI is dying, not deadlocking in the GC). Before that it printed the
   "FrameTask Entry 'DefaultTasks' ..." dump of every registered UI task and called
   `mdbg_service(3, 0xa0028401)`: the **PSM runtime's unhandled-exception report** (the same runtime that
   creates `ScePsmExceptionInfo` at boot). The rest of the shell then stops rendering.
2. **The exception.** `exc_catch.py` (hooks `System.Exception::ToString` in the mscorlib AOT image and reads
   the object's string fields): **`System.DllNotFoundException: BgmPlayStatusCheck`**, thrown by
   `Sce.PlayStation.HighLevel.UI2 ... BgmPlayerWrapper.PortUsablePollingHandler` (a UI timer) through
   `Sce.PlayStation.Core.dll`'s `[DllImport("BgmPlayStatusCheck")] sceGetBgmPlayStatusNative`. The timer only
   starts once the user is associated with a pad, which is why the pad-off runs never see it.
3. **Why the library is missing.** Sony's Mono asks registered dl-fallbacks (`mono_dl_fallback_register`) before
   touching the file system. `libScePsm` registers one whose user data is a one-entry table
   `{"BgmPlayStatusCheck", {"sceGetBgmPlayStatusNative" -> libScePsm+0x128e60}}`
   (`libScePsm+0x1d68c6`), but only on the path taken when its audio start-up succeeds
   (`libScePsm+0x1d66a9: call 0x7c6a0` must return 0). It returns `0x80b3f001` (in pad-on **and** pad-off
   runs), so the table is never registered and the lookup falls through to `lt_dlopen`
   (`libBgmPlayStatusCheck.la` ENOENT, four probes) and the exception.
4. **Why audio start-up fails.** `libScePsm+0x6b400` creates the audio engine and its first device call is
   `ioctl(/dev/ajm, 0xc0288903)` (`sceAjmModuleRegister`): the AJM decoder device is unmodelled, so the generic
   stub returns 0 **without writing the status dword the wrapper then returns**, i.e. stack garbage.
   (`dynproc._audioout_null_client` already noted "PSM's sound init ... fails first on the unmodelled
   /dev/ajm".)
5. **`/dev/ajm` is now modelled** (`devices.AjmDevice`, opt-in `PSEMU_AJM=1`): twelve `0xc0288900+n` requests
   of 0x28 bytes, status u32 at +0 (0 = OK), instance create returns an id at +0x14 (layouts from libSceAjm's
   wrappers; unit-tested). With it, PSM's audio init gets further: `sceAudioOutOpen` (the BGM/system port,
   `ch=7`) reaches the **audio server** (`SceSysAudioSystemIpc`, methods `0x12340000..0x1234002c`, shm
   `/shm_<pid>_<port>_A`), which is unmodelled ("empty success"), and `libSceAudioOut+0x3f05` writes through its
   port-state table into unmapped memory (SIGSEGV, boot dies at ~5.6 s). That is a regression for the default
   boot, so **AJM is opt-in until the audio server exists**.

Next step: model the audio server enough for `sceAudioOutInit` / `sceAudioOutOpen` to succeed (client create,
the 45 IPMI methods' replies, the shared port table and event queue), then enable `/dev/ajm` by default; the
Bgm table registers, `BgmPlayStatusCheck` resolves to `libScePsm+0x128e60`, and the pad-attached run should keep
rendering. (Not tried: registering the Bgm table from the host, which would hide that audio is down.)

## Update 2026-11-18 (night): audio start-up - the real cause was thread priorities, not the audio server

The previous section ended with "model the audio server". Chasing why `scePssSoundPlayerInitialize()` still
returned `0x80b3f001` with `/dev/ajm` modelled, one step at a time with `regs_at`-style hooks on the return
values (not by guessing at the 193 `mov imm, 0x80b3f001` sites: a hook on the *mov* fires whether or not the
error branch is taken - `strlcpy` at `+0x87980` falsely looked like the culprit), gave this chain:

1. `libScePsm+0x8af20` (AudioSystem init) -> `+0x94a10` (the sound player): `sceAudioOutOpen` returned
   `0x20000007` (fine), the mixer thread was created (fine), then
2. `+0x9f900` calls `+0x893d0` -> `+0x89300` to set the new thread's priority to `0x208`:
   `pthread_getschedparam` -> `sched_get_priority_min/max(policy)` -> `pthread_setschedparam`. It requires
   `min < max` for the policy, a value in range, and libkernel's `pthread_setschedparam` (`+0xada0`) only
   accepts `SCHED_FIFO` (1) or `SCHED_RR` (3).
3. Two gaps in psemu made that fail: syscalls 332/333 (`sched_get_priority_max/min`) were unmodelled and
   returned 0 for both (min == max), and `rtprio_thread` (466) was unmodelled so the thread's policy read
   back as 2 (`SCHED_OTHER`) -> `EINVAL`. The failure returned `0x80b3f001` after `sceAudioOutClose`, so
   the whole sound system was torn down, the Bgm table never registered, and `BgmPlayStatusCheck` threw.

Fixes (all in psemu, nothing hard-wired into the guest):
* `sys_sched_get_priority_{min,max}`: the PS4 range 256..767 (SCE_KERNEL_PRIO_FIFO_HIGHEST/LOWEST) for
  policies 1-3; `sys_rtprio_thread`: lookup returns `RTP_PRIO_FIFO` at the default 700, set is remembered
  per thread (struct rtprio {u16 type; u16 prio}). Unverified against hardware: that FIFO/700 is the exact
  default a console reports; it is what the libkernel logic and the SDK's default priority imply.
* **Shared-memory spans round to 16 KiB** (Orbis mmap granularity; libSceAudioOut writes past the first
  4 KiB page of its port shm) - this was the earlier SIGSEGV.
* **Audio server pacing** (`audioserver.py`): the owner of `sceAudioOutMix<pid>` posts one bit per port per
  period. The old external-evf stand-in granted the bits instantly, so with audio working the mixer thread
  spun (750 000 `evf_wait` calls in 50 s, 1/20th of the frames). A wait on that flag now ends at the next
  256-frame / 48 kHz period boundary of virtual time (5.33 ms) with the requested bits set. Nothing is
  mixed or played yet.
* `/dev/ajm` (`AjmDevice`) is now **on by default** (`PSEMU_AJM=0` -> old generic stub).

Verification: `[PSM] scePssSoundPlayerInitialize()` no longer prints a failure; hooks at `libScePsm+0x1d66ae`
(`rax == 0`) and `+0x1d68c6` (Bgm table registered) fire; 60 s direct ShellUI runs: pad off 9500 DCBs, pad
attached (`PSEMU_PAD=none`) 9500 DCBs (before: 500 with the pad, 11500 pad-off without audio); SceSysCore ->
ShellUI chain with a pad: 9000 DCBs, exit 0. Unit tests: `python -m psemu.tools_audiotest` (new),
`tools_hidtest`, `tools_synctest` (40/0), `tools_policytest` (34/0), `tools_whp_uc_test`, `tools_lazywb_test`.

Cost: with sound alive the decode loop runs flat out (~2500 AJM batch ioctls/s) - about 17% fewer frames than
the audio-less boot. Pacing/results for AJM jobs are the next audio item; the audio *server* (mixing,
`SceSysAudioSystemIpc` replies) is still "empty success" and not needed for start-up.

## Update 2026-11-18 (late night): AJM pacing, the real pad read, how far input gets

* **AJM decode spin fixed.** After audio start-up worked, thread 0x10097 (libScePsm mixer ->
  `libSceAudiodec+0x1600` decode helper) ran Batch start/wait (`/dev/ajm` 0xc0288907 / 0xc0288908, ~2500 per
  s) with no sleep: nothing in the model made a batch take time. `AjmDevice` now parks the caller on batch
  wait until the next 256-frame period of virtual time (`devices.BLOCKED` sentinel: the device calls
  `sched.block` itself, `sys_ioctl` then writes no return value). Result: 11500 DCBs/60 s with audio on, the
  same as the audio-less boot (it was 9500).
* **The pad read is `0x8030482e`**, not `0x80204829`. libScePad `+0xe00` (scePadRead/ReadState) calls it with
  `{u32 handle; _; record *buf; u32 count; _; u32 *out_a; u32 *out_b; _}` (0x30 bytes). The kernel fills
  0xa8-byte records (`+0` u64 timestamp us, `+0x0c` buttons, `+0x10` lx ly rx ry l2 r2, `+0x17` touch
  count, ...) and returns how many; `out_a` is a generation id the library compares with its own (0 = skip),
  `out_b` non-zero = touch data. Unmodelled it returned 0, i.e. "no reports": the controller never moved.
  (The ShellUI's own `eboot` has a second copy of the reader, `0x80204814`, over 0x20-byte keyboard-style
  records at `eboot+0x1888c0`; it only polls at ~10 Hz and is not the DualShock path.)
* **Scripted input**: `PSEMU_PAD_BUTTONS` takes a timeline `start+duration=BTN[+BTN]` in virtual seconds
  after start (`"14+0.5=RIGHT,20+0.5=CROSS+DOWN"`); plain names are held from the start.
* **Pad input: how far it gets** (all verified by hooks; `tools/gamepad_out.py`): `scePadReadState` (libScePsm
  `+0x80c3d`, InputCtrl thread, ~11/s) returns buttons=0x20 for RIGHT -> `+0x80ca0` -> `+0x82440` detects the
  edge and calls the registered callback `+0x74b10`, which sets the bit in libScePsm's per-slot table (`+0x31e2a0`,
  0x18 bytes/slot, state bits at +4) -> managed `GamePad::GetDataNative` (`+0x1cdf50`, called every frame by
  the UI) copies the slot (`+0x74910`) and returns buttons=4 (Right) with ButtonsDown=4 on the edge, then
  ButtonsUp. So the UI is handed correct pad events, yet UP/DOWN/RIGHT/CROSS pulses change nothing on the
  home screen (frame diffs show only the idle hint-bar fade). Not yet known: whether the shell scene is
  modal/unfocused (login or first-run state; user shows "Unknown"), waits for ShellCore input-focus events
  (`SceShellCoreUtilCtrlFocus` is an always-set stand-in), or uses a second path. A pitfall found on the way:
  `emu._time()` is an absolute perf counter, so a script timeline must subtract `emu._t0` (a timeline that
  never fired looked exactly like "UI ignores input").

## Update 2026-11-18 (night, later): the user name - and why the pad seemed ignored

* **`SceUserService` 0x30004 is the generic per-user string call.** `libSceUserService+0x630` (used by
  `sceUserServiceGetUserName` `+0x3f20`, `GetThemeEntitlementId` `+0x8110`, ...) sends `{u32 user id; u32 kind}`
  and receives a NUL-terminated string (kind 1 = name, 0x800 = theme entitlement id, capacity 17 for the
  name). It was an "empty success", so the name came back empty and ProfileCache showed "Unknown".
  `Syscalls._ipmi_user_name` answers kind 1 with `Player1` (`PSEMU_USER_NAME` overrides; max 16 characters),
  any other kind with an empty string, an unknown user id with `0x80960005`.
* **First attempt answered every kind with the name** and killed the shell: the theme manager read the
  entitlement id as "Player1", took the "packaged theme" branch (`[Theme/I] Mount : packaged theme : [EID:Player1]`),
  got an empty mount path from `SceAppContent` 0x20019 and died on `ArgumentException: UNC paths should be of
  the form ...`. Found by decoding which libSceUserService export called the same method with another kind,
  not by guessing: another reason not to give "empty success" answers a plausible value without checking.
* **Effect on the pad question**: with a named user the avatar/profile path (`//priv/etc/default_avatar_64.dds`),
  the GLS/QuickMenu/Notification scenes and the user entry in the hint bar load, and scripted pad pulses
  (`PSEMU_PAD=script PSEMU_PAD_BUTTONS="14+0.5=RIGHT,20+0.5=RIGHT,26+0.5=DOWN"`) now move the content row -
  the UI had been dropping input because it had no logged-in user. Verified on frame montages; chain run
  with a pad: 9000 DCBs/60 s, exit 0, no managed fatal. `python -m psemu.tools_usertest` covers the method.

## Update 2026-11-18 (night, last): CROSS on a tile - where the launch stops

* **New tools.** `tools/cil.py` reads the IL embedded in the managed `.dll.sprx` files (all of the ShellUI's
  logic is managed): `python cil.py app.exe.sprx list AppLauncher`, `... dis "DisplayClass26::<Start>b__24"`.
  It resolves tokens to names and strings; the first run per assembly extracts the PE (30 s), later runs use a
  cache. `tools/icall.py <secs> <after> GetBootEvent ...` finds eboot internal-call implementations (name
  string -> `{name, fn}` entry) and logs their calls. Both replaced guessing: the launch path below was read,
  not inferred. (`pip install` of a .NET reader was refused by the sandbox, so `cil.py` is hand-written.)
* **The press, step by step** (`PSEMU_PAD=script PSEMU_PAD_BUTTONS="22+0.4=CROSS"`; the log now prints
  `pad state -> buttons 0x4000` once per change): the UI thread runs the `AppLauncher.RegisterLaunchMessage`
  handler -> `InvitationManager.OnNewSessionStarted` -> eboot native `ClearAutoAcceptInvitation(user)`; a worker runs
  the `AppLauncher.Start` job (`<Start>b__24`): CheckInitDaemons (waits for boot flag `0x8000000`, which
  `BackgroundInitDaemons` sets at ~14.7 s - fine), `LaunchTargetInfo..ctor` (the `tbl_appbrowse ... where
  titleId = ?` query; found), IsRunning/IsAppKilling/PowerManager/LaunchPSCloudSubs checks (all passed), and
  finally `LncUtil.LaunchApp` -> `sceLncUtilLaunchApp` in libSceSystemService.
* **Where it blocks.** `libSceSystemService+0x5e22` does `sceKernelWaitSema(SceLncAsyncCallSema, 1)` (the sema
  is created with 2 slots; each async Lnc call takes one and its completion gives it back). Both slots are
  gone (async calls made at boot never complete: `ipmimgr_call cmd 0x241` is an "empty success" with no
  completion), so `LaunchApp` never gets to send anything: no IPMI after the press, no error, no dialog, the
  UI just keeps running. Diagnostic (not committed): forcing that sema wait to succeed lets it issue the call,
  and the thread then parks in `cmd 0x490` (wait event flag) on `SceLncService`.
* **A tried shortcut that failed**: adding `SceLncService` to `IPMI_EVF_SATISFY` (the stand-in that completes
  the compositor / AvSetting / ShellCoreUtil event-flag waits) made the whole shell crawl (5495 context switches,
  no frames): the Lnc client also has event-wait loops that must keep blocking, so completion has to be tied to
  the async call's own slot bit (`1 << (counter % 64)`, passed with the 0x241 request), not to the service name.
* **Next**: implement `cmd 0x241` properly (request struct `{ptr method, numIn, numOut, ... }` at
  `libSceIpmi+0x49c0`: run the modelled/empty method at once, store the out buffers, and signal the slot bit that
  the client's `0x490` wait names); then model `SceLncService`'s launch method so a tile press at least produces
  an app-status/launch event; separate app processes are still not run.

## Update 2026-11-18 (night, end): the PlayStation startup - what draws it and what keeps it from showing

Reference: a 21 s clip, "The REAL PS4 Startup" (power-on: PlayStation logo, then the system). The clip itself
could not be played here, so what follows is from the firmware, not from watching it.

* **Who draws the logo.** Not the ShellUI. `SceSysAvControl.elf` (the AV-control daemon that `mini-syscore.elf`
  forks and execs first) contains the splash: `SceBootSplash` / `prepareSplashImage` /
  `sceBootSplashUpdate`, the logo bitmaps embedded in the ELF, software alpha fade-in/out into four 1920x1080
  display buffers, `sceVideoOutSubmitFlip` per frame, `waitFlipArg` to keep three flips in flight. It runs until
  somebody sets `SCE_BOOT_STAT_STOP_SPLASH` in `SceBootStatusFlags`; the ShellUI does that through
  `PowerOnSplash.Hide()` -> `NativeCall.StopSplash` (`sceShellCoreUtilSetSplashScreenState`, 500 ms later it
  reports the splash gone). The sound is a separate piece (not found yet; `orbis_audiod.elf` is in
  `system/sys`). No logo/animation asset exists in the dump; the splash is code + embedded bitmaps.
* **What we do today.** Every ShellUI run starts at `SceSysCore.elf` (`--then NPXS20001`), i.e. after the
  stage that shows the logo: the splash code is never executed, and the first thing on screen is the home
  screen (preceded by black frames while the shell loads).
* **Running that stage found three bugs, fixed here** (`mini-syscore.elf` -> `SceSysAvControl.elf`):
  1. `sceVideoOutRegisterBuffers` failed (`0x80290015`): libSceVideoOut checks that every display buffer's virtual
     address is congruent to its direct-memory offset modulo 64 KiB (`virtual_query` start vs offset). psemu mapped
     the 2 MiB-aligned (`MAP_ALIGNED`, flags bits 24..28) direct-memory allocation at an arbitrary address;
     `emulator.map_anon(..., align)` + `sys_mmap` now honour the alignment (at least 64 KiB for direct memory).
  2. `waitFlipArg` timed out: `sceVideoOutGetFlipStatus` (DCE cmd `0xa`, 0x48 bytes) was an all-zero answer, so
     flipArg never caught up. `DceDevice` now reports `{count, time, tsc, flipArg, submitTsc, gcQueue 0,
     flipPending 0, currentBuffer}` from the newest submitted flip (flips complete at once).
  3. Flip events collapsed: three flips before the first wait produced one event with count 1; uncollected display
     events now accumulate in data bits 12..15 like the kernel's.
  Result: `python -m psemu.run mini-syscore.elf --backend whp --frames DIR` renders the PlayStation logo fading in
  and holding (681 frames in 40 s of wall time; checked on a montage of frames). `python -m psemu.tools_dcetest`.
* **What still prevents the full sequence** (in order):
  1. **One process at a time.** On a console `mini-syscore` forks `SceSysAvControl` (splash, keeps running as a
     daemon) and carries on to start `SceSysCore` -> `SceShellCore` -> the ShellUI while the logo is up. psemu's
     `execve` chain-loads (`--spawn-mode follow`: the parent is replaced, so the boot stops inside AvControl's HDMI
     event loop) or retires the child (`stay`: no splash). Running the splash *and* the boot needs real
     multi-process execution (separate address spaces, shared kernel objects/IPMI between them); today only
     SceSysCore + ShellUI-in-one-image works.
  2. **The splash is never taken down.** `SCE_BOOT_STAT_STOP_SPLASH` / `PowerOnSplash.Hide` only matter once (1)
     exists; the ShellUI's call is currently a stub.
  3. **No sound.** The startup chime is not produced (audio output is accepted but nothing is mixed/played;
     the chime's source is not identified).
  4. **No kernel/loader stage.** Everything before `mini-syscore` (secure loader, kernel boot, the first
     kernel-drawn frame, the power LED/EMC) is not emulated; psemu supplies a kernel interface, not a kernel.
  5. After the logo a real console may show the user-selection screen ("Who is using this controller?") when
     several users exist; psemu has one placeholder user, so it goes straight to the home screen (the correct
     single-user behaviour).

## Update 2026-11-18 (night, end): multi-process execution (`--spawn-mode spawn`)

* **Constraint found first.** A process can back only one WHP partition with host memory: the second
  `WHvMapGpaRange` in the same process fails with `0x8007054f` (probed with a bare partition; it is the second
  partition, not the pool size). So concurrent processes cannot be separate partitions. Guest-physical space
  is 48 bits (`< 2**48` maps, `2**48` is rejected).
* **Design (the "shared area" is the machine itself).** `whp_uc.Machine` = the one partition, one vCPU and the
  page-table pool. Each process is a `WhpUc` *address space* on it: own PML4 and region table; the vCPU switches
  CR3 + registers + XSAVE between processes at slice boundaries (`Machine.acquire`, called from `emu_start`;
  `context_save/restore` of a not-loaded space keep the extended state in `_xs_saved`). The first space maps
  GPA == VA and keeps "guest memory is host memory at the same address" (the GPU path needs it: it should be the
  ShellUI); every other space gets guest-physical pages from a bump allocator at `2**47..2**48` and CPU-only host
  memory (`hostvm.HostVM(identity=False)`). The same guest address therefore holds different memory per process
  (`python -m psemu.tools_mptest`: two programs on one vCPU, separate data pages).
* **Shared kernel state** (`process.System`): one kernel-handle space and by-name event flags / semaphores - the
  same Python object in every process, so `SceBootStatusFlags` created by mini-syscore is the one AvControl opens
  and sets (logged `[evf] open ... shared with another process`). Shared guest *memory* (shm) and cross-process
  IPMI are not routed yet (`ipmibus.py` is still the scaffold); IPMI keeps the HLE answers.
* **Scheduling.** `ProcessManager` round-robins `_run_segment`; a process whose threads all wait returns `IDLE`
  and is retried (`try_resume`) after the others ran, instead of stopping as "idle in event loop"; the machine
  has one wall-clock budget and a deadlock detector (every process idle for 5000 rounds).
* **Spawning.** `--spawn-mode spawn`: `execve` from an rfork'd child starts the image as a new process
  (`ProcessManager.spawn`), retires the child thread, and tells the parent's `EVFILT_PROC` watch (NOTE_EXEC).
  `python -m psemu.run mini-syscore.elf --backend whp --spawn-mode spawn --max-seconds 40`.
* **Result.** mini-syscore and SceSysAvControl now run concurrently (AvControl draws its logo while the parent
  continues). The parent then runs the part of the boot nobody had executed before - and stops at the storage
  bring-up: `filecheck /dev/da0x8...` (fixed: `stat` of the console's storage/sensor device nodes succeeds),
  `nmount` of `/system` and `/system_ex` (accepted), then `sceFsUfsCheckCleanFlag` on `/dev/da0x9.crypt` fails
  (the sector-size ioctl `0x40046480` and the UFS superblock are not modelled), so it reboots into fsck/rescue
  mode. **Next blocker for a full boot: emulated block devices for the partitions** (sector size, a superblock with
  the clean flag; the rest of the tree is the host firmware directory), then the `SceSysCore` launch.
* Regressions: all suites, the SceSysCore -> ShellUI chain (10500 DCBs / 60 s) and the single-process splash
  run are unchanged.

## Update 2026-11-18 (night, end 2): the real boot chain runs as concurrent processes

`python -m psemu.run mini-syscore.elf --fw-root FW --backend whp --spawn-mode spawn --max-seconds 90`
(`--max-modules 80` is implied by the manager) now boots like the console up to the shell launch:

    mini-syscore -> SceSysAvControl (logo splash, runs on)
                 -> SceSysCore -> orbis_audiod, GnmCompositor, SceShellCore, coredump
                                  SceShellCore: "RESTART Shell UI" -> SceLncService launchApp(NPXS20001)

What had to be added (all unit-light, verified by the log of the real firmware's own checks):
* `/dev/da*` block devices (`devices.BlockDevice`): DIOCGSECTORSIZE/MEDIASIZE etc., seekable `pread`/`lseek`,
  a UFS2 superblock marked clean at 64 KiB (sceFsUfsCheckCleanFlag); `stat` of the console's storage nodes.
  With that every `nmount` of mini-syscore (/system, /system_ex, /system_data, /preinst ...) passes and it prints
  `Entering normal mode...` / `BEGIN NORMAL BOOT`.
* `wait4` (reap a zombie, block while children run, ECHILD otherwise; it spun before), per-process child
  bookkeeping (`children`, `child_done`), a failed spawn `execve` ends the child (NOTE_EXIT + zombie).
* A process yields after an 8 ms wall slice (`PROC_SLICE`, in `_whp_preempt`): a segment used to run until a
  thread switch, so a spinning process starved the others.
* A closed kqueue drops its registrations (fd reuse brought stale EVFILT_PROC knotes back: the parent saw a
  child exec that had not happened); `rdup` restarts at fd 3 for every rfork child (the child checks 3, 4, 5...);
  `/dev/notification*` reads block (EOF made SceSysCore's button thread spin).
* Result in 45-90 s of wall time: 8-9 processes alive at once, splash frames rendering (logo fades in and holds),
  audiod's "SceSysAudioSystemIpc" server, GnmCompositor, SceShellCore up to AppMgr; regressions unchanged
  (ShellUI chain 10000 DCBs / 60 s).

**What stops the ShellUI from starting this way (the next blocker): cross-process IPMI.** ShellCore's
`launchApp(NPXS20001)` fails (`LNC_ISOK::0x8094000b`): it talks to `SceSysCoreApp` (hosted by SceSysCore, a
different process now) over IPMI, but IPMI is still the per-process HLE stub (every invoke gets an empty
success, `create server` in one process is invisible to a client in another). The routing needs the design in
`psemu/ipmibus.py` (servers by name -> owning process, requests queued to the server's `receive`, the client
parked until the reply, out buffers copied between address spaces: all host-side reads/writes through each
process's own `uc`). Other leftovers seen: one process dies with a stack-guard style fault at
`0x4300203a40f5` (a 48-bit pointer with the high bits set: a pointer that crossed address spaces), a
`GnmCompositor` that only prints its banner, `sceKernelIccGetThermalAlert` (unmodelled ICC syscall, polled in a loop),
`machdep.*`/`kern.*` sysctls (`idps`, `rcmgr_intdev`, `curr_manumode`, `backup_restore_mode`, `dmem.init_swap`).

## Update 2026-11-19: cross-process IPMI routing (`psemu/ipmikernel.py`)

`System.ipmi` (an `IpmiKernel`) now carries IPMI between real processes: a server created in one process
(`ipmimgr_call` cmd 0 registers it by name) is reached by a client in another (connect cmd 0x400, sync invoke
0x320), buffers are copied through each side's own `uc`, and the client parks until the server answers. Servers
that no process hosts (and `SceSysAudioSystemIpc`, see below) still go through the old per-process HLE.
`python -m psemu.tools_ipmitest` covers the protocol with fake processes; the real firmware verifies the rest.

What the firmware itself showed about the kernel interface (read from libSceIpmi/SceSysCore, then confirmed
by running): 
* **Create server** `{u64 libIpmi server object; u64 name; u64 *param}`; the 0x38-byte param struct holds the
  server's *user object* at +0x30, and **that** (not the first qword) is what the kernel echoes in every packet
  header (`hdr+0x10`): libIpmi calls `userobj->vtable[...]` with it. Echoing the libIpmi object instead made the
  receive thread call its own destructor and exit after the first connect.
* **Receive** (0x201) `{data buf, size, hdr out (0x28), *len}` blocks until a packet is queued. Header:
  `+0 len, +8 type, +0xc session id, +0x10 user object`. Types: 1 connect (data: `+0x148` u64 = 0 on arrival,
  `+0x150` connect-data length, `+0x154` bytes), `0x41` a client sync invoke, `0x43` the *other* kind of
  method call (it reaches `synchMethodDispatch`, which SceSysCoreApp/2 leave as a stub returning
  `0x800205c1`). Invoke data: `u64 ctx, u32 token, u32 method, u32 n_in, u32 n_out`, inputs as `{u32 len;
  bytes}`, then each output's capacity.
* **Connect**: the server answers with cmd `0x212` (kid = session id, `{u32 result}`); the client's connect
  struct is `{data, len, *status, ...}` and *status gets the answer (the syscall result stays 0).
* **Session object**: while handling a connect the server builds a per-session object and registers it with
  cmd `0x4` (kid -1, `{u64 object, ...}`); the kernel returns a handle (libIpmi keeps it in `object+8`) and
  puts that object pointer into `ctx` of every later request on the session. Replies are cmd `0x232` on the
  handle; `0x444` ends an async dispatch (6th argument = the token). Cmd `0x46a` writes the service name.
* The client's invoke needs the transport status written through its syscall result pointer as well as the
  method result: an unwritten `0xffffffff` there was `sceApplicationInitializeForShellCore: 0xffffffff`.

Other findings on the way (all fixed):
* The executable's static TLS offset was rounded up to 16 although the linker had baked the `p_align` (8)
  offset into its code (`%fs:-0x78`), so the block sat 8 bytes off; and new threads' executable block was
  never initialised (the guest allocates it from its heap), so SceSysCore's lock-order checker (TLS)
  asserted. `thr_new` now writes the executable's .tdata/.tbss for the new thread.
* System processes need `libkernel_sys.sprx` instead of `libkernel` (SceSysCore's `sceKernelIcc*`, the
  process monitor ... come from it; they were stubs returning 0, and one of them was polled in a hot loop).
  `--spawn-mode spawn` links it (`PSEMU_LIBKERNEL_SYS=0` keeps `libkernel`).
* `SceSysAudioSystemIpc` stays on the HLE: orbis_audiod's request handler waits for the audio tick event
  (`SceSysAudioSystemEvfTick`), which the audio model does not produce, and AvControl's main thread blocks
  on that call. `PSEMU_IPMI_ROUTE_AUDIO=1` routes it anyway.

State after this: SceShellCore connects to SceSysCoreApp/SceSysCoreApp2, the invoke is answered by the real
SceSysCore handler, `sceApplicationInitializeForShellCore` succeeds, AppMgr starts and ShellCore goes on
(SceUserService, regmgr keys). The ShellUI launch (NPXS20001 as a spawned process) is the next step.
Debugging aids: `PSEMU_IPMI_TRACE=1|2` (kernel-side log; 2 = every ipmimgr call), `PSEMU_TRACE_TID`/`PSEMU_TRACE_PROC`
(log every syscall of one thread).

### 2026-11-19 (later): ShellCore past its own start-up
More of the kernel side of IPMI, found by running the real firmware:
* `0x302 {u32 *out}` on a session handle, while the server serves a request, returns the **client's pid**
  (the process monitor registers it: `0xaa120012` adds the ShellCore pid, `0xaa120009` then checks it with
  `get_authinfo(pid)` and the registry; before, `0x80aa000b` came back and ShellCore dereferenced the
  missing result). It is a 4-byte out: writing 8 clobbered the caller's stack.
* The server's reply `0x232` is `{u32 method result; u32; u64 descriptor; u32 count}` with `{ptr, len}` per
  output; the kernel copies each into the client's output buffer and writes the method result. A reply is
  matched to its request by the serving thread (several requests are in flight per session).
* A **non-negative connect answer** accepts the client (AvSetting answers with the slot index); the value is
  the client's status. A negative one refuses.
* One machine, one clock: the idle time a process skips (`clock_ns`) is shared through `System`, and it is
  only skipped when EVERY process is idle (the manager does it); `get_authinfo(pid)` looks the process up
  by its spawn pid; `rdup` fails with EBADF past 64 (a "dup until it fails" loop ran 380k times).
State: ShellCore runs its whole start-up (about 240 threads, the SceXxx servers), calls SceSysCoreApp2
`0xaa120016`, which SceSysCore does not answer yet (the next thing to chase), and SceAvSettingIpc methods
come back `0x809a00ff` from AvControl.

### 2026-11-19 (later still): AvSetting answers - cmd 0x468 and what the session handle is
`SceAvSettingIpc` methods came back `0x809a00ff` from AvControl. Its gate (every method handler) asks the
session object for its slot record: `object->vtable[4]` = `ipmimgr_call(0x468, handle, {u64 *out})`, then
checks `slot[0] == object` and the per-client permission flags it computed at connect time from
`get_authinfo(handle)`. So:
* the **handle** cmd 4 returns is fed to `get_authinfo` as the client's pid: low 16 bits = the client's pid
  (the upper bits keep one client's sessions apart); `get_authinfo(pid)` resolves it to that process and its
  authority id (ShellCore `0x3800000000000010`, ...), which AvControl compares with its allow-list;
* cmd 4's second operand points at `{u64 0x10; u64 slot record; ...}`; the kernel remembers the slot and
  returns it for `0x468(handle)`. Cmd `0x302` is the client's pid (u32 out).
* one pid space for the whole machine (`System.alloc_pid`, `getpid` = the rfork pid); before, every parent
  numbered its children from 1001 and two processes shared a pid.
Result: `SceAvSettingIpc` methods 0, 2, 0xd return 0. Still open: SceSysCoreApp2 `0xaa120016` (ShellCore main
waits for it), VdecProxy (`/dev/uvd`).
Disk note: a 200 s spawn run logs several GB; filter with grep instead of saving the whole log.

### 2026-11-19 (end): the unanswered `0xaa120016` was ShellCore shutting itself down - and the launch now reaches `spawnApp`
SceSysCoreApp2 method `0xaa120016` is **SystemReboot** (`[Syscore App] Start SystemReboot`, suspends NPXS20000 ...);
ShellCore's main thread sent it because one of its init tasks failed and it ran its normal teardown
(`ShellCoreMain::OnShutdown(true)` -> `sceApplicationSystemReboot`). The failed task was
`*CRITICAL ERROR* Failed to initialize DataTransfer (0x80020002)`: **`sysctl kern.backup_restore_mode`**
did not exist (now 0 = not in backup/restore mode; mini-syscore printed the same ENOENT).
Next gate: `launchApp(NPXS20001)` -> `initializeMountRoot: LNC_CHECK::0x8094000b (0 == sceSblDevActIsExpired2(...))`.
The check (compiled into ShellCore) asks `/dev/devact` `0x40105303` {u32 activated; ...; u32 status @+12} and, when
the unit is not activated, calls any plain-ELF executable "expired" - and the firmware psemu runs is decrypted. A
new `DevActDevice` reports an activated unit. Now LncService goes on: `Num. of logged-in users is 0`, `spawnApp`,
`execve /app0/eboot.bin` -> **a new process (the ShellUI) starts** and immediately faults at `rip=0` (unmapped, the
loader does not handle it yet) while ShellCore reports `Main thread has frozen in
sceApplicationSignalShellCoreHeartBeat()`. Also: `/app0` must map to `/system_ex/app/NPXS20001`, the process
needs the same module set as the single-process ShellUI run (app.exe.sprx, the mono runtime, ...).

### 2026-11-19 (end 2): the spawned ShellUI ran the wrong app - `/app0` comes from the nmount
`execve('/app0/eboot.bin')` was resolved by a basename search to another app's `system/vsh/app/ITEM00002/eboot.bin`
(the one that faulted at `rip=0`). The real way: LncService first `nmount`s a sandbox with a nullfs for the app,
`{fstype: nullfs, fspath: /mnt/sandbox/NPXS20001_000/app0, target: /system/vsh/app/NPXS20001}` (then dev,
system_tmp, user, system_ex ...). `sys_nmount` now records the name/value pairs machine-wide (`System.mounts`) and
the spawn takes the newest `.../app0` mount, looks its target's last component up under `system/vsh/app` and
`system_ex/app` (the dump keeps NPXS20001 in `system_ex/app`) and gives the child that directory as its own
`app_root`. The right 12 MB `eboot.bin` now loads (96 modules) and runs: it opens its clients to SceLncService
(hosted by ShellCore - routed), SceShellCoreUtil, SceAppMessaging ...
What it hits next (open): `SceLncService.0x30010` (getAppStatus) -> `0x80940004`, and SceSysCoreApp methods
`0xaa110012`/`0xaa110002` -> `0x80aa000c` (the app is not a registered application in SceSysCore/LncService: the
real launch registers the spawned pid with SceSysCoreApp2 and LncService before the app asks), then the process
ends with `exit(0)`. ShellCore itself reports `Main thread has frozen in sceApplicationSignalShellCoreHeartBeat()`.

### 2026-11-19 (end 3): the spawned ShellUI gets through Mono/PSM start-up and fails in `initializeSystemAfterPsm`
What it took (each found from the real firmware's own output):
* **App id**: SceSysCore's spawn *sets* `sysctl kern.proc.appinfo.<pid>` (0x48-byte AppInfo, app id first: ShellCore
  `0x60000100`, NPXS20001 `0x60000201`); a read returns that. The ShellUI asked SceSysCore about the id psemu used to
  invent (`0x3e8`) and got `0x80aa000c`. The set is stored machine-wide (`System.appinfo`), reads use it, each
  process's own id follows, and the old HLE "my app id" answer (SceSysCoreApp2 0xaa120009) returns it too.
* **SceLncService.0x30010 (getAppStatus)** now answers 0 for the ShellUI; **SceNpService / SceNpTrophyIpc / SceNpMgrIpc**
  stay on the HLE: ShellCore's np_ipc2 servers answer the ShellUI's first calls with "invalid syncMethodId" and never
  reply (their method tables depend on state psemu does not model), and the ShellUI then fails. A request the server
  drops (thread back in `receive` without a reply) now completes with an error instead of hanging the client.
* `kern.backup_restore_mode`, `machdep.curr_manumode`, `machdep.idps` (dummy 16 bytes) exist.
Now the process prints `[PSM] ... Loading ...`, starts MonoVM, the Login manager, the pad stack, `/dev/dce` ... and stops
with `init_system.cpp(715) initializeSystemAfterPsm: LX_ISOK2::0x80f61308` -> `Assertion Failed (0 <=
initializeSystemAfterPsm())`. The failing call (`eboot+0x87860` -> `0x87fb0`) is two libSceAudioIn/Out exports (NIDs
`IQtWgnrw6v8`, `O3FM2WXIJaI`, both called with `(0x107, 0)`, the restricted-port type) that must return 0; one
does not. Next: find what they check (state kept in libSceAudioIn/Out, filled by the SceSysAudioSystemIpc answers).

### 2026-11-19 (end 4): what `initializeSystemAfterPsm` is really calling - SceMbusIpc `0xce11000d`
The two functions that must return 0 (NIDs `IQtWgnrw6v8` = libSceAudioIn, `O3FM2WXIJaI` = libSceAudioOut, called with
`(0x107, 0)`) are one-line wrappers around **libSceMbus `eTpWp430DA4`**, an IPMI call to **SceMbusIpc method
`0xce11000d`** with `{u32 kind (1 out / 2 in); u32 0x107; u32 0; u32 pid}`. The real server (SceMbusIpc, inside SceSysCore)
answers `0x809b00ff`, printing `**setStateIndex:L93 not registered pid(0x000003ef:0x00000007)` /
`ProcessMediaInfo::setMuduleStateIndex failed (0xFFFFFFFD)`: the process is not registered for module 7 in its
ProcessMediaInfo table, although the same client registered it a moment before (`0xce110007` with module records
`{1, 0x20000007, 0xff, ..., pid}` and `{1, 0x20010008, ...}` -> 0; `0xce11002a`/`0xce110029` create the process entry).
Also changed: the session handle cmd 4 returns is exactly the client's pid (the Mbus/AvSetting handlers compare it with
the pid in the request); a server thread resolves "its" session by what it is serving, not by the handle (several
sessions of one client share the pid).
Open: why the lookup of (pid, 7) fails after the registration succeeded - either the registration stores under
another key (module id `0x20000007` vs index 7), or the 48-byte/4096-byte outputs of `0xce110029`/`0xce110028` (the
reply descriptor of those has an unexpected length field and psemu does not copy them yet) carry state the client
library needs.

### 2026-11-19 (end 5): correction - the reply/output copy is fine; Mbus registration is the open question
Following an outside review of d7bc76e (copy of its advice: instrument the existing reply path before rebuilding anything):
`IpmiKernel.reply` now logs, with `PSEMU_IPMI_TRACE=1`, each output's client capacity, the server descriptor and pointer,
the server length, any output it does NOT copy (length above capacity, with the raw descriptor entry) and what was
copied. The run shows every output copied (`0xce110029` 48 bytes, `0xce110028` 4096 bytes, `0xaa120009` 4 bytes,
`SceLncService.0x30010` 12 bytes ...), no skipped output: **the earlier note that the Mbus descriptor "has an
unexpected length" was wrong** (that reply was `0xce11002a`, which has no output). The Mbus outputs really are zero
(an empty device list).
So the `0xce11000d` rejection (`not registered pid(0x3ef:0x7)`) is a server-side lookup miss, not a reply problem.
What is known about the registration: `0xce110007` record = `{u32 1; u32 0x20000007; u32 0xff; 0; 0; 0; u32 pid}`;
the handler (`SceSysCore+0x7dfe0`) checks the session handle == the pid field, then calls `0x48a30(1, 0x20000007,
0xff, 0, 0, 0, pid)`, which reads the process's AppInfo (`sysctl kern.proc.appinfo.<pid>` = the 0x48 bytes SceSysCore
itself set) and switches on a type derived from it (accepts types 0..9, bitmasks `0x2000000`/`0xf`...). The lookup
(`0xce11000d {kind, 0x107, 0, pid}`) wants index 7 of that process. Next: log what `0x48a30` stores (key) against what
`setStateIndex` compares (an instruction-level trace of those two functions in SceSysCore).

### 2026-11-19 (end 6): tracing the Mbus registration vs lookup (function tracer `PSEMU_TRACE_FUNCS`)
New debug aid: `PSEMU_TRACE_FUNCS="SceSysCore.elf+0x48a30,..."` (with `PSEMU_TRACE_PROC=<path substring>`) logs every
entry of those functions (process, thread, six argument registers, first stack words) and lets them run.
Regression check first: all 11 unit-test tools pass; the SceSysCore -> ShellUI chain (`--spawn-mode stay --then
.../NPXS20001/eboot.bin`, 60 s, `--frames`) writes 4607 frame files at HEAD against 4622 for the sources of e820560
over the same tree (a plain `git worktree` of an old commit cannot be compared: it lacks the untracked assets), 0 failed draws.
What the trace of the failing `SceMbusIpc 0xce11000d` shows (SceSysCore offsets):
* Process creation (`0xce11002a`) builds one entry per module group with `0x79640(obj, ..., mask, ..., pid)`; the
  groups are `0x1,0x2,0x4,0x8,0x10,(5),0x100,0x200,0x400,0x800,0x4000,(0xb),0x1000,0x2000,0x10000,0x100000,(0x10),(0x11)`.
* The ShellUI registers two modules (`0xce110007` -> `0x7dfe0` -> `0x48a30` -> `0x79c90`): `{1, 0x20000007, ...}` lands in
  the object of group `0x1` (`0x20001248a0`), `{1, 0x20010008, ..., 1, ...}` in group `0x2` (`0x2000125380`).
* The failing call `0xce11000d {2, 0x107, 0, pid}` (`0x7e320` -> `0x54c80` -> `0x79890`) searches the entries (stride
  0x38, compared by `0x8d1a0`) of a **different** object, group `0x800` (`0x200012aa80`), for (pid `0x3ef`, index 7):
  none matches -> `not registered`. So registration and lookup disagree on the object (module group), not on the key.
Open: how `0x54c80` maps (kind 2, module `0x107`) to group `0x800`, and which registration the real client sends to
that group (the ShellUI sends none; either its registration depends on an answer psemu gave differently - e.g. the
48-byte `0xce110029` / `0xce110028` outputs, all zero - or group `0x800` entries are created by SceSysCore itself when
it spawns the app). Next step: trace `0x54c80`, `0x565a0`, `0x55fc0`, `0x558e0` and the `0x48a30` switch.

### 2026-11-19 (end 7): the Mbus lookup miss decoded to the entry level
(`PSEMU_TRACE_FUNCS` now also takes `PSEMU_TRACE_MEM="rdi:56,rsi:56"` to dump memory behind argument registers;
`PSEMU_IPMI_TRACE=4` dumps SceMbusIpc's process table when `0xce11000d` is answered.)
* SceMbusIpc keeps a process table (singleton, 0x30 entries x 0x20: `{valid, appId, pid, ...}`): entry 0 = app
  `0x60000100` (ShellCore) with pid `0x3ed`?, entry 1 = app `0x60000201` (the ShellUI) with pid `0x3ef`. (ShellCore's
  entry carrying `0x3ed`, the compositor's pid, rather than `0x3ee` is itself suspicious and not explained yet.)
* The failing call reaches `ProcessMediaInfo::setModuleStateIndex` (`SceSysCore+0x760a0`) -> `0x79890`, a linear search of
  the group's entries (stride 0x38) with the key compare at `0x59c10`: equal when pid is equal and `(module & 0xffff00ff)`
  (negative -> -1) is equal. The lookup key is `(pid 0x3ef, module 0x107)`; the entry the registration created for
  pid `0x3ef` has module **0**. The registration (`0xce110007` -> `0x7dfe0` -> `0x48a30`) builds its key with
  `0x59b80(out, pid, module=0, ...)` in both calls (records `{1, 0x20000007, 0xff, 0|1, ...}`): module slots 0 and 1, never 7.
* `0x48a30` first reads `sysctl [1,14,0x24,pid]` (libkernel_sys `8BrtU9maWG4`, 8 bytes out: the process's SDK version;
  its fallback on failure is `0x2500000`). psemu answered that mib with the generic 4-byte `1000`; it now serves
  `kern.proc.sdk_version.<pid>` = 5.05 (`0x05050001`). That did not change the outcome, so the module-0 key is not (only)
  a consequence of the wrong SDK answer.
Open: why the registration's module index is 0/1 where the lookup wants 7: either the client's record layout is read
differently by SceSysCore (the layout may depend on a process attribute psemu still answers wrongly, e.g. the AppInfo
fields after the app id, which SceSysCore itself sets), or entry creation for module 7 happens elsewhere (process
creation `0xce11002a`, `0x79640` per module group).

### 2026-11-19 (end 8): the module-0 registration key is a search key, the real gap is the module entry
(`PSEMU_TRACE_MEM` now takes `rdi.0x10:N`: dump N bytes at the qword stored at `[rdi+0x10]`.)
* Correction to end 7: `0x48a30` builds its key with `xor edx,edx; call 0x59b80`, so module 0 in the registration
  key is only a *search* key for the process entry; it says nothing about the module the entry should have.
* SceMbusIpc keeps 17 group objects (`0x2000124 8a0`, stride 0xae0; `[g]` = capacity 0x30, `[g+0x10]` = entry array,
  entry = 0x38 bytes `{u32 pid, u32 module, ...}`, free entry = pid/module -1). For ShellUI's pid the entries in the
  groups used by `0xce11000d` (group 0 for kind 1, group 9 for kind 2) are `{pid, module 0}`, byte-identical to
  ShellCore's. The lookup key `{pid, 0x107}` (compare masks `& 0xffff00ff`) can never equal them.
* Call order at SceSysCore (ShellUI): `0xce110007` x2 (record 0x20000007 / 0x20010008; handled while the
  Mbus init flag `0x5ceb2c` is still 0, so `0x48a30` takes its fallback path `0x5e420`, not the group tables) ->
  `0xce11002a` (process add) -> `0xce110028` x5 -> `0xce11003b` (handler `0x80350`, this is what lazily initialises
  Mbus: `0x47ac0` -> `0x71bf0`, flag := 1) -> `0xce11002f {0x20000, pid}` (handler `0x7fa00`, permission check then
  `0x51de0`, which only enables group `0x20000` globally) -> `0xce11000d {kind, 0x107, 0, pid}` -> `0x809b00ff`.
* So the group entry for module 7 has to be created between the registrations and `0xce11000d`; nothing on that
  path calls the entry-add functions (`0x799f0`, `0x75fe0`). Either the registration with the flag at 0 is supposed
  to land in the group tables (the init order differs from the real console: on hardware Mbus is probably
  initialised before any client registers, e.g. by a method ShellCore calls that psemu's ShellCore never reaches) or
  `0xce11002a` should have produced module entries from process data psemu answers differently.
Next: find what initialises Mbus on the real boot (writers of `0x5ceb2c`: only the lazy sites `0x462a4`, `0x46fc6`,
`0x47b09`, `0x49444`) and check whether ShellCore's own startup reaches one of those before the ShellUI registers.

### 2026-11-19 (end 9): the real boot log (psdevwiki "Bootprocess", 5.05-era kit log) against our run
Reference: a real boot log (user-supplied text; not committed). What it fixes in our picture:
* SceSysCore prints `[MbusBaseEnv] alloc_count/free_count/alloc_size` right after `nmount /data to /user/data`
  and before `ExpandCpuSetMode`, then spawns orbis_audiod, GnmCompositor, and ShellCore starts. We never print
  it. That text is in the Mbus kernel-event worker (`SceSysCore+0x71460`, started on thread 0x10005): it opens
  `/dev/mbus`, registers it on a kqueue and, per event, `read(fd, buf, 0x30)` then dispatches through
  `0x724c0` (switch on the u32 at +4, 0..0xb; sub 0 = "device disconnect", id at +8; sub 1 -> second switch on
  the u32 at +0 and an `ioctl(0xc0288c01)` back to /dev/mbus; sub 3 = `0x7269a`). It prints the MbusBaseEnv stats
  from that path. In psemu `/dev/mbus` is a generic stub that never signals, so the worker waits forever.
* The ShellUI's LoginMgr then sees devices that exist from boot: ids 0x0002000000000000..2 (type 2, subtype 1),
  0x1030f (type 2, subtype 13), later 0x9000000000001 (type 2, subtype 10) and the pad 0x40301 (type 1, subtype 2),
  announced as SCE_MBUS_EVENT_DEVICE_ADDED / OWNER_CHANGED. Our device list answers only the emulated pad.
  The `{1, 0x20000007}` / `{1, 0x20010008}` registrations and the module-0x107 lookup that fails are most
  likely about these kernel-reported devices, which is why the group tables hold no module-7 entry.
* Also seen against the real log: our SceSysCore gets `EVFILT_PROC NOTE_EXIT` for the pid it just added
  (`Add event : pid=0x3eb` then `NOTE_EXIT received : pid=0x3eb`), real boot has no exit; `sysctlbyname: failed -1`
  and `sceNetDuplicateIpStart failed 80410111` appear only in ours.
Next step (not done): implement `/dev/mbus` as a real event source (needs the 0x30-byte event layout and the
`0xc0288c01` ioctl reversed from `0x724c0`), delivering the boot devices above; fix the false NOTE_EXIT.

### 2026-11-19 (end 10): /dev/mbus as an event source - mechanism in, semantics only partly known
* `MbusDevice` (`/dev/mbus`): 0x30-byte messages `{u32 kind, u32 code, u64 id, ...}` (same layout as `/dev/mbus_av`),
  `read` -> EAGAIN when empty, and `sys_kevent` now marks a read filter (-1) on a device fd ready when the device
  has `ready()` data. Default behaviour is unchanged (no events). `PSEMU_MBUS_EVENTS="kind:code:id,..."` queues
  experimental events at open time.
* Gate: SceSysCore's worker (`0x71460`) only starts reading after `0x71bf0` (the lazy Mbus init, first reached by
  `0xce11003b`) sets `[0x5cf904]`; until then it sleeps in a 100 ms cond-wait loop. With the init done it consumes
  queued events (verified: kq delivers, read pops).
* What a sweep of kind 2, codes 0..11 showed (SceSysCore's own messages): code 0 = `removeDevice` (log says
  "device disconnect"), 1 = per-kind ioctl notification (kinds 0/1/5/12/13/15 only, else ignored), 2 =
  `handleKmodEvent: unknown status 2`, 3 = `busTransition`, 5 = `ownerChangeEvent`, 9 = `functionChangeEvent`
  (these three call `getDeviceType` -> `mbusGetDeviceInfoInternal` and fail `0x809b0005` for ids not in the
  registry), 10/11 = jack connected/disconnected (kind and bytes +0x18..+0x1d carry the jack), 4 = control word at +8.
  Device id = `(kind << 48) | id`.
* None of the codes *creates* a device: all look the id up in SceSysCore's own registry (`0x4deb0` -> `0x5ffd0`)
  and fail for unknown ids. So the boot devices (0x2000000000000..2, 0x1030f) get into that registry some other
  way (not a kernel event). The module-7 gap is therefore not closed by delivering events alone; the registry's
  producer (callers of `0x5ffd0`'s add counterpart, probably an IPMI method from another system process) is the
  next thing to find. No guessed events are delivered by default.

### 2026-11-19 (end 11): where the Mbus device/module registry comes from (investigation, not solved)
* SceSysCore reads `/system_ex/mbus/app_info.dat` (8472 B, a serialized dump of the module tables, contains module
  `0x107` at 0x17c and 0x540) at start-up through `readModuleInfo` (`0x56a10`: 0x18-byte header, 0x10-byte
  records via `read()`), filling `setModuleInfo`/`setModuleStateInfo` (`0x573a0`, `0x57800`). Those reads happen in
  our run (tid 0x10001, many small reads); nothing failed visibly.
* Process entries are created by SceSysCore itself at spawn: `0x16360` (called from `0x14ed8`/`0x16b87`, args
  `(table, pid, flag byte)`) runs for ShellCore (pid 0x3eb) and ShellUI (0x3f0).
* No function in `0x5e000-0x68000` runs except `0x5e420` (the type/state registrar used by `0xce110007` while the
  Mbus init flag is 0), and no event/IPMI method on our path calls `registerDevice` (`0x61990`, callers `0x50196`,
  `0x681e4`), `connectDevice` (`0x61590`, callers inside `0x5e420`'s family), `mbusOnDeviceAttach` (`0x50110`,
  caller `0x74d3c` = the kernel-event code `addDevice` path) or `mbusAddProcess` (`0x4ea20`, no direct callers).
* The lazy Mbus init is triggered by the *first LoginMgr call*: handlers `0x46290` = `mbusDeviceBindingModeDecided`,
  `0x466e0` = `mbusResolveByUserId`, `0x47ac0` = `mbusSetUserColor` (we reach it through `0xce11003b`); so on
  hardware too the registrations (`0xce110007`) precede the init, and the lookup `0xce11000d` must be satisfied by
  what `0x5e420` records, not by the group tables built at init. In our run `0x5e420` is entered for type 1 and 2
  but the group lookup (`0x79890`) still sees entries with module 0.
Next: trace the return values and effects of `0x6e430`, `0x6cd30`, `0x6c500`, `0x88370`, `0x8a110` inside `0x5e420`
(a type-1/2 module record is created there; the group entry's module field must become 7 at that point) and compare
with what `0xce11000d` searches.

### 2026-11-19 (end 12): trace of the registration path - the per-pid module entries come from app_info.dat rows
(Tracer now logs the return address `ra`; `PSEMU_TRACE_READ=<name suffix>` logs every read of a file with
position, length and first bytes.)
* `0x5e420` (the flag-0 registration of `0xce110007`) only records global module/state groups
  (`0x6cd30`/`0x6c500`/`0x88370`/`0x8a110`; `0x5f7b0` is a no-op for types 1/2). It never sees the pid, so it
  cannot create the `{pid, module}` entries the lookup needs. Registration is not where module 7 gets attached.
* The per-process entries are created at spawn by `0x4e110` (= mbusAddProcess; called from `0x4e0b9`/`0x8141e`,
  args `(appId, pid, type, ..., &appParam)`; for ShellUI `type 2`, appParam byte 5 = the app type, matching the real
  log's `appType = 0x5` for NPXS20001). It asks `0x56640(table, appType, out)` for the app type's module list and
  registers one `{pid, module}` entry per element (`0x59bd0` + `0x76ca0`), module = u32 at +0 of each 0x18-byte node
  (`0x57980`). The global `[0x5ceb58]` = 0x10d (set from the dat header by `0x56e50`) only selects the path.
* In our run the node list for app type 5 (and for ShellCore's type 0) contains module **0**, so the entries are
  `{pid, 0}`. A real ShellUI must get module 7 here (the dat holds elements `{kind 2, 7, 1}` = 0x107).
* The dat is parsed without a logged error (12 `readModuleInfo` calls, 21 `setModuleInfo`, 100 `0x57800`, 367
  element writes `0x57120`, all reads are plain sequential file reads with the expected bytes - verified with
  `PSEMU_TRACE_READ`). So the zeros are produced by the parse code itself on our run, not by a failed read.
Next: follow `0x57800`/`0x578e0`/`0x57120`/`0x57980` for the app-type-5 row: which element is written into the list
that `0x57980` later copies (it reads u32 +0 of stride-0x18 nodes at `[row+8]`, the parse writes stride-0x10
elements) - find which row the parse writes the module elements into and why the type-5 row stays empty.

### 2026-11-19 (end 13): ROOT CAUSE of the Mbus `0xce11000d` failure - ShellCore saw NPXS20001 as a DAEMON
* `app_info.dat` is a table of app kinds (verified by parsing it with the reader's own grammar down to the last
  byte): kind 5 (ShellUI) has modules 0x100..0x107, so a ShellUI process gets `{pid, 0x107}` - **if** SceSysCore's
  app type for it is SHELL_UI (5). Ours was 2 (DAEMON): row 2's modules are {0}, hence `{pid, 0}` entries and
  "not registered pid(0x3f0:0x7)".
* Why DAEMON: ShellCore opened `/system/vsh/app/NPXS20001/sce_sys/param.sfo`, which does not exist in the 5.05 dump
  (the app lives in `system_ex/app/NPXS20001`), but `Emulator.resolve_path` fell back to a basename search and
  returned the system_ex file. A real kernel answers ENOENT, ShellCore then uses `/system_ex/app/...` and classifies the
  app as SCE_LNC_APP_TYPE_SHELL_UI. Fix: app directories (`system/vsh/app/`, `system_ex/app/`) are looked up
  exactly (no basename fallback); `PSEMU_EXACT_APP_PATHS=0` restores the old behaviour.
* Result: `[SceLncService] appType={SCE_LNC_APP_TYPE_SHELL_UI}`, `appParam: appType = 0x5`, `fullPath =
  /system_ex/app/NPXS20001/eboot.bin`, processSpawn flags `1, 1, 1` as in the real log. `0xce11000d` succeeds,
  `initializeSystemAfterPsm` passes, the ShellUI initialises its UI system (UISystem timer, RenderingSettings
  1920x1080, PGraphicsDevice, compositor index 0, SystemSound, SoundScriptManager) and runs its pad loop
  (`LOST PAD DATA` messages). Single-process regression chain: no change (8500 command buffers, 0 failed).
* Also in this stretch: EVFILT_PROC events now only reach the watch of the pid that exited/exec'd (the false
  NOTE_EXIT for ShellCore's pid is gone); `debug.tentativeppid` sysctl added (the "sysctlbyname: failed -1" is gone).
* The /dev/mbus event device and the registry investigation (end 10..12) were not needed for this; they stay as
  groundwork.

### 2026-11-19 (end 14): what was eating the CPU after the ShellUI got through (SceSysCore spun at 80 %)
With the spawned ShellUI past `initializeSystemAfterPsm`, SceSysCore itself used 80 of 100 wall-seconds (the ShellUI got 9).
Three causes, all unmodelled kernel behaviour, fixed:
* `select(2)` was a stub that returned 0 at once: SceSysCore's main loop uses `select(nfds, &rfds, 0, 0, &tv)` as a
  timer. Now a real `sys_select`: ready fds (devices with `ready()`), otherwise sleep for the timeout on the virtual clock.
* `/dev/deci_*` (the debug-console pipes) and `/dev/metadbg` (the meta-debugger event stream) were opened as plain
  files; their reader threads got EOF forever. They are now blocking event devices (a read blocks, like
  `/dev/notification*`).
* `read()` on a descriptor that is not open returned 0 (EOF); the kernel answers EBADF. A SceSysCore thread
  polling `{mdbg_call; read(garbage fd, 8)}` spun 480k times (`PSEMU_READ_EBADF=0` restores EOF). `mdbg_call` itself
  is still a stub that returns 0; it reports the calling thread once when it is hammered (call #2000).
New debug aids: `PSEMU_TID_COUNTS=1` (per-thread syscall histogram for threads above 2000 calls in the summary).
Effect: SceSysCore 80 s -> 18 s of a 120 s run, the ShellUI 9 s -> 41 s; it now loads `BlankScene` and
`TransitionScene` (`UISystem` initialised). Single-process chain unchanged (9000 command buffers, 0 failed).

### 2026-11-19 (end 15): the ShellUI's authority id; PsmSharedDmem serves it; the UI loads its scenes
* ShellCore's `ScePsmSharedDmem` server (Create `0x34560000`, Lock `0x34560003`) only serves a caller whose
  `get_authinfo` authority id is the ShellUI's: `SceShellCore+0x612a70` compares it with `0x380000000000000f`. psemu
  answered the generic `0x38000000000000ff` for every non-ShellCore process, so the ShellUI's first call was refused
  (`0x81668204`, "LockSharedDmem: SharedMemory is not created"). Now `AUTHORITY_IDS_BY_TITLE` gives NPXS20001 (looked up
  through the process's `app_root`) `0x380000000000000f`; Create makes `/ScePsmSharedDmem_00000000`, Lock returns 0.
* The ShellUI now loads its whole scene list (BlankScene, TransitionScene, PSMenu, QuickMenu, SystemFG,
  Notification, VoiceRecognition, SystemOverlay, TopMenuBG, Navigation, StackScene, ShellAppBG, ShellAppScreen,
  SystemErrorDialog). It ends the run waiting in `sceVisionManagerInitialize -> 0x802e0000` (no camera) with the main
  thread on a mutex.
* What stopped other processes in the run (all known, unchanged): coredump.elf `unmapped 19 at 0x4300203a40f5`;
  SceVdecProxy `int 0x44` (/dev/uvd); SceVencProxy `exit(-1)`; fs_cleaner `exit(0)`.
Open: shm objects created by one process are still a per-process stand-in in the others ("owned by another system
process -> stand-in", 0x1000 bytes): ShellCore and ShellUI map `/ScePsmSharedDmem_00000000` separately, so nothing
written through the shared dmem is visible to the other side; `sceKernelIccGetThermalAlert` -> 0x80020002 in a loop in
ShellCore; `sceVisionManagerInitialize` 0x802e0000; `LOST PAD DATA` (no pad source yet in the spawned ShellUI).

### 2026-11-19 (end 16): why the ShellUI dies after ~1.1 s, and what was fixed on the way
* **Named shm objects are machine-wide** (`System.shm_objs`): one namespace, the same host pages mapped into every
  process that opens the object (`Emulator.map_anon(host_ptr=...)`, `mem_map_ptr`). ShellCore and the ShellUI now see each
  other's `/ScePsmSharedDmem_00000000`, `/SceShellCoreUtil`, `/SceCompositorControl` ... no more per-process stand-ins for
  objects another process created.
* **The thread that is hot at exit and the mutex owner** are in the end-of-run thread summary (`running at module+off`,
  `owner=`); `PSEMU_SHM_DUMP=<substr>` dumps shm contents at exit.
* **The ShellUI is killed by ShellCore's watchdog.** `SceShellCore+0x2f1b10` polls the LNC app record of the running ShellUI
  (`0x328bc0`: record found by `[rec+0x88]==1`; pid at `+0`, heartbeat counter at `+0x3598`); when the counter has not changed for
  1 s it logs "No heart beat of Shell UI has been observed for N msec" and, with its enable flag (`+0x28`, set by the
  constructor `0x2f19c0`), "Killing Shell UI since HP3D has timed out" -> `BlockingKill` -> `SceSysCoreApp2 0xaa12000d` ->
  `sceKernelTerminateProcess`. The counter is fed by a keep-alive the ShellUI sends to SceLncService (strings
  `SCE_LNCUTIL_KEEP_ALIVE_SHELL_UI`); in our run the ShellUI does not send one within its first second (the real boot log
  shows the same 1012 ms warning, then the keep-alive arrives). Not solved: find the keep-alive call and why it is late
  (emulation speed vs a real missing dependency). `PSEMU_TIME_SCALE=<f>` (WHP) slows the guest clock against the wall
  clock; at 0.1 the kill still came after the first 1 s window, so it is not only speed.
* **Fixed because the relaunch exposed them:** `sceKernelTerminateProcess` (652) now really stops the process
  (`ProcessManager.terminate`), so the killed ShellUI no longer keeps running next to its replacement; a finished or killed
  process's IPMI sessions are closed (the server gets a type-3 disconnect packet: libSceIpmi's server loop dispatches 1 =
  connect, 3 = disconnect, 0x41.. = requests) and its servers are removed - the restarted ShellUI was refused by
  `SceCompAppProxyUtil` ("one client of type 2" slot still held); named event flags/semaphores are machine-wide, so a
  waiter from another process is woken in its own address space (an `evf_set` in the new ShellUI wrote the dead one's
  result pointer into the wrong address space: `UC_ERR_WRITE_UNMAPPED`) and dead processes' waiters are dropped.
* **`SceSysAvControl` is a system process of the console** (mini-syscore starts it before SceSysCore): without it SceSysCore's
  `[Syscore Umd] Timeout detected ... AV control server` also terminated the ShellUI. `--also <elf>` starts extra system
  processes in spawn mode (`--also .../SceSysAvControl.elf`).

### 2026-11-20: the ShellUI's keep-alive call found
* **The protocol.** ShellCore's watchdog (`SceShellCore+0x2f1b10`, polled from its main loop about every 100 ms of guest time)
  *posts* the semaphore `SceLncUtilKeepAliveShellUI` (max 1). If the post succeeds, the previous token was consumed = the
  ShellUI is alive and the timer restarts; if it fails (the token is still there) the elapsed time grows, and after 1.0 s
  the watchdog warns ("No heart beat of Shell UI ... N msec") and, with its enable flag set, kills the ShellUI.
* **The consumer** is `eboot.bin+0x2720` (NPXS20001's eboot), called from the ShellUI's **main thread** (return address in
  the managed/PSM side, tid 0x10001) once per UI iteration. It calls `libSceSystemService` export `ZucoOmNsb7w`
  (`+0x4dd0` -> `+0x77e0`), which does `sceKernelPollSema` on the keep-alive semaphore and, when it gets the token, reports
  its status (0x1558-byte struct) to SceLncService over IPMI. The opener is export `awS+eYVuXJA` (`+0x4db0` -> `+0x7670`:
  LncService method `0x30016`, then the semaphore), called once from the ShellUI's start-up chain (`eboot+0x26d0`).
* **Verified** (`PSEMU_NO_TERMINATE=1` ignores the kill; `PSEMU_TRACE_SEMA=KeepAlive` logs polls/posts): the ShellUI that
  survives does poll the semaphore alternately taken/busy at ~40-140 ms intervals and the warnings stop - the keep-alive works;
  it just starts late. In our run the first call happens at guest time ~640 s after the spawn (the real console: within the
  first second), i.e. the main thread's start-up is what has to get faster/unblocked, not the keep-alive code.
* Where the time goes (`PSEMU_TRACE_IDLE=1` prints the virtual time skipped while every process waited, by wait kind):
  mostly the audio mix event flags (`sceAudioOutMix3f1`, ~200 s of 300), kevent waits of the ShellUI (~70 s),
  `SceVideoCoreServer` (~40 s, an IPMI event wait; the service is hosted by the ShellUI itself through
  libSceVideoCoreServerInterface) and `SceStickerCoreServer` (~18 s). Those waits expire on timeouts instead of being answered.
Next: find what the ShellUI's main thread is waiting for during its first seconds (its blocked state at the moment of the kill)
and answer it.

### 2026-11-20 (end 2): the block in the ShellUI's start-up - the compositor frame wait
* **Where the main thread stood** (`PSEMU_TRACE_BLOCK=eboot:0x10001` logs every block of a thread with its call stack and
  timeout; long waits report who ended them). At the moment ShellCore's watchdog fires, the ShellUI main thread is not blocked
  on a missing answer: it is in a native loop (`eboot+0xac3b0`) that does `usleep(1000)` until the compositor posts an event.
  It polls `libSceComposite` export `9M7HkbwUs-E` (+0x29c0): test-and-clear of bit *n* of the u32 at **control block +0x1c**
  (the shared `/SceCompositorControl` page; the server sets the bits). While it polls it never returns to the managed UI tick
  (`platform.dll+0x6dadb`) that calls the keep-alive, so the heartbeat stops. Every 1 ms sleep with nothing else runnable also
  advances the idle-skipped guest clock by 1 ms, so the 1 s watchdog window passes in 1000 polls.
* **The stand-in compositor did not answer it.** The ring commands `libSceComposite` queues are served by
  `GnmCompositorServer` (unixsock.py) on the ShellUI's vblank waits. Two fixes:
  - `0x13` (queued by `+0x15a0`, `(n << 8) | 0x13`): "sync event n" - the bit is set when the ring reaches it (in-order ring).
  - `Flip` (`0x14`) now also sets bit 1 (the frame wait polls bit 1): `PSEMU_FLIP_BIT1=0` turns this off.
  With bit 1 on every flip the main loop leaves the wait, the keep-alive polls run every ~100 ms (taken each time ShellCore
  posts), 113 flips go through and the ShellUI mounts its theme ("Mount finished [ANONYMOUS]").
* **A regression of my own shm change, fixed:** `GnmCompositorServer._locate` took the control block's address from the shm
  object's `addr`, which since the machine-wide shm is the *last mapper's* address (GnmCompositor's, not the ShellUI's) - the
  stand-in then read the ring at an address that is not mapped in the ShellUI, so the ring was never served in spawn runs.
  It now uses this process's own mapping (`shm_maps`). `PSEMU_COMP_LOG=<n>` raises the ring log limit (default 40).
* **Time dilation is still needed** to fit the first second: `PSEMU_TIME_SCALE=0.01` (guest clock 100x slower than the wall
  clock) makes the first keep-alive arrive inside the watchdog window (vt 0.4 s); at 1.0 the emulated ShellUI needs ~40 s of wall
  time for what the console does in ~1 s.
* **Next stall** (still killed at ~1.0 s of guest time): right after "Mount finished" the main thread blocks in an IPMI call to
  `SceUserService` (from `libSceUserService`, via `app.exe.sprx`), then in a Mono `sem_wait`; the keep-alive stops again.

### 2026-11-20 (end 3): the SceUserService call is not what stalls the ShellUI
(`PSEMU_TRACE_REGS="rax,r12"` prints extra registers at a hook; `PSEMU_TRACE_SEMA_ALL=1` logs every keep-alive post/poll;
`PSEMU_BLOCK_FRAMES=n` sets the stack depth of block traces.)
* **Every SceUserService request the ShellUI makes is answered within 1-2 ms of guest time** (0x3000f, 0x3000c, 0x30008,
  0x30006, 0x30004, 0x3000d). The "blocked in ipmi_invoke SceUserService" at the end of the first second was just the call in
  flight when the watchdog fired.
* **The watchdog's real timeline** (guest clock 100x slow, hook at `SceShellCore+0x2f1c6b`, regs `rax` = last good heartbeat,
  `r12` = now): ShellCore posts the keep-alive semaphore every 100 ms; each post that succeeds (the ShellUI took the previous
  token) resets the timer. Resets at vt 0.399, 0.600, 0.700, 0.801, 0.901, 1.001; from 1.001 on every post fails (nobody
  polls) and the kill comes 1.001 s later, at vt ~2.0. So the keep-alive was healthy for ~0.6 s of guest time and then the
  ShellUI main thread stopped ticking at vt ~1.0 - it did not miss its first heartbeat.
* **What the main thread does at vt ~1.0:** after the last UserService call (0x3000d, from managed
  `Sce.Vsh.UserServiceWrapper` -> `app.exe`) it enters a Mono-internal semaphore wait with no usable timeout
  (`libmonosgen+0x4e78d0 <- 0x13f12b <- 0x4dc720 <- 0x4eabf8 <- 0x247d41 <- 0x21e3d8`) and never returns; other ShellUI threads
  are all parked (cv/sem/evf/IPMI waits). Candidate cause: the one UserService answer that is an error - `0x30002` (a
  registration with the names "User1" / "sceUserServ...", in=2 chunks) returns `0x80960001` (SCE_USER_SERVICE_ERROR_NOT_
  INITIALIZED) from ShellCore's own server at vt 0.503. A failed event-callback registration would leave the managed side
  waiting for an event that can never arrive.
Next: why ShellCore's UserService server answers 0x30002 with NOT_INITIALIZED (what state it expects before it: the client's
init / user-login sequence), and whether the managed side's wait is for that registration.

### 2026-11-20 (end 4): why the ShellUI's UserService registration fails - the console has no user
* ShellCore's own `SceUserService` server (the real one, now that processes talk over IPMI) reports **no user at all**:
  `0x3000f` (GetUserIdList) returns twenty `-1`, `0x3000c` (GetForegroundUser) returns `-1`. The single-process HLE used to
  hide this by reporting one placeholder user ("Player1", `_ipmi_user_id_list`).
* Why it is empty: ShellCore reads `/system_data/priv/home/user_list.dat`, finds nothing (first boot), and writes a fresh
  empty 72-byte list (`0x40`-byte header + two u32). Per-user data would live under `/user/home/%08x/` (savedata, mms, trophy,
  webkit ...). On a real console a user exists from the first-time setup; in the real boot log the ShellUI registers
  `userId(0x10000000)` for its notification tables and later prints `#LOGIN MGR# ... UserId:0x000000ff` (no one logged in).
* The failing request is `SceUserService.0x30002`, sent by the libSceUserService function at `+0x2c90` -> `+0x530`
  (`{int userId = 0; u64; u8 flag}` + a 17-byte NUL-terminated name buffer holding "User1"): userId 0 is not in ShellCore's
  empty user table, so the server answers `0x80960001` (user service not initialized / unknown user).
* **Files are not shared between processes**: `SyscallDispatcher.vfs` (the in-memory file system for created and modified files)
  is per process, so a file one process writes (`user_list.dat`, anything under `/user`, `/system_data`) is invisible to the others.
  That has to become machine-wide (on `System`, like the shm objects) for ShellCore and the ShellUI to agree on users.
Next: (1) make the virtual file system machine-wide; (2) give the console its first user through the real path - either seed
a `user_list.dat` + `/user/home/<id>` in the format ShellCore writes, or find what makes ShellCore accept the creation
request - and check that the ShellUI's main thread then gets past the Mono wait.

### 2026-11-20 (end 5): the writable file layer is machine-wide - the ShellUI gets to its first real scene
* `SyscallDispatcher.vfs / vdirs / vgone` (files and directories the guests create, change or delete) now live on `System` when
  several processes run (properties; a lone process keeps its own). ShellCore and the ShellUI therefore see the same
  `/system_data/priv/home/user_list.dat`, `/user/home/<id>/...`, databases and flags.
* Result (guest clock 100x slow, `PSEMU_TIME_SCALE=0.01`, 100 s wall): no watchdog warning at all any more, and the ShellUI shows
  its **DbRecoveryScene** (`DbRecoveryCheckRequest() = 0 : FirstBoot = True`, `DbRecoveryProgressPanel`, then
  `OnFocusActiveSceneChanged [TopMenuBG] -> [DbRecoveryScene]`, `Scene [DbRecoveryScene : Scene] : Alive`); user id
  `0x10000001` appears (`/user/home/10000001/topmenu/conf`). At the normal clock it is still killed after ~1 s of guest time
  (speed).
Open: the "DbCorruptionOccured 0x809c112c //priv/mms/notification.db" message of the recovery scene (the notification db is
created per process from a seed), and what the first-boot recovery/preparation does next.
