"""ProcessManager: round-robin several PS4 processes (see MULTIPROCESS.md).

psemu's Emulator drives one process with run(). run() is now a thin wrapper over
three steps - begin_run() (prologue), _run_segment() (one scheduling segment),
end_run() (epilogue) - so a manager can start several Emulators and interleave
their segments instead of running one to completion.

This is the phase-2 scaffold: for a single process it is exactly equivalent to
Emulator.run(). Running MORE than one process concurrently additionally needs
(phase 3) each process to have its own unicorn.Uc and native CPU state, and
(phase 4) a shared System (IPMI bus, named objects, shared host memory) that the
processes communicate through. Those are not here yet; the manager is kept
minimal and correct for one process so the stepping contract is exercised and
regression-tested before the harder pieces land.
"""


import os


class System:
    """Kernel state every process on the machine sees: one kernel-handle space and the named
    event flags / semaphores (the same Python object in every process's table, so a bit one process
    sets wakes another's waiter). IPMI routing between processes still goes through the HLE layer."""

    def __init__(self):
        self._next_handle = 0x100
        self.evfs = {}            # name -> sys_sync.EventFlag
        self.sems = {}            # name -> sys_sync.Semaphore
        self.mounts = {}          # nmount fspath -> its name/value pairs
        self.vfs = {}             # the writable file layer (guest path -> contents) every process sees
        self.vdirs = {"/sqlite"}  # directories the guests created
        self.vgone = set()        # firmware paths a guest deleted
        self.shm_objs = {}        # shm_open name -> object (size, shared host pages): one namespace per machine
        self.appinfo = {}         # pid -> the 0x48-byte AppInfo set through sysctl kern.proc.appinfo.<pid>
        self.clock_ns = 0         # virtual time skipped while everything slept (shared: one clock per machine)
        from .ipmikernel import IpmiKernel
        self.ipmi = IpmiKernel(log=lambda m: print(m, flush=True))

    def alloc_pid(self):
        self._next_pid = getattr(self, '_next_pid', 1001)
        self._next_pid += 1
        return self._next_pid - 1

    def alloc_handle(self):
        h = self._next_handle
        self._next_handle += 1
        return h


class ProcessManager:
    def __init__(self):
        self.procs = []           # list of [emu, cur]  (cur None once finished)

    def add(self, emu, start=None):
        """Register and start a process; returns the emulator."""
        if getattr(self, "system", None) is None:
            self.system = System()
        emu.system = self.system
        emu.manager = self
        if emu.whp and emu.shared_machine is None:
            emu.shared_machine = emu.uc.m          # later images (and exec'd ones) join this partition
        cur = emu.begin_run(start)
        self.procs.append([emu, cur])
        return emu

    def spawn(self, parent, path, argv, app_root=None):
        """Start `path` as a new process next to `parent` (sys_execve with --spawn-mode spawn)."""
        from .emulator import Emulator
        emu = Emulator(path, trace=parent.trace, max_insns=parent.max_insns, fw_root=parent.fw_root,
                       backend="whp" if parent.whp else "unicorn", shared_machine=parent.shared_machine,
                       host_identity=False)
        emu.parent = parent
        if app_root:
            emu.app_root = app_root              # this app's own /app0
        emu.max_seconds = parent.max_seconds
        emu._t0 = parent._t0
        emu.max_modules = parent.max_modules
        emu.spawn_mode = parent.spawn_mode
        emu.gpu_enabled = getattr(parent, "gpu_enabled", True)
        emu.frame_dir = getattr(parent, "frame_dir", None)
        emu.frame_every = getattr(parent, "frame_every", 60)
        tag = "%s" % path.replace("\\", "/").rsplit("/", 1)[-1]
        plog = parent.log
        emu.log = lambda *a, **k: plog(f"[{tag}]", *a)
        return self.add(emu)

    def _process_gone(self, p):
        """A process finished (or was terminated): its IPMI sessions and servers go away, and its parent's
        EVFILT_PROC watch and wait4() see the exit."""
        emu = p[0]
        if getattr(emu, "_exit_told", False):
            return
        emu._exit_told = True
        sysm = getattr(self, "system", None)
        ipk = getattr(sysm, "ipmi", None)
        if ipk is not None:
            ipk.process_gone(emu)
        for objs in ((sysm.evfs, sysm.sems) if sysm is not None else ()):      # its threads no longer wait on shared objects
            for o in objs.values():
                o.waiters[:] = [t for t in o.waiters
                                if not (isinstance(t.wait, dict) and t.wait.get("emu") is emu)]
        if getattr(emu, "parent", None) is not None:
            parent = emu.parent
            parent.syscalls.proc_event(parent.syscalls.NOTE_EXIT, 0, getattr(emu, "child_pid", 0))
            parent.syscalls.child_done(getattr(emu, "child_pid", 0), 0)

    def terminate(self, pid):
        """sceKernelTerminateProcess: stop the process with this pid. True when there was one running."""
        for p in self.procs:
            if p[1] is not None and getattr(p[0], "child_pid", 0) == pid:
                p[1] = None
                p[0]._stop_reason = p[0]._stop_reason or f"terminated (pid {pid:#x})"
                self._process_gone(p)
                return True
        return False

    def others_alive(self, emu):
        return any(p[0] is not emu and p[1] is not None for p in self.procs)

    def step_all(self):
        """Advance every live process by one scheduling segment. Returns True
        while at least one process is still runnable."""
        from .emulator import IDLE
        import time
        alive = False
        progressed = False
        for p in list(self.procs):
            if p[1] is None:
                continue
            if p[1] == IDLE:
                p[1] = p[0].try_resume()
                if p[1] != IDLE:
                    progressed = True
            else:
                _t = time.perf_counter()
                p[1] = p[0]._run_segment(p[1])
                p[0]._seg_wall = getattr(p[0], '_seg_wall', 0.0) + time.perf_counter() - _t
                p[0]._seg_n = getattr(p[0], '_seg_n', 0) + 1
                if p[1] != IDLE:
                    progressed = True
            if p[1] is not None:
                alive = True
            else:
                self._process_gone(p)
        for p in self.procs:                    # one wall-clock budget for the whole machine
            ms = p[0].max_seconds
            if p[1] is not None and ms is not None and p[0]._time() - p[0]._t0 >= ms:
                for q in self.procs:
                    if q[1] is not None:
                        q[0]._stop_reason = q[0]._stop_reason or f"wall-clock budget reached ({ms:g} s)"
                        q[1] = None
                return False
        if alive and not progressed:
            # every process is idle: skip the machine's clock to the earliest sleeper's deadline
            dl = [(p[0].sched.next_deadline(), p[0]) for p in self.procs if p[1] is not None and p[0].sched is not None]
            dl = [(d, e) for d, e in dl if d is not None]
            if dl:
                d, e = min(dl, key=lambda x: x[0])
                delta = d - e.sched.now_ns()
                if delta > 0:
                    if os.environ.get("PSEMU_TRACE_IDLE"):       # who made the machine skip idle time (by wait kind)
                        t0 = next((t for t in e.sched.threads.values() if t.state == "blocked" and t.deadline == d), None)
                        w = t0.wait if t0 is not None and isinstance(t0.wait, dict) else {}
                        key = (e.path.replace(chr(92), "/").rsplit("/", 1)[-1], w.get("kind"), str(w.get("name") or w.get("sema") or w.get("evf") or ""),
                               "%#x" % t0.tid if t0 else "?")
                        acc = self.__dict__.setdefault("_idle_acc", {})
                        acc[key] = acc.get(key, 0) + delta
                    self.system.clock_ns += delta
                for q in self.procs:
                    if q[1] is not None and q[0].sched is not None:
                        q[0].sched.expire_timeouts()
                self._stalled = 0
                return alive
            self._stalled = getattr(self, "_stalled", 0) + 1
            time.sleep(0.001)
            if self._stalled > 5000:
                for q in self.procs:
                    if q[1] is not None:
                        q[0]._stop_reason = "deadlock: every process is waiting for another"
                        q[1] = None
                return False
        else:
            self._stalled = 0
        return alive

    def run(self):
        """Drive all processes to completion, round-robin. Returns the list of
        per-process stop reasons."""
        while self.step_all():
            pass
        for emu, _ in self.procs:
            print(f"  [sched] {emu.path.rsplit(chr(92),1)[-1]}: {getattr(emu,'_seg_wall',0):.1f} s in {getattr(emu,'_seg_n',0)} segments", flush=True)
        acc = self.__dict__.get("_idle_acc")
        if acc:
            print("  [idle] virtual time skipped while every process waited (s, process, wait, name, tid):", flush=True)
            for k, v in sorted(acc.items(), key=lambda kv: -kv[1])[:12]:
                print(f"    {v / 1e9:9.1f}  {k}", flush=True)
        if os.environ.get("PSEMU_SHM_DUMP"):          # PSEMU_SHM_DUMP=<name>: the first words of that shm object at exit
            import ctypes
            for name, o in getattr(self.system, "shm_objs", {}).items():
                if o.get("host") and os.environ["PSEMU_SHM_DUMP"] in name:
                    n = min(o["host_size"], 0x4000)
                    raw = ctypes.string_at(o["host"], n)
                    print(f"  [shm] {name}: {n:#x} bytes; +0 {raw[:32].hex()}; " +
                          ("+0x3590 " + raw[0x3590:0x35b0].hex() if n > 0x35b0 else ""), flush=True)
        for emu, _ in self.procs:
            emu.end_run()
        return [emu._stop_reason for emu, _ in self.procs]
