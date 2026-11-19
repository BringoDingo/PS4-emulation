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


class System:
    """Kernel state every process on the machine sees: one kernel-handle space and the named
    event flags / semaphores (the same Python object in every process's table, so a bit one process
    sets wakes another's waiter). IPMI routing between processes still goes through the HLE layer."""

    def __init__(self):
        self._next_handle = 0x100
        self.evfs = {}            # name -> sys_sync.EventFlag
        self.sems = {}            # name -> sys_sync.Semaphore
        from .ipmikernel import IpmiKernel
        self.ipmi = IpmiKernel(log=lambda m: print(m, flush=True))

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

    def spawn(self, parent, path, argv):
        """Start `path` as a new process next to `parent` (sys_execve with --spawn-mode spawn)."""
        from .emulator import Emulator
        emu = Emulator(path, trace=parent.trace, max_insns=parent.max_insns, fw_root=parent.fw_root,
                       backend="whp" if parent.whp else "unicorn", shared_machine=parent.shared_machine,
                       host_identity=False)
        emu.parent = parent
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
            elif getattr(p[0], "parent", None) is not None and not getattr(p[0], "_exit_told", False):
                p[0]._exit_told = True           # a child process finished: its parent's proc watch fires
                parent = p[0].parent
                parent.syscalls.proc_event(parent.syscalls.NOTE_EXIT, 0)
                parent.syscalls.child_done(getattr(p[0], "child_pid", 0), 0)
        for p in self.procs:                    # one wall-clock budget for the whole machine
            ms = p[0].max_seconds
            if p[1] is not None and ms is not None and p[0]._time() - p[0]._t0 >= ms:
                for q in self.procs:
                    if q[1] is not None:
                        q[0]._stop_reason = q[0]._stop_reason or f"wall-clock budget reached ({ms:g} s)"
                        q[1] = None
                return False
        if alive and not progressed:
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
        for emu, _ in self.procs:
            emu.end_run()
        return [emu._stop_reason for emu, _ in self.procs]
