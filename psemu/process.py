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


class ProcessManager:
    def __init__(self):
        self.procs = []           # list of [emu, cur]  (cur None once finished)

    def add(self, emu, start=None):
        """Register and start a process; returns the emulator."""
        cur = emu.begin_run(start)
        self.procs.append([emu, cur])
        return emu

    def step_all(self):
        """Advance every live process by one scheduling segment. Returns True
        while at least one process is still runnable."""
        alive = False
        for p in self.procs:
            if p[1] is not None:
                p[1] = p[0]._run_segment(p[1])
            if p[1] is not None:
                alive = True
        return alive

    def run(self):
        """Drive all processes to completion, round-robin. Returns the list of
        per-process stop reasons."""
        while self.step_all():
            pass
        for emu, _ in self.procs:
            emu.end_run()
        return [emu._stop_reason for emu, _ in self.procs]
