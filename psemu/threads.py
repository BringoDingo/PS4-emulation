"""Guest threads on psemu's single emulated CPU.

The PS4 kernel runs each `thr_new` thread on its own core. psemu has one
Unicorn CPU, so threads take turns on it: each thread owns a saved CPU
context (`uc.context_save()`, which includes FS/GS base and the SSE/AVX
state), and the scheduler switches by saving the running thread's context and
restoring the next one's, then restarting emulation at its RIP.

Switches happen
  * when the running thread has used its time slice (preemption, from the
    per-instruction hook: the current instruction is not executed yet and
    simply runs when the thread resumes), and
  * when a syscall blocks the thread (`block()`), or the thread exits.

A blocked thread waits for `wake(thread, ret)`; the value is placed in RAX
(with the carry flag for errors, FreeBSD convention) when it next runs.
Blocked threads may carry a deadline on psemu's virtual clock: when no
thread is runnable the clock jumps to the earliest deadline and that thread
times out (the emulated machine never really idles). No runnable thread and
no deadline is a deadlock, reported with what every thread is waiting for.
"""
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSP,
                               UC_X86_REG_RIP, UC_X86_REG_RFLAGS, UC_X86_REG_FS_BASE,
                               UC_X86_REG_GS_BASE, UC_X86_REG_RBP)

READY, RUNNING, BLOCKED, EXITED = "ready", "running", "blocked", "exited"


class Thread:
    def __init__(self, tid, name=""):
        self.tid = tid
        self.name = name
        self.state = READY
        self.ctx = None           # saved UcContext while not running
        self.pending = None       # (value, error) to load into RAX on resume
        self.wait = None          # description of what a blocked thread waits for
        self.deadline = None      # virtual ns; None = no timeout
        self.timeout_ret = None   # (value, error) delivered when the deadline passes
        self.insns = 0
        self.switches_in = 0
        self.spawn_child = False   # created by rfork() for a process spawn
        # Stopped by another thread (thr_suspend_ucontext, used by Mono's
        # stop-the-world): it keeps its state (a blocked thread stays blocked and
        # may even become READY) but the scheduler will not run it until resumed.
        self.suspended = False

    def __repr__(self):
        return (f"<thread {self.tid:#x} {self.name!r} {self.state}"
                + (" suspended" if self.suspended else "") + ">")


class Scheduler:
    SLICE = 100_000               # instructions per time slice

    def __init__(self, emu):
        self.emu = emu
        self.threads = {}         # tid -> Thread (exited ones kept for the summary)
        self.order = []           # round-robin order of tids
        self.current = None
        self.next_tid = 0
        self.slice_left = self.SLICE
        self.clock_ns = 0         # virtual time added by timeouts / sleeps (property)
        self.switch_pending = False
        self.switches = 0
        self.created = 0

    @property
    def clock_ns(self):
        # one machine, one clock: with several processes the skipped idle time is shared through System
        sysm = getattr(self.emu, 'system', None)
        return sysm.clock_ns if sysm is not None else self._clock_ns

    @clock_ns.setter
    def clock_ns(self, v):
        self._clock_ns = v
        sysm = getattr(self.emu, 'system', None)
        if sysm is not None:
            sysm.clock_ns = v
        native = getattr(self.emu, "native", None)
        if native is not None:
            native.s.clock_ns = v         # the native rdtsc hook reads it

    # ---- setup -----------------------------------------------------------
    def adopt_main(self, tid, name="main"):
        t = Thread(tid, name)
        t.state = RUNNING
        self.threads[tid] = t
        self.order.append(tid)
        self.current = t
        self.next_tid = tid + 1
        return t

    @property
    def multi(self):
        return sum(1 for t in self.threads.values() if t.state != EXITED) > 1

    # ---- creation / exit ------------------------------------------------
    def spawn(self, start, arg, stack_top, tls_base, name=""):
        """A new thread that starts at `start(arg)` on `stack_top` with FS base
        `tls_base` (amd64 thr_new semantics); runnable immediately."""
        uc = self.emu.uc
        tid = self.next_tid
        self.next_tid += 1
        t = Thread(tid, name or f"thread{tid:#x}")
        # build its initial register state on the live CPU, snapshot it, then
        # put the running thread's state back
        cur = uc.context_save()
        rsp = (stack_top & ~0xF) - 8          # as if `call start` pushed a return
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.mem_write(rsp, b"\x00" * 8)        # returning from start_func faults cleanly
        uc.reg_write(UC_X86_REG_RBP, 0)
        uc.reg_write(UC_X86_REG_RDI, arg)
        uc.reg_write(UC_X86_REG_RIP, start)
        uc.reg_write(UC_X86_REG_RFLAGS, 0x202)
        uc.reg_write(UC_X86_REG_FS_BASE, tls_base)
        t.ctx = uc.context_save()
        uc.context_restore(cur)
        self.threads[tid] = t
        self.order.append(tid)
        self.created += 1
        return t

    def fork_current(self, rip, regs, name=""):
        """A copy of the running thread's CPU state that resumes at `rip`
        with `regs` ({unicorn reg: value}) changed: the child of a vfork-style
        rfork(RFPROC|RFMEM), which shares the address space."""
        uc = self.emu.uc
        tid = self.next_tid
        self.next_tid += 1
        t = Thread(tid, name or f"child{tid:#x}")
        cur = uc.context_save()
        for r, v in regs.items():
            uc.reg_write(r, v)
        uc.reg_write(UC_X86_REG_RIP, rip)
        t.ctx = uc.context_save()
        uc.context_restore(cur)
        self.threads[tid] = t
        self.order.append(tid)
        self.created += 1
        return t

    def exit_current(self):
        t = self.current
        t.state = EXITED
        self.request_switch()

    # ---- blocking --------------------------------------------------------
    def block(self, what, deadline_ns=None, timeout_ret=None):
        """Block the running thread (called from inside a syscall handler)."""
        t = self.current
        t.state = BLOCKED
        t.wait = what
        t.deadline = deadline_ns
        t.timeout_ret = timeout_ret
        self.request_switch()

    def wake(self, t, value=0, error=False):
        if t.state != BLOCKED:
            return False
        t.state = READY
        t.wait = None
        t.deadline = None
        t.pending = (value, error)
        return True

    # ---- switching -------------------------------------------------------
    def request_switch(self):
        self.switch_pending = True
        self.emu.uc.emu_stop()

    def tick(self, uc, address):
        """Python per-instruction hook (no native hook): True when the slice ran out and another
        thread is runnable (the CPU is stopped *before* `address` runs)."""
        self.slice_left -= 1
        if self.slice_left > 0:
            return False
        if not self.slice_expired(uc, address):
            return False
        self.emu.uc.emu_stop()
        return True

    def slice_expired(self, uc, address):
        """The running thread used its slice (the CPU is stopped before
        `address`): True when another thread is runnable and a switch is now
        pending."""
        self.slice_left = self.SLICE
        self.expire_timeouts()
        if not any(self.threads[tid].state == READY for tid in self.order):
            return False
        uc.reg_write(UC_X86_REG_RIP, address)
        self.switch_pending = True
        return True

    def _pick(self):
        n = len(self.order)
        start = self.order.index(self.current.tid) if self.current else -1
        for k in range(1, n + 1):
            t = self.threads[self.order[(start + k) % n]]
            if t.state == READY and not t.suspended:
                return t
        return None

    def switch(self):
        """Run-loop side of a switch: returns the RIP to restart at, or None
        when nothing can run (all threads exited, or deadlocked)."""
        uc = self.emu.uc
        self.switch_pending = False
        cur = self.current
        if cur is not None and cur.state != EXITED and cur.ctx is None:
            cur.ctx = uc.context_save()
            if cur.state == RUNNING:
                cur.state = READY
        self.expire_timeouts()
        nxt = self._pick()
        if nxt is None:
            nxt = self._advance_clock()
        if nxt is None:
            return None
        if nxt is not cur or cur.ctx is not None:
            uc.context_restore(nxt.ctx)
        nxt.ctx = None
        nxt.state = RUNNING
        nxt.switches_in += 1
        if nxt.pending is not None:
            value, error = nxt.pending
            nxt.pending = None
            uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
            fl = uc.reg_read(UC_X86_REG_RFLAGS)
            uc.reg_write(UC_X86_REG_RFLAGS, (fl | 1) if error else (fl & ~1))
        if nxt is not cur:
            self.switches += 1
        self.current = nxt
        self.slice_left = self.SLICE
        return uc.reg_read(UC_X86_REG_RIP)

    # ---- virtual time ----------------------------------------------------
    NS_PER_INSN = 1               # ~1 GHz guest: one instruction = 1 ns

    def now_ns(self):
        """Virtual time: executed instructions plus idle time skipped while
        every thread was waiting for a deadline."""
        return self.emu._insn_count * self.NS_PER_INSN + self.clock_ns

    def expire_timeouts(self):
        """Wake every blocked thread whose deadline has passed."""
        now = self.now_ns()
        for t in self.threads.values():
            if t.state == BLOCKED and t.deadline is not None and t.deadline <= now:
                on_timeout = t.wait.get("on_timeout") if isinstance(t.wait, dict) else None
                if on_timeout:
                    on_timeout(t)             # may set t.timeout_ret (e.g. events delivered)
                ret = t.timeout_ret or (0, False)
                self.wake(t, *ret)

    def next_deadline(self):
        d = [t.deadline for t in self.threads.values() if t.state == BLOCKED and t.deadline is not None]
        return min(d) if d else None

    def _advance_clock(self):
        # Skip idle time to the next deadline. A thread that wakes up but is
        # suspended cannot run, so keep skipping until something runnable wakes
        # (or nothing is left with a deadline -> real deadlock).
        mgr = getattr(self.emu, 'manager', None)
        if mgr is not None and mgr.others_alive(self.emu):
            return None            # the machine's idle time is skipped by the manager once EVERY process is idle
        for _ in range(64):
            timed = [t for t in self.threads.values()
                     if t.state == BLOCKED and t.deadline is not None]
            if not timed:
                return None
            t = min(timed, key=lambda x: x.deadline)
            delta = t.deadline - self.now_ns()
            if delta > 0:
                self.clock_ns += delta
            self.expire_timeouts()
            nxt = self._pick_any_ready()
            if nxt is not None:
                return nxt
        return None

    def _pick_any_ready(self):
        for tid in self.order:
            t = self.threads[tid]
            if t.state == READY and not t.suspended:
                return t
        return None

    # ---- reporting -------------------------------------------------------
    def describe(self):
        def what(w):
            if isinstance(w, dict):
                txt = ", ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}"
                                for k, v in w.items() if not callable(v))
                if w.get("kind") in ("mutex_wait", "mutex_lock") and isinstance(w.get("addr"), int):
                    try:                      # struct umutex: u32 owner tid at +0
                        txt += ", owner=%#x" % int.from_bytes(bytes(self.emu.uc.mem_read(w["addr"], 4)), "little")
                    except Exception:
                        pass
                return txt
            return str(w)
        def where(t):
            # the thread that is on the CPU when the run ends: say where (module+offset)
            if t is not self.current or t.state != RUNNING:
                return ""
            try:
                from unicorn.x86_const import UC_X86_REG_RIP
                rip = self.emu.uc.reg_read(UC_X86_REG_RIP)
                m = self.emu.dyn.module_at(rip) if getattr(self.emu, "dyn", None) else None
                return f" at {m.name}+{rip - m.base:#x}" if m else f" at {rip:#x}"
            except Exception:
                return ""
        return "; ".join(f"{t.tid:#x} {t.name}: {t.state}" + where(t) +
                         (f" ({what(t.wait)})" if t.wait else "")
                         for t in self.threads.values())

    def summary(self):
        if self.created == 0:
            return "threads: main only; " + self.describe()
        return (f"threads: {len(self.threads)} ({self.created} created), "
                f"{self.switches} switches; " + self.describe())
