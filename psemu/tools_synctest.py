"""Scenario test for the blocking semaphore and event-flag syscalls.

    python -m psemu.tools_synctest

Drives SyncSyscalls directly: three guest threads on a real Scheduler, a
Unicorn CPU for registers and guest memory, and syscalls issued "as" a given
thread. Checks return values, who is blocked/woken with what, token counts,
timeouts on the virtual clock and the timeout write-back.
"""
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI,
                               UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_RFLAGS)

from .sys_sync import EACCES, EBUSY, ECANCELED, EINVAL, ESRCH, ETIMEDOUT
from .syscalls import SyscallDispatcher
from .threads import Scheduler

MEM = 0x10000


class FakeEmu:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc.mem_map(MEM, 0x10000)
        self.trace = False
        self.native = None
        self._insn_count = 0
        self.lines = []
        self.sched = Scheduler(self)
        self.syscalls = SyscallDispatcher(self)
        self.dyn = None

    def log(self, msg):
        self.lines.append(msg)

    def stop(self, reason):
        raise AssertionError("emulator stopped: " + reason)


class Harness:
    def __init__(self):
        self.emu = FakeEmu()
        s = self.emu.sched
        self.A = s.adopt_main(0x10001, "A")
        self.B = s.spawn(0, 0, MEM + 0x8000, 0, "B")
        self.C = s.spawn(0, 0, MEM + 0x9000, 0, "C")
        self.failures = 0
        self.checks = 0
        self.uc = self.emu.uc
        self.uc.mem_write(MEM, b"TestSema\x00")

    def run_as(self, t, name, *args):
        """Issue syscall `name` as thread t; returns (value, error) or 'blocked'."""
        s = self.emu.sched
        s.current = t
        t.state = "running"
        s.switch_pending = False
        regs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10)
        for r, v in zip(regs, args + (0,) * (4 - len(args))):
            self.uc.reg_write(r, v & 0xFFFFFFFFFFFFFFFF)
        getattr(self.emu.syscalls, "sys_" + name)(self.uc)
        if t.state == "blocked":
            return "blocked"
        return (self.uc.reg_read(UC_X86_REG_RAX), bool(self.uc.reg_read(UC_X86_REG_RFLAGS) & 1))

    def check(self, what, got, want):
        self.checks += 1
        if got != want:
            self.failures += 1
            print(f"  FAIL {what}: got {got!r}, want {want!r}")

    def woken(self, t):
        """(value, error) a woken thread will see, or its state."""
        if t.state != "ready":
            return t.state
        return t.pending[0], t.pending[1]

    def u32(self, a):
        return struct.unpack("<I", bytes(self.uc.mem_read(a, 4)))[0]


def sema_tests(h):
    A, B, C = h.A, h.B, h.C
    sems = lambda: h.emu.syscalls.sems
    TO = MEM + 0x100                       # u32 timeout_us
    NW = MEM + 0x110                       # s32 num_waiters

    h.check("create init>max", h.run_as(A, "osem_create", MEM, 1, 3, 2), (EINVAL, True))
    hd, err = h.run_as(A, "osem_create", MEM, 1, 0, 2)
    h.check("create ok", err, False)
    h.check("wait unknown handle", h.run_as(A, "osem_wait", 0x7777, 1, 0), (ESRCH, True))
    h.check("wait need>max", h.run_as(A, "osem_wait", hd, 3, 0), (EINVAL, True))
    h.check("poll empty", h.run_as(B, "osem_trywait", hd, 1), (EBUSY, True))
    h.check("A waits (no timeout)", h.run_as(A, "osem_wait", hd, 1, 0), "blocked")
    h.check("post 1 ok", h.run_as(B, "osem_post", hd, 1), (0, False))
    h.check("A woken with 0", h.woken(A), (0, False))
    h.check("token went to A", sems()[hd].count, 0)

    # a waiter that needs 2 doesn't block one behind it that needs 1
    h.uc.mem_write(TO, struct.pack("<I", 500))
    h.check("B waits need 2, 500us", h.run_as(B, "osem_wait", hd, 2, TO), "blocked")
    h.check("C waits need 1", h.run_as(C, "osem_wait", hd, 1, 0), "blocked")
    h.check("A posts 1", h.run_as(A, "osem_post", hd, 1), (0, False))
    h.check("B still waiting", B.state, "blocked")
    h.check("C woken", h.woken(C), (0, False))
    h.check("count after C", sems()[hd].count, 0)
    h.check("post over max", h.run_as(A, "osem_post", hd, 3), (EINVAL, True))
    h.check("post 1 (B needs 2)", h.run_as(A, "osem_post", hd, 1), (0, False))
    h.check("B still waiting (1 of 2)", B.state, "blocked")
    # time passes on the virtual clock: B times out, *timeout = 0
    h.emu._insn_count += 600_000           # 600 us at 1 ns/insn
    h.emu.sched.expire_timeouts()
    h.check("B timed out", h.woken(B), (ETIMEDOUT, True))
    h.check("timeout written back 0", h.u32(TO), 0)
    h.check("token left after timeout", sems()[hd].count, 1)
    h.check("zero timeout fails at once", (h.uc.mem_write(TO, b"\0" * 4),
                                           h.run_as(B, "osem_wait", hd, 2, TO))[1],
            (ETIMEDOUT, True))

    # timeout remaining is written back on success
    h.uc.mem_write(TO, struct.pack("<I", 1000))
    h.check("B waits need 2, 1000us", h.run_as(B, "osem_wait", hd, 2, TO), "blocked")
    h.emu._insn_count += 300_000
    h.check("C posts 1 -> B gets 2", h.run_as(C, "osem_post", hd, 1), (0, False))
    h.check("B woken", h.woken(B), (0, False))
    h.check("remaining written back", h.u32(TO), 700)

    # cancel: waiters get ECANCELED, count reset; -1 restores the initial count
    h.check("A waits", h.run_as(A, "osem_wait", hd, 1, 0), "blocked")
    h.check("C waits", h.run_as(C, "osem_wait", hd, 2, 0), "blocked")
    h.check("cancel set 2", h.run_as(B, "osem_cancel", hd, 2, NW), (0, False))
    h.check("num waiters", h.u32(NW), 2)
    h.check("A canceled", h.woken(A), (ECANCELED, True))
    h.check("C canceled", h.woken(C), (ECANCELED, True))
    h.check("count after cancel", sems()[hd].count, 2)
    h.check("cancel -1", h.run_as(B, "osem_cancel", hd, -1, 0), (0, False))
    h.check("count back to init", sems()[hd].count, 0)

    # delete: waiters get EACCES; the handle is gone
    h.check("A waits", h.run_as(A, "osem_wait", hd, 1, 0), "blocked")
    h.check("delete", h.run_as(B, "osem_delete", hd), (0, False))
    h.check("A sees EACCES", h.woken(A), (EACCES, True))
    h.check("deleted handle", h.run_as(B, "osem_post", hd, 1), (ESRCH, True))

    # open by name finds the same object
    hd2, _ = h.run_as(A, "osem_create", MEM, 1, 1, 1)
    h.check("open by name", h.run_as(B, "osem_open", MEM), (hd2, False))


def main():
    h = Harness()
    sema_tests(h)
    print(f"semaphores: {h.checks} checks, {h.failures} failed")
    return 1 if h.failures else 0


if __name__ == "__main__":
    sys.exit(main())
