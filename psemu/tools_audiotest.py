"""Unit test of the pieces the audio start-up needs: the audio server's period pacing, the
sched_get_priority_{min,max} / rtprio_thread syscalls libScePsm's mixer thread setup relies on.

    python -m psemu.tools_audiotest
"""
import struct
import sys

from . import audioserver
from .syscalls import SyscallDispatcher


class Mem:
    def __init__(self):
        self.m = {}

    def mem_write(self, a, d):
        for i, b in enumerate(bytes(d)):
            self.m[a + i] = b

    def mem_read(self, a, n):
        return bytearray(self.m.get(a + i, 0) for i in range(n))


class Sc(SyscallDispatcher):
    """Dispatcher without an emulator: arguments in, (value, error) out."""

    def __init__(self, args):
        self._a = args
        self.out = None
        self.emu = type("E", (), {"sched": None})()

    def _args(self, uc):
        return tuple(self._a) + (0,) * (6 - len(self._a))

    def _ret(self, uc, value, error=False):
        self.out = (value, error)


def main():
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print("  %-66s %s %s" % (name, "PASS" if cond else "FAIL", extra))

    p = audioserver.PERIOD_NS
    check("period is 256 frames at 48 kHz (5.333 ms)", p == 5_333_333, "(%d ns)" % p)
    check("next_period is strictly after now and on a boundary",
          audioserver.next_period(0) == p and audioserver.next_period(p) == 2 * p
          and audioserver.next_period(p - 1) == p and audioserver.next_period(3 * p + 1) == 4 * p)
    check("mix event flags are recognised by name", audioserver.is_mix_evf("sceAudioOutMix3e8")
          and not audioserver.is_mix_evf("SceShellCoreUtilAppFocus"))

    for pol in (1, 2, 3):
        lo, hi = Sc([pol]), Sc([pol])
        lo.sys_sched_get_priority_min(None)
        hi.sys_sched_get_priority_max(None)
        check("policy %d: priorities 256..767 (min < max, 0x208 inside)" % pol,
              lo.out == (256, False) and hi.out == (767, False) and 256 <= 0x208 <= 767, "(%s %s)" % (lo.out, hi.out))
    bad = Sc([9])
    bad.sys_sched_get_priority_max(None)
    check("an unknown policy is EINVAL", bad.out == (22, True))

    uc = Mem()
    look = Sc([0, 0x10006, 0x9000])
    look.emu = type("E", (), {"sched": type("S", (), {"current": type("T", (), {"tid": 0x10006})()})()})()
    look.sys_rtprio_thread(uc)
    typ, prio = struct.unpack("<HH", bytes(uc.mem_read(0x9000, 4)))
    check("rtprio lookup: FIFO (policy 1 for libkernel) at the default 700",
          look.out == (0, False) and (typ, prio) == (10, 700), "(%d, %d)" % (typ, prio))
    uc.mem_write(0x9100, struct.pack("<HH", 10, 520))
    look._a = [1, 0x10006, 0x9100]
    look.sys_rtprio_thread(uc)
    look._a = [0, 0, 0x9000]                                  # lwpid 0 = the calling thread
    look.sys_rtprio_thread(uc)
    check("rtprio set is remembered per thread",
          struct.unpack("<HH", bytes(uc.mem_read(0x9000, 4))) == (10, 520))
    # AJM batch wait parks the thread until the next audio period
    from . import devices

    class Sched:
        current = object()
        got = None

        def now_ns(self):
            return 7_000_000

        def block(self, what, deadline_ns=None, timeout_ret=None):
            Sched.got = (what, deadline_ns, timeout_ret)

    class Emu:
        sched = Sched()

        def log(self, m):
            pass
    sc = type("Sc", (), {"emu": Emu()})()
    aj = devices.AjmDevice(sc, "/dev/ajm")
    check("AJM batch start (0xc0288907) does not block", aj.ioctl(uc, 0xC0288907, 0xA000) == 0 and Sched.got is None)
    rv = aj.ioctl(uc, 0xC0288908, 0xA000)
    check("AJM batch wait (0xc0288908) parks the thread to the next period",
          rv is devices.BLOCKED and Sched.got[1] == audioserver.next_period(7_000_000) and Sched.got[2] == (0, False))
    print("audio model:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
