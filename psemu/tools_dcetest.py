"""Unit test of the display controller's flip bookkeeping (devices.DceDevice): the flip status the boot
splash polls (cmd 0xa) and the counting of uncollected flip events.

    python -m psemu.tools_dcetest
"""
import struct
import sys

from . import devices


class Mem:
    def __init__(self):
        self.m = {}

    def mem_write(self, a, d):
        for i, b in enumerate(bytes(d)):
            self.m[a + i] = b

    def mem_read(self, a, n):
        return bytearray(self.m.get(a + i, 0) for i in range(n))


class Emu:
    def __init__(self, uc):
        self.uc = uc
        self.frame_dir = None

    def log(self, m):
        pass

    def _time(self):
        return 1.5


class Sc:
    """Just the kqueue bookkeeping the device touches."""

    def __init__(self, uc):
        self.emu = Emu(uc)
        self.knotes = {7: {(6 << 48, devices.EVFILT_DISPLAY): {"data": 0}}}
        self.kq_pending = {}

    def trigger(self, filt, ident=None, data=None):
        for kq, notes in self.knotes.items():
            kn = notes.get((ident, filt))
            if kn is not None:
                kn["data"] = data
                self.kq_pending.setdefault(kq, []).append((ident, filt))
        return 1


def main():
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print("  %-70s %s %s" % (name, "PASS" if cond else "FAIL", extra))

    uc = Mem()
    dev = devices.DceDevice(Sc(uc), "/dev/dce")

    def flip(index, arg):
        uc.mem_write(0x1000, struct.pack("<QqIxxxxQQIxxxxQQQ", 0x100, index, 1, arg, 0, 0, 0, 0, 0))
        return dev.ioctl(uc, devices.DCE_SUBMIT_FLIP, 0x1000)

    def status():
        uc.mem_write(0x2000, bytes(0x48))
        uc.mem_write(0x3000, struct.pack("<IIQQQQQ", devices.DCE_CMD_FLIP_STATUS, 0, 0x100, 0x2000, 0x48, 0, 0))
        rv = dev.ioctl(uc, devices.DCE_IOCTL, 0x3000)
        return rv, struct.unpack("<QQQqQiii", bytes(uc.mem_read(0x2000, 0x34)))

    rv, st = status()
    check("flip status before any flip: count 0, flipArg 0", rv == 0 and st[0] == 0 and st[3] == 0)
    flip(0, 1)
    flip(1, 2)
    flip(2, 3)
    rv, st = status()
    check("after three flips: count 3, flipArg = the newest argument (3), current buffer 2",
          st[0] == 3 and st[3] == 3 and st[7] == 2, "(%s)" % (st,))
    check("no flips pending, GC queue empty", st[5] == 0 and st[6] == 0)
    n = (dev.sc.knotes[7][(6 << 48, devices.EVFILT_DISPLAY)]["data"] >> 12) & 0xF
    check("three uncollected flip events are counted (data bits 12..15), not collapsed to one", n == 3, "(%d)" % n)
    dev.sc.kq_pending.clear()                   # the waiter collected it
    flip(3, 4)
    n = (dev.sc.knotes[7][(6 << 48, devices.EVFILT_DISPLAY)]["data"] >> 12) & 0xF
    check("after the event is collected the count starts again at 1", n == 1, "(%d)" % n)
    print("dce model:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
