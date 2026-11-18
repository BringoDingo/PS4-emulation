"""Unit test of the emulated /dev/hid (devices.HidDevice + padsrc): ioctl layout, return values,
report encoding, XInput mapping.

    python -m psemu.tools_hidtest
"""
import ctypes
import struct
import sys

from . import devices, padsrc


class FakeMem:
    """Just enough of the Unicorn surface for a device ioctl."""

    def __init__(self):
        self.m = {}

    def mem_write(self, addr, data):
        for i, b in enumerate(bytes(data)):
            self.m[addr + i] = b

    def mem_read(self, addr, n):
        return bytearray(self.m.get(addr + i, 0) for i in range(n))


class FakeEmu:
    def __init__(self):
        self.msgs = []
        self.t = 12.5

    def log(self, m):
        self.msgs.append(m)

    def _time(self):
        return self.t


class FakeSc:
    def __init__(self):
        self.emu = FakeEmu()


def main():
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print("  %-62s %s %s" % (name, "PASS" if cond else "FAIL", extra))

    uc = FakeMem()
    sc = FakeSc()
    padsrc._source = padsrc.ScriptSource("CROSS,DOWN,R2")
    dev = devices.open_device(sc, "/dev/hid")
    check("/dev/hid is a modelled device", isinstance(dev, devices.HidDevice))

    # request: {u32 port; u32 _; u64 buf; u32 count; u32 _; u64 out_count*}
    REQ, BUF, CNT = 0x1000, 0x2000, 0x3000
    uc.mem_write(BUF, b"\xee" * 0x98)

    def request(port=0, count=1):
        uc.mem_write(REQ, struct.pack("<IIQIIQ", port, 0, BUF, count, 0, CNT))
        uc.mem_write(CNT, struct.pack("<I", 0xFFFF))

    request()
    rv = dev.ioctl(uc, devices.HID_PAD_READ, REQ)
    check("read returns 1 report", rv == 1, "(rv=%r)" % (rv,))
    check("out_count is written", struct.unpack("<I", bytes(uc.mem_read(CNT, 4)))[0] == 1)
    rep = bytes(uc.mem_read(BUF, 0x20))
    ts, buttons = struct.unpack_from("<QI", rep, 0)[0], struct.unpack_from("<I", rep, 0x0C)[0]
    check("timestamp is the virtual time in microseconds", ts == 12_500_000, "(%d)" % ts)
    want = padsrc.BUTTONS["CROSS"] | padsrc.BUTTONS["DOWN"] | padsrc.BUTTONS["R2"]
    check("button word at +0x0c", buttons == want, "(%#x)" % buttons)
    check("sticks centred, R2 fully pressed at +0x10", list(rep[0x10:0x16]) == [128, 128, 128, 128, 0, 255],
          "(%s)" % list(rep[0x10:0x16]))
    check("bytes past the 0x20 head are not touched", bytes(uc.mem_read(BUF + 0x20, 8)) == b"\xee" * 8)

    request(port=7)
    check("a port >= 4 is EINVAL", dev.ioctl(uc, devices.HID_PAD_READ, REQ) == -22)
    request(count=0)
    check("count 0 returns 0 and writes nothing", dev.ioctl(uc, devices.HID_PAD_READ, REQ) == 0)

    uc.mem_write(0x4000, struct.pack("<ii", -1, 3))
    h1 = dev.ioctl(uc, devices.HID_PAD_OPEN, 0x4000)
    h2 = dev.ioctl(uc, devices.HID_PAD_OPEN, 0x4000)
    check("pad open returns distinct non-negative handles", h1 >= 0 and h2 > h1, "(%d, %d)" % (h1, h2))
    check("set-process-privilege returns 0", dev.ioctl(uc, devices.HID_SET_PROCESS_PRIVILEGE, 0x4000) == 0)

    uc.mem_write(0x5000, struct.pack("<QIi", 0x6000, 3, 0))
    uc.mem_write(0x6000, b"\xff" * 8)
    check("0x0f writes a u64 through its pointer",
          dev.ioctl(uc, devices.HID_QUERY_U64, 0x5000) == 0
          and struct.unpack("<Q", bytes(uc.mem_read(0x6000, 8)))[0] == 0)
    check("an unknown request is logged once and answered 0",
          dev.ioctl(uc, 0x80104899, 0x5000) == 0 and dev.ioctl(uc, 0x80104899, 0x5000) == 0
          and sum("not modelled" in m for m in sc.emu.msgs) == 1)

    # sources
    idle = padsrc.NullSource().poll()
    check("idle controller: nothing pressed, sticks centred",
          idle.buttons == 0 and (idle.lx, idle.ly, idle.rx, idle.ry) == (128, 128, 128, 128))
    gp = padsrc._Gamepad(0x1000 | 0x0001 | 0x0100, 200, 0, 32767, -32768, 32767, -32768)  # A, DPAD_UP, LB
    st = padsrc.encode_xinput(gp)
    check("XInput A/up/LB -> cross/up/L1", st.buttons == padsrc.BUTTONS["CROSS"] | padsrc.BUTTONS["UP"]
          | padsrc.BUTTONS["L1"] | padsrc.BUTTONS["L2"], "(%#x; the 200 trigger also sets L2)" % st.buttons)
    check("XInput axes: LX +max -> 255, LY -max (down) -> 255, RX +max -> 255, RY -max -> 255",
          (st.lx, st.ly, st.rx, st.ry) == (255, 255, 255, 255), "(%s)" % ((st.lx, st.ly, st.rx, st.ry),))
    mid = padsrc.encode_xinput(padsrc._Gamepad(0, 0, 0, 0, 0, 0, 0))
    check("XInput centred -> 128 on every axis", (mid.lx, mid.ly, mid.rx, mid.ry) == (128, 128, 128, 128))
    full = padsrc.encode_xinput(padsrc._Gamepad(0, 0, 0, 0, 32767, 0, 0))
    check("XInput up on the left stick -> ly 0", full.ly == 0, "(ly=%d)" % full.ly)
    check("XInput source degrades to an idle pad without a controller",
          isinstance(padsrc.XInputSource().poll(), padsrc.PadState))
    print("hid model:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
