"""Unit test of the emulated /dev/hid (devices.HidDevice + padsrc): ioctl layout, return values,
report encoding, XInput mapping.

    python -m psemu.tools_hidtest
"""
import ctypes
import struct
import sys

from . import devices, mbus, padsrc


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
    # ---- the SceMbusIpc device list (mbus.py)
    ent = mbus.pad_entry(0, 0x10000001)
    check("pad entry is 0x100 bytes with a non-zero device id", len(ent) == 0x100
          and struct.unpack_from("<Q", ent, 0)[0] != 0)
    check("entry: class 2, local connection (not remote/share play), user id",
          struct.unpack_from("<III", ent, 0x08)[0] == 0 and struct.unpack_from("<I", ent, 0x0C)[0] == 2
          and struct.unpack_from("<I", ent, 0xC8)[0] == 0x10000001)
    wild = b"\xff" * 0x100
    f2 = bytearray(wild)
    struct.pack_into("<I", f2, 0x0C, 2)
    f3 = bytearray(wild)
    struct.pack_into("<I", f3, 0x0C, 3)
    fu = bytearray(wild)
    struct.pack_into("<I", fu, 0xC8, 0x10000002)
    check("class filter 2 matches the pad, class 3 does not",
          len(mbus.device_list([ent], bytes(f2))) == 1 and mbus.device_list([ent], bytes(f3)) == [])
    check("a wildcard filter matches; another user's filter does not",
          len(mbus.device_list([ent], wild)) == 1 and mbus.device_list([ent], bytes(fu)) == [])
    check("the result is capped by the requested count", mbus.device_list([ent, ent, ent], wild, 2) == [ent, ent])

    # ---- open / close / info / capability ioctls
    uc.mem_write(0x7000, struct.pack("<iii", -1, 3, 0))
    h = [dev.ioctl(uc, devices.HID_PAD_OPEN, 0x7000) for _ in range(4)]
    check("pad open (0x800c4802) hands out handles 1..3 (a port number <= 3, never 0)",
          all(1 <= x <= 3 for x in h) and h[0] != 0, "(%s)" % h)
    uc.mem_write(0x7100, struct.pack("<ii", 3, h[0]))
    check("pad close (0x80084803) returns 0", dev.ioctl(uc, devices.HID_PAD_CLOSE, 0x7100) == 0)
    uc.mem_write(0x7200, struct.pack("<IIQ", h[0], 0, 0x7300))
    uc.mem_write(0x7300, b"\xee" * 0x60)
    check("controller information (0x8010480e) returns 0", dev.ioctl(uc, devices.HID_PAD_INFO, 0x7200) == 0)
    blk = bytes(uc.mem_read(0x7300, 0x60))
    check("info block: class 2, Sony vendor, DS4 v2 (not the blocked 0x0bb2), touchpad, dead zones",
          blk[0] == 2 and struct.unpack_from("<HH", blk, 0x10) == (0x054C, 0x09CC)
          and struct.unpack_from("<HH", blk, 0x38) == (1920, 942) and blk[0x3C] == blk[0x3D] == 0x20)
    check("info block stays inside the guest's 0x48-byte buffer (the canary follows it)",
          blk[0x48:0x60] == b"\xee" * 0x18)
    uc.mem_write(0x7300, b"\xee" * 0x60)
    check("capability (0x80104801) returns 0 and writes <= 0x30 bytes",
          dev.ioctl(uc, devices.HID_PAD_CAPABILITY, 0x7200) == 0
          and bytes(uc.mem_read(0x7330, 0x20)) == b"\xee" * 0x20)
    # ---- /dev/ajm (opt-in: PSEMU_AJM=1)
    import os as _os
    saved = _os.environ.pop("PSEMU_AJM", None)
    check("/dev/ajm stays the generic stub unless PSEMU_AJM is set", devices.open_device(sc, "/dev/ajm") is None)
    _os.environ["PSEMU_AJM"] = "1"
    aj = devices.open_device(sc, "/dev/ajm")
    check("with PSEMU_AJM=1 /dev/ajm is the AjmDevice", isinstance(aj, devices.AjmDevice))
    uc.mem_write(0x8000, b"\xee" * 0x28)
    check("module register (0xc0288903) writes status 0 at +0 and returns 0",
          aj.ioctl(uc, 0xC0288903, 0x8000) == 0 and struct.unpack("<I", bytes(uc.mem_read(0x8000, 4)))[0] == 0)
    uc.mem_write(0x8100, b"\xee" * 0x28)
    aj.ioctl(uc, 0xC0288905, 0x8100)
    i1 = struct.unpack("<I", bytes(uc.mem_read(0x8114, 4)))[0]
    aj.ioctl(uc, 0xC0288905, 0x8100)
    i2 = struct.unpack("<I", bytes(uc.mem_read(0x8114, 4)))[0]
    check("instance create (0xc0288905) returns distinct ids at +0x14", i1 >= 1 and i2 == i1 + 1, "(%d, %d)" % (i1, i2))
    check("an AJM request outside 0..0xb is logged, not answered", aj.ioctl(uc, 0xC028890C, 0x8000) == 0
          and any("not modelled" in m for m in sc.emu.msgs))
    if saved is None:
        del _os.environ["PSEMU_AJM"]
    else:
        _os.environ["PSEMU_AJM"] = saved
    print("hid model:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
