"""Host-side controller state for the emulated /dev/hid (DualShock 4).

The guest never sees host devices: devices.HidDevice asks a PadSource for the current button/stick
state and encodes it the way libScePad's kernel interface reports it.

Sources (PSEMU_PAD selects; default "auto"):
  auto     XInput pad if one is connected (DS4Windows exposes a DualShock 4 as an Xbox 360 pad),
           otherwise an idle controller;
  xinput   XInput only (idle when none is connected);
  none     an idle controller (sticks centred, nothing pressed): the console has a pad plugged in;
  script   PSEMU_PAD_BUTTONS="CROSS,DOWN" holds those buttons down.

Button bits are ScePadButtonDataOffset (libScePad): the same word scePadReadState returns.
"""
import ctypes
import os
import struct

BUTTONS = {
    "L3": 0x2, "R3": 0x4, "OPTIONS": 0x8, "UP": 0x10, "RIGHT": 0x20, "DOWN": 0x40, "LEFT": 0x80,
    "L2": 0x100, "R2": 0x200, "L1": 0x400, "R1": 0x800, "TRIANGLE": 0x1000, "CIRCLE": 0x2000,
    "CROSS": 0x4000, "SQUARE": 0x8000, "TOUCHPAD": 0x100000,
}


class PadState:
    """One sampled controller state: button word + 8-bit sticks (128 = centre) and triggers."""
    __slots__ = ("buttons", "lx", "ly", "rx", "ry", "l2", "r2")

    def __init__(self, buttons=0, lx=128, ly=128, rx=128, ry=128, l2=0, r2=0):
        self.buttons, self.lx, self.ly, self.rx, self.ry, self.l2, self.r2 = \
            buttons, lx, ly, rx, ry, l2, r2

    def __eq__(self, o):
        return isinstance(o, PadState) and all(getattr(self, k) == getattr(o, k) for k in self.__slots__)

    def __repr__(self):
        return "PadState(buttons=%#x, L=(%d,%d) R=(%d,%d) L2=%d R2=%d)" % (
            self.buttons, self.lx, self.ly, self.rx, self.ry, self.l2, self.r2)


class NullSource:
    """A connected controller nobody touches."""
    name = "idle"

    def poll(self):
        return PadState()


class ScriptSource:
    """Holds the buttons named in PSEMU_PAD_BUTTONS (comma separated) down."""
    name = "script"

    def __init__(self, spec=None):
        spec = os.environ.get("PSEMU_PAD_BUTTONS", "") if spec is None else spec
        self.buttons = 0
        for n in spec.replace(" ", "").upper().split(","):
            if n:
                self.buttons |= BUTTONS[n]

    def poll(self):
        st = PadState(self.buttons)
        if self.buttons & BUTTONS["L2"]:
            st.l2 = 255
        if self.buttons & BUTTONS["R2"]:
            st.r2 = 255
        return st


# XInput button bits -> PS4 buttons (A/B/X/Y = cross/circle/square/triangle, Back = touchpad click)
_XI = ((0x0001, "UP"), (0x0002, "DOWN"), (0x0004, "LEFT"), (0x0008, "RIGHT"), (0x0010, "OPTIONS"),
       (0x0020, "TOUCHPAD"), (0x0040, "L3"), (0x0080, "R3"), (0x0100, "L1"), (0x0200, "R1"),
       (0x1000, "CROSS"), (0x2000, "CIRCLE"), (0x4000, "SQUARE"), (0x8000, "TRIANGLE"))


class _Gamepad(ctypes.Structure):
    _fields_ = [("wButtons", ctypes.c_ushort), ("bLT", ctypes.c_ubyte), ("bRT", ctypes.c_ubyte),
                ("sLX", ctypes.c_short), ("sLY", ctypes.c_short), ("sRX", ctypes.c_short),
                ("sRY", ctypes.c_short)]


class _XState(ctypes.Structure):
    _fields_ = [("packet", ctypes.c_uint32), ("gp", _Gamepad)]


def _axis(v, invert=False):
    """int16 -> 0..255 with 0 -> 128 (the DS4's centre) and both extremes reachable; the DS4 reports
    up as 0 where XInput reports it as +, hence `invert` for the Y axes."""
    x = v / 256.0
    return max(0, min(255, int(round(128 - x if invert else 128 + x))))


def encode_xinput(gp):
    """XInput gamepad -> PadState (pure function, unit-tested)."""
    buttons = 0
    for bit, name in _XI:
        if gp.wButtons & bit:
            buttons |= BUTTONS[name]
    l2, r2 = gp.bLT, gp.bRT
    if l2 > 30:
        buttons |= BUTTONS["L2"]
    if r2 > 30:
        buttons |= BUTTONS["R2"]
    return PadState(buttons, _axis(gp.sLX), _axis(gp.sLY, True), _axis(gp.sRX), _axis(gp.sRY, True),
                    l2, r2)


class XInputSource:
    """The first connected XInput pad (slots 0-3), or an idle controller when none is."""
    name = "xinput"

    def __init__(self):
        self._dll = None
        for n in ("xinput1_4", "xinput1_3", "xinput9_1_0"):
            try:
                self._dll = ctypes.WinDLL(n)
                break
            except (OSError, AttributeError):
                continue
        self._slot = 0
        self.connected = False

    def poll(self):
        if self._dll is None:
            return PadState()
        st = _XState()
        # the slot that answered last time first, then the rest
        order = [self._slot] + [i for i in range(4) if i != self._slot]
        for i in order:
            if self._dll.XInputGetState(i, ctypes.byref(st)) == 0:
                self._slot = i
                self.connected = True
                return encode_xinput(st.gp)
        self.connected = False
        return PadState()


class AutoSource(XInputSource):
    name = "auto"


def make_source(mode=None):
    mode = (mode or os.environ.get("PSEMU_PAD", "auto")).lower()
    if mode == "none":
        return NullSource()
    if mode == "script":
        return ScriptSource()
    if mode == "xinput":
        return XInputSource()
    return AutoSource()


_source = None


def get_source():
    """The process-wide source (one physical controller feeding every emulated /dev/hid fd)."""
    global _source
    if _source is None:
        _source = make_source()
    return _source


def encode_report(state, timestamp_us):
    """The 0x20-byte head of one /dev/hid pad report as libScePad's read (ioctl 0x29) consumes it:
    +0x00 u64 timestamp (us), +0x0c u32 buttons, +0x10 lx ly rx ry l2 r2 (u8 each)."""
    rep = bytearray(0x20)
    struct.pack_into("<Q", rep, 0, timestamp_us & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<I", rep, 0x0C, state.buttons & 0xFFFFFFFF)
    rep[0x10:0x16] = bytes((state.lx, state.ly, state.rx, state.ry, state.l2, state.r2))
    return bytes(rep)
