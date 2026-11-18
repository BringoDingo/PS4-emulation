"""Hook a code vaddr and dump chosen rbp-relative dwords/qwords when the app-DB thread hits it (WHP).

    python peek.py 9 0x10023b60a -0x88:d -0x70:d
"""
import os
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
addr = int(sys.argv[2], 16)
specs = []
for s_ in sys.argv[3:]:
    loc, typ = s_.rsplit(":", 1)
    if loc.startswith("r"):                       # register-relative, e.g. rbx+0x10
        reg, _, off = loc.partition("+")
        specs.append((reg, int(off, 16) if off else 0, typ))
    else:
        specs.append(("rbp", int(loc, 16), typ))
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
st = {"armed": False, "last": 0.0, "n": 0}


def hit(e, uc):
    if st["n"] >= 8:
        return None
    st["n"] += 1
    tid = e.sched.current.tid if e.sched and e.sched.current else 0
    out = []
    for reg, off, typ in specs:
        try:
            base = uc.reg_read(getattr(X, "UC_X86_REG_" + reg.upper()))
            if typ == "d":
                v = struct.unpack("<i", bytes(uc.mem_read(base + off, 4)))[0]
            else:
                v = struct.unpack("<Q", bytes(uc.mem_read(base + off, 8)))[0]
            out.append(f"[{reg}{off:+#x}]={v:#x}({v})")
        except Exception as ex:
            out.append(f"[{reg}{off:+#x}]=err{ex}")
    print(f"[{e._time()-e._t0:7.2f}s] tid {tid:#x} @ {addr:#x}: " + "  ".join(out), flush=True)
    return None


def tick():
    orig()
    if st["armed"] or emu.sched is None or emu._time() - st["last"] < 1.0:
        return
    st["last"] = emu._time()
    lm = emu.dyn.by_name("eboot.bin") if emu.dyn else None
    if lm is None or not lm.base:
        return
    emu.hle.register(addr, hit, name="peek", mode="fixup")
    st["armed"] = True
    print("[peek] armed", flush=True)


emu.uc.tick_cb = tick
emu.run()
