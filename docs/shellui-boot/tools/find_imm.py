"""Find every compiled managed method (app.exe + UI2) that contains a given 64-bit immediate.

    python find_imm.py 40 0x40000000000 [0x...]

Boot-flag constants are `movabs reg, imm64` in the AOT code, so a byte scan of the code locates
each method that waits on / sets that flag.
"""
import bisect
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
vals = [int(a, 0) for a in sys.argv[2:]]
MODS = ["app.exe.sprx", "Sce.PlayStation.HighLevel.UI2.dll.sprx"]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
orig = emu._whp_tick
st = {"done": False, "last": 0.0}


def scan():
    imgs = []
    for m in MODS:
        lm = emu.dyn.by_name(m) if emu.dyn else None
        img = res._image(lm) if lm is not None else None
        if img is None:
            return False
        imgs.append((lm, img))
    for lm, img in imgs:
        items = sorted(zip(img.starts, img.rids))
        starts = [s for s, _ in items]
        lo, hi = starts[0], starts[-1] + 0x2000
        code = bytes(emu.uc.mem_read(lo, hi - lo))
        for v in vals:
            pat = struct.pack("<Q", v)
            pos = code.find(pat)
            hits = []
            while pos >= 0:
                a = lo + pos
                i = bisect.bisect_right(starts, a) - 1
                if i >= 0:
                    hits.append((img.method_name(items[i][1]), a - starts[i]))
                pos = code.find(pat, pos + 1)
            print(f"\n{v:#x} in {lm.name}: {len(hits)} hit(s)")
            for n, off in hits:
                print(f"   {n}+{off:#x}")
    return True


def tick():
    orig()
    if st["done"] or emu.sched is None:
        return
    now = emu._time()
    if now - st["last"] < 1.0:
        return
    st["last"] = now
    if scan():
        st["done"] = True
        emu.stop("scan done")


emu.uc.tick_cb = tick
emu.run()
