"""Full native rbp-stack of whoever creates the app.db-corrupt marker / checks the app DB (WHP).

    python who_corrupt.py 10
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 10
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
sc = emu.syscalls
orig = sc.dispatch
done = {"n": 0}


def rd(uc, a):
    return struct.unpack("<Q", bytes(uc.mem_read(a, 8)))[0]


def frame(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    if lm is None:
        return hex(a)
    img = res._image(lm)
    hit = img.lookup(a) if img is not None else None
    return (hit[1] if hit else f"{lm.name}+{a - lm.base:#x}")


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    if nr == 5 and done["n"] < 2:   # open
        try:
            p = bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RDI), 64)).split(bytes([0]))[0].decode("latin1")
        except Exception:
            p = ""
        if "app.db-corrupt" in p and (uc.reg_read(X.UC_X86_REG_RSI) & 0x200):   # O_CREAT
            done["n"] += 1
            tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
            th = emu.sched.current
            print(f"\n[{emu._time() - emu._t0:.2f}s] tid {tid:#x} name={getattr(th,'name','?')!r} creates {p!r}")
            rbp = uc.reg_read(X.UC_X86_REG_RBP)
            for _ in range(30):
                try:
                    ra, nx = rd(uc, rbp + 8), rd(uc, rbp)
                except Exception:
                    break
                print("   ", frame(ra))
                if nx <= rbp:
                    break
                rbp = nx
    return orig(uc)


sc.dispatch = dispatch
emu.run()
