"""At the end of a run, print every live thread's state, suspend flag and the top frames of its stack
(module+offset; managed frames symbolized). Shows who is inside the GC, who holds what.

    python all_stacks.py 30 [only-states-comma]   e.g.  all_stacks.py 30 blocked,ready,running
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
secs = float(sys.argv[1])
states = set((sys.argv[2] if len(sys.argv) > 2 else "blocked,ready,running").split(","))
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
emu.run()
s = emu.sched


def what(w):
    if isinstance(w, dict):
        return ", ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}" for k, v in w.items() if not callable(v))
    return str(w)


for t in sorted(s.threads.values(), key=lambda t: t.tid):
    if t.state not in states:
        continue
    try:
        ctx = t.ctx if t.ctx is not None else emu.uc
        rsp = ctx.reg_read(X.UC_X86_REG_RSP)
        blob = bytes(emu.uc.mem_read(rsp, 0x800))
    except Exception:
        continue
    frames = []
    for off in range(0, len(blob) - 8, 8):
        v = struct.unpack_from("<Q", blob, off)[0]
        if 0x100000000 <= v < 0x4000000000 and emu.dyn.module_at(v) is not None:
            nm = res.name(v)
            if nm not in frames:
                frames.append(nm)
        if len(frames) >= 7:
            break
    print(f"{t.tid:#x} {t.state}{' SUSPENDED' if t.suspended else ''} {what(t.wait)[:60] if t.wait else ''}")
    print("      " + " < ".join(frames))
