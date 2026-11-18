"""Frame-pointer stack walk of chosen ShellUI threads on the WHP backend.

    python fp_stacks.py 20s [tid ...|all]    # run 20 wall-clock seconds, then walk the stacks

Unlike shellui_stacks.py (which scans the stack for anything that looks like a return address and
so shows stale frames), this follows the rbp chain, which Mono AOT code and libkernel maintain, so
it lists the frames that are really live. Native frames print as module+offset, managed ones by
name. Threads default to the main thread (0x10001).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1].rstrip("s")) if len(sys.argv) > 1 else 20
every = sys.argv[2:] == ["all"]
want = [int(a, 0) for a in sys.argv[2:] if a != "all"] or [0x10001]

emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
emu.run()
uc, r = emu.uc, AotResolver(emu)


def name(addr):
    lm = emu.dyn.module_at(addr)
    if lm is None:
        return f"{addr:#x}"
    img = r._image(lm)
    hit = img.lookup(addr) if img is not None else None
    if hit:
        return f"{hit[1]}+{hit[2]:#x}"
    return f"{lm.name}+{addr - lm.base:#x}" if hasattr(lm, "name") else f"{addr:#x}"


def rd(a):
    return struct.unpack("<Q", bytes(uc.mem_read(a, 8)))[0]


for t in emu.sched.threads.values():
    if not every and t.tid not in want:
        continue
    if t.state == "exited" or (t.ctx is None and t is not emu.sched.current):
        continue
    regs = (list(uc.context_save().r) if t is emu.sched.current else t.ctx.r)
    rip, rbp, rsp = regs[16], regs[5], regs[4]
    print(f"== tid {t.tid:#x} {t.state} {t.wait if not callable(t.wait) else ''}")
    print(f"   rip  {name(rip)}")
    seen = 0
    while rbp and seen < 40:
        try:
            ret, nxt = rd(rbp + 8), rd(rbp)
        except Exception:
            break
        print(f"   {name(ret)}")
        if nxt <= rbp:
            break
        rbp, seen = nxt, seen + 1
