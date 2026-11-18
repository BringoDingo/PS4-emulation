"""Sample one ShellUI thread's live (frame-pointer) managed stack every few seconds on WHP.

    python fp_timeline.py 120 5 [tid]     # run 120 s, sample every 5 s (default tid 0x10001)

Prints the innermost managed frames per sample, so progress through a long Initialize() sequence
(BasePlugin.OnLoaded etc.) shows up as the stack moves.
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
total = float(sys.argv[1]) if len(sys.argv) > 1 else 60
step = float(sys.argv[2]) if len(sys.argv) > 2 else 5
tid = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x10001

emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = total
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = {}


def managed_stack(limit=60, which=None):
    uc = emu.uc
    r = res.setdefault("r", AotResolver(emu))
    t = emu.sched.threads.get(which or tid)
    if t is None:
        return None
    regs = uc.context_save().r if t is emu.sched.current else (t.ctx.r if t.ctx else None)
    if regs is None:
        return None
    rbp = regs[5]
    out, n = [], 0
    while rbp and n < limit:
        try:
            ret, nxt = (struct.unpack("<Q", bytes(uc.mem_read(rbp + 8, 8)))[0],
                        struct.unpack("<Q", bytes(uc.mem_read(rbp, 8)))[0])
        except Exception:
            break
        lm = emu.dyn.module_at(ret)
        img = r._image(lm) if lm is not None else None
        hit = img.lookup(ret) if img is not None else None
        if hit:
            out.append(f"{hit[1]}+{hit[2]:#x}")
        if nxt <= rbp:
            break
        rbp, n = nxt, n + 1
    return out


last = [0.0]
orig_tick = emu._whp_tick


def tick():
    orig_tick()
    now = emu._time() - emu._t0
    if emu.sched is not None and now - last[0] >= step:
        last[0] = now
        st = managed_stack()
        t = emu.sched.threads.get(tid)
        w = t.wait.get("kind") if t is not None and isinstance(t.wait, dict) else None
        print(f"[{now:6.1f}s] {t.state if t else '?'}/{w}: " + " <- ".join((st or [])[:7]), flush=True)
        if t is not None and w in ("mutex_lock", "mutex_wait") and os.environ.get("OWNER"):
            addr = t.wait.get("addr")
            try:
                owner = struct.unpack("<I", bytes(emu.uc.mem_read(addr, 4)))[0] & 0x7fffffff
            except Exception:
                owner = None
            ot = emu.sched.threads.get(owner)
            print(f"           mutex {addr:#x} owner {owner and hex(owner)} "
                  f"{ot.state if ot else '?'} {ot.wait.get('kind') if ot is not None and isinstance(ot.wait, dict) else ''}",
                  flush=True)
            if ot is not None:
                ost = managed_stack(which=owner)
                print("           owner stack: " + " <- ".join((ost or [])[:9]), flush=True)


emu.uc.tick_cb = tick
emu.run()
