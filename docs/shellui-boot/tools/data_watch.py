"""Data breakpoint via the WhpUc page watch: log the RIP (module+offset) and faulting address of accesses
to a page of a loaded module's data, re-arming on the next time slice.

    python data_watch.py 30 libScePsm.prx 0x315000 [lo hi]   # only log accesses with module+lo <= addr < module+hi
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs, mod, page = float(sys.argv[1]), sys.argv[2], int(sys.argv[3], 0)
lo = int(sys.argv[4], 0) if len(sys.argv) > 4 else page
hi = int(sys.argv[5], 0) if len(sys.argv) > 5 else page + 0x1000
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
state = {"armed": False, "base": 0, "rearm": False, "hits": 0, "shown": 0}
orig_tick = emu._whp_tick


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def cb(start, size):
    uc = emu.uc
    state["hits"] += 1
    state["rearm"] = True
    cr2 = uc.reg_read(X.UC_X86_REG_CR2)
    rel = cr2 - state["base"]
    if lo <= rel < hi and state["shown"] < 40:
        state["shown"] += 1
        rip = uc.reg_read(X.UC_X86_REG_RIP)
        rbp = uc.reg_read(X.UC_X86_REG_RBP)
        chain = [where(rip)]
        for _ in range(5):
            try:
                ra, nx = struct.unpack("<QQ", bytes(uc.mem_read(rbp + 8, 8)) + bytes(uc.mem_read(rbp, 8)))
            except Exception:
                break
            chain.append(where(ra))
            if nx <= rbp:
                break
            rbp = nx
        print(f"[{emu._time() - emu._t0:6.2f}s] tid {emu.sched.current.tid:#x} access {mod}+{rel:#x}  "
              f"{' < '.join(chain)}", flush=True)


def tick():
    orig_tick()
    if emu.dyn is None:
        return
    if not state["armed"]:
        lm = emu.dyn.by_name(mod)
        if lm is not None and lm.base:
            state["base"] = lm.base
            state["armed"] = True
            emu.uc.watch_add(lm.base + page, 0x1000, cb)
            print(f"watching {mod}+{page:#x} (base {lm.base:#x})", flush=True)
    elif state["rearm"]:
        state["rearm"] = False
        emu.uc.watch_add(state["base"] + page, 0x1000, cb)


emu.uc.tick_cb = tick
emu.run()
print("\npage faults taken:", state["hits"])
