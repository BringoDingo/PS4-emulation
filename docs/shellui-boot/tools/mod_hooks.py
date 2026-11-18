"""Hook function entries (module-relative offsets) of a loaded module and log calls with registers
and the caller chain (WHP, 'fixup' hooks: the real function still runs).

    python mod_hooks.py 50 libScePsm.prx 0x80bac 0x81890 0x817a0 ...
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs, modname = float(sys.argv[1]), sys.argv[2]
import os
GOT = int(os.environ.get("GOT", "0"), 0)       # optional: GOT slot (module-relative) of a PLT thunk hook
offs = [int(a, 0) for a in sys.argv[3:]]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
armed = set()
counts = {}
orig_tick = emu._whp_tick


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def stack(uc, depth=6):
    out = [where(struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0])]
    rbp = uc.reg_read(X.UC_X86_REG_RBP)
    for _ in range(depth):
        try:
            ra, nx = struct.unpack("<QQ", bytes(uc.mem_read(rbp + 8, 8)) + bytes(uc.mem_read(rbp, 8)))
        except Exception:
            break
        out.append(where(ra))
        if nx <= rbp:
            break
        rbp = nx
    return " < ".join(out)


def make(off):
    def hit(e, uc):
        counts[off] = counts.get(off, 0) + 1
        if counts[off] <= 4:
            a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX,
                                          X.UC_X86_REG_RCX)]
            print(f"[{e._time() - e._t0:7.2f}s] {off:#x}({a[0]:#x}, {a[1]:#x}, {a[2]:#x}, {a[3]:#x}) "
                  f"<- {stack(uc)}", flush=True)
            if GOT:                                   # PLT thunk: show where its GOT slot points
                lm = emu.dyn.by_name(modname)
                tgt = struct.unpack("<Q", bytes(uc.mem_read(lm.base + GOT, 8)))[0]
                print(f"        GOT[{GOT:#x}] -> {where(tgt)}", flush=True)
        return None
    return hit


def tick():
    orig_tick()
    if emu.dyn is None:
        return
    for lm in emu.dyn.modules:
        if lm.name == modname and lm.base and lm.base not in armed:
            armed.add(lm.base)
            for off in offs:
                try:
                    emu.hle.register(lm.base + off, make(off), name=f"hook_{off:x}", mode="fixup")
                except Exception as ex:
                    print("hook failed", hex(off), ex)
            print(f"hooked {modname} @ {lm.base:#x}: {[hex(o) for o in offs]}", flush=True)


emu.uc.tick_cb = tick
emu.run()
print("\ncalls:", {hex(k): v for k, v in counts.items()})
