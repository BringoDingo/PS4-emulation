"""Histogram of kevent registrations by (filter, ident) with the registering module, to see what kernel
event sources the shell subscribes to (e.g. the pad/HID connect event).

    python kev_filters.py 50
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 50
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
hist = {}


def caller(uc):
    rbp = uc.reg_read(X.UC_X86_REG_RBP)
    for _ in range(5):
        try:
            ra, nx = struct.unpack("<QQ", bytes(uc.mem_read(rbp + 8, 8)) + bytes(uc.mem_read(rbp, 8)))
        except Exception:
            break
        lm = emu.dyn.module_at(ra) if emu.dyn else None
        if lm is not None and not lm.name.startswith("libkernel"):
            return f"{lm.name}+{ra - lm.base:#x}"
        if nx <= rbp:
            break
        rbp = nx
    return "?"


def dispatch(uc):
    if uc.reg_read(X.UC_X86_REG_RAX) == 363:
        a1, a2 = uc.reg_read(X.UC_X86_REG_RSI), uc.reg_read(X.UC_X86_REG_RDX) & 0xFFFFFFFF
        if 0 < a2 < 64 and a1:
            who = caller(uc)
            for i in range(a2):
                try:
                    ident, filt, flags, fflags = struct.unpack("<QhHI", bytes(uc.mem_read(a1 + 32 * i, 16)))
                except Exception:
                    continue
                key = (filt, ident if filt not in (-7, -11) else 0, who)
                hist[key] = hist.get(key, 0) + 1
    return orig(uc)


sc.dispatch = dispatch
emu.run()
print("\nfilter  ident  registered-by  count")
for (f, i, w), n in sorted(hist.items()):
    print(f"{f:5d}  {i:#10x}  {w}  x{n}")
