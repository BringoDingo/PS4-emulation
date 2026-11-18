"""Who spins on a syscall? Logs the first few callers (module+offset chain) and arguments of given syscalls.

    python spin_who.py 25 99 29 105
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
want = {int(a) for a in sys.argv[2:]}
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
seen = {}


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    if nr in want:
        tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
        k = (nr, tid)
        seen[k] = seen.get(k, 0) + 1
        if seen[k] <= 2:
            rbp = uc.reg_read(X.UC_X86_REG_RBP)
            chain = [where(struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0])]
            for _ in range(7):
                try:
                    ra, nx = struct.unpack("<QQ", bytes(uc.mem_read(rbp + 8, 8)) + bytes(uc.mem_read(rbp, 8)))
                except Exception:
                    break
                chain.append(where(ra))
                if nx <= rbp:
                    break
                rbp = nx
            a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX,
                                          X.UC_X86_REG_R10)]
            print(f"[{emu._time() - emu._t0:6.2f}s] tid {tid:#x} sys{nr} args=({a[0]:#x}, {a[1]:#x}, "
                  f"{a[2]:#x}, {a[3]:#x}) <- {' < '.join(chain)}", flush=True)
    return orig(uc)


sc.dispatch = dispatch
emu.run()
print("\ncounts per (syscall, thread):", {f"sys{k[0]}@{k[1]:#x}": v for k, v in sorted(seen.items())})
