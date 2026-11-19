"""Log mdbg_service (syscall 601) calls: thread, args, return value, caller chain.

    python mdbg_trace.py 30 [max-lines]
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
cap = int(sys.argv[2]) if len(sys.argv) > 2 else 25
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
n = [0]
hist = {}


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def dispatch(uc):
    if uc.reg_read(X.UC_X86_REG_RAX) == 601:
        a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_R10)]
        tid = emu.sched.current.tid
        ra = struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0]
        key = (a[0] & 0xFFFFFFFF, a[1] if a[0] & 0xFFFFFFFF == 3 else 0)
        hist[key] = hist.get(key, 0) + 1
        r = orig(uc)
        rv = uc.reg_read(X.UC_X86_REG_RAX)
        cf = uc.reg_read(X.UC_X86_REG_RFLAGS) & 1
        if n[0] < cap:
            n[0] += 1
            data = ""
            if a[0] & 0xFFFFFFFF in (1, 2) and a[1] > 0x10000:
                try:
                    data = " buf=" + bytes(uc.mem_read(a[1], 24)).hex(" ", 4)
                except Exception:
                    pass
            print(f"[{emu._time() - emu._t0:6.2f}s] tid {tid:#x} mdbg_service({a[0]:#x}, {a[1]:#x}, {a[2]:#x}){data} -> "
                  f"{'ERR ' if cf else ''}{rv:#x}  <- {where(ra)}", flush=True)
        return r
    return orig(uc)


sc.dispatch = dispatch
emu.run()
print("\nby (op, arg1 for op 3):", {f"{k[0]}/{k[1]:#x}": v for k, v in sorted(hist.items())})
