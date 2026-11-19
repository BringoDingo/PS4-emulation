"""Trace umtx semaphore waits/wakes in an address range and Mono's thread suspend/resume calls.

    python sem_trace.py 30 0x106d27000 0x106d29000
Syscalls: _umtx_op(454) ops SEM_WAIT 0x13 / SEM_WAKE 0x14 / SEM2_WAIT 0x17 / SEM2_WAKE 0x18,
thr_suspend_ucontext 632 / thr_resume_ucontext 633 / thr_get_ucontext / thr_set_ucontext.
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
lo, hi = int(sys.argv[2], 0), int(sys.argv[3], 0)
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
OPN = {0x13: "SEM_WAIT", 0x14: "SEM_WAKE", 0x17: "SEM2_WAIT", 0x18: "SEM2_WAKE"}
n = [0]
count = {}


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def chain(uc, depth=7):
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


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_R10)]
    tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
    show = None
    if nr == 454 and (a[1] & 0xFFFFFFFF) in OPN and lo <= a[0] < hi:
        show = f"{OPN[a[1] & 0xFFFFFFFF]} addr={a[0]:#x} val={a[2]:#x}"
    elif nr in (632, 633):
        show = ("SUSPEND" if nr == 632 else "RESUME") + f" tid={a[0] & 0xFFFFFFFF:#x}"
    if show:
        key = (show.split()[0], tid)
        count[key] = count.get(key, 0) + 1
        if n[0] < 60 and count[key] <= 3:
            n[0] += 1
            print(f"[{emu._time() - emu._t0:6.2f}s] tid {tid:#x} {show} <- {chain(uc)}", flush=True)
    return orig(uc)


sc.dispatch = dispatch
emu.run()
print("\ncounts:", {f"{k[0]}@{k[1]:#x}": v for k, v in sorted(count.items())})
