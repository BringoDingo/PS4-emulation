"""Who waits on / wakes a given synchronisation address? Logs the _umtx_op / ksem / osem calls whose
address argument matches, with thread, op and the caller chain.

    python addr_sync.py 30 0x106d278d4
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.syscalls import SYSCALLS

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
want = int(sys.argv[2], 0)
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
n = [0]


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def chain(uc):
    out = [where(struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0])]
    rbp = uc.reg_read(X.UC_X86_REG_RBP)
    for _ in range(6):
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
    hit = a[0] == want or (nr == 454 and a[0] == want)
    if nr in (454, 401, 402, 548, 549, 550, 551) and (a[0] == want or a[0] & ~3 == want):
        if n[0] < 40:
            n[0] += 1
            tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
            print(f"[{emu._time() - emu._t0:6.2f}s] tid {tid:#x} {SYSCALLS.get(nr, nr)} op={a[1]:#x} "
                  f"val={a[2]:#x} <- {chain(uc)}", flush=True)
    return orig(uc)


sc.dispatch = dispatch
emu.run()
