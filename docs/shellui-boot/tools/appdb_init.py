"""Trace the SceAppDbIpc client's DbAccessor::Init exchange on WHP: the IPMI command it sends and
what the calling thread does next (does it block waiting for a daemon response?).

    python appdb_init.py 9
"""
import os
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.syscalls import SYSCALLS

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 9
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
st = {"tid": None, "n": 0}
IPMI_INVOKE = 0x320


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    cur = emu.sched.current if emu.sched else None
    tid = cur.tid if cur else 0
    # detect the AppDb client's invoke: ipmimgr_call(cmd=0x320, kid=0x112, ...)
    if st["tid"] is None and nr == 651:  # sys_ipmimgr_call (ORBIS 0x28b)
        a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX)]
        if a[0] == IPMI_INVOKE:
            # resolve kid from the call struct (best-effort: just watch all invokes from here)
            pass
    if st["tid"] is not None and tid == st["tid"] and st["n"] < 60:
        a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_R10)]
        r = orig(uc)
        st["n"] += 1
        print(f"  {emu._time()-emu._t0:6.2f}s {SYSCALLS.get(nr, f'sys_{nr}'):22s} "
              f"{a[0]:#x} {a[1]:#x} {a[2]:#x} -> {uc.reg_read(X.UC_X86_REG_RAX):#x}"
              + (" [CF]" if uc.reg_read(X.UC_X86_REG_RFLAGS) & 1 else ""))
        return r
    return orig(uc)


# Simpler: latch onto the thread that first writes the "InitClient" console line, by watching writes.
orig2 = sc.dispatch


def dispatch2(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    cur = emu.sched.current if emu.sched else None
    tid = cur.tid if cur else 0
    if st["tid"] is None and nr == 4:  # write
        try:
            buf = bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSI), min(uc.reg_read(X.UC_X86_REG_RDX), 200)))
            if b"openDb()" in buf and b"app.db" in buf:
                st["tid"] = tid
                print(f"[{emu._time()-emu._t0:.2f}s] latched AppDb thread {tid:#x}; next syscalls:")
        except Exception:
            pass
    if st["tid"] is not None and tid == st["tid"] and st["n"] < 70:
        a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX)]
        txt = ""
        if nr == 4 and a[2] < 220:
            try:
                txt = "  " + bytes(uc.mem_read(a[1], a[2])).decode("latin1").strip()
            except Exception:
                pass
        r = orig2(uc)
        st["n"] += 1
        print(f"  {emu._time()-emu._t0:6.2f}s {SYSCALLS.get(nr, f'sys_{nr}'):20s} {a[0]:#x} {a[1]:#x} {a[2]:#x} -> {uc.reg_read(X.UC_X86_REG_RAX):#x}{txt}"[:200])
        return r
    return orig2(uc)


sc.dispatch = dispatch2
emu.run()
