"""Mono stop-the-world trace on WHP: every thr_suspend/get/resume_ucontext call (target tid, the target's
state, and for get_ucontext the rip/rsp it was given) after a start time.

    python stw_trace.py 30 16
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs, t0 = float(sys.argv[1]), float(sys.argv[2])
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
NAMES = {632: "SUSPEND", 633: "RESUME", 634: "GET_UCTX", 635: "SET_UCTX"}


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    now = emu._time() - emu._t0
    if nr in NAMES and now >= t0:
        a0 = uc.reg_read(X.UC_X86_REG_RDI) & 0xFFFFFFFF
        a1 = uc.reg_read(X.UC_X86_REG_RSI)
        cur = emu.sched.current.tid
        tgt = emu.sched.threads.get(a0)
        st = f"{tgt.state}{'/susp' if tgt and tgt.suspended else ''}" if tgt else "?"
        r = orig(uc)
        extra = ""
        if nr == 634:
            try:
                rip = struct.unpack("<Q", bytes(uc.mem_read(a1 + 0x40 + 0xA0, 8)))[0]
                rsp = struct.unpack("<Q", bytes(uc.mem_read(a1 + 0x40 + 0xB8, 8)))[0]
                extra = f" -> rip={where(rip)} rsp={rsp:#x}"
            except Exception:
                pass
        print(f"[{now:6.2f}s] tid {cur:#x} {NAMES[nr]} target={a0:#x} ({st}){extra}", flush=True)
        return r
    return orig(uc)


sc.dispatch = dispatch
emu.run()
