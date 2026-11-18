"""Trace native (non-managed) guest functions given as module+offset on WHP: args and return value.

    python native_trace.py 20 libkernel.prx+0x1a250 libkernel.prx+0x1a3d0 [mod+off ...]

Env FILTER=0x98100000034 prints only calls whose rdi/rsi equals that value. Each hit prints wall
time, tid, rdi/rsi/rdx/rcx, the caller (module+off) and, on return, rax. Function entries are int3
fixup traps (never patch call sites: Mono re-reads the call bytes).
"""
import os
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
targets = []
for spec in sys.argv[2:]:
    m, o = spec.rsplit("+", 1)
    targets.append((m, int(o, 0)))
flt = os.environ.get("FILTER")
flt = int(flt, 0) if flt else None
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
st = {"done": False, "last": 0.0}


def where(a):
    lm = emu.dyn.module_at(a)
    return f"{lm.name}+{a - lm.base:#x}" if lm else hex(a)


def make(name):
    def h(e, uc):
        regs = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_RCX)]
        if flt is not None and flt not in regs[:2]:
            return None
        rsp = uc.reg_read(X.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
        tid = e.sched.current.tid if e.sched and e.sched.current else 0
        print(f"[{e._time() - e._t0:7.2f}s] tid {tid:#x} {name} ({', '.join(f'{r:#x}' for r in regs)})  <- {where(ret)}",
              flush=True)
        if ret not in e.hle.table:
            def on_ret(e2, uc2, ra=ret, nm=name):
                print(f"[{e2._time() - e2._t0:7.2f}s]   {nm} -> rax={uc2.reg_read(X.UC_X86_REG_RAX):#x}", flush=True)
                uc2.hle_remove(ra)
                e2.hle.table.pop(ra, None)
                return None
            e.hle.register(ret, on_ret, name="ret", mode="fixup")
        return None
    return h


def tick():
    orig()
    if st["done"] or emu.sched is None:
        return
    now = emu._time()
    if now - st["last"] < 1.0:
        return
    st["last"] = now
    lms = [emu.dyn.by_name(m) if emu.dyn else None for m, _ in targets]
    if any(lm is None or not lm.base for lm in lms):
        return
    for (m, off), lm in zip(targets, lms):
        emu.hle.register(lm.base + off, make(f"{m}+{off:#x}"), name=f"nt_{off:x}", mode="fixup")
    st["done"] = True
    print("[native_trace] armed", [f"{m}+{o:#x}" for m, o in targets], flush=True)


emu.uc.tick_cb = tick
emu.run()
