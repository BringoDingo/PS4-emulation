"""Print what DbPreparationWrapper.CexDbRecoveryGetStatus(out finished, out error, out progress,
out stage) returns over time while the shell's DB-recovery screen is up (WHP).

    python dbstatus.py 120

The plugin calls it every frame; the tool prints the first call, every change, and a line per
~10 s so a stuck progress value is visible. Args: rdi,rsi,rdx,rcx are pointers to the 4 outs
(int/uint8, int, float, int) read at the return address.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 120
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
orig = emu._whp_tick
st = {"armed": False, "last": 0.0, "prev": None, "t_print": 0.0, "n": 0}
MOD = "Sce.Vsh.DbPreparationWrapper.dll.sprx"


def hit(e, uc):
    ptrs = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_RCX)]
    rsp = uc.reg_read(X.UC_X86_REG_RSP)
    ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
    st["n"] += 1

    def on_ret(e2, uc2, ra=ret, p=ptrs):
        try:
            fin = bytes(uc2.mem_read(p[0], 1))[0]
            err = struct.unpack("<I", bytes(uc2.mem_read(p[1], 4)))[0]
            prog = struct.unpack("<f", bytes(uc2.mem_read(p[2], 4)))[0]
            stage = struct.unpack("<i", bytes(uc2.mem_read(p[3], 4)))[0]
        except Exception as ex:
            fin = err = prog = stage = f"?{ex}"
        rax = uc2.reg_read(X.UC_X86_REG_RAX)
        cur = (rax, fin, err, prog, stage)
        now = e2._time() - e2._t0
        if cur != st["prev"] or now - st["t_print"] > 10:
            print(f"[{now:7.2f}s] call#{st['n']} -> rc={rax:#x} finished={fin} error={err if isinstance(err, str) else hex(err)} "
                  f"progress={prog} stage={stage}", flush=True)
            st["prev"], st["t_print"] = cur, now
        uc2.hle_remove(ra)
        e2.hle.table.pop(ra, None)
        return None
    if ret not in e.hle.table:
        e.hle.register(ret, on_ret, name="dbstatus_ret", mode="fixup")
    return None


def tick():
    orig()
    now = emu._time()
    if st["armed"] or emu.sched is None or now - st["last"] < 1.0:
        return
    st["last"] = now
    lm = emu.dyn.by_name(MOD) if emu.dyn else None
    img = res._image(lm) if lm is not None else None
    if img is None:
        return
    for start, rid in zip(img.starts, img.rids):
        if img.method_name(rid).endswith("::CexDbRecoveryGetStatus"):
            emu.hle.register(start, hit, name="CexDbRecoveryGetStatus", mode="fixup")
            st["armed"] = True
            print(f"[dbstatus] armed at {start:#x}", flush=True)


emu.uc.tick_cb = tick
emu.run()
