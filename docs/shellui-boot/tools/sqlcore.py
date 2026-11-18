"""Trace the statically linked SQLite *core* (every caller: native AppDb wrapper AND managed
Sce.Vsh.SQLite), by resolving its exports by name (NID) in the eboot module (WHP).

    python sqlcore.py 45 [grep]

Hooks sqlite3_open_v2 / prepare_v2 / exec / step / errmsg. Prints, per call: time, thread, the SQL
or file name, and the return code (sqlite3 result codes: 0 OK, 1 ERROR, 14 CANTOPEN, 100 ROW,
101 DONE, ...). A failing prepare is followed by sqlite3_errmsg text when the engine asks for it.
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.sys_dynlib import nid

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 45
only = sys.argv[2] if len(sys.argv) > 2 else None
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
st = {"armed": False, "last": 0.0, "n": 0}
pending = {}
retsites = set()
NAMES = ["sqlite3_open_v2", "sqlite3_prepare_v2", "sqlite3_exec", "sqlite3_step", "sqlite3_errmsg"]


def cstr(uc, p, n=400):
    try:
        return bytes(uc.mem_read(p, n)).split(bytes([0]))[0].decode("latin1", "replace")
    except Exception:
        return None


def tid_of(e):
    return e.sched.current.tid if e.sched and e.sched.current else 0


def ret_hook(e, uc):
    p = pending.pop(tid_of(e), None)
    if p is None:
        return None
    rc = uc.reg_read(X.UC_X86_REG_RAX) & 0xFFFFFFFF
    if p["fn"] == "step":
        if rc not in (100, 101) and st["n"] < 4000:
            print(f"        step rc={rc}", flush=True)
    elif p["fn"] == "errmsg":
        print(f"        errmsg -> {cstr(uc, uc.reg_read(X.UC_X86_REG_RAX))!r}", flush=True)
    else:
        print(f"        {p['fn']} rc={rc}", flush=True)
    return None


def arm(e, ret):
    if ret not in retsites and ret not in e.hle.table:
        retsites.add(ret)
        e.hle.register(ret, ret_hook, name="sqlcore_ret", mode="fixup")


def make(fn):
    def h(e, uc):
        tid = tid_of(e)
        rsp = uc.reg_read(X.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
        rdi, rsi = uc.reg_read(X.UC_X86_REG_RDI), uc.reg_read(X.UC_X86_REG_RSI)
        text = None
        if fn == "open_v2":
            text = cstr(uc, rdi)
        elif fn in ("prepare_v2", "exec"):
            text = cstr(uc, rsi)
        if fn in ("open_v2", "prepare_v2", "exec") and (only is None or (text and only in text)):
            st["n"] += 1
            print(f"[{e._time() - e._t0:7.2f}s tid {tid:#x}] {fn}: {text!r}"[:380], flush=True)
            pending[tid] = {"fn": fn}
            arm(e, ret)
        elif fn in ("step", "errmsg") and only is None:
            pending[tid] = {"fn": fn}
            arm(e, ret)
        return None
    return h


def tick():
    orig()
    if st["armed"] or emu.sched is None or emu._time() - st["last"] < 1.0:
        return
    st["last"] = emu._time()
    lm = emu.dyn.by_name("eboot.bin") if emu.dyn else None
    if lm is None or not lm.base:
        return
    exports = lm.mod.exports
    for nm in NAMES:
        addr = exports.get(nid(nm))
        if addr is None:
            print(f"[sqlcore] {nm}: not exported", flush=True)
            continue
        emu.hle.register(addr, make(nm.replace("sqlite3_", "")), name=nm, mode="fixup")
        print(f"[sqlcore] {nm} @ {addr:#x}", flush=True)
    st["armed"] = True


emu.uc.tick_cb = tick
emu.run()
