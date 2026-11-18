"""Trace the app-DB SQLite wrapper during app.db access on WHP: prepare (SQL text), step (rc),
column. Reveals the exact queries the engine runs against app.db and which fails.

    python sqltrace.py 9

Wrapper fns (found via xref): prepare=eboot+0x2d1700(conn, std::string* sql, &stmt),
step=eboot+0x2d7800(&stmt, ...), column=eboot+0x2d80d0(&stmt, col, &out).
"""
import os
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 9
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
st = {"armed": False, "last": 0.0, "appdb": False}
PREP, STEP, COL = 0x1002d1700, 0x1002d7800, 0x1002d80d0


def read_stdstring(uc, p):
    # libc++ std::string: if LSB of [p] is 0 -> long form {cap,size,data@+16}; else short (inline @ p+1)
    try:
        first = bytes(uc.mem_read(p, 24))
        if first[0] & 1:  # short SSO: size in (first[0]>>1), data at p+1
            n = first[0] >> 1
            return first[1:1+n].decode("latin1", "replace")
        ptr = struct.unpack("<Q", first[16:24])[0]
        size = struct.unpack("<Q", first[8:16])[0]
        if 0 < size < 400:
            return bytes(uc.mem_read(ptr, size)).decode("latin1", "replace")
    except Exception:
        pass
    return None


def prep(e, uc):
    sql = read_stdstring(uc, uc.reg_read(X.UC_X86_REG_RSI))
    tid = e.sched.current.tid if e.sched and e.sched.current else 0
    if sql and ("app" in (sql.lower()) or "tbl_" in sql or "sqlite_master" in sql or "PRAGMA" in sql or st["appdb"]):
        print(f"[{e._time()-e._t0:7.2f}s] tid {tid:#x} prepare: {sql[:150]!r}", flush=True)
        st["appdb"] = True
        ret = struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0]
        if ret not in e.hle.table:
            def on_ret(e2, uc2, ra=ret):
                print(f"          prepare -> rc={uc2.reg_read(X.UC_X86_REG_RAX):#x}", flush=True)
                uc2.hle_remove(ra); e2.hle.table.pop(ra, None); return None
            e.hle.register(ret, on_ret, name="prepret", mode="fixup")
    return None


def step(e, uc):
    if not st["appdb"]:
        return None
    ret = struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0]
    if ret not in e.hle.table:
        def on_ret(e2, uc2, ra=ret):
            print(f"          step -> rc={uc2.reg_read(X.UC_X86_REG_RAX):#x}", flush=True)
            uc2.hle_remove(ra); e2.hle.table.pop(ra, None); return None
        e.hle.register(ret, on_ret, name="stepret", mode="fixup")
    return None


def tick():
    orig()
    if st["armed"] or emu.sched is None or emu._time() - st["last"] < 1.0:
        return
    st["last"] = emu._time()
    lm = emu.dyn.by_name("eboot.bin") if emu.dyn else None
    if lm is None or not lm.base:
        return
    emu.hle.register(PREP, prep, name="prep", mode="fixup")
    emu.hle.register(STEP, step, name="step", mode="fixup")
    st["armed"] = True
    print("[sqltrace] armed", flush=True)


emu.uc.tick_cb = tick
emu.run()
