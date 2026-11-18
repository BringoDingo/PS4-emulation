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


import re as _re
_SQL = _re.compile(r"^\s*(SELECT|INSERT|REPLACE|UPDATE|DELETE|CREATE|PRAGMA|BEGIN|COMMIT|ROLLBACK|DROP|ALTER|ATTACH|VACUUM|WITH|END|SAVEPOINT|RELEASE)", _re.I)


def _rd(uc, a, n):
    return bytes(uc.mem_read(a, n))


def read_stdstring(uc, p):
    """The call sites pass the SQL in more than one string representation; try each and keep the
    one that decodes to something that starts like SQL."""
    cands = []
    try:                                   # {?@0; union{char* heap; char inline[16]}@8; size@0x18; cap@0x20}
        size, cap = struct.unpack("<QQ", _rd(uc, p + 0x18, 16))
        if 0 < size < 4000:
            if cap <= 0xF:
                cands.append(_rd(uc, p + 8, size))
            else:
                cands.append(_rd(uc, struct.unpack("<Q", _rd(uc, p + 8, 8))[0], size))
    except Exception:
        pass
    try:                                   # {ptr@0; inline@8; size@0x18; cap@0x20} (app string)
        size, cap = struct.unpack("<QQ", _rd(uc, p + 0x18, 16))
        if 0 < size < 4000:
            cands.append(_rd(uc, p + 8, size) if cap <= 0xF else _rd(uc, struct.unpack("<Q", _rd(uc, p, 8))[0], size))
    except Exception:
        pass
    try:                                   # libc++ short/long
        first = _rd(uc, p, 24)
        if first[0] & 1 == 0:
            n = first[0] >> 1
            cands.append(first[1:1 + n])
        else:
            cands.append(_rd(uc, struct.unpack("<Q", first[16:24])[0], min(struct.unpack("<Q", first[8:16])[0], 4000)))
    except Exception:
        pass
    for off in (0, 8, 0x10):               # {ptr, size} / {size, ptr} / char* at p
        try:
            q = struct.unpack("<Q", _rd(uc, p + off, 8))[0]
            if 0x100000 < q < 0x7fffffffffff:
                cands.append(_rd(uc, q, 600).split(bytes([0]))[0])
        except Exception:
            pass
    try:
        cands.append(_rd(uc, p, 600).split(bytes([0]))[0])
    except Exception:
        pass
    for c in cands:
        t = c.decode("latin1", "replace")
        if _SQL.match(t):
            return t
    return None


def prep(e, uc):
    st["n"] = st.get("n", 0) + 1
    try:
        sql = read_stdstring(uc, uc.reg_read(X.UC_X86_REG_RSI))
    except Exception as ex:
        print("prep error", ex, flush=True); return None
    if sql is None and st["n"] <= 3:
        _p = uc.reg_read(X.UC_X86_REG_RSI)
        _sz, _cp = struct.unpack("<QQ", _rd(uc, _p + 0x18, 16))
        _dp = struct.unpack("<Q", _rd(uc, _p + 8, 8))[0]
        try:
            _txt = _rd(uc, _p + 8, _sz) if _cp <= 0xF else _rd(uc, _dp, min(_sz, 90))
        except Exception as _e:
            _txt = repr(_e)
        print(f"  [undecoded prepare #{st['n']}] size={_sz} cap={_cp} text={_txt!r}", flush=True)
    tid = e.sched.current.tid if e.sched and e.sched.current else 0
    if sql:
        print(f"[{e._time()-e._t0:7.2f}s] tid {tid:#x} prepare: {sql[:700]!r}", flush=True)
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
