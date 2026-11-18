"""Per-statement SQL lifecycle trace on the app-DB wrapper (WHP): SQL, bound values, step results,
row count and the column values returned, with thread and time.

    python sqltrace2.py 45 [grep]            # grep: only statements whose SQL contains it

Wrapper functions (found by xref): prepare=eboot+0x2d1700(conn, string*, &stmt),
step=0x2d7800(stmt, ...), column=0x2d80d0(stmt, col, &value), bind=0x2d7e10(stmt, idx, &value).
step returns 0 = ROW, 1 = DONE. Typed value struct: {type@0 (1 int, 3 text), ?, len@0x10, data@0x18}.
Output: one block per statement, printed when the run ends (statements in order).
"""
import re
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 45
only = sys.argv[2] if len(sys.argv) > 2 else None
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
PREP, STEP, COL, BIND = 0x1002d1700, 0x1002d7800, 0x1002d80d0, 0x1002d7e10
st = {"armed": False, "last": 0.0}
stmts = {}            # stmt ptr -> current record
records = []          # all records in order
pending = {}          # (tid, kind) -> data for the return hook
_SQL = re.compile(r"^\s*(SELECT|INSERT|REPLACE|UPDATE|DELETE|CREATE|PRAGMA|BEGIN|COMMIT|ROLLBACK|DROP|ALTER|WITH)", re.I)
retsites = set()


def _rd(uc, a, n):
    return bytes(uc.mem_read(a, n))


def read_sql(uc, p):
    try:
        size, cap = struct.unpack("<QQ", _rd(uc, p + 0x18, 16))
        if 0 < size < 4000:
            raw = _rd(uc, p + 8, size) if cap <= 0xF else _rd(uc, struct.unpack("<Q", _rd(uc, p + 8, 8))[0], size)
            t = raw.decode("latin1", "replace")
            if _SQL.match(t):
                return t
    except Exception:
        pass
    return None


def val_str(uc, vp):
    try:
        typ, _x, ln, dp = struct.unpack("<QQQQ", _rd(uc, vp, 32))
        t = typ & 0xF                       # high bits are noise; 1 int, 3 text, 5 null
        ln &= 0xFFFFFFFF
        if t == 3 and 0 <= ln < 300:
            return "'" + _rd(uc, dp, ln).decode("latin1", "replace") + "'"
        if t == 1:
            return str(struct.unpack('<q', struct.pack('<Q', dp))[0])
        if t == 5:
            return "NULL"
        return f"?t{t}"
    except Exception:
        return "?"


def tid_of(e):
    return e.sched.current.tid if e.sched and e.sched.current else 0


def on_ret_hook(e, uc):
    """Shared return-site hook: finish whatever call this thread has pending."""
    tid = tid_of(e)
    p = pending.pop(tid, None)
    if p is None:
        return None
    kind = p["kind"]
    rax = uc.reg_read(X.UC_X86_REG_RAX)
    if kind == "prep":
        stmt = struct.unpack("<Q", _rd(uc, p["out"], 8))[0]
        rec = {"sql": p["sql"], "rc": rax, "tid": tid, "t": p["t"], "binds": [], "rows": 0,
               "steps": [], "cols": [], "stmt": stmt}
        stmts[stmt] = rec
        records.append(rec)
    elif kind == "step":
        rec = p["rec"]
        rec["steps"].append(rax)
        if rax == 0:
            rec["rows"] += 1
            rec["cur"] = rec["rows"]
    elif kind == "col":
        rec = p["rec"]
        if rec["rows"] <= 2:               # first 2 rows only
            rec["cols"].append((rec["rows"], p["col"], val_str(uc, p["out"])))
    return None


def arm_ret(e, ret):
    if ret not in retsites and ret not in e.hle.table:
        retsites.add(ret)
        e.hle.register(ret, on_ret_hook, name="sqlret", mode="fixup")


def ret_of(uc):
    return struct.unpack("<Q", _rd(uc, uc.reg_read(X.UC_X86_REG_RSP), 8))[0]


def h_prep(e, uc):
    sql = read_sql(uc, uc.reg_read(X.UC_X86_REG_RSI))
    if sql is None:
        return None
    ret = ret_of(uc)
    pending[tid_of(e)] = {"kind": "prep", "sql": sql, "out": uc.reg_read(X.UC_X86_REG_RDX),
                          "t": e._time() - e._t0}
    arm_ret(e, ret)
    return None


def h_step(e, uc):
    rec = stmts.get(uc.reg_read(X.UC_X86_REG_RDI))
    if rec is None:
        return None
    pending[tid_of(e)] = {"kind": "step", "rec": rec}
    arm_ret(e, ret_of(uc))
    return None


def h_col(e, uc):
    rec = stmts.get(uc.reg_read(X.UC_X86_REG_RDI))
    if rec is None:
        return None
    pending[tid_of(e)] = {"kind": "col", "rec": rec, "col": uc.reg_read(X.UC_X86_REG_RSI) & 0xFFFFFFFF,
                          "out": uc.reg_read(X.UC_X86_REG_RDX)}
    arm_ret(e, ret_of(uc))
    return None


def h_bind(e, uc):
    rec = stmts.get(uc.reg_read(X.UC_X86_REG_RDI))
    if rec is not None:
        rec["binds"].append((uc.reg_read(X.UC_X86_REG_RSI) & 0xFFFFFFFF, val_str(uc, uc.reg_read(X.UC_X86_REG_RDX))))
    return None


def tick():
    orig()
    if st["armed"] or emu.sched is None or emu._time() - st["last"] < 1.0:
        return
    st["last"] = emu._time()
    lm = emu.dyn.by_name("eboot.bin") if emu.dyn else None
    if lm is None or not lm.base:
        return
    for a, h, n in ((PREP, h_prep, "prep"), (STEP, h_step, "step"), (COL, h_col, "col"), (BIND, h_bind, "bind")):
        emu.hle.register(a, h, name=n, mode="fixup")
    st["armed"] = True


emu.uc.tick_cb = tick
emu.run()
print(f"\n==== {len(records)} statements ====")
for i, r in enumerate(records):
    sql = r["sql"]
    if re.match(r"\s*(begin|commit|rollback|pragma)", sql, re.I):
        continue
    if only and only not in sql:
        continue
    short = re.sub(r"SELECT titleId, contentId.*? FROM", "SELECT <49 browse cols> FROM", sql)
    print(f"[{r['t']:6.2f}s tid {r['tid']:#x}] #{i} prep rc={r['rc']:#x} rows={r['rows']} steps={r['steps'][:6]}")
    print(f"    SQL: {short[:300]}")
    if r["binds"]:
        print(f"    binds: {r['binds']}")
    if r["cols"]:
        by_row = {}
        for row, col, v in r["cols"]:
            by_row.setdefault(row, []).append(f"c{col}={v}")
        for row, vs in list(by_row.items())[:3]:
            print(f"    row{row}: " + " ".join(vs)[:400])
