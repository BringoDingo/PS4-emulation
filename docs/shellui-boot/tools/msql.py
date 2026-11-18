"""Trace the MANAGED SQLite layer (Sce.Vsh.SQLite.SQLite3 + Sce.Vsh.Db.Shared.ConnectionManager) on WHP.

    python msql.py 45 [grep]

Hooks the static SQLite3 methods (Open, Prepare2, Step, Column*, Errmsg/GetErrmsg, Close) and the
ConnectionManager Open/Close. Each hit prints time, thread, method and its first args (decoding
Mono strings: MonoString = header(0x10) + int32 length + UTF-16 chars); on return it prints the
result (Step: 100 ROW / 101 DONE, others are errors; Prepare2/Open: handle; ColumnInt: the value;
Errmsg: the message). This is where the content list's count query (EnhancedAppBrowseItemAccessor ->
ExecuteCountQuery) is run, which the native AppDb-wrapper tools cannot see.
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
sys.path.insert(0, r"D:\CLAUDEGODOT2\PS4-emulation\docs\shellui-boot\tools")
import unicorn.x86_const as X
from aotsym import AotResolver
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 45
only = sys.argv[2] if len(sys.argv) > 2 else None
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
orig = emu._whp_tick
st = {"armed": False, "last": 0.0}
pending = {}
retsites = {}
LOG = []

SQL3 = ("Open", "Prepare2", "Step", "Reset", "Finalize", "Errmsg", "GetErrmsg", "ColumnInt", "ColumnInt64",
        "ColumnText", "ColumnString", "ColumnCount", "ColumnType", "BindText", "BindInt", "BindNull", "Close")
CM = ("Open", "Close", "createConnectionForSingleDb", "findConnectionFromHashTable")
RETTYPE = {"Step": "result", "Open": "handle", "Prepare2": "handle", "Errmsg": "string", "GetErrmsg": "string",
           "ColumnText": "string", "ColumnString": "string", "ColumnInt": "int", "ColumnInt64": "int",
           "ColumnCount": "int", "ColumnType": "int"}
RESULT = {0: "OK", 1: "ERROR", 5: "BUSY", 6: "LOCKED", 14: "CANTOPEN", 11: "CORRUPT", 100: "ROW", 101: "DONE",
          21: "MISUSE", 26: "NOTADB", 8: "READONLY", 10: "IOERR"}


def rd(uc, a, n):
    return bytes(uc.mem_read(a, n))


def mstr(uc, p):
    """Decode a MonoString at p, else None."""
    try:
        if not 0x100000 < p < 0x7fffffffffff:
            return None
        n = struct.unpack("<i", rd(uc, p + 0x10, 4))[0]
        if 0 <= n < 6000:
            s = rd(uc, p + 0x14, n * 2).decode("utf-16le", "strict")
            if all(32 <= ord(c) < 0x2fff or c in "\n\t" for c in s):
                return s
    except Exception:
        pass
    return None


def tid_of(e):
    return e.sched.current.tid if e.sched and e.sched.current else 0


def fmt_ret(uc, kind, rax):
    if kind == "string":
        return repr(mstr(uc, rax))
    if kind == "result":
        v = rax & 0xFFFFFFFF
        return f"{v} {RESULT.get(v, '')}".strip()
    if kind == "int":
        v = rax & 0xFFFFFFFF
        return str(v - (1 << 32) if v >= (1 << 31) else v)
    return f"{rax:#x}"


def ret_hook(e, uc):
    p = pending.pop(tid_of(e), None)
    if p is None:
        return None
    line = f"        {p['name']} -> {fmt_ret(uc, p['kind'], uc.reg_read(X.UC_X86_REG_RAX))}"
    if p.get("show", True):
        print(line, flush=True)
    return None


def make(name, kind):
    def h(e, uc):
        regs = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_RCX)]
        parts = []
        text = None
        for v in regs:
            s = mstr(uc, v)
            if s is not None and len(s) >= 2:
                text = s
                i_from = s.lower().find(" from tbl_appbrowse")
                parts.append(repr(("<sel> " + s[i_from:i_from + 700]) if i_from > 0 and len(s) > 400
                                  else (s if len(s) < 400 else s[:230] + " ... " + s[-150:])))
            else:
                parts.append(f"{v:#x}")
                if name.endswith("Prepare2") and 0x100000 < v < 0x7fffffffffff:
                    try:                       # raw peek (the query arrives as a non-string managed object)
                        parts[-1] += " raw=" + rd(uc, v, 40).hex(" ", 8)
                    except Exception:
                        pass
        show = only is None or (text is not None and only in text) or name.endswith(("Step", "Errmsg", "GetErrmsg")) \
            or "Column" in name
        if show:
            print(f"[{e._time() - e._t0:7.2f}s tid {tid_of(e):#x}] {name}({', '.join(parts)})", flush=True)
        rsp = uc.reg_read(X.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", rd(uc, rsp, 8))[0]
        pending[tid_of(e)] = {"name": name.split(".")[-1], "kind": kind, "show": show}
        if ret not in retsites and ret not in e.hle.table:
            retsites[ret] = True
            e.hle.register(ret, ret_hook, name="msql_ret", mode="fixup")
        return None
    return h


def install():
    n = 0
    for mod, want, cls in (("Sce.Vsh.SQLite.dll.sprx", SQL3, "SQLite3::"),
                           ("Sce.Vsh.Db.Shared.dll.sprx", CM, "ConnectionManager::")):
        lm = emu.dyn.by_name(mod) if emu.dyn else None
        img = res._image(lm) if lm is not None else None
        if img is None:
            return False
        for start, rid in zip(img.starts, img.rids):
            nm = img.method_name(rid)
            if cls in nm and nm.split("::")[-1] in want:
                short = cls.replace("::", ".") + nm.split("::")[-1]
                emu.hle.register(start, make(short, RETTYPE.get(nm.split("::")[-1], "handle")), name=short, mode="fixup")
                n += 1
    print(f"[msql] hooked {n} managed methods", flush=True)
    return True


def tick():
    orig()
    if st["armed"] or emu.sched is None or emu._time() - st["last"] < 1.0:
        return
    st["last"] = emu._time()
    if install():
        st["armed"] = True


emu.uc.tick_cb = tick
emu.run()
