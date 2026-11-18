"""Watch candidate sqlite-wrapper bind functions and print any printable text/int passed to them.

    python bindwatch.py 20 0x2d7b00 0x2d7b50 ...      (eboot code offsets)

For each hit prints the function, then rsi/rdx/rcx both as raw values and, when they point at
readable ASCII (a C string or the app's {?;union{heap,inline}@8;size@0x18;cap@0x20} string),
the text. Used to see which titleId / key a prepared statement is bound with.
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
offs = [int(a, 16) for a in sys.argv[2:]]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
st = {"armed": False, "last": 0.0, "n": {}}


def ascii_at(uc, p, n=64):
    try:
        raw = bytes(uc.mem_read(p, n)).split(bytes([0]))[0]
    except Exception:
        return None
    return raw.decode("latin1") if len(raw) >= 3 and all(32 <= c < 127 for c in raw) else None


def appstr(uc, p):
    try:
        size, cap = struct.unpack("<QQ", bytes(uc.mem_read(p + 0x18, 16)))
        if not 0 < size < 200:
            return None
        raw = bytes(uc.mem_read(p + 8, size)) if cap <= 0xF else bytes(
            uc.mem_read(struct.unpack("<Q", bytes(uc.mem_read(p + 8, 8)))[0], size))
        return raw.decode("latin1") if all(32 <= c < 127 for c in raw) else None
    except Exception:
        return None


def make(off):
    def h(e, uc):
        k = st["n"].get(off, 0)
        st["n"][off] = k + 1
        if k >= 25:
            return None
        parts = []
        for nm, r in (("rsi", X.UC_X86_REG_RSI), ("rdx", X.UC_X86_REG_RDX), ("rcx", X.UC_X86_REG_RCX)):
            v = uc.reg_read(r)
            t = ascii_at(uc, v) if v > 0x10000 else None
            t2 = appstr(uc, v) if v > 0x10000 else None
            parts.append(f"{nm}={v:#x}" + (f" c'{t}'" if t else "") + (f" s'{t2}'" if t2 else ""))
        raw = ""
        try:                               # typed value {type@0 (3=text); len@0x10; char* data@0x18}
            vp = uc.reg_read(X.UC_X86_REG_RDX)
            typ, _, ln, dp = struct.unpack("<QQQQ", bytes(uc.mem_read(vp, 32)))
            if typ == 3 and 0 < ln < 200:
                raw = f"  VALUE text={bytes(uc.mem_read(dp, ln)).decode('latin1', 'replace')!r}"
            else:
                raw = f"  value type={typ} q1={_:#x} q2={ln:#x} q3={dp:#x}"
        except Exception:
            pass
        print(f"[{e._time() - e._t0:6.2f}s] fn {off:#x}: " + "  ".join(parts) + raw, flush=True)
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
    for off in offs:
        emu.hle.register(0x100000000 + off, make(off), name=f"bw_{off:x}", mode="fixup")
    st["armed"] = True
    print("[bindwatch] armed", [hex(o) for o in offs], flush=True)


emu.uc.tick_cb = tick
emu.run()
