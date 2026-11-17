"""Who calls a method (by Type::name), across one or more assemblies; plus the call sequence of chosen methods."""
import sys, struct
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil_scan import *
from psemu.syscalls import _embedded_cil
LIB = r"D:\Ps4Tools\ps4kernel\firmware\system\common\lib"
APP = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\psm\Application"
import os

def load(name):
    for d in (LIB, APP):
        p = os.path.join(d, name + ".dll.sprx")
        if os.path.exists(p): return build(_embedded_cil(open(p, "rb").read()))
    raise SystemExit("not found " + name)

def index(a):
    n = a.rows[0x06]; nt = a.rows[0x02]
    starts = [(a.row(0x02, i)[5], i) for i in range(1, nt + 1)]
    owner = {}
    for k, (ms, ti) in enumerate(starts):
        me = starts[k+1][0] if k + 1 < len(starts) else n + 1
        for m in range(ms, me): owner[m] = a.typename(0x02, ti)
    names = {m: (owner.get(m, "?"), a.string(a.row(0x06, m)[3])) for m in range(1, n + 1)}
    return names

def calls_in(il):
    out = []
    for pos in range(len(il) - 4):
        if il[pos] in (0x28, 0x6F, 0x73):
            t = struct.unpack_from("<I", il, pos + 1)[0]
            if (t >> 24) in (0x06, 0x0A, 0x2B): out.append((pos, il[pos], t))
    return out

def resolve(a, names, tok):
    t, i = tok >> 24, tok & 0xFFFFFF
    if t == 0x06 and i in names: return "%s::%s" % names[i]
    if t == 0x0A and i <= a.rows.get(0x0A, 0): return "%s::%s" % memberref_target(a, i)
    return f"<{tok:#x}>"

def method_il(a):
    out = {}
    n = a.rows[0x06]
    for m in range(1, n + 1):
        r = a.row(0x06, m)
        if not r[0]: continue
        try: o = a.off(r[0])
        except Exception: continue
        b = a.pe[o]
        if b & 3 == 2: size = b >> 2; il = o + 1
        elif b & 3 == 3: size = U32(a.pe, o + 4); il = o + (U16(a.pe, o) >> 12) * 4
        else: continue
        out[m] = bytes(a.pe[il:il + size])
    return out

if __name__ == "__main__":
    asm, mode, *rest = sys.argv[1:]
    a = load(asm); names = index(a); il = method_il(a)
    if mode == "callers":          # callers Type::Method
        want = rest[0]
        toks = {0x06000000 | m for m, (t, n) in names.items() if f"{t.split('.')[-1]}::{n}" == want or f"{t}::{n}" == want}
        print("target tokens:", [hex(t) for t in toks])
        for m, body in il.items():
            for pos, op, t in calls_in(body):
                if t in toks: print(f"  {names[m][0]}::{names[m][1]} @IL{pos}")
    elif mode == "seq":            # seq Type::Method ...
        for want in rest:
            for m, body in il.items():
                t, n = names[m]
                if f"{t.split('.')[-1]}::{n}" == want or f"{t}::{n}" == want:
                    print(f"\n=== {t}::{n} (IL {len(body)}B) ===")
                    for pos, op, tok in calls_in(body):
                        print(f"  {pos:5d}: {'call' if op==0x28 else 'callvirt' if op==0x6F else 'newobj'} {resolve(a, names, tok)}")
    elif mode == "find":           # methods whose name contains a substring
        for m, (t, n) in names.items():
            if rest[0].lower() in (t + "::" + n).lower(): print(f"  {t}::{n}  (IL {len(il.get(m,b''))}B)")
