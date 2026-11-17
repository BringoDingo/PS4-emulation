import os
"""cil_callers for the ShellUI assemblies (app.exe / platform.dll); pick with env ASM."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import cil_callers as C
from cil_scan import build
from psemu.syscalls import _embedded_cil

APP = os.path.join(r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\psm\Application",
                   os.environ.get("ASM", "app.exe.sprx"))
a = build(_embedded_cil(open(APP, "rb").read()))
names = C.index(a)
il = C.method_il(a)
mode, *rest = sys.argv[1:]
if mode == "find":
    for m, (t, n) in names.items():
        if rest[0].lower() in (t + "::" + n).lower():
            print(f"  {t}::{n}  (IL {len(il.get(m, b''))}B)")
elif mode == "callers":
    want = rest[0]
    toks = {0x06000000 | m for m, (t, n) in names.items()
            if f"{t.split('.')[-1]}::{n}" == want or f"{t}::{n}" == want}
    print("target tokens:", [hex(t) for t in toks])
    for m, body in il.items():
        for pos, op, t in C.calls_in(body):
            if t in toks:
                arg = None
                for k in range(max(0, pos - 6), pos):
                    if body[k] == 0x20:
                        arg = int.from_bytes(body[k + 1:k + 5], "little")
                    elif 0x16 <= body[k] <= 0x1E:
                        arg = body[k] - 0x16
                print(f"  {names[m][0]}::{names[m][1]} @IL{pos} arg={hex(arg) if arg is not None else '?'}")
elif mode == "seq":
    for want in rest:
        for m, body in il.items():
            t, n = names[m]
            if f"{t.split('.')[-1]}::{n}" == want or f"{t}::{n}" == want:
                print(f"\n=== {t}::{n} (IL {len(body)}B) ===")
                for pos, op, tok in C.calls_in(body):
                    print(f"  {pos:5d}: {'call' if op==0x28 else 'callvirt' if op==0x6F else 'newobj'} {C.resolve(a, names, tok)}")
if mode == "xcallers":        # callers of a cross-assembly member by name suffix
    want = rest[0]
    for m, body in il.items():
        for pos, op, t in C.calls_in(body):
            try:
                r = C.resolve(a, names, t)
            except Exception:
                continue
            if r.endswith(want):
                arg = None
                for k in range(max(0, pos - 8), pos):
                    if body[k] == 0x20:
                        arg = int.from_bytes(body[k + 1:k + 5], "little")
                    elif 0x16 <= body[k] <= 0x1E:
                        arg = body[k] - 0x16
                print(f"  {names[m][0]}::{names[m][1]} @IL{pos} arg={hex(arg) if arg is not None else '?'}")
