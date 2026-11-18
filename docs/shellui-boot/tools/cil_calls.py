"""Print the calls (in IL order) made by a managed method, plus its ldstr / ldc / branch markers.

    set ASM=<path to the .dll.sprx>      (default app.exe.sprx under the ShellUI psm/Application dir)
    python cil_calls.py "AppBrowseItemAccessor::ExecuteCountQuery"

Uses cil_callers / cil_scan (CIL metadata + IL bodies extracted from the AOT .sprx).
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import cil_callers as C
from cil_scan import build
from psemu.syscalls import _embedded_cil

APP = os.path.join(r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\psm\Application",
                   os.environ.get("ASM", "app.exe.sprx"))
a = build(_embedded_cil(open(APP, "rb").read()))
names = C.index(a)
il = C.method_il(a)
want = sys.argv[1]
for m, (t, n) in names.items():
    full = f"{t.split('.')[-1]}::{n}"
    if full == want or f"{t}::{n}" == want:
        body = il.get(m, b"")
        print(f"== {t}::{n}  IL {len(body)} bytes")
        # raw walk for ldstr(0x72) / call(0x28) / callvirt(0x6f) / newobj(0x73) / ldfld(0x7b) / brtrue / brfalse
        i = 0
        while i < len(body):
            op = body[i]
            if op in (0x28, 0x6f, 0x73) and i + 5 <= len(body):
                tok = struct.unpack_from("<I", body, i + 1)[0]
                nm = names.get(tok & 0x00FFFFFF)
                kind = {0x28: "call", 0x6f: "callvirt", 0x73: "newobj"}[op]
                print(f"  {i:4d}: {kind} {nm[0].split('.')[-1] + '::' + nm[1] if nm else hex(tok)}")
                i += 5
            elif op in (0x72, 0x7b, 0x7c, 0x7d, 0x80, 0x7e, 0x7f, 0x81) and i + 5 <= len(body):
                tok = struct.unpack_from("<I", body, i + 1)[0]
                name = {0x72: "ldstr", 0x7b: "ldfld", 0x7c: "ldflda", 0x7d: "stfld", 0x7e: "ldsfld",
                        0x7f: "ldsflda", 0x80: "stsfld", 0x81: "stobj"}[op]
                print(f"  {i:4d}: {name} {tok:#x}")
                i += 5
            elif op in (0x2c, 0x2d, 0x2b, 0x2e, 0x2f, 0x3a, 0x39, 0x38) and i + 2 <= len(body):
                print(f"  {i:4d}: branch({op:#x}) -> {i + 2 + struct.unpack_from('<b', body, i + 1)[0]}")
                i += 2
            else:
                i += 1
