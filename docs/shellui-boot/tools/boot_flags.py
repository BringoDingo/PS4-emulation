"""Decode ShellUI's boot pipeline from app.exe's managed code (needs your own firmware dump).

Prints (1) the ordered BootManager.Eval* steps registered in BootManager..cctor and
(2) every BootManager flag each method sets / waits on / tests (SetFlag, SetEventFlag,
WaitEventFlag, GetEventFlag with the constant that is pushed right before the call).

    python boot_flags.py            # uses PS4_FW or D:\\Ps4Tools\\ps4kernel\\firmware
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "..")))
sys.argv = ["x", "find", "zzzz"]          # reuse cil_app's loader without running a query
exec(open(os.path.join(HERE, "cil_app.py"), encoding="utf-8").read())


def const_before(b, pos):
    p = pos
    if p >= 1 and b[p - 1] == 0x6A:                       # conv.i8
        p -= 1
    if p >= 9 and b[p - 9] == 0x21:                       # ldc.i8
        return struct.unpack_from("<q", b, p - 8)[0]
    if p >= 5 and b[p - 5] == 0x20:                       # ldc.i4
        return struct.unpack_from("<i", b, p - 4)[0] & 0xFFFFFFFF
    if p >= 2 and b[p - 2] == 0x1F:                       # ldc.i4.s
        return b[p - 1]
    if p >= 1 and 0x16 <= b[p - 1] <= 0x1E:              # ldc.i4.0..8
        return b[p - 1] - 0x16
    return None


# ---- 1. ordered steps
for m, (t, n) in names.items():
    if t.endswith("AppMain.BootManager") and n == ".cctor":
        order = []
        b = il[m]
        for p in range(len(b) - 6):
            if b[p] == 0xFE and b[p + 1] == 0x06:         # ldftn
                tok = struct.unpack_from("<I", b, p + 2)[0]
                if tok >> 24 == 6 and (tok & 0xFFFFFF) in names:
                    order.append(names[tok & 0xFFFFFF][1])
        print("Boot steps in evaluation order:")
        for i, o in enumerate(order, 1):
            print(f"  {i:2d}. {o}")

# ---- 2. flags per method
tok_name = {0x06000000 | m: n for m, (t, n) in names.items() if t.endswith("AppMain.BootManager")}
interesting = {"GetEventFlag", "SetFlag", "SetEventFlag", "WaitEventFlag"}
cur = None
print("\nFlags per method (call, constant pushed just before it):")
for m, (t, n) in names.items():
    if "BootManager" not in t:
        continue
    body = il.get(m)
    if not body:
        continue
    for pos, op, tk in C.calls_in(body):
        nm = tok_name.get(tk)
        if nm in interesting:
            v = const_before(body, pos)
            fn = n if t.endswith("BootManager") else t.split(".")[-1] + "." + n
            if fn != cur:
                print(f"\n{fn}:")
                cur = fn
            print(f"    {nm:14s} {hex(v) if v is not None else '?'}")
