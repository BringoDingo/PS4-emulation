"""Show the guest-visible virtual filesystem state after N seconds (WHP): files the guest created
or modified (emu.syscalls.vfs), created dirs, deletions, and how selected paths resolve.

    python vfs_dump.py 16 [substring ...]       # default substring: mms, priv, dbr
"""
import os
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 16
subs = sys.argv[2:] or ["mms", "priv", "dbr"]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
emu.run()
sc = emu.syscalls
print(f"\nvfs: {len(sc.vfs)} guest-held files, {len(sc.vdirs)} dirs created, {len(sc.vgone)} deleted")
for p, d in sorted(sc.vfs.items()):
    if any(s in p for s in subs):
        print(f"  {p}  {len(d)} B  {bytes(d[:32])!r}")
for p in sorted(sc.vdirs):
    if any(s in p for s in subs):
        print(f"  dir {p}")
for p in ("/system_data/priv/mms/dbr.db-err", "/system_data/priv/mms", "/system_data/priv/mms/app.db"):
    real = emu.resolve_path(p)
    print(f"resolve {p} -> {real}  exists={bool(real and os.path.exists(real))} in_vfs={p in sc.vfs}")
