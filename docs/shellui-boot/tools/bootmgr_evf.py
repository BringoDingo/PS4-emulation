"""Log every set/clear on the BootManager event flag (SceShellUIBootManager) with the wall time.

    python bootmgr_evf.py 60        # run 60 s on the WHP backend

Shows which boot-step flags actually get set (and when) -- the waits on 0x400 / 0x8000000 /
0x100000000000 in the thread dump are the flags that never arrive.
"""
import os
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 60
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
target = {}


def wrap(name):
    orig = getattr(sc, name)

    def f(uc, *a, **k):
        h, bits = sc._args(uc)[:2]
        ef = sc._evf(h)
        nm = getattr(ef, "name", "") if ef is not None else ""
        if "BootManager" in str(nm):
            tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
            print(f"[{emu._time() - emu._t0:7.2f}s] tid {tid:#x} {name} {bits:#x}  (before: {ef.bits:#x})", flush=True)
        return orig(uc, *a, **k)
    setattr(sc, name, f)


wrap("sys_evf_set")
wrap("sys_evf_clear")
if os.environ.get("WAITS"):                      # also the waits (bits, mode in rdx), first-time per thread+bits
    wrap("sys_evf_wait")
emu.run()
