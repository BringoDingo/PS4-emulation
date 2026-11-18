"""Statistical guest profile on WHP: sample RIP at every time-slice exit, histogram by module/function.

    python rip_sample.py 40            # PSEMU_PAD=... etc. are honoured
"""
import collections
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 40
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
hist = collections.Counter()
bythread = collections.Counter()
orig_tick = emu._whp_tick
n = [0]


def tick():
    orig_tick()
    uc = emu.uc
    try:
        rip = uc.reg_read(X.UC_X86_REG_RIP)
    except Exception:
        return
    lm = emu.dyn.module_at(rip) if emu.dyn else None
    key = f"{lm.name}+{(rip - lm.base) >> 8 << 8:#x}" if lm else f"{rip >> 12 << 12:#x}"
    hist[key] += 1
    t = emu.sched.current.tid if emu.sched and emu.sched.current else 0
    bythread[t] += 1
    n[0] += 1


emu.uc.tick_cb = tick
emu.run()
print(f"\nsamples {n[0]}")
print("top code regions (256-byte buckets):")
for k, v in hist.most_common(14):
    print(f"  {v:6d} {100 * v / max(n[0], 1):5.1f}%  {k}")
print("top threads:", [(hex(t), c) for t, c in bythread.most_common(6)])
