"""Wall time spent in the Python syscall handlers, per syscall (and per thread class), on WHP.

    python syscall_time.py 30          # run 30 s, then print the top consumers

Separates "the guest is slow" from "our HLE handlers are slow": total handler time vs wall time,
top syscalls by total / max time, and the same for the main thread only.
"""
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.syscalls import SYSCALLS

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 30
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
tot = defaultdict(float)
cnt = defaultdict(int)
mx = defaultdict(float)
main_tot = defaultdict(float)
main_cnt = defaultdict(int)
orig = sc.dispatch
pc = time.perf_counter


def dispatch(uc):
    t0 = pc()
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    r = orig(uc)
    dt = pc() - t0
    name = SYSCALLS.get(nr, f"sys_{nr}")
    tot[name] += dt
    cnt[name] += 1
    mx[name] = max(mx[name], dt)
    cur = emu.sched.current if emu.sched else None
    if cur is not None and cur.tid == 0x10001:
        main_tot[name] += dt
        main_cnt[name] += 1
    return r


sc.dispatch = dispatch
emu.run()
wall = emu._time() - emu._t0
print(f"\nwall {wall:.1f}s, in syscall handlers {sum(tot.values()):.1f}s "
      f"({sum(cnt.values())} calls), main thread {sum(main_tot.values()):.1f}s ({sum(main_cnt.values())} calls)")
print("top by total time:")
for k in sorted(tot, key=tot.get, reverse=True)[:10]:
    print(f"  {k:36s} {tot[k]:7.2f}s  x{cnt[k]:<7d} max {mx[k] * 1000:8.1f} ms")
print("main thread:")
for k in sorted(main_tot, key=main_tot.get, reverse=True)[:8]:
    print(f"  {k:36s} {main_tot[k]:7.2f}s  x{main_cnt[k]}")
