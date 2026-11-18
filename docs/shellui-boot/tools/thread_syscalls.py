"""Per-thread syscall histogram (what each guest thread is busy doing) on WHP.

    python thread_syscalls.py 40
"""
import collections
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.syscalls import SYSCALLS

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 40
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
per = collections.defaultdict(collections.Counter)


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
    per[tid][SYSCALLS.get(nr, f"sys_{nr}")] += 1
    return orig(uc)


sc.dispatch = dispatch
emu.run()
tot = sorted(per.items(), key=lambda kv: -sum(kv[1].values()))
print("\nthread  total  top syscalls")
for tid, c in tot[:8]:
    print(f"{tid:#8x} {sum(c.values()):7d}  " + ", ".join(f"{k} {v}" for k, v in c.most_common(5)))
