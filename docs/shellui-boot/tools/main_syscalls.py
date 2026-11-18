"""What does one thread do syscall-by-syscall in a time window on WHP?

    python main_syscalls.py WINDOW_START WINDOW_END [tid]     # seconds of wall time; default tid 0x10001

Prints a histogram of syscall names for the thread plus the first 40 calls in the window with
rdi/rsi/rdx and the wall time they took (blocking ones show their wait).
"""
import sys
import time
from collections import Counter

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.syscalls import SYSCALLS

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
t0w, t1w = float(sys.argv[1]), float(sys.argv[2])
want = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x10001
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = t1w
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
hist = Counter()
first = []


def dispatch(uc):
    now = emu._time() - emu._t0
    cur = emu.sched.current if emu.sched else None
    if cur is not None and cur.tid == want and t0w <= now <= t1w:
        nr = uc.reg_read(X.UC_X86_REG_RAX)
        name = SYSCALLS.get(nr, f"sys_{nr}")
        hist[name] += 1
        if len(first) < 40:
            first.append((now, name, uc.reg_read(X.UC_X86_REG_RDI), uc.reg_read(X.UC_X86_REG_RSI),
                          uc.reg_read(X.UC_X86_REG_RDX)))
    return orig(uc)


sc.dispatch = dispatch
emu.run()
print(f"\nthread {want:#x} syscalls in {t0w}-{t1w}s:", hist.most_common(12))
for t, n, a, b, c in first:
    print(f"  {t:7.2f}s {n:28s} {a:#x} {b:#x} {c:#x}")
