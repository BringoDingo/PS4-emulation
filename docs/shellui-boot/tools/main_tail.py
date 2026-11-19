"""The last N syscalls of the main thread (0x10001) before it first waits on a given semaphore address.

    python main_tail.py 30 0x106d278d4 60
"""
import collections
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.syscalls import SYSCALLS

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs, want, keep = float(sys.argv[1]), int(sys.argv[2], 0), int(sys.argv[3])
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
ring = collections.deque(maxlen=keep)
done = [False]


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
    if tid == 0x10001 and not done[0]:
        a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX)]
        txt = ""
        if nr == 4 and a[2] < 300:
            try:
                txt = bytes(uc.mem_read(a[1], a[2])).decode("latin1")
            except Exception:
                pass
        ra = struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0]
        ring.append(f"[{emu._time() - emu._t0:6.2f}s] {SYSCALLS.get(nr, nr)}({a[0]:#x}, {a[1]:#x}, {a[2]:#x}) "
                    f"{txt!r}" if txt else
                    f"[{emu._time() - emu._t0:6.2f}s] {SYSCALLS.get(nr, nr)}({a[0]:#x}, {a[1]:#x}, {a[2]:#x})")
        if nr == 454 and a[0] == want and (a[1] & 0xFFFFFFFF) == 0x13:
            done[0] = True
            print("main waits on the semaphore; its last syscalls:")
            for line in ring:
                print("  ", line)
    return orig(uc)


sc.dispatch = dispatch
emu.run()
