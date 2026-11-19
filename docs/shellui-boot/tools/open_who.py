"""Native call chain of the first open() of a path containing a substring (WHP).

    python open_who.py 30 BgmPlayStatusCheck
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs, sub = float(sys.argv[1]), sys.argv[2]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
shown = [0]


def where(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else f"{a:#x}"


def dispatch(uc):
    if uc.reg_read(X.UC_X86_REG_RAX) == 5 and shown[0] < 2:
        p = uc.reg_read(X.UC_X86_REG_RDI)
        try:
            path = bytes(uc.mem_read(p, 160)).split(bytes([0]))[0].decode("latin1")
        except Exception:
            path = ""
        if sub in path:
            shown[0] += 1
            rbp = uc.reg_read(X.UC_X86_REG_RBP)
            out = [where(struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0])]
            for _ in range(14):
                try:
                    ra, nx = struct.unpack("<QQ", bytes(uc.mem_read(rbp + 8, 8)) + bytes(uc.mem_read(rbp, 8)))
                except Exception:
                    break
                out.append(where(ra))
                if nx <= rbp:
                    break
                rbp = nx
            print(f"[{emu._time() - emu._t0:6.2f}s] tid {emu.sched.current.tid:#x} open({path!r})")
            for f in out:
                print("     ", f)
    return orig(uc)


sc.dispatch = dispatch
emu.run()
