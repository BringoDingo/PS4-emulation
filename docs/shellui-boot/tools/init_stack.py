"""At the moment the '[Cnt] DbAccessor::Init() : 80f50044' line is written, dump the native rbp
stack (eboot offsets) so DbAccessor::Init's call site can be disassembled (WHP).

    python init_stack.py 9
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 9
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
done = {"v": False}


def frame(a):
    lm = emu.dyn.module_at(a) if emu.dyn else None
    return f"{lm.name}+{a - lm.base:#x}" if lm else hex(a)


def rd(uc, a):
    return struct.unpack("<Q", bytes(uc.mem_read(a, 8)))[0]


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    if not done["v"] and nr == 4:
        try:
            b = bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSI), min(uc.reg_read(X.UC_X86_REG_RDX), 80)))
        except Exception:
            b = b""
        if b"DbAccessor::Init" in b:
            done["v"] = True
            print(f"[{emu._time()-emu._t0:.2f}s] '{b.decode('latin1').strip()}' native stack:")
            rbp = uc.reg_read(X.UC_X86_REG_RBP)
            for _ in range(24):
                try:
                    ra, nx = rd(uc, rbp + 8), rd(uc, rbp)
                except Exception:
                    break
                print("   ", frame(ra))
                if nx <= rbp:
                    break
                rbp = nx
    return orig(uc)


sc.dispatch = dispatch
emu.run()
