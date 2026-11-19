"""Symbolize the managed stack of the thread that waits on a given umtx semaphore address (WHP).

Scans the thread's stack for return addresses into loaded modules, symbolizes managed ones with the
AOT resolver. Prints the first 40 distinct frames, innermost first.

    python wait_stack.py 30 0x106d278d4
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs, want = float(sys.argv[1]), int(sys.argv[2], 0)
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
sc = emu.syscalls
orig = sc.dispatch
done = [False]


def dispatch(uc):
    if not done[0] and uc.reg_read(X.UC_X86_REG_RAX) == 454 and uc.reg_read(X.UC_X86_REG_RDI) == want \
            and (uc.reg_read(X.UC_X86_REG_RSI) & 0xFFFFFFFF) == 0x13:
        done[0] = True
        tid = emu.sched.current.tid
        rsp = uc.reg_read(X.UC_X86_REG_RSP)
        print(f"tid {tid:#x} waits on {want:#x}; stack scan from rsp={rsp:#x}")
        blob = bytes(uc.mem_read(rsp, 0x1000))
        seen = []
        for off in range(0, len(blob) - 8, 8):
            v = struct.unpack_from("<Q", blob, off)[0]
            if not 0x100000000 <= v < 0x4000000000:
                continue
            lm = emu.dyn.module_at(v)
            if lm is None:
                continue
            nm = res.name(v)
            if nm in seen:
                continue
            seen.append(nm)
            if len(seen) <= 45:
                print(f"  +{off:#6x}  {nm}")
    return orig(uc)


sc.dispatch = dispatch
emu.run()
