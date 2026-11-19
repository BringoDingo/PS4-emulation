"""Catch managed exceptions as they are formatted: hook System.Exception::ToString (mscorlib AOT code) and
print the exception's string fields (class name, message, ...) and the managed caller chain.

    python exc_catch.py 30 [max-hits]
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
secs = float(sys.argv[1])
cap = int(sys.argv[2]) if len(sys.argv) > 2 else 6
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
armed = [False]
hits = [0]
orig_tick = emu._whp_tick


def mono_str(uc, p):
    try:
        n = struct.unpack("<i", bytes(uc.mem_read(p + 0x10, 4)))[0]
        if 0 <= n <= 4000:
            return bytes(uc.mem_read(p + 0x14, 2 * n)).decode("utf-16le", "replace")
    except Exception:
        pass
    return None


def hit(e, uc):
    hits[0] += 1
    if hits[0] > cap:
        return None
    this = uc.reg_read(X.UC_X86_REG_RDI)
    print(f"[{e._time() - e._t0:6.2f}s] Exception::ToString this={this:#x} tid={e.sched.current.tid:#x}", flush=True)
    try:
        for off in range(0x10, 0x70, 8):
            p = struct.unpack("<Q", bytes(uc.mem_read(this + off, 8)))[0]
            if p > 0x10000:
                s = mono_str(uc, p)
                if s:
                    print(f"    +{off:#x}: {s[:600]!r}", flush=True)
    except Exception as ex:
        print("   (read failed)", ex)
    return None


def tick():
    orig_tick()
    if armed[0] or emu.dyn is None:
        return
    lm = emu.dyn.by_name("mscorlib.dll.sprx")
    if lm is None or not lm.base:
        return
    img = res._image(lm)
    for start, rid in zip(img.starts, img.rids):
        if img.method_name(rid) == "System.Exception::ToString":
            emu.hle.register(start, hit, name=f"exc_tostring_{start:x}", mode="fixup")
            print(f"hooked {img.method_name(rid)} at {start:#x}", flush=True)
    armed[0] = True


emu.uc.tick_cb = tick
emu.run()
print("\nExceptions formatted:", hits[0])
