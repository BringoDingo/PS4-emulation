import struct, sys
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
"""Dump what libScePsm hands managed GamePad.GetData (GamePad::GetDataNative +0x1cdf50, output struct
+0 buttons, +4 ButtonsDown?, +8 ... see README) at its return (+0x1cf666), distinct values only.

    PSEMU_PAD=script PSEMU_PAD_BUTTONS="14+0.5=RIGHT" python gamepad_out.py
"""
emu = Emulator(EXE, fw_root=FW, backend="whp"); emu.max_seconds = 30; emu.max_modules = 80
emu.log = lambda *a, **k: None
armed = [False]; orig_tick = emu._whp_tick; seen = {}
def rd(e, uc):
    src = uc.reg_read(X.UC_X86_REG_R12)
    b = bytes(uc.mem_read(src, 0x24))
    k = b.hex()
    if k not in seen:
        seen[k] = 1
        print(f"[{e._time()-e._t0:6.2f}s] GetData out {k}", flush=True)
def tick():
    orig_tick()
    if armed[0] or emu.dyn is None: return
    lm = emu.dyn.by_name("libScePsm.prx")
    if lm is not None and lm.base:
        emu.hle.register(lm.base + 0x1cf666, rd, name="rd", mode="fixup"); armed[0] = True
emu.uc.tick_cb = tick
emu.run()
