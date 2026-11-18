"""Disassemble native guest code at module+offset ranges after the run reaches a given time (WHP).

    python disasm_mem.py 16 libSceVisionManager.prx 0x18780 0x180 [mod off len ...]

Calls/jumps are annotated with the module+offset of the target (and the import name when the target
is a PLT stub that jumps through the GOT).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import capstone
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
reqs = [(sys.argv[i], int(sys.argv[i + 1], 0), int(sys.argv[i + 2], 0)) for i in range(2, len(sys.argv) - 2, 3)]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
emu.run()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
uc = emu.uc


def where(a):
    lm = emu.dyn.module_at(a)
    return f"{lm.name}+{a - lm.base:#x}" if lm else hex(a)


for mod, off, ln in reqs:
    lm = emu.dyn.by_name(mod)
    base = lm.base
    code = bytes(uc.mem_read(base + off, ln))
    print(f"\n== {mod}+{off:#x} (abs {base + off:#x})")
    for ins in md.disasm(code, base + off):
        note = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            note = "   ; " + where(t)
            try:
                b = bytes(uc.mem_read(t, 6))
                if b[:2] == b"\xff\x25":
                    slot = t + 6 + struct.unpack("<i", b[2:6])[0]
                    note += f" -> [{slot:#x}] = {where(struct.unpack('<Q', bytes(uc.mem_read(slot, 8)))[0])}"
            except Exception:
                pass
        elif "rip" in ins.op_str:
            try:
                d = ins.op_str.split("rip")[1].split("]")[0].replace(" ", "")
                tgt = ins.address + ins.size + int(d, 0)
                note = f"   ; [{where(tgt)}]"
            except Exception:
                pass
        print(f"  {ins.address - base:#8x}: {ins.mnemonic} {ins.op_str}{note}")
