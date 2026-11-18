"""Static, emulator-free disassembly of the eboot with the correct segment mapping
(vaddr = 0x100000000 + file_off - 0x4000). Linear sweep from a known function entry so
instruction alignment is guaranteed.

    python sdis.py START_VADDR LENGTH [GREP]      e.g.  python sdis.py 0x100239ab0 0xd00 0x80f5
"""
import struct
import sys

import capstone

EBOOT = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
BASE = 0x100000000
b = open(EBOOT, "rb").read()
start = int(sys.argv[1], 16)
length = int(sys.argv[2], 16)
grep = sys.argv[3] if len(sys.argv) > 3 else None
fo = (start - BASE) + 0x4000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False
for ins in md.disasm(b[fo:fo + length], start):
    line = f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}"
    if ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j"):
        pass
    if grep is None or grep in line:
        print(line)
