"""List the 'H'-group (/dev/hid) ioctl request codes compiled into the pad-related binaries.

    python hid_ioctls.py
"""
import re

FW = r"D:/Ps4Tools/ps4kernel/firmware/"
FILES = {"libScePad": FW + "system/common/lib/libScePad.sprx",
         "libSceHidControl": FW + "system/common/lib/libSceHidControl.sprx",
         "ShellUI eboot": FW + "system_ex/app/NPXS20001/eboot.bin"}


def decode(r):
    d = {1: "W(in)", 2: "R(out)", 3: "RW", 0: "-"}[(r >> 30) & 3]
    return f"{r:#010x} {d} size={(r >> 16) & 0x1fff:#x} nr={r & 0xff:#x}"


for name, p in FILES.items():
    b = open(p, "rb").read()
    found = {}
    for m in re.finditer(rb"\xbe(.)\x48(.)([\x00-\xff])", b, re.S):      # mov esi, imm32
        r = int.from_bytes(m.group(0)[1:5], "little")
        if (r >> 8) & 0xFF == 0x48 and (r >> 30) & 3 in (1, 2, 3) and 1 <= ((r >> 16) & 0x1FFF) <= 0x400:
            found.setdefault(r, []).append(m.start())
    print(f"== {name}: {len(found)} 'H' ioctls")
    for r in sorted(found, key=lambda x: x & 0xFF):
        print("  ", decode(r), "x%d" % len(found[r]))
