"""List the paths the guest opens that do not exist (psemu's permissive '(missing)' opens).

    python missing_opens.py 25

sys_open returns a working fd for a missing file opened without O_CREAT ('kept permissive'),
which is wrong POSIX/FreeBSD behaviour (ENOENT). This tool shows who depends on it.
"""
import re
import sys
from collections import Counter

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 25
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
seen = Counter()


def log(*a, **k):
    s = " ".join(str(x) for x in a)
    m = re.search(r"\[open\] '(.*)' -> fd \d+ \(missing\)", s)
    if m:
        seen[m.group(1)] += 1


emu.log = log
emu.run()
print(f"\n{sum(seen.values())} missing opens, {len(seen)} distinct paths:")
for p, n in seen.most_common(60):
    print(f"  {n:4d} {p}")
