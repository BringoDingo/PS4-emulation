"""Sample where threads are executing: run START instructions, then for WINDOW more
instructions record, at the end of every scheduling slice, the current thread's resume
address (module + offset). Slices end on instruction counts, so this is an unbiased
sample (unlike sampling at context switches, which lands on syscall stubs).

    python rip_sample.py START WINDOW [tid-hex]     e.g.  rip_sample.py 1400000000 300000000
"""
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "..")))
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
START, WINDOW = int(sys.argv[1]), int(sys.argv[2])
WANT = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x10001

emu = Emulator(EXE, max_insns=START + WINDOW + 1_000_000, fw_root=FW)
emu.max_modules = 80
emu.log = lambda *a, **k: None


def where(addr):
    lm = emu.dyn.module_at(addr)
    if lm is None:
        return "?%#x" % addr
    return "%s+%#x" % (lm.mod.name if hasattr(lm.mod, "name") else os.path.basename(lm.mod.path),
                       addr - lm.base)


samples = defaultdict(Counter)       # tid -> Counter(where)
cur = emu.begin_run()
while cur is not None:
    cur = emu._run_segment(cur)
    n = emu._insn_count
    if n >= START and cur is not None and emu.sched.current is not None:
        samples[emu.sched.current.tid][where(cur)] += 1
    if n >= START + WINDOW:
        break

tot = sum(sum(c.values()) for c in samples.values()) or 1
print("insns now %d; samples %d" % (emu._insn_count, tot))
for tid, c in sorted(samples.items(), key=lambda kv: -sum(kv[1].values()))[:6]:
    print("tid %#x: %d samples" % (tid, sum(c.values())))
    for w, k in c.most_common(12 if tid == WANT else 4):
        print("    %-48s %d" % (w, k))
