import os
import sys
from collections import defaultdict, Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu import threads
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
N = int(sys.argv[1])
emu = Emulator(EXE, max_insns=N, fw_root=FW)
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = threads.Scheduler.switch
samples = defaultdict(list)      # window -> [rip of main thread at a switch away from it]


def sw(self):
    cur = self.current
    if cur is not None and cur.tid == 0x10001:
        samples[emu._insn_count // 250_000_000].append(emu.uc.reg_read(X.UC_X86_REG_RIP))
    return orig(self)


threads.Scheduler.switch = sw
emu.run()
r = AotResolver(emu)


def name(rip):
    try:
        n = r.name(rip)
        if n:
            return n
    except Exception:
        pass
    lm = emu.dyn.module_at(rip)
    return "%s+%#x" % (lm.mod.name if lm else "?", rip - (lm.base if lm else 0))


for w in sorted(samples):
    c = Counter(name(x) for x in samples[w])
    print("RES window %dM: %d samples; %s" % (w * 250, len(samples[w]),
          " | ".join("%s x%d" % (k[:70], v) for k, v in c.most_common(5))))
