"""Unbiased guest-time profile on the WHP backend: where does the vCPU spend its time?

    python rip_hist.py 30            # run 30 s, then print the histogram

The preemption timer already interrupts the vCPU every few ms (a VM exit with the guest rip
intact), so the rip seen there is a statistical sample of what the guest is executing. Samples are
grouped by guest thread and by symbol (managed method via the AOT tables, else module+0x1000
bucket) so a long compute loop or a spin shows up directly.
"""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 30

emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
samples = []                      # (tid, rip)
orig = emu._whp_preempt


def preempt(uc, rip):
    t = emu.sched.current if emu.sched else None
    samples.append((t.tid if t else 0, rip))
    return orig(uc, rip)


emu.uc.preempt_cb = preempt
emu.run()


def sym(rip):
    lm = emu.dyn.module_at(rip) if emu.dyn else None
    if lm is None:
        return f"?{rip >> 20:#x}"
    img = res._image(lm)
    hit = img.lookup(rip) if img is not None else None
    if hit:
        return hit[1]
    return f"{lm.name}+{(rip - lm.base) & ~0xFFF:#x}"


by_thread = Counter(t for t, _ in samples)
by_sym = Counter(sym(r) for _, r in samples)
print(f"\n{len(samples)} samples")
print("by thread:", [(hex(t), n) for t, n in by_thread.most_common(8)])
print("by symbol:")
for s, n in by_sym.most_common(18):
    print(f"  {n:5d} {100 * n / len(samples):5.1f}%  {s}")
top = by_thread.most_common(1)[0][0] if by_thread else 0
print(f"symbols for the busiest thread {top:#x}:")
for s, n in Counter(sym(r) for t, r in samples if t == top).most_common(10):
    print(f"  {n:5d}  {s}")
