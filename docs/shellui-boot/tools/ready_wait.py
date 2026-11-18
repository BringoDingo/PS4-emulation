"""Scheduler starvation meter on WHP: how long does a READY thread wait before it gets the vCPU?

    python ready_wait.py 40

Wraps Scheduler.switch: records when each thread became READY (first seen READY at a switch) and
when it was picked. Prints, per thread, the max / mean ready-wait and the guest time it received,
plus the distribution of the number of READY threads at each switch and who ran for how long
(wall time between switches, split into in-guest vs. host handling is not attempted here).
"""
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 40
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
pc = time.perf_counter

ready_since = {}                 # tid -> perf time first seen READY
maxwait = defaultdict(float)
sumwait = defaultdict(float)
nwait = defaultdict(int)
ran = defaultdict(float)         # tid -> wall seconds between pick and next switch
nready_hist = defaultdict(int)
state = {"cur": None, "t": pc()}
orig = None


def wrapped():
    now = pc()
    sc = emu.sched
    cur = state["cur"]
    if cur is not None:
        ran[cur] += now - state["t"]
    for t in sc.threads.values():
        if t.state == "ready" and not t.suspended and t.tid not in ready_since and t.tid != cur:
            ready_since[t.tid] = now
    r = orig()
    nxt = sc.current.tid if sc.current else None
    nready_hist[min(sum(1 for t in sc.threads.values() if t.state == "ready" and not t.suspended), 20)] += 1
    if nxt in ready_since:
        w = now - ready_since.pop(nxt)
        maxwait[nxt] = max(maxwait[nxt], w)
        sumwait[nxt] += w
        nwait[nxt] += 1
    state["cur"], state["t"] = nxt, pc()
    return r


emu.run_prepare = None
sc_holder = {}
_orig_tick = emu._whp_tick


def tick():
    global orig
    _orig_tick()
    sc = emu.sched
    if sc is not None and orig is None:
        orig = sc.switch
        sc.switch = wrapped


emu.uc.tick_cb = tick
emu.run()
wall = emu._time() - emu._t0
print(f"\nwall {wall:.1f}s, switches {emu.sched.switches}")
print("READY-thread count at each switch (capped 20):", dict(sorted(nready_hist.items())))
print("per thread: tid  wall-ran(s)  picks  maxwait(ms)  meanwait(ms)")
for tid in sorted(ran, key=ran.get, reverse=True)[:14]:
    n = nwait.get(tid, 0)
    print(f"  {tid:#x} {ran[tid]:7.2f}s {n:6d} {maxwait[tid] * 1000:9.1f} {1000 * sumwait[tid] / max(n, 1):9.2f}")
print("worst waiters:")
for tid in sorted(maxwait, key=maxwait.get, reverse=True)[:8]:
    th = emu.sched.threads[tid]
    print(f"  {tid:#x} {th.name!r} max {maxwait[tid] * 1000:.1f} ms over {nwait[tid]} picks, ran {ran[tid]:.2f}s")
