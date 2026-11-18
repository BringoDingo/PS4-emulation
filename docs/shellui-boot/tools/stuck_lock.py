"""Detect a mutex the main thread is stuck on and report the owner thread's state.

    python stuck_lock.py 90

Samples every 2 s; when the main thread has been blocked on the same umtx mutex for 4 samples in a
row, prints the owner (tid from the lock word), whether the scheduler considers it suspended
(thr_suspend_ucontext), its wait state, and every currently suspended thread, then stops the run.
"""
import os
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 90
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
st = {"t": 0.0, "addr": None, "n": 0}


def tick():
    orig()
    now = emu._time()
    if emu.sched is None or now - st["t"] < 2.0:
        return
    st["t"] = now
    m = emu.sched.threads.get(0x10001)
    w = m.wait if m is not None and isinstance(m.wait, dict) else {}
    if m is not None and m.state == "blocked" and str(w.get("kind", "")).startswith("mutex") and w.get("addr"):
        if st["addr"] == w["addr"]:
            st["n"] += 1
        else:
            st["addr"], st["n"] = w["addr"], 1
    else:
        st["addr"], st["n"] = None, 0
    if st.get("until") and now >= st["until"]:
        from collections import Counter
        from aotsym import AotResolver
        r = AotResolver(emu)

        def name(a):
            lm = emu.dyn.module_at(a)
            img = r._image(lm) if lm is not None else None
            hit = img.lookup(a) if img is not None else None
            return hit[1] if hit else (f"{lm.name}+{a - lm.base:#x}" if lm else hex(a))
        c = Counter(name(a) for a in st["samples"])
        print(f"  owner {st['owner']:#x}: {len(st['samples'])} rip samples; top:")
        for n_, k in c.most_common(8):
            print(f"    {k:4d} {n_}")
        by = Counter(t_ for t_, _ in st["all"])
        print("  who ran during the window (tid: samples):", [(hex(a), b) for a, b in by.most_common(6)])
        for t_, _ in by.most_common(2):
            cc = Counter(name(a) for tt, a in st["all"] if tt == t_)
            print(f"    tid {t_:#x} top:", cc.most_common(4))
        emu.stop("stuck_lock: reported")
        return
    if st["n"] >= 4 and not st.get("until"):
        uc = emu.uc
        word = struct.unpack("<I", bytes(uc.mem_read(st["addr"], 4)))[0]
        owner = word & 0x7fffffff
        o = emu.sched.threads.get(owner)
        print(f"\n[{now - emu._t0:.1f}s] main stuck on umtx mutex {st['addr']:#x} (word {word:#x}); owner {owner:#x}")
        if o is None:
            print("  owner thread does not exist")
        else:
            print(f"  owner state={o.state} suspended={o.suspended} wait={ {k: v for k, v in (o.wait or {}).items() if not callable(v)} if isinstance(o.wait, dict) else o.wait}")
        print("  suspended threads:", [hex(t.tid) for t in emu.sched.threads.values() if t.suspended])
        print("  blocked on that mutex:", [hex(t.tid) for t in emu.sched.threads.values()
                                           if isinstance(t.wait, dict) and t.wait.get("addr") == st["addr"]])
        cur = emu.sched.current
        print(f"  current thread {cur.tid:#x} {cur.state}; step_addr={emu.uc._step_addr}; "
              f"rflags={emu.uc._r[17]:#x}; switch_pending={emu.sched.switch_pending}; "
              f"ready={[hex(t.tid) for t in emu.sched.threads.values() if t.state == 'ready' and not t.suspended][:8]}")
        sc = emu.sched
        pk = sc._pick()
        print(f"  _pick() -> {pk and hex(pk.tid)}; slice_left={sc.slice_left}; switches={sc.switches}; "
              f"order idx cur={sc.order.index(cur.tid)} owner={sc.order.index(owner) if owner in sc.order else None}; "
              f"exits={emu.uc.exits}")
        st["owner"], st["until"] = owner, now + 8
        print("  sampling the owner's rip for 8 s ...", flush=True)


st["samples"] = []
st["all"] = []
orig_pre = emu._whp_preempt


def pre(uc, rip):
    t = emu.sched.current if emu.sched else None
    if st.get("until") and t is not None:
        st["all"].append((t.tid, rip))
        if t.tid == st["owner"]:
            st["samples"].append(rip)
    return orig_pre(uc, rip)


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
emu.uc.preempt_cb = pre
emu.uc.tick_cb = tick
emu.run()
