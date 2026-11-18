"""Cost of the 60 Hz compositor service on WHP: frames, wall time in ring.service, ring work per frame.

    python frame_cost.py 40
"""
import sys
import time

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
st = {"n": 0, "t": 0.0, "mx": 0.0, "hooked": False, "times": []}
orig_tick = emu._whp_tick


def tick():
    orig_tick()
    if st["hooked"] or emu.syscalls is None:
        return
    srv = emu.syscalls.unix_servers.get("GnmCompositor")
    if srv is None:
        return
    ring = srv.ring
    o = ring.service

    def service(uc, *a, **k):
        t = pc()
        r = o(uc, *a, **k)
        dt = pc() - t
        st["n"] += 1
        st["t"] += dt
        st["mx"] = max(st["mx"], dt)
        st["times"].append((emu._time() - emu._t0, dt))
        return r
    ring.service = service
    st["hooked"] = True


emu.uc.tick_cb = tick
emu.run()
wall = emu._time() - emu._t0
n = max(st["n"], 1)
print(f"\nwall {wall:.1f}s; ring.service calls {st['n']} total {st['t']:.2f}s "
      f"mean {1000 * st['t'] / n:.1f} ms max {1000 * st['mx']:.0f} ms")
ts = st["times"]
if ts:
    print("first/last call at", f"{ts[0][0]:.1f}s", f"{ts[-1][0]:.1f}s")
    big = sorted(ts, key=lambda x: -x[1])[:6]
    print("slowest calls (t, ms):", [(round(a, 1), round(b * 1000)) for a, b in big])
    third = len(ts) // 3
    for i in range(3):
        seg = ts[i * third:(i + 1) * third] or ts
        print(f"  third {i}: mean {1000 * sum(b for _, b in seg) / len(seg):.1f} ms")
