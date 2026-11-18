"""Where does the compositor's ring.service time go (Python-side split)?

    python ring_split.py 45

Wraps the pieces of GnmCompositorServer._run_dcb (guest read, DCB patching, native submit,
rt0 scan) and the flip, and reports total/mean per piece plus the number of draws.
"""
import sys
import time
from collections import defaultdict

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 45
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
pc = time.perf_counter
T = defaultdict(float)
N = defaultdict(int)
st = {"hooked": False, "draws": 0, "dcbs": 0, "words": 0}
orig_tick = emu._whp_tick


def timed(name, fn):
    def w(*a, **k):
        t = pc()
        try:
            return fn(*a, **k)
        finally:
            T[name] += pc() - t
            N[name] += 1
    return w


def tick():
    orig_tick()
    if st["hooked"] or emu.syscalls is None:
        return
    srv = emu.syscalls.unix_servers.get("GnmCompositor")
    if srv is None:
        return
    ring = srv.ring
    for nm in ("service", "_run_dcb", "_patch_dcb", "_dcb_rt0", "_present", "_post_event",
               "_gpu_setup"):
        setattr(ring, nm, timed(nm, getattr(ring, nm)))
    be_mod = None
    try:
        from psemu.gnm import backend
        be_mod = backend
        backend.submit = timed("backend.submit", backend.submit)
        backend.flush_range = timed("backend.flush_range", backend.flush_range)
    except Exception as e:
        print("no backend hook", e)
    st["hooked"] = True


emu.uc.tick_cb = tick
emu.run()
wall = emu._time() - emu._t0
print(f"\nwall {wall:.1f}s")
for k in sorted(T, key=lambda x: -T[x]):
    n = max(N[k], 1)
    print(f"{k:22s} calls {N[k]:6d}  total {T[k]:7.2f}s  mean {1000 * T[k] / n:7.2f} ms")
srv = emu.syscalls.unix_servers.get("GnmCompositor")
if srv is not None:
    print("gpu_totals:", getattr(srv.ring, "gpu_totals", None))
try:
    from psemu.gnm import backend as _b
    print("native profile:", _b.profile(reset=False))
except Exception as e:
    print("profile unavailable", e)
