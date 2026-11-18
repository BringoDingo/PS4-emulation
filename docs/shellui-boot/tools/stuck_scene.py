"""Find the scene action SceneManager.UpdateSceneAction keeps retrying, and name its scene.

    python stuck_scene.py 20       # run 20 s on WHP, then report

UpdateSceneAction(action) processes ONE queued scene action per call and returns early while the
scene's load has not finished; a stuck head-of-queue action blocks every later one (e.g. the Base
plugin's Loaded dispatch). The tool hooks UpdateSceneAction, counts calls per action object, then
prints the managed class of the most-retried action's scene and of its neighbours in the queue.
Mono class names are read from MonoClass (the name offset is probed against a known object).
"""
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 20

emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
calls = Counter()
orig_tick = emu._whp_tick
done = {"v": False, "t": 0.0}


def q(uc, a):
    return struct.unpack("<Q", bytes(uc.mem_read(a, 8)))[0]


def cstr(uc, a, n=80):
    try:
        raw = bytes(uc.mem_read(a, n))
    except Exception:
        return None
    raw = raw.split(b"\0")[0]
    return raw.decode("ascii", "replace") if raw and all(32 <= c < 127 for c in raw) else None


def klass_names(uc, obj):
    """Every printable string reachable as klass+off (probing; the real one is name / name_space)."""
    try:
        kl = q(uc, q(uc, obj))
    except Exception:
        return {}
    out = {}
    for off in range(0x20, 0xA0, 8):
        try:
            s = cstr(uc, q(uc, kl + off))
        except Exception:
            continue
        if s and 2 <= len(s) < 60:
            out[off] = s
    return out


def make_handler(name):
    def h(e, uc):
        action = uc.reg_read(X.UC_X86_REG_RSI)
        calls[action] += 1
        return None
    return h


def install():
    ui2 = emu.dyn.by_name("Sce.PlayStation.HighLevel.UI2.dll.sprx") if emu.dyn else None
    img = res._image(ui2) if ui2 is not None else None
    if img is None:
        return
    for start, rid in zip(img.starts, img.rids):
        if img.method_name(rid).endswith("SceneManager::UpdateSceneAction"):
            emu.hle.register(start, make_handler("UpdateSceneAction"), name="UpdateSceneAction", mode="fixup")
    done["v"] = True


def tick():
    orig_tick()
    if not done["v"] and emu.sched is not None and emu._time() - done["t"] > 1.0:
        done["t"] = emu._time()
        install()


emu.uc.tick_cb = tick
emu.run()
uc = emu.uc
print("UpdateSceneAction calls per action object:", calls.most_common(6))
for action, n in calls.most_common(3):
    print(f"\naction {action:#x} x{n}")
    for fld in (0x10, 0x18, 0x20):
        v = q(uc, action + fld)
        names = klass_names(uc, v) if v > 0x10000 else {}
        print(f"  +{fld:#x} = {v:#x}  class strings: {names}")
