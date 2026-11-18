"""Trace calls to named managed (Mono AOT) methods of app.exe on the WHP backend.

    python trace_methods.py 40 "BootManager::SetEventFlag" "PluginManager::LoadInternal" ...

Each substring selects every compiled method of app.exe whose "Type::method" name contains it. An
int3 HLE trap ('fixup': the real method then runs unchanged) logs the wall time, the method and the
managed caller. Needs --backend whp (the traps are WHP breakpoints).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
subs = sys.argv[2:]

emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
state = {"done": False, "last": 0.0}
orig_tick = emu._whp_tick


def make_handler(name):
    def h(e, uc):
        focus_key = os.environ.get("FOCUS")        # e.g. BasePlugin::OnLoading: then only trace that `this`
        if focus_key:
            this = uc.reg_read(X.UC_X86_REG_RDI)
            if focus_key in name and "this" not in state:
                state["this"] = this
            if state.get("this") is None or (this != state["this"] and focus_key not in name):
                return None
        rsp = uc.reg_read(X.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
        tid = e.sched.current.tid if e.sched and e.sched.current else 0
        extra = ""
        if os.environ.get("ARGS"):
            extra = "  args=" + ",".join(f"{uc.reg_read(r):#x}" for r in
                                         (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_RCX))
        if os.environ.get("DEPTH"):
            frames, rbp = [], uc.reg_read(X.UC_X86_REG_RBP)
            for _ in range(int(os.environ["DEPTH"])):
                try:
                    r_ = struct.unpack("<Q", bytes(uc.mem_read(rbp + 8, 8)))[0]
                    nx = struct.unpack("<Q", bytes(uc.mem_read(rbp, 8)))[0]
                except Exception:
                    break
                n_ = res.name(r_)
                if "[" in n_:
                    frames.append(n_.split(" [")[0])
                if nx <= rbp:
                    break
                rbp = nx
            extra += "".join("\n        " + f for f in frames)
        print(f"[{e._time() - e._t0:7.2f}s] tid {tid:#x} {name}   <- {res.name(ret)}{extra}", flush=True)
        if os.environ.get("RET") and ret not in e.hle.table:
            def on_ret(e2, uc2, ra=ret, nm=name):
                print(f"[{e2._time() - e2._t0:7.2f}s]   {nm} returned rax={uc2.reg_read(X.UC_X86_REG_RAX):#x}", flush=True)
                uc2.hle_remove(ra)
                e2.hle.table.pop(ra, None)
                return None
            e.hle.register(ret, on_ret, name="ret", mode="fixup")
        return None
    return h


def install():
    mods = os.environ.get("MODULE", "app.exe.sprx").split(",")
    total = 0
    for mod in mods:
        lm = emu.dyn.by_name(mod) if emu.dyn else None
        img = res._image(lm) if lm is not None else None
        if img is None:
            return                     # not loaded yet: retry on the next tick
    for mod in mods:
        img = res._image(emu.dyn.by_name(mod))
        n = 0
        for start, rid in zip(img.starts, img.rids):
            nm = img.method_name(rid)
            if any(s in nm for s in subs):
                emu.hle.register(start, make_handler(nm), name=nm, mode="fixup")
                n += 1
                if os.environ.get("LIST"):
                    print(f"[trace]   {start:#x} {nm}", flush=True)
        print(f"[trace] hooked {n} methods in {mod}", flush=True)
    state["done"] = True


def tick():
    orig_tick()
    if not state["done"] and emu.sched is not None:
        now = emu._time()
        if now - state["last"] > 1.0:
            state["last"] = now
            install()


emu.uc.tick_cb = tick
emu.run()
