"""Hook a mid-method address (e.g. a managed catch block) on WHP and describe the exception in rax.

    python catch_hit.py 40 0x108210344 [0x... ...]

At each hit prints wall time, thread, the exception's managed class strings and its Message string
(MonoException.message at +0x20; MonoString = header(0x10) + int32 length + UTF-16 chars) and the
live frame-pointer stack. `fixup` mode: the original instruction then runs unchanged.
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
addrs = [int(a, 0) for a in sys.argv[2:]]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
orig = emu._whp_tick
st = {"done": False, "last": 0.0}


def q(uc, a):
    return struct.unpack("<Q", bytes(uc.mem_read(a, 8)))[0]


def cstr(uc, a, n=80):
    try:
        raw = bytes(uc.mem_read(a, n)).split(b"\0")[0]
    except Exception:
        return None
    return raw.decode("ascii", "replace") if raw and all(32 <= c < 127 for c in raw) else None


def mstr(uc, p):
    try:
        n = struct.unpack("<i", bytes(uc.mem_read(p + 0x10, 4)))[0]
        if 0 <= n < 400:
            return bytes(uc.mem_read(p + 0x14, n * 2)).decode("utf-16le", "replace")
    except Exception:
        pass
    return None


def hit(e, uc):
    obj = uc.reg_read(X.UC_X86_REG_RAX)
    names = {}
    try:
        kl = q(uc, q(uc, obj))
        for off in range(0x20, 0xA0, 8):
            s = cstr(uc, q(uc, kl + off))
            if s and 2 <= len(s) < 60:
                names[off] = s
    except Exception:
        pass
    msg = None
    try:
        msg = mstr(uc, q(uc, obj + 0x20))
    except Exception:
        pass
    tid = e.sched.current.tid if e.sched and e.sched.current else 0
    print(f"[{e._time() - e._t0:7.2f}s] tid {tid:#x} catch @ {uc.reg_read(X.UC_X86_REG_RIP):#x} rax={obj:#x} "
          f"class {names} msg={msg!r}", flush=True)
    rbp = uc.reg_read(X.UC_X86_REG_RBP)
    for _ in range(14):
        try:
            r_ = q(uc, rbp + 8)
            nx = q(uc, rbp)
        except Exception:
            break
        n_ = res.name(r_)
        if "[" in n_:
            print("      ", n_.split(" [")[0])
        if nx <= rbp:
            break
        rbp = nx
    return None


def tick():
    orig()
    if st["done"] or emu.sched is None:
        return
    now = emu._time()
    if now - st["last"] < 1.0:
        return
    st["last"] = now
    lm = emu.dyn.by_name("app.exe.sprx") if emu.dyn else None
    if lm is None or res._image(lm) is None:
        return
    for a in addrs:
        emu.hle.register(a, hit, name=f"catch@{a:#x}", mode="fixup")
    st["done"] = True
    print("[catch_hit] armed", [hex(a) for a in addrs], flush=True)


emu.uc.tick_cb = tick
emu.run()
