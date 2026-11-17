import os
import sys, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from aotsym import AotResolver, FILE_INFO_NID
EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 900_000_000
emu = Emulator(EXE, max_insns=N, fw_root=FW); emu.max_modules = 80
emu.log = lambda *a, **k: None
emu.run()
uc = emu.uc
r = AotResolver(emu)

# --- 1. validation: every ShellUI AppMain method entry must resolve to itself
app = emu.dyn.by_name("app.exe.sprx")
print("RES app.exe path:", app.mod.path, "size", __import__("os").path.getsize(app.mod.path))
img = r._image(app)
print("RES app.exe: version", img.version, "methods", img.nmethods, "compiled starts", len(img.starts))
ok = bad = 0
for rid in range(0x7f, 0x95):
    i = rid - 1
    op, rel = struct.unpack("<Bi", bytes(uc.mem_read(img.method_addresses + 5 * i, 5)))
    tgt = img.method_addresses + 5 * i + 5 + rel
    got = img.lookup(tgt)
    want = img.method_name(rid)
    good = bool(got and got[1] == want and got[2] == 0)
    ok += good; bad += (not good)
    print(f"RES  {rid:#x} {want:70s} -> {got[1] if got else None}{'' if good else '   <-- MISMATCH'}")
print(f"RES validation: {ok} ok, {bad} mismatching")

# --- 2. name every thread's managed stack
def stack_names(sp, base_limit=0x4000):
    out = []
    try:
        data = bytes(uc.mem_read(sp, base_limit))
    except Exception:
        try:
            data = bytes(uc.mem_read(sp, 0x1000))
        except Exception:
            return out
    last = None
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack_from("<Q", data, off)[0]
        lm = emu.dyn.module_at(v)
        if lm is None:
            continue
        img = r._image(lm)
        if img is None:
            continue
        hit = img.lookup(v)
        if hit and hit[1] != last:
            out.append(f"{hit[1]}+{hit[2]:#x}")
            last = hit[1]
    return out

sched = emu.sched
print("\nRES === thread stacks (managed frames, innermost first) ===")
for t in sched.threads.values():
    if t.state == "exited":
        continue
    if t is sched.current:
        rsp = uc.reg_read(X.UC_X86_REG_RSP)
    else:
        try:
            rsp = t.ctx.reg_read(X.UC_X86_REG_RSP)
        except Exception:
            continue
    w = t.wait if isinstance(t.wait, dict) else t.wait
    kind = w.get("kind") if isinstance(w, dict) else w
    names = stack_names(rsp)
    print(f"RES tid {t.tid:#x} {t.state} {kind}: " + (" <- ".join(names[:9]) if names else "(no managed frames)"))
