"""Disassemble managed (AOT) methods of app.exe / UI2 from live guest memory on WHP.

    python disasm_method.py 20 "QuickMenuPlugin::<OnLoading>b__7" ["ResourceManager::IsResourceLoaded" ...]

Runs `secs` seconds until the modules are mapped, then prints each matching method with capstone
(call targets resolved through the AOT symbol tables) and stops.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import capstone
from psemu.emulator import Emulator
from aotsym import AotResolver

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
subs = sys.argv[2:]
MODS = ["app.exe.sprx", "Sce.PlayStation.HighLevel.UI2.dll.sprx"]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
res = AotResolver(emu)
orig = emu._whp_tick
st = {"done": False, "last": 0.0}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def dump():
    imgs = []
    for m in MODS:
        lm = emu.dyn.by_name(m) if emu.dyn else None
        img = res._image(lm) if lm is not None else None
        if img is None:
            return False
        imgs.append((m, img))
    for m, img in imgs:
        items = sorted(zip(img.starts, img.rids))
        for i, (start, rid) in enumerate(items):
            nm = img.method_name(rid)
            if not any(s in nm for s in subs):
                continue
            end = items[i + 1][0] if i + 1 < len(items) else start + 0x200
            end = min(end, start + 0x600)
            code = bytes(emu.uc.mem_read(start, end - start))
            print(f"\n== {nm}  {start:#x}..{end:#x}")
            for ins in md.disasm(code, start):
                note = ""
                if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
                    tgt = int(ins.op_str, 16)
                    note = "   ; " + res.name(tgt)
                    try:                       # AOT PLT thunk: jmp [rip+disp] -> GOT slot -> real method
                        b = bytes(emu.uc.mem_read(tgt, 6))
                        if b[:2] == b"\xff\x25":
                            slot = tgt + 6 + struct.unpack("<i", b[2:6])[0]
                            val = struct.unpack("<Q", bytes(emu.uc.mem_read(slot, 8)))[0]
                            note += f"  -> got {val:#x} {res.name(val)}"
                    except Exception:
                        pass
                print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}{note}")
    return True


def tick():
    orig()
    if st["done"] or emu.sched is None:
        return
    now = emu._time()
    if now - st["last"] < 1.0:
        return
    st["last"] = now
    if now - emu._t0 < float(os.environ.get("AFTER", "0")):
        return
    if dump():
        st["done"] = True
        emu.stop("disasm done")


emu.uc.tick_cb = tick
emu.run()
