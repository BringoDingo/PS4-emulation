"""Find eboot internal calls ('Namespace.Class::Method' name strings, each referenced by a {name, fn}
table entry) and log their calls with the first integer args.

    python icall.py <secs> <hook-after-secs> Sce.Vsh.ShellUI.AppMain.NativeCall::GetBootEvent ...
"""
import struct, sys
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs, after, names = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3:]
emu = Emulator(EXE, fw_root=FW, backend="whp"); emu.max_seconds = secs; emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick; armed = [False]; counts = {}
def mk(nm):
    def hit(e, uc):
        counts[nm] = counts.get(nm, 0) + 1
        if counts[nm] <= 12 or uc.reg_read(X.UC_X86_REG_RDI) == 0x8000000:
            a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX)]
            print(f"[{e._time()-e._t0:6.2f}s] {nm.split('::')[-1]}({a[0]:#x}, {a[1]:#x}, {a[2]:#x})", flush=True)
    return hit
def tick():
    orig()
    if armed[0] or emu._time() - emu._t0 < after or emu.dyn is None: return
    armed[0] = True
    lm = emu.dyn.by_name("eboot.bin"); base = lm.base
    img = bytearray()
    for off in range(0, 0x1030000, 0x10000):
        try: img += bytes(emu.uc.mem_read(base + off, 0x10000))
        except Exception: img += bytes(0x10000)
    for nm in names:
        key = bytes(1) + nm.encode() + bytes(1)
        p = img.find(key) + 1 if img.find(key) >= 0 else -1
        if p < 0: print("name not found", nm, flush=True); continue
        ptr = struct.pack("<Q", base + p)
        refs = [i for i in range(0, len(img) - 16, 8) if img[i:i+8] == ptr]
        for r in refs[:1]:
            fn = struct.unpack_from("<Q", img, r + 8)[0]
            print("icall", nm, "fn eboot+%#x" % (fn - base), flush=True)
            emu.hle.register(fn, mk(nm), name="ic", mode="fixup")
emu.uc.tick_cb = tick
emu.run()
