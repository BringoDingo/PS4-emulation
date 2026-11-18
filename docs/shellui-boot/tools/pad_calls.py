"""Log calls to the libScePad exports (scePadInit/Open/Read/ReadState/...) with their arguments and the
calling module, on WHP, for every loaded instance of libScePad.

    python pad_calls.py 60
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

sys.path.insert(0, r"D:\CLAUDEGODOT2\PS4-emulation\docs\shellui-boot\tools")
import elfsyms

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
LIB = FW + r"\system\common\lib\libScePad.sprx"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 60
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None

NAMES = ("scePadInit scePadOpen scePadClose scePadRead scePadReadState scePadGetHandle "
         "scePadGetControllerInformation scePadGetCapability scePadSetVibration scePadSetLightBar "
         "scePadIsValidHandle scePadSetProcessPrivilege scePadSetProcessFocus scePadReadHistory "
         "scePadOpenExt scePadResetLightBar scePadSetMotionSensorState").split()
tab = {elfsyms.nid(n): n for n in NAMES}
tab["d7bXuEBycDI"] = "scePadOpenByMbusDevice"      # internal: (u64 device id, type, flags)
exports = {}
for sym, val in elfsyms.symtab(LIB).items():
    k = sym.split("#")[0]
    if k in tab:
        exports[tab[k]] = val
print("libScePad exports hooked:", {k: hex(v) for k, v in exports.items()}, flush=True)
armed = set()
counts = {}
orig_tick = emu._whp_tick


def stack(uc, depth=4):
    out, rbp = [], uc.reg_read(X.UC_X86_REG_RBP)
    ra0 = struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RSP), 8)))[0]
    lm = emu.dyn.module_at(ra0)
    out.append(f"{lm.name}+{ra0 - lm.base:#x}" if lm else f"{ra0:#x}")
    for _ in range(depth):
        try:
            ra = struct.unpack("<Q", bytes(uc.mem_read(rbp + 8, 8)))[0]
            nx = struct.unpack("<Q", bytes(uc.mem_read(rbp, 8)))[0]
        except Exception:
            break
        lm = emu.dyn.module_at(ra)
        out.append(f"{lm.name}+{ra - lm.base:#x}" if lm else f"{ra:#x}")
        if nx <= rbp:
            break
        rbp = nx
    return " < ".join(out)


def make(name, base):
    def hit(e, uc):
        counts[name] = counts.get(name, 0) + 1
        if counts[name] <= 6:
            a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX,
                                          X.UC_X86_REG_RCX)]
            print(f"[{e._time() - e._t0:7.2f}s] {name}({a[0]:#x}, {a[1]:#x}, {a[2]:#x}, {a[3]:#x}) "
                  f"from {stack(uc)}", flush=True)
        return None
    return hit


def tick():
    orig_tick()
    if emu.dyn is None:
        return
    for lm in emu.dyn.modules:
        if lm.name.startswith("libScePad.") and lm.base and lm.base not in armed:
            armed.add(lm.base)
            for n, off in exports.items():
                try:
                    emu.hle.register(lm.base + off, make(n, lm.base), name=f"pad_{n}", mode="fixup")
                except Exception as ex:
                    print("hook failed", n, ex)
            print(f"hooked libScePad @ {lm.base:#x}", flush=True)


emu.uc.tick_cb = tick
emu.run()
print("\ncalls:", counts)
