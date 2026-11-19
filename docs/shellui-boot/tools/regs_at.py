import struct, sys
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
mod, offs = sys.argv[1], [int(a, 0) for a in sys.argv[2:]]
emu = Emulator(EXE, fw_root=FW, backend="whp"); emu.max_seconds = 12; emu.max_modules = 80
emu.log = lambda *a, **k: None
armed = [False]; orig_tick = emu._whp_tick
R = [("rax",X.UC_X86_REG_RAX),("rbx",X.UC_X86_REG_RBX),("rcx",X.UC_X86_REG_RCX),("rdx",X.UC_X86_REG_RDX),("rsi",X.UC_X86_REG_RSI),("rdi",X.UC_X86_REG_RDI),("r12",X.UC_X86_REG_R12),("r13",X.UC_X86_REG_R13),("r14",X.UC_X86_REG_R14),("r15",X.UC_X86_REG_R15)]
def mk(off):
    def hit(e, uc):
        print(f"[{e._time()-e._t0:6.2f}s] {mod}+{off:#x} " + " ".join(f"{n}={uc.reg_read(r):#x}" for n, r in R), flush=True)
        return None
    return hit
def tick():
    orig_tick()
    if armed[0] or emu.dyn is None: return
    lm = emu.dyn.by_name(mod)
    if lm is not None and lm.base:
        for o in offs: emu.hle.register(lm.base + o, mk(o), name=f"r{o:x}", mode="fixup")
        armed[0] = True
emu.uc.tick_cb = tick
emu.run()
