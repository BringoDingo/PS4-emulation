"""Syscall log of the thread that runs BootManager.<StartInitializeVisionEngine>b__33, from its
call into VisionRecognitionUtil.InitializeVisionEngine on (WHP).

    python vision_sys.py 24
"""
import os
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator
from psemu.syscalls import SYSCALLS

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 24
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
st = {"tid": None, "armed": False, "last": 0.0, "log": []}
orig_dispatch = sc.dispatch
orig_tick = emu._whp_tick
HOOK = int(os.environ.get('HOOK', '0x108210320'), 0)      # method entry of b__33 (never patch a call site: Mono re-reads the call bytes)


def hit(e, uc):
    if st["tid"] is None:
        st["tid"] = e.sched.current.tid
        st["t"] = e._time() - e._t0
    return None


def dispatch(uc):
    tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
    if tid != st["tid"] and tid not in st.setdefault("kids", set()):
        return orig_dispatch(uc)
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    before = emu.sched.next_tid
    a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_R10)]
    txt = ""
    if nr == 4 and a[2] < 400:                     # write(fd, buf, n): keep the text
        try:
            txt = bytes(uc.mem_read(a[1], a[2])).decode("latin1")
        except Exception:
            pass
    extra = ""
    if nr == 455:                                  # thr_new(param): start_func at +0, arg at +8
        import struct
        sf, ar = struct.unpack("<QQ", bytes(uc.mem_read(a[0], 16)))
        lm = emu.dyn.module_at(sf)
        extra = f" start={lm.name + '+' + hex(sf - lm.base) if lm else hex(sf)} arg={ar:#x}"
        try:
            blob = bytes(uc.mem_read(ar, 0x300))
            for off in range(0, 0x300, 8):
                v = struct.unpack_from("<Q", blob, off)[0]
                m = emu.dyn.module_at(v) if 0x100000000 <= v < 0x108000000 else None
                if m is not None:
                    print(f"      pthread+{off:#x} = {m.name}+{v - m.base:#x}", flush=True)
        except Exception as ex:
            print("      (pthread read failed)", ex)
    if nr == 363:                                  # kevent(kq, chl, nch, evl, nev, timeout)
        import struct
        nch, nev, to = a[2] & 0xFFFFFFFF, uc.reg_read(X.UC_X86_REG_R8) & 0xFFFFFFFF, uc.reg_read(X.UC_X86_REG_R9)
        extra = f" nev={nev} timeout={to:#x}"
        for i in range(min(nch, 4)):
            try:
                ident, filt, fl, ff, dat, ud = struct.unpack("<QhHIqQ", bytes(uc.mem_read(a[1] + 32 * i, 32)))
                if fl == 0 and ff & 0x1000000 and ud:
                    print(f"      trigger payload @ {ud:#x}:", bytes(uc.mem_read(ud - 0x10, 0x60)).hex(" ", 8), flush=True)
                extra += f" [chg ident={ident:#x} filt={filt} flags={fl:#x} fflags={ff:#x} data={dat:#x} udata={ud:#x}]"
            except Exception:
                pass
    for ri, rr in enumerate((X.UC_X86_REG_RDI, X.UC_X86_REG_RSI)):
        try:
            raw = bytes(uc.mem_read(uc.reg_read(rr), 96)).split(bytes([0]))[0]
            if len(raw) >= 3 and all(32 <= c < 127 for c in raw):
                extra += f" arg{ri}={raw.decode()!r}"
        except Exception:
            pass
    r = orig_dispatch(uc)
    for k in range(before, emu.sched.next_tid):          # threads this thread just created
        st["kids"].add(k)
    if txt:
        print(f"  [write fd {a[0]}] {txt!r}", flush=True)
    st["log"].append((emu._time() - emu._t0, f"{tid:#x} " + SYSCALLS.get(nr, f"sys_{nr}") + extra, a,
                      uc.reg_read(X.UC_X86_REG_RAX)))
    return r


def tick():
    orig_tick()
    now = emu._time()
    if not st["armed"] and emu.sched is not None and now - st["last"] > 1.0:
        st["last"] = now
        if emu.dyn and emu.dyn.by_name("app.exe.sprx") is not None and emu.dyn.by_name("app.exe.sprx").base:
            try:
                emu.hle.register(HOOK, hit, name="vis_b33", mode="fixup")
                st["armed"] = True
            except Exception:
                pass


sc.dispatch = dispatch
emu.uc.tick_cb = tick
emu.run()
print(f"\nvision thread {st['tid'] and hex(st['tid'])} entered InitializeVisionEngine at {st.get('t')}")
log = st["log"]
print(len(log), "syscalls; first 70:")
for t, n, a, r in log[:int(sys.argv[2]) if len(sys.argv) > 2 else 70]:
    print(f"  {t:7.2f}s {n}  {a[0]:#x} {a[1]:#x} {a[2]:#x} {a[3]:#x} -> {r:#x}")
