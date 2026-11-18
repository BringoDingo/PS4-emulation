"""Log every open/stat/access/unlink/rename of guest paths matching a substring, with the caller's
managed/native frame-pointer stack (WHP).

    python path_watch.py 16 dbr.db-err app.db [substring ...]

Shows who creates or probes a file and the syscall result (errno values are returned as
positive codes with the carry flag; ENOENT=2).
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
sc = emu.syscalls
orig = sc.dispatch
NAMES = {5: "open", 188: "stat", 33: "access", 10: "unlink", 128: "rename", 391: "lstat", 475: "pread", 216: "ftruncate"}
count = {}


def rd(uc, a):
    return struct.unpack("<Q", bytes(uc.mem_read(a, 8)))[0]


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    if nr in NAMES and nr != 475 and nr != 216:
        try:
            raw = bytes(uc.mem_read(uc.reg_read(X.UC_X86_REG_RDI), 200)).split(bytes([0]))[0].decode("latin1")
        except Exception:
            raw = ""
        if any(s in raw for s in subs):
            fl = uc.reg_read(X.UC_X86_REG_RSI)
            r = orig(uc)
            tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
            key = (NAMES[nr], raw)
            count[key] = count.get(key, 0) + 1
            if count[key] <= 2:
                rax = uc.reg_read(X.UC_X86_REG_RAX)
                cf = uc.reg_read(X.UC_X86_REG_RFLAGS) & 1
                print(f"[{emu._time() - emu._t0:7.2f}s] tid {tid:#x} {NAMES[nr]}({raw!r}, {fl:#x}) -> "
                      f"{'ERR ' if cf else ''}{rax:#x}", flush=True)
                rbp = uc.reg_read(X.UC_X86_REG_RBP)
                shown = 0
                for _ in range(40):
                    try:
                        ra, nx = rd(uc, rbp + 8), rd(uc, rbp)
                    except Exception:
                        break
                    nm = res.name(ra)
                    if "[" in nm:
                        print("        ", nm.split(" [")[0])
                        shown += 1
                    if nx <= rbp or shown >= 12:
                        break
                    rbp = nx
            return r
    return orig(uc)


sc.dispatch = dispatch
emu.run()
