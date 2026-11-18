"""Trace every syscall on /dev/hid and /dev/ctrlp_sync descriptors (what libScePad does).

    python hid_trace.py 40 [path-substring ...]

Logs ioctl (request decoded as direction/size/group/number + the first bytes of the argument before and
after the call), read/readv/write/poll/kevent on those fds, with the calling thread id and the
virtual time. Defaults to /dev/hid and ctrlp.
"""
import os
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
import unicorn.x86_const as X
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
subs = sys.argv[2:] or ["/dev/hid", "ctrlp"]
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
sc = emu.syscalls
orig = sc.dispatch
NAMES = {3: "read", 4: "write", 54: "ioctl", 120: "readv", 121: "writev", 209: "poll",
         363: "kevent", 6: "close", 475: "pread", 476: "pwrite", 477: "mmap"}
count = {}


def mine(fd):
    d = sc.fds.get(fd)
    return isinstance(d, str) and any(s in d for s in subs)


def stack(uc, depth=6):
    out = []
    rbp = uc.reg_read(X.UC_X86_REG_RBP)
    for _ in range(depth):
        try:
            ra, nx = struct.unpack("<QQ", bytes(uc.mem_read(rbp + 8, 8)) + bytes(uc.mem_read(rbp, 8)))
        except Exception:
            break
        lm = emu.dyn.module_at(ra) if emu.dyn else None
        out.append(f"{lm.name}+{ra - lm.base:#x}" if lm else f"{ra:#x}")
        if nx <= rbp:
            break
        rbp = nx
    return " < ".join(out)


def hexs(uc, a, n):
    try:
        return bytes(uc.mem_read(a, n)).hex(" ", 4)
    except Exception:
        return "?"


def ioc(req):
    d = {1: "W", 2: "R", 3: "RW", 0: "-"}[(req >> 30) & 3]
    return f"{d} size={(req >> 16) & 0x1FFF:#x} '{chr((req >> 8) & 0xFF)}' nr={req & 0xFF:#x}"


def dispatch(uc):
    nr = uc.reg_read(X.UC_X86_REG_RAX)
    if nr in NAMES:
        a = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX,
                                      X.UC_X86_REG_R10, X.UC_X86_REG_R8, X.UC_X86_REG_R9)]
        fd = a[0] & 0xFFFFFFFF
        if nr == 477 and mine(a[4] & 0xFFFFFFFF):        # mmap(addr, len, prot, flags, fd, off)
            fd = a[4] & 0xFFFFFFFF
        if nr != 363 and mine(fd):
            tid = emu.sched.current.tid if emu.sched and emu.sched.current else 0
            t = emu._time() - emu._t0
            pre = ""
            n = 0
            if nr == 54:
                n = (a[1] >> 16) & 0x1FFF
                pre = f"{ioc(a[1] & 0xFFFFFFFF)} in={hexs(uc, a[2], min(n, 48))}"
            r = orig(uc)
            rax = uc.reg_read(X.UC_X86_REG_RAX)
            cf = uc.reg_read(X.UC_X86_REG_RFLAGS) & 1
            key = (nr, a[1] & 0xFFFFFFFF if nr == 54 else 0)
            count[key] = count.get(key, 0) + 1
            if count[key] <= 3:
                post = ""
                if nr == 54 and n:
                    post = f" out={hexs(uc, a[2], min(n, 48))}"
                elif nr in (3, 475) and not cf and 0 < rax < 0x10000:
                    post = f" data={hexs(uc, a[1], min(rax, 48))}"
                elif nr in (4, 476):
                    post = f" data={hexs(uc, a[1], min(a[2] & 0xFFFF, 48))}"
                print(f"[{t:7.2f}s] tid {tid:#x} {NAMES[nr]}(fd {fd} {sc.fds.get(fd)}, "
                      f"{a[1]:#x}, {a[2]:#x}) {pre} -> {'ERR ' if cf else ''}{rax:#x}{post}"
                      f" <- {stack(uc)}", flush=True)
            return r
        if nr == 363 and a[2] and a[2] < 64:          # kevent(kq, changelist, nchanges, ...)
            try:
                for i in range(int(a[2])):
                    ident, filt, flags = struct.unpack("<QhH", bytes(uc.mem_read(a[1] + 32 * i, 12)))
                    if mine(ident & 0xFFFFFFFF):
                        print(f"[{emu._time() - emu._t0:7.2f}s] kevent register fd {ident} "
                              f"{sc.fds.get(ident)} filter {filt} flags {flags:#x}", flush=True)
            except Exception:
                pass
    return orig(uc)


sc.dispatch = dispatch
emu.run()
print("\ncounts:", {f"{NAMES[k[0]]}{'' if not k[1] else ' ' + hex(k[1])}": v for k, v in count.items()})
