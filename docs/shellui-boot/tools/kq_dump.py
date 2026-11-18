"""Dump what a kqueue a blocked thread waits on actually has registered (WHP run).

    python kq_dump.py 24 [kq]      # default: every kqueue some thread is blocked on

For each kqueue: the knotes (ident, filter, flags, udata) and what the ident resolves to in the fd
table (socket / ipmi / device), plus the threads blocked on it.
"""
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 24
only = int(sys.argv[2], 0) if len(sys.argv) > 2 else None
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
emu.run()
sc = emu.syscalls
FILT = {-1: "READ", -2: "WRITE", -3: "AIO", -4: "VNODE", -5: "PROC", -6: "SIGNAL", -7: "TIMER",
        -8: "NETDEV", -9: "FS", -10: "LIO", -11: "USER"}
waiters = {}
for t in emu.sched.threads.values():
    w = t.wait
    if t.state == "blocked" and isinstance(w, dict) and w.get("kind") == "kevent":
        waiters.setdefault(w["kq"], []).append(t.tid)
print("blocked-on kqueues:", {hex(k): [hex(t) for t in v] for k, v in waiters.items()})
fdt = getattr(sc, "fds", None) or getattr(sc, "fd_table", None) or {}
for kq in sorted(set(waiters) | ({only} if only is not None else set())):
    if only is not None and kq != only:
        continue
    print(f"\nkq {kq:#x}: waiters {[hex(t) for t in waiters.get(kq, [])]}  pending {sc.kq_pending.get(kq)}")
    for (ident, filt), kn in sc.knotes.get(kq, {}).items():
        fd = fdt.get(ident) if isinstance(fdt, dict) else None
        print(f"   ident {ident:#x} filter {FILT.get(filt, filt)} flags {kn['flags']:#x} "
              f"fflags {kn['fflags']:#x} data {kn['data']:#x} udata {kn['udata']:#x}  fd={fd!r}"[:230])
