import os
"""Mono AOT (format v133) address -> managed method name resolver for psemu.

Each AOT image (*.dll.sprx / app.exe.sprx) exports `mono_aot_file_info`.
Fields used (qword index after the 8-byte header):
  q[5] = code start, q[6] = code end, q[7] = method_addresses
method_addresses is one 5-byte `jmp rel32` per MethodDef (entry i = rid i+1)
pointing at that method's compiled code (methods that were not compiled
point outside the code range or at a shared stub). The managed name comes
from the assembly's own CIL metadata (embedded in the .sprx).

Usage (inside a script holding a live Emulator):
    from aotsym import AotResolver
    r = AotResolver(emu); print(r.name(addr))
"""
import bisect
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cil_scan import build                       # noqa: E402
from psemu.sys_dynlib import nid                 # noqa: E402
from psemu.syscalls import _embedded_cil         # noqa: E402

FILE_INFO_NID = nid("mono_aot_file_info")
SUPPORTED_VERSION = 133


class AotImage:
    def __init__(self, emu, lm):
        uc = emu.uc
        self.lm = lm
        fi = lm.mod.exports[FILE_INFO_NID]
        raw = bytes(uc.mem_read(fi, 0x48))
        self.version = struct.unpack_from("<I", raw, 0)[0]
        q = struct.unpack_from("<8Q", raw, 8)
        # q[5]..q[6] is the trampoline/stub area; compiled method bodies sit
        # at the start of the module, below it (method_addresses entries are
        # `call rel32` into that region).
        self.code_start, self.code_end, self.method_addresses = lm.base, q[6], q[7]
        path = getattr(lm.mod, "path", None) or getattr(lm, "path", None)
        self.meta = build(_embedded_cil(open(emu.resolve_path(path) if hasattr(emu, "resolve_path") and not _isfile(path) else path, "rb").read()))
        a = self.meta
        self.nmethods = a.rows.get(0x06, 0)
        # owning type for every MethodDef
        nt = a.rows.get(0x02, 0)
        starts = [(a.row(0x02, i)[5], i) for i in range(1, nt + 1)]
        self.owner = {}
        for k, (ms, ti) in enumerate(starts):
            me = starts[k + 1][0] if k + 1 < len(starts) else self.nmethods + 1
            for m in range(ms, me):
                self.owner[m] = ti
        tbl = bytes(uc.mem_read(self.method_addresses, 5 * self.nmethods))
        starts_ = {}
        for i in range(self.nmethods):
            op, rel = struct.unpack_from("<Bi", tbl, 5 * i)
            if op not in (0xE9, 0xE8):
                continue
            tgt = self.method_addresses + 5 * i + 5 + rel
            if self.code_start <= tgt < self.code_end:
                starts_.setdefault(tgt, i + 1)          # first rid wins for shared code
        self.starts = sorted(starts_)
        self.rids = [starts_[s] for s in self.starts]

    def method_name(self, rid):
        a = self.meta
        ti = self.owner.get(rid)
        tn = a.typename(0x02, ti) if ti else "?"
        return f"{tn}::{a.string(a.row(0x06, rid)[3])}"

    def lookup(self, addr):
        """(rid, name, offset into method) or None."""
        if not (self.code_start <= addr < self.code_end) or not self.starts:
            return None
        k = bisect.bisect_right(self.starts, addr) - 1
        if k < 0:
            return None
        rid = self.rids[k]
        return rid, self.method_name(rid), addr - self.starts[k]


def _isfile(p):
    import os
    return bool(p) and os.path.isfile(p)


class AotResolver:
    def __init__(self, emu):
        self.emu = emu
        self.images = {}          # module name -> AotImage (or None)

    def _image(self, lm):
        if lm.name not in self.images:
            img = None
            if FILE_INFO_NID in lm.mod.exports:
                try:
                    img = AotImage(self.emu, lm)
                except Exception as e:          # keep resolving other modules
                    print(f"[aotsym] {lm.name}: {e}")
            self.images[lm.name] = img
        return self.images[lm.name]

    def name(self, addr):
        lm = self.emu.dyn.module_at(addr) if self.emu.dyn else None
        if lm is None:
            return f"{addr:#x}"
        img = self._image(lm)
        hit = img.lookup(addr) if img else None
        if hit:
            rid, nm, off = hit
            return f"{nm}+{off:#x} [{lm.name}]"
        return f"{lm.name}+{addr - lm.base:#x}"
