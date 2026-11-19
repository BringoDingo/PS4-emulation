"""Guest memory that is also host memory at the same address.

Every guest mapping is backed by host pages reserved with VirtualAlloc at the
*identical* virtual address and handed to Unicorn with `mem_map_ptr`. A guest
pointer is therefore directly a valid host pointer, which is what the native
GNM backend needs: command buffers, shaders, textures and render targets
written by emulated PS4 code can be passed to the GPU path without copying or
translating addresses (the real PS4 shares one address space between CPU and
GPU in the same way).

If the host address is taken (by a Windows DLL, the Python heap...), the
mapping falls back to Unicorn-private memory: the CPU still works, only that
range is not GPU-visible. `host_backed(addr)` tells which is which.
"""
import ctypes as C

from unicorn import UC_PROT_ALL

MEM_COMMIT, MEM_RESERVE, MEM_DECOMMIT = 0x1000, 0x2000, 0x4000
PAGE_READWRITE = 0x04
GRANULE = 0x10000          # VirtualAlloc reservation granularity
PAGE = 0x1000

_k32 = C.WinDLL("kernel32", use_last_error=True)
_VirtualAlloc = _k32.VirtualAlloc
_VirtualAlloc.restype = C.c_void_p
_VirtualAlloc.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32]
_VirtualFree = _k32.VirtualFree
_VirtualFree.restype = C.c_int
_VirtualFree.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32]


# Reservations belong to the process, not to one CPU instance: execve builds a
# new Unicorn but reuses the same host address ranges.
_RESERVED = set()


class HostVM:
    def __init__(self, uc, log=None, identity=True):
        self.uc = uc
        self.identity = identity   # False: a secondary address space (host memory anywhere, CPU-only)
        self.log = log or (lambda *a: None)
        self.reserved = _RESERVED  # 64 KiB granules reserved by us (persist for the process)
        self.backed = []           # (start, end) ranges mapped host-backed
        self.private = []          # (start, end) ranges Unicorn-only
        self.fallbacks = 0

    # -------------------------------------------------------------- helpers
    def _reserve(self, addr, size):
        first = addr & ~(GRANULE - 1)
        last = (addr + size + GRANULE - 1) & ~(GRANULE - 1)
        newly = []
        for g in range(first, last, GRANULE):
            if g in self.reserved:
                continue
            got = _VirtualAlloc(C.c_void_p(g), GRANULE, MEM_RESERVE, PAGE_READWRITE)
            if got != g:
                if got:
                    _VirtualFree(C.c_void_p(got), 0, 0x8000)
                for n in newly:                       # roll back this call's granules
                    _VirtualFree(C.c_void_p(n), 0, 0x8000)
                    self.reserved.discard(n)
                return False
            self.reserved.add(g)
            newly.append(g)
        return True

    @staticmethod
    def _commit(addr, size):
        # each 64 KiB granule is its own reservation, and one VirtualAlloc
        # call cannot span reservations: commit piece by piece
        a, end = addr, addr + size
        while a < end:
            piece = min(end, (a & ~(GRANULE - 1)) + GRANULE) - a
            if _VirtualAlloc(C.c_void_p(a), piece, MEM_COMMIT, PAGE_READWRITE) != a:
                return False
            a += piece
        return True

    # -------------------------------------------------------------- API
    def map(self, addr, size, prot=UC_PROT_ALL):
        """Map [addr, addr+size) (page-aligned). Host-backed when possible."""
        if not self.identity:
            self.uc.mem_map(addr, size, prot)
            self.private.append((addr, addr + size))
            return False
        if self._reserve(addr, size) and self._commit(addr, size):
            C.memset(addr, 0, size)
            self.uc.mem_map_ptr(addr, size, prot, addr)
            self.backed.append((addr, addr + size))
            return True
        self.fallbacks += 1
        self.log(f"  [hostvm] {addr:#x}+{size:#x} not available on the host; "
                 f"mapped CPU-only (not GPU-visible)")
        self.uc.mem_map(addr, size, prot)
        self.private.append((addr, addr + size))
        return False

    def unmap(self, addr, size):
        self.uc.mem_unmap(addr, size)
        end = addr + size
        if any(s <= addr and end <= e for s, e in self.backed):
            a = addr
            while a < end:
                piece = min(end, (a & ~(GRANULE - 1)) + GRANULE) - a
                _VirtualFree(C.c_void_p(a), piece, MEM_DECOMMIT)
                a += piece
            self.backed = _cut(self.backed, addr, end)
        else:
            self.private = _cut(self.private, addr, end)

    def host_backed(self, addr, size=1):
        return any(s <= addr and addr + size <= e for s, e in self.backed)

    def summary(self):
        b = sum(e - s for s, e in self.backed)
        p = sum(e - s for s, e in self.private)
        return f"{b >> 10} KiB host-backed, {p >> 10} KiB CPU-only"


def _cut(ranges, lo, hi):
    out = []
    for s, e in ranges:
        if e <= lo or hi <= s:
            out.append((s, e))
            continue
        if s < lo:
            out.append((s, lo))
        if hi < e:
            out.append((hi, e))
    return out
