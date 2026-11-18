"""Resolve a cpu_sampler.py raw sample dump (SAMPLES_OUT) offline, in a fresh process.

    python resolve_samples.py samples.bin [path/to/gnm_native.dll]

The dump holds every sampled stack (DEPTH return addresses) plus the load base of
gnm_native.dll in the sampled process. Here DbgHelp loads the DLL's PDB at that same base, so
the addresses resolve to backend function names. Prints, for stacks that pass through the backend:
  - inclusive time per backend function
  - the innermost backend function per sample (where its own time + memcpy/ntdll calls go)
"""
import collections
import ctypes
import json
import os
import struct
import sys
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DLL = os.path.normpath(os.path.join(HERE, "..", "..", "..", "psemu", "gnm", "native",
                                            "build", "release", "gnm_native.dll"))


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG),
                ("Reserved", ctypes.c_uint64 * 2), ("Index", wintypes.ULONG), ("Size", wintypes.ULONG),
                ("ModBase", ctypes.c_uint64), ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64),
                ("Address", ctypes.c_uint64), ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG),
                ("Tag", wintypes.ULONG), ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG),
                ("Name", ctypes.c_wchar * 512)]


def main():
    path = sys.argv[1]
    dll = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("GNM_DLL", DEFAULT_DLL)
    raw = open(path, "rb").read()
    nl = raw.index(b"\n")
    hdr = json.loads(raw[:nl])
    n, depth = hdr["n"], hdr["depth"]
    base = hdr["modules"]["gnm_native.dll"]
    frames = struct.unpack("<%dQ" % (n * depth), raw[nl + 1: nl + 1 + n * depth * 8])
    size = os.path.getsize(dll)
    if base < (1 << 32):
        # older dumps stored the handle through an untyped (32-bit) call: recover the upper half
        # from the sampled return addresses whose low 32 bits fall inside the module image
        hi = collections.Counter(f >> 32 for f in frames
                                 if f and base <= (f & 0xFFFFFFFF) < base + max(size, 0x2000000))
        if hi:
            base = (hi.most_common(1)[0][0] << 32) | base
            print("recovered gnm_native.dll base %#x" % base)

    k32 = ctypes.WinDLL("kernel32")
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    dh = ctypes.WinDLL("dbghelp")
    proc = k32.GetCurrentProcess()
    dh.SymSetOptions(0x2 | 0x4 | 0x10)          # UNDNAME | DEFERRED_LOADS | LOAD_LINES
    dh.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dh.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                    ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    dh.SymLoadModuleExW.restype = ctypes.c_uint64
    dh.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
                                ctypes.c_void_p]
    if not dh.SymInitializeW(proc, os.path.dirname(dll), False):
        sys.exit("SymInitialize failed")
    got = dh.SymLoadModuleExW(proc, None, dll, None, base, size, None, 0)
    if not got:
        sys.exit("SymLoadModuleEx failed for %s at %#x (err %d)" % (dll, base, ctypes.GetLastError()))

    end = base + 0x4000000      # generous upper bound of the module image
    cache = {}

    def name(a):
        hit = cache.get(a)
        if hit is None:
            s = SYMBOL_INFOW()
            s.SizeOfStruct = SYMBOL_INFOW.Name.offset
            s.MaxNameLen = 512
            d = ctypes.c_uint64()
            hit = s.Name if dh.SymFromAddrW(proc, a, ctypes.byref(d), ctypes.byref(s)) else "?%#x" % (a - base)
            cache[a] = hit
        return hit

    incl, inner = collections.Counter(), collections.Counter()
    touched = 0
    for i in range(n):
        st = [f for f in frames[i * depth:(i + 1) * depth] if f]
        g = [f for f in st if base <= f < end]
        if not g:
            continue
        touched += 1
        names = []
        for f in g:
            nm = name(f)
            if nm not in names:
                names.append(nm)
        for nm in names:
            incl[nm] += 1
        inner[names[0]] += 1
    print("samples %d, through gnm_native %d (%.1f %%)" % (n, touched, 100.0 * touched / n))
    print("-- inclusive (%% of all samples)")
    for nm, c in incl.most_common(25):
        print("  %5.1f %%  %s" % (100.0 * c / n, nm[:120]))
    print("-- innermost backend function (its own work + the memcpy/ntdll it calls)")
    for nm, c in inner.most_common(20):
        print("  %5.1f %%  %s" % (100.0 * c / n, nm[:120]))


if __name__ == "__main__":
    main()
