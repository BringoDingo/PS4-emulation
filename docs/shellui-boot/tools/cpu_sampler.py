"""Where does the emulator's main thread spend its CPU time? (Windows, x64)

    python cpu_sampler.py MAX_INSNS [psemu.run args...]
    SAMPLE_DELAY=330 python cpu_sampler.py 6000000000     # skip the first 330 s (startup)
    PSEMU_ROOT=D:/path/to/psemu-checkout ...               # which psemu to import (default: this repo)

Runs `psemu.run <eboot> --max N ...` normally while a native sampler thread
(rip_sampler.c, built on first use with MSVC) suspends the main thread ~1000x/s, unwinds its
stack (no Python in between) and resumes it. Each sample's top frame is attributed to the
module containing it:

  jit          translated guest code (Unicorn/QEMU TCG buffer, not inside any module)
  unicorn.dll  Unicorn/QEMU helpers, the translator, memory-access slow paths
  psemu_cpu    psemu's per-instruction native hook (cpuhook.c) and native VEX emulation (vex.c)
  python*      the interpreter (+ _ctypes, numpy ...): syscalls, scheduler, GPU glue
  gnm_native   the Vulkan GPU backend and shader recompiler (symbols from its PDB)

Samples whose stack passes through gnm_native.dll are also broken down by backend function
(inclusive), and by (innermost backend function, module doing the work) so time spent in
memcpy/ntdll can be traced to the backend code that called it.
"""
import collections
import ctypes
import os
import runpy
import subprocess
import sys
import time
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("PSEMU_ROOT", os.path.normpath(os.path.join(HERE, "..", "..", "..")))
sys.path.insert(0, ROOT)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetModuleHandleExW.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HMODULE)]
k32.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
k32.GetCurrentProcess.restype = wintypes.HANDLE
FROM_ADDRESS, UNCHANGED = 0x4, 0x2
CAP = 200_000


def build_sampler():
    dll = os.path.join(HERE, "rip_sampler.dll")
    src = os.path.join(HERE, "rip_sampler.c")
    if not os.path.exists(dll) or os.path.getmtime(dll) < os.path.getmtime(src):
        from psemu.native import build as nb
        gb = nb._gnm_build()
        env = gb.msvc_env()
        r = subprocess.run([gb.TOOLS["cl"], "/nologo", "/O2", "/LD", src, "/Fe:" + dll,
                            "/Fo:" + os.path.join(HERE, "rip_sampler.obj")], env=env, cwd=HERE)
        if r.returncode:
            sys.exit("could not build rip_sampler.dll")
    return ctypes.CDLL(dll)


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG),
                ("Reserved", ctypes.c_uint64 * 2), ("Index", wintypes.ULONG), ("Size", wintypes.ULONG),
                ("ModBase", ctypes.c_uint64), ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64),
                ("Address", ctypes.c_uint64), ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG),
                ("Tag", wintypes.ULONG), ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG),
                ("Name", ctypes.c_wchar * 512)]


class Symbols:
    def __init__(self, search_path):
        self.dh = ctypes.WinDLL("dbghelp")
        self.dh.SymSetOptions(0x2 | 0x4)                    # UNDNAME | DEFERRED_LOADS
        self.proc = k32.GetCurrentProcess()
        self.dh.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
        self.dh.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64,
                                         ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p]
        self.ok = bool(self.dh.SymInitializeW(self.proc, search_path, False))
        self.cache = {}
        # load the backend's symbols explicitly: it is already mapped in this process, so
        # DbgHelp does not find its PDB on its own
        self.dh.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR,
                                             wintypes.LPCWSTR, ctypes.c_uint64, wintypes.DWORD,
                                             ctypes.c_void_p, wintypes.DWORD]
        self.dh.SymLoadModuleExW.restype = ctypes.c_uint64
        k32.GetModuleHandleW.restype = wintypes.HMODULE
        k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.loaded = {}
        for mod in ("gnm_native.dll", "psemu_cpu.dll"):
            hm = k32.GetModuleHandleW(mod)
            if hm:
                d = search_path if mod == "gnm_native.dll" else os.path.join(ROOT, "psemu", "native", "build")
                self.loaded[mod] = self.dh.SymLoadModuleExW(self.proc, None, os.path.join(d, mod), None,
                                                            ctypes.c_void_p(hm).value, 0, None, 0)

    def name(self, addr):
        hit = self.cache.get(addr)
        if hit is None:
            hit = "?"
            if self.ok:
                s = SYMBOL_INFOW()
                s.SizeOfStruct = SYMBOL_INFOW.Name.offset
                s.MaxNameLen = 512
                disp = ctypes.c_uint64()
                if self.dh.SymFromAddrW(self.proc, addr, ctypes.byref(disp), ctypes.byref(s)):
                    hit = s.Name
            self.cache[addr] = hit
        return hit


def module_of(rip, cache):
    page = rip >> 12
    hit = cache.get(page)
    if hit is None:
        hm = wintypes.HMODULE()
        if k32.GetModuleHandleExW(FROM_ADDRESS | UNCHANGED, ctypes.c_void_p(rip), ctypes.byref(hm)):
            b = ctypes.create_unicode_buffer(260)
            k32.GetModuleFileNameW(hm, b, 260)
            hit = os.path.basename(b.value).lower()
        else:
            hit = "jit"
        cache[page] = hit
    return hit


def report(lib, buf, n, wall):
    depth = lib.sampler_depth()
    out = os.environ.get("SAMPLES_OUT")
    if out:                                    # raw addresses + module bases, for offline re-analysis
        import json
        mods = {}
        for mod in ("gnm_native.dll", "psemu_cpu.dll", "unicorn.dll"):
            hm = k32.GetModuleHandleW(mod)
            mods[mod] = ctypes.c_void_p(hm).value if hm else 0
        with open(out, "wb") as f:
            f.write((json.dumps({"n": n, "depth": depth, "modules": mods}) + "\n").encode())
            f.write(bytes(buf)[: n * depth * 8])
    cache = {}
    gnm_dir = os.path.join(ROOT, "psemu", "gnm", "native", "build", "release")
    syms = Symbols(gnm_dir)
    top = collections.Counter()
    incl = collections.Counter()
    via = collections.Counter()
    for i in range(n):
        frames = [buf[i * depth + j] for j in range(depth) if buf[i * depth + j]]
        if not frames:
            continue
        mods = [module_of(f, cache) for f in frames]
        top[mods[0]] += 1
        gi = [j for j, m in enumerate(mods) if m == "gnm_native.dll"]
        if gi:
            names = []
            for j in gi:
                nm = syms.name(frames[j])
                if nm not in names:
                    names.append(nm)
            for nm in names:
                incl[nm] += 1
            via[(names[0], mods[0])] += 1          # innermost backend fn, module doing the work
    print("\nCPUSAMPLER wall %.0fs, %d samples" % (wall, n))
    for m, c in top.most_common(12):
        print("CPUSAMPLER %-26s %6.1f %%  (%d)" % (m, 100.0 * c / max(n, 1), c))
    in_gnm = sum(c for (nm, md), c in via.items())
    print("CPUSAMPLER stacks passing through gnm_native.dll: %.1f %% of samples" % (100.0 * in_gnm / max(n, 1)))
    print("CPUSAMPLER -- backend functions (inclusive, %% of all samples)")
    for nm, c in incl.most_common(16):
        print("CPUSAMPLER   %5.1f %%  %s" % (100.0 * c / max(n, 1), nm[:110]))
    print("CPUSAMPLER -- innermost backend function -> module where the time is spent")
    for (nm, md), c in via.most_common(14):
        print("CPUSAMPLER   %5.1f %%  %-22s <- %s" % (100.0 * c / max(n, 1), md, nm[:90]))


def main():
    max_insns = sys.argv[1]
    args = ["psemu.run",
            r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin",
            "--fw-root", r"D:\Ps4Tools\ps4kernel\firmware",
            "--max", max_insns, "--max-modules", "80"] + sys.argv[2:]
    lib = build_sampler()
    lib.sampler_start.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.c_uint32, wintypes.DWORD]
    lib.sampler_stop.restype = ctypes.c_uint32
    depth = lib.sampler_depth()
    buf = (ctypes.c_uint64 * (CAP * depth))()
    delay = float(os.environ.get("SAMPLE_DELAY", "0"))      # seconds to wait before sampling
    tid = k32.GetCurrentThreadId()
    if delay <= 0:
        if not lib.sampler_start(tid, buf, CAP, 1):
            sys.exit("sampler_start failed")
    else:
        import threading
        threading.Timer(delay, lambda: lib.sampler_start(tid, buf, CAP, 1)).start()
    t0 = time.perf_counter()
    sys.argv = args
    try:
        runpy.run_module("psemu.run", run_name="__main__")
    finally:
        n = lib.sampler_stop()
        report(lib, buf, n, time.perf_counter() - t0)


if __name__ == "__main__":
    main()
