"""ctypes wrapper for psemu_cpu.dll, the native per-instruction hook.

See native/cpuhook.c. `NativeCpu.load()` returns None when the DLL is missing
(build it with `python psemu/native/build.py`) or PSEMU_PY_HOOK=1 is set; the
emulator then uses its Python hook.
"""
import ctypes
import os
import re

R_NONE, R_LIMIT, R_TRAP, R_PAGE = 0, 1, 2, 3
RING = 32

DLL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native", "build",
                   "psemu_cpu.dll")


class CpuState(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint64),
        ("limit", ctypes.c_uint64),
        ("last", ctypes.c_uint64),
        ("stop_addr", ctypes.c_uint64),
        ("skip", ctypes.c_uint64),
        ("reason", ctypes.c_uint32),
        ("ring_pos", ctypes.c_uint32),
        ("ring", ctypes.c_uint64 * RING),
        ("emu_stop", ctypes.c_void_p),
        ("vex_native", ctypes.c_uint64),
        ("vex_passed", ctypes.c_uint64),
        ("clock_ns", ctypes.c_uint64),
        ("tsc_mul", ctypes.c_uint64),
        ("tsc_div", ctypes.c_uint64),
    ]

TSC_HZ = 1_600_000_000            # machdep.tsc_freq (Jaguar @ 1.6 GHz)


# VEX candidates: C4/C5 (always VEX in 64-bit mode), optionally behind one
# 66/F2/F3 prefix -- the same shapes Emulator._classify_vex accepts.
_VEX_RE = re.compile(rb"[\xc4\xc5]")
_PREFIX = (0x66, 0xF2, 0xF3)


class NativeCpu:
    _lib = None

    @classmethod
    def load(cls):
        if os.environ.get("PSEMU_PY_HOOK"):
            return None
        if cls._lib is None:
            if not os.path.exists(DLL):
                try:
                    from .native.build import build
                    build()
                except BaseException:
                    return None
            if not os.path.exists(DLL):
                return None
            lib = ctypes.CDLL(DLL)
            lib.cpu_state.restype = ctypes.POINTER(CpuState)
            lib.cpu_hook_ptr.restype = ctypes.c_void_p
            lib.cpu_rdtsc_ptr.restype = ctypes.c_void_p
            lib.cpu_rdtscp_ptr.restype = ctypes.c_void_p
            lib.cpu_init.argtypes = [ctypes.c_void_p]
            lib.cpu_init.restype = ctypes.c_int
            lib.cpu_vex_stats.restype = ctypes.POINTER(ctypes.c_uint64 * 1024)
            lib.cpu_vex_first.restype = ctypes.POINTER(ctypes.c_uint64 * 1024)
            lib.cpu_vex_run.argtypes = [ctypes.c_void_p, ctypes.c_uint64,
                                        ctypes.POINTER(ctypes.c_int)]
            for f in ("cpu_trap_add", "cpu_trap_remove", "cpu_hle_add"):
                getattr(lib, f).argtypes = [ctypes.c_uint64]
                getattr(lib, f).restype = ctypes.c_int
            lib.cpu_page_scanned.argtypes = [ctypes.c_uint64]
            lib.cpu_pages_forget.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
            from unicorn.unicorn_py3.unicorn import uclib
            if not lib.cpu_init(ctypes.cast(uclib.uc_emu_stop, ctypes.c_void_p).value):
                return None
            cls._lib = lib
        return cls()

    def __init__(self):
        lib = self._lib
        self.lib = lib
        self.s = lib.cpu_state().contents
        from unicorn.unicorn_py3.unicorn import uclib
        self._uclib = uclib
        self.trap_add = lib.cpu_trap_add
        self.hle_add = lib.cpu_hle_add
        self.trap_remove = lib.cpu_trap_remove
        self.page_scanned = lib.cpu_page_scanned
        self.vex_traps = set()
        # PSEMU_NATIVE_VEX=0: run every VEX instruction through the Python shim
        lib.cpu_set_vex(0 if os.environ.get("PSEMU_NATIVE_VEX") == "0" else 1)

    def attach(self, uc, hle_addrs=()):
        """Install the hook on a new CPU (one address space); traps restart."""
        from unicorn import UC_HOOK_CODE
        self.lib.cpu_reset()
        self.vex_traps.clear()
        h = ctypes.c_size_t()
        err = self._uclib.uc_hook_add(uc._uch, ctypes.byref(h), UC_HOOK_CODE,
                                      self.lib.cpu_hook_ptr(), None, 1, 0)
        if err:
            raise RuntimeError(f"uc_hook_add(native) failed: {err}")
        # rdtsc/rdtscp from the virtual clock (the Python binding can't hook
        # these, the C API can)
        from unicorn import UC_HOOK_INSN
        from unicorn.x86_const import UC_X86_INS_RDTSC, UC_X86_INS_RDTSCP
        self.s.tsc_mul, self.s.tsc_div = TSC_HZ // 1_000_000, 1000
        for ins, fn in ((UC_X86_INS_RDTSC, self.lib.cpu_rdtsc_ptr()),
                        (UC_X86_INS_RDTSCP, self.lib.cpu_rdtscp_ptr())):
            h = ctypes.c_size_t()
            self._uclib.uc_hook_add(uc._uch, ctypes.byref(h), UC_HOOK_INSN, fn, None,
                                    ctypes.c_uint64(1), ctypes.c_uint64(0), ctypes.c_int(ins))
        for a in hle_addrs:
            self.hle_add(a)

    def pages_forget(self, lo, hi):
        """Code in [lo, hi) was (re)written: rescan it when it next runs."""
        self.lib.cpu_pages_forget(lo, hi)
        self.vex_traps = {a for a in self.vex_traps if not lo <= a < hi}

    # the instruction counter is the emulator's clock
    @property
    def count(self):
        return self.s.count

    @count.setter
    def count(self, v):
        self.s.count = v

    def recent(self):
        n = self.s.ring_pos
        k = min(n, RING)
        return [self.s.ring[(n - k + i) % RING] for i in range(k)]

    def scan_page(self, uc, addr):
        """Trap every VEX instruction start candidate on addr's page (C4/C5,
        optionally behind a 66/F2/F3 prefix). Executed ones are decoded once:
        vex.c runs the ones it knows, untraps the ones QEMU gets right, and
        hands the rest to the Python shim."""
        page = addr & ~0xFFF
        try:
            code = bytes(uc.mem_read(page, 0x1000 + 1))
        except Exception:
            try:
                code = bytes(uc.mem_read(page, 0x1000))
            except Exception:
                self.page_scanned(addr)
                return 0
        n = 0
        for m in _VEX_RE.finditer(code):
            i = m.start()
            cands = (i, i - 1) if i and code[i - 1] in _PREFIX else (i,)
            for p in cands:
                if p >= 0x1000:
                    continue
                a = page + p
                if a not in self.vex_traps:
                    self.vex_traps.add(a)
                    self.trap_add(a)
                    n += 1
        self.page_scanned(addr)
        return n

    def vex_summary(self, md=None):
        """'native VEX: N executed (top ops)'; md (capstone) names opcodes."""
        s = self.s
        if not s.vex_native:
            return f"native VEX: none executed ({s.vex_passed} left to QEMU)"
        stats = self.lib.cpu_vex_stats().contents
        first = self.lib.cpu_vex_first().contents
        top = sorted(((stats[i], i) for i in range(1024) if stats[i]), reverse=True)[:12]
        parts = []
        for cnt, i in top:
            name = f"{('', '0F', '0F38', '0F3A')[i >> 8]}{i & 0xFF:02X}"
            parts.append(f"{name} x{cnt}")
        return (f"native VEX: {s.vex_native} executed, {s.vex_passed} addresses left to "
                f"QEMU; by opcode: " + ", ".join(parts))
