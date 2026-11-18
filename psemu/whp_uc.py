"""WhpUc: a Unicorn-compatible CPU object whose code runs on the host CPU inside a Windows
Hypervisor Platform partition (see docs/whp-backend-plan.md).

The rest of psemu (Emulator, syscalls, threads, devices, hostvm) talks to the CPU through the small
Unicorn surface -- reg_read/reg_write, mem_read/mem_write/mem_map*/mem_protect/mem_unmap,
hook_add, emu_start/emu_stop, context_save/context_restore -- so this class implements exactly that
and nothing in the HLE layer changes. What differs underneath:

* Memory: guest VA == guest physical == host VA (hostvm already allocates every guest mapping at the
  identical host address). Guest page tables, built here with numpy, carry the PS4 protections
  (RW / RX / NX), so protection faults are real hardware faults.
* `syscall`: EFER.SCE + LSTAR -> a one-instruction `hlt` stub. The HLT exit is the syscall; the
  stub's frame (RCX = return rip, R11 = rflags) is converted into the "after the syscall
  instruction" state Unicorn presents, host handlers run, and the guest resumes directly at the return rip.
* HLE function hooks: an `int3` patched over the first byte; the #BP exit runs the Python handler;
  `fixup` hooks restore the byte, single-step (TF -> #DB exit) and re-arm.
* AVX/F16C/BMI run natively (no VEX shim, no per-instruction hook).
* Preemption: a host timer thread calls WHvCancelRunVirtualProcessor; the exit is the end of a
  time slice, handed to the scheduler.
* Faults: #PF / #UD / #GP(int n) exits are mapped onto Unicorn's MEM_UNMAPPED / WRITE_PROT /
  INSN_INVALID / INTR hooks and UcError, which the Emulator already knows how to turn into a
  SIGSEGV delivered to the guest.

Not deterministic: the virtual clock follows wall time (Emulator._whp_clock); the Unicorn backend
stays the reference.
"""
import bisect
import ctypes
import struct
import threading
import time

import numpy as np
import unicorn.x86_const as X
from unicorn import (UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INSN_INVALID, UC_HOOK_INTR,
                     UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE_PROT, UC_PROT_EXEC, UC_PROT_WRITE,
                     UcError)
from unicorn.unicorn_const import (UC_ERR_EXCEPTION, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNMAPPED,
                                   UC_ERR_INSN_INVALID, UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_PROT,
                                   UC_ERR_WRITE_UNMAPPED)

from . import whp

PAGE = 0x1000
MASK48 = (1 << 48) - 1

# ---- fixed guest-physical layout of the psemu "firmware" ------------------------------------
POOL_GPA = 0x3F00_0000_0000          # page tables, GDT and the syscall stub live up here, clear of
POOL_SIZE = 128 << 20                # every address a PS4 process uses
POOL_PAGES = POOL_SIZE // PAGE
PG_PML4, PG_GDT, PG_STUB = 0, 1, 2   # first pool pages; dynamic tables are allocated after these
FIRST_TABLE = 3
KSTUB_VA = 0xFFFF_FFFF_8000_0000     # where LSTAR points (kernel half, canonical)

# long mode, SSE/AVX enabled
CR0_VAL = 0x8001_0033                # PG | WP | NE | ET | MP | PE
CR4_VAL = (1 << 5) | (1 << 9) | (1 << 10) | (1 << 18)   # PAE | OSFXSR | OSXMMEXCPT | OSXSAVE
EFER_VAL = 0x1 | 0x100 | 0x400 | 0x800                  # SCE | LME | LMA | NXE
XCR0 = 0x27                          # WHvX64RegisterXCr0 (after Dr0-3 = 0x21-0x24, Dr6, Dr7; probed)
XCR0_VAL = 0x7                       # x87 | SSE | AVX

KCODE_SEL, KDATA_SEL = 0x08, 0x10

# exception vectors we take exits for: every vector WHP lets a partition intercept (it rejects
# 2/NMI, 9, 15 and 20-31; probed on AMD)
EXC_BITMAP = sum(1 << v for v in (0, 1, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19))
EXT_EXITS_EXCEPTION = 1 << 2

# unicorn MEM hook access codes (UC_MEM_READ_UNMAPPED, ...)
ACC_READ_UNMAPPED, ACC_WRITE_UNMAPPED, ACC_FETCH_UNMAPPED = 19, 20, 21
ACC_WRITE_PROT = 22

# ---- register cache layout: the 16 GPRs, RIP, RFLAGS (WHP names 0..0x11 are contiguous) -------
_GPR_ORDER = [X.UC_X86_REG_RAX, X.UC_X86_REG_RCX, X.UC_X86_REG_RDX, X.UC_X86_REG_RBX,
              X.UC_X86_REG_RSP, X.UC_X86_REG_RBP, X.UC_X86_REG_RSI, X.UC_X86_REG_RDI,
              X.UC_X86_REG_R8, X.UC_X86_REG_R9, X.UC_X86_REG_R10, X.UC_X86_REG_R11,
              X.UC_X86_REG_R12, X.UC_X86_REG_R13, X.UC_X86_REG_R14, X.UC_X86_REG_R15,
              X.UC_X86_REG_RIP, X.UC_X86_REG_RFLAGS]
IDX = {r: i for i, r in enumerate(_GPR_ORDER)}
IDX[X.UC_X86_REG_EFLAGS] = 17
I_RAX, I_RCX, I_R11, I_RIP, I_RFLAGS = 0, 1, 11, 16, 17
NREG = 18

_OTHER = {X.UC_X86_REG_CR0: whp.CR0, X.UC_X86_REG_CR2: whp.CR2, X.UC_X86_REG_CR3: whp.CR3,
          X.UC_X86_REG_CR4: whp.CR4, X.UC_X86_REG_CR8: whp.CR8}
_SEG = {X.UC_X86_REG_CS: whp.CS, X.UC_X86_REG_SS: whp.SS, X.UC_X86_REG_DS: whp.DS,
        X.UC_X86_REG_ES: whp.ES}

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.VirtualAlloc.restype = ctypes.c_void_p
_k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
_k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]


def _valloc(size):
    p = _k32.VirtualAlloc(None, size, 0x3000, 0x04)
    if not p:
        raise MemoryError("VirtualAlloc(%#x) failed" % size)
    return p


def _pte_flags(prot):
    """x86 PTE flag bits for a Unicorn UC_PROT_* mask (0 = not present)."""
    if not prot:
        return 0
    f = 1 | 4                                  # present | user
    if prot & UC_PROT_WRITE:
        f |= 2
    if not prot & UC_PROT_EXEC:
        f |= 1 << 63
    return f


class WhpUc:
    """Drop-in for the parts of unicorn.Uc that psemu uses (see module docstring)."""

    # callbacks installed by the Emulator
    hle_cb = None          # (uc, addr) -> True when a 'replace' hook already moved RIP
    preempt_cb = None      # (uc, rip) -> True when a thread switch is now pending
    tick_cb = None         # () called after every exit (time budget etc.)

    def __init__(self):
        self.p = whp.Partition(1, exception_bitmap=EXC_BITMAP, extended_exits=EXT_EXITS_EXCEPTION)
        self._d = whp.dll()
        self._h = self.p.h
        self._closed = False
        # ---- register cache ----
        self._names = (ctypes.c_int * NREG)(*range(NREG))
        self._vals = (whp.WHV_REGISTER_VALUE * (NREG + 2))()
        self._u64 = np.frombuffer(self._vals, dtype=np.uint64)       # entry i -> _u64[2*i]
        self._r = [0] * NREG
        self._dirty = False
        self.fs_base = 0
        self.gs_base = 0
        self._seg_dirty = False
        self._ctx = (ctypes.c_ubyte * 256)()
        # ---- memory ----
        self._starts = []                      # sorted region starts
        self._rec = {}                         # start -> [end, host_base_for_start]
        self._last = None                      # (start, end, host) lookup cache
        self._keep = []                        # private host allocations
        # ---- page tables ----
        self._pool = _valloc(POOL_SIZE)
        self.p.map_gpa(self._pool, POOL_GPA, POOL_SIZE)
        self._pool_np = np.frombuffer((ctypes.c_ubyte * POOL_SIZE).from_address(self._pool),
                                      dtype=np.uint64)
        self._pool_next = FIRST_TABLE
        self._pml4 = self._pool_np[0:512]
        self._pdpt, self._pd, self._pt = {}, {}, {}
        self._tlb_dirty = True
        self._build_firmware()
        # ---- hooks / run state ----
        self._h_syscall = []
        self._h_unmapped = []
        self._h_invalid = []
        self._h_intr = []
        self._h_wprot = []
        self._stop = False
        self._in_guest = False
        self._traps = {}                       # addr -> original byte (HLE int3 patches)
        self._traps_pending = set()
        self._step_addr = None
        self.exits = {}                        # exit statistics
        self.n_syscalls = 0
        self._xs_len = 0
        self._xs_buf = (ctypes.c_ubyte * 16384)()
        self._timer = None
        self.slice_s = 0.004
        self._init_vcpu()

    # ------------------------------------------------------------------ firmware / vCPU setup
    def _pool_page(self, i):
        return self._pool_np[i * 512:(i + 1) * 512]

    def _build_firmware(self):
        # GDT: null, kernel code64 (0x08), kernel data (0x10)
        gdt = self._pool_page(PG_GDT)
        gdt[1] = np.uint64(0x00AF9B000000FFFF)
        gdt[2] = np.uint64(0x00CF93000000FFFF)
        self._gdt_gpa = POOL_GPA + PG_GDT * PAGE
        # syscall stub: a single HLT; the HLT exit at KSTUB_VA is "the guest executed syscall"
        stub = (ctypes.c_ubyte * PAGE).from_address(self._pool + PG_STUB * PAGE)
        stub[0] = 0xF4
        self._pml4[:] = 0
        self._pt_set_pages(KSTUB_VA, [POOL_GPA + PG_STUB * PAGE], 1 | 4)   # present, user, RO, exec

    def _init_vcpu(self):
        gp = whp.ATTR_DATA
        tbl = whp.WHV_REGISTER_VALUE()
        struct.pack_into("<6xHQ", tbl.bytes, 0, 0x17, self._gdt_gpa)
        idt = whp.WHV_REGISTER_VALUE()
        struct.pack_into("<6xHQ", idt.bytes, 0, 0, 0)
        self.p.set_regs([
            (whp.CR3, POOL_GPA), (whp.CR4, CR4_VAL), (whp.CR0, CR0_VAL), (whp.EFER, EFER_VAL),
            (whp.STAR, (KCODE_SEL << 32) | ((KDATA_SEL - 8) << 48)),
            (whp.LSTAR, KSTUB_VA), (whp.SFMASK, 0),
            (whp.GDTR, tbl), (whp.IDTR, idt),
            (whp.CS, whp.seg(0, KCODE_SEL, whp.ATTR_CODE64)),
            (whp.SS, whp.seg(0, KDATA_SEL, gp)), (whp.DS, whp.seg(0, KDATA_SEL, gp)),
            (whp.ES, whp.seg(0, KDATA_SEL, gp)),
            (whp.FS, whp.seg(0, KDATA_SEL, gp)), (whp.GS, whp.seg(0, KDATA_SEL, gp)),
            (XCR0, XCR0_VAL),
            (whp.RFLAGS, 0x202), (whp.RIP, 0),
        ])
        self._pull()
        self._tlb_dirty = False

    # ------------------------------------------------------------------ register access
    def _pull(self):
        _chk = whp._chk
        _chk(self._d.WHvGetVirtualProcessorRegisters(self._h, 0, self._names, NREG, self._vals),
             "get regs")
        self._r = self._u64[0:2 * NREG:2].tolist()

    def _push(self):
        r = self._r
        u = self._u64
        u[0:2 * NREG:2] = r
        whp._chk(self._d.WHvSetVirtualProcessorRegisters(self._h, 0, self._names, NREG, self._vals),
                 "set regs")
        self._dirty = False

    def _flush(self):
        if self._dirty:
            self._push()
        if self._seg_dirty:
            gp = whp.ATTR_DATA
            self.p.set_regs([(whp.FS, whp.seg(self.fs_base, 0, gp)),
                             (whp.GS, whp.seg(self.gs_base, 0, gp))])
            self._seg_dirty = False
        if self._tlb_dirty:
            self.p.set_regs([(whp.CR3, POOL_GPA)])
            self._tlb_dirty = False
        if self._traps_pending:
            self._apply_traps()

    def reg_read(self, reg):
        i = IDX.get(reg)
        if i is not None:
            return self._r[i]
        if reg == X.UC_X86_REG_FS_BASE:
            return self.fs_base
        if reg == X.UC_X86_REG_GS_BASE:
            return self.gs_base
        w = _OTHER.get(reg)
        if w is not None:
            return self.p.get_regs([w])[0]
        w = _SEG.get(reg)
        if w is not None:
            return self.p.get_regs([w])[0]
        raise UcError(21)

    def reg_write(self, reg, value):
        i = IDX.get(reg)
        if i is not None:
            self._r[i] = value & 0xFFFFFFFFFFFFFFFF
            self._dirty = True
            return
        if reg == X.UC_X86_REG_FS_BASE:
            self.fs_base = value & 0xFFFFFFFFFFFFFFFF
            self._seg_dirty = True
            return
        if reg == X.UC_X86_REG_GS_BASE:
            self.gs_base = value & 0xFFFFFFFFFFFFFFFF
            self._seg_dirty = True
            return
        w = _OTHER.get(reg)
        if w is not None:
            self.p.set_regs([(w, value)])
            return
        raise UcError(21)

    def syscall_args(self):
        """(rdi, rsi, rdx, r10, r8, r9) -- the PS4 syscall argument registers."""
        r = self._r
        return (r[7], r[6], r[2], r[10], r[8], r[9])

    # ------------------------------------------------------------------ context save / restore
    def _xsave_get(self):
        n = ctypes.c_uint32()
        whp._chk(self._d.WHvGetVirtualProcessorXsaveState(self._h, 0, self._xs_buf, 16384,
                                                         ctypes.byref(n)), "xsave get")
        self._xs_len = n.value
        return ctypes.string_at(self._xs_buf, n.value)

    def _xsave_set(self, blob):
        whp._chk(self._d.WHvSetVirtualProcessorXsaveState(self._h, 0, blob, len(blob)),
                 "xsave set")

    def context_save(self):
        return (list(self._r), self.fs_base, self.gs_base, self._xsave_get())

    def context_restore(self, ctx):
        r, fs, gs, xs = ctx
        self._r = list(r)
        self._dirty = True
        if (fs, gs) != (self.fs_base, self.gs_base):
            self.fs_base, self.gs_base = fs, gs
            self._seg_dirty = True
        self._xsave_set(xs)

    # ------------------------------------------------------------------ guest memory
    def _find(self, addr):
        c = self._last
        if c is not None and c[0] <= addr < c[1]:
            return c
        i = bisect.bisect_right(self._starts, addr) - 1
        if i >= 0:
            s = self._starts[i]
            e, host = self._rec[s]
            if addr < e:
                c = self._last = (s, e, host)
                return c
        return None

    def mem_read(self, addr, size):
        c = self._find(addr)
        if c is not None and addr + size <= c[1]:
            data = ctypes.string_at(c[2] + (addr - c[0]), size)
        else:
            parts, a, left = [], addr, size
            while left > 0:
                c = self._find(a)
                if c is None:
                    raise UcError(UC_ERR_READ_UNMAPPED)
                n = min(left, c[1] - a)
                parts.append(ctypes.string_at(c[2] + (a - c[0]), n))
                a += n
                left -= n
            data = b"".join(parts)
        if self._traps:
            data = self._unpatch(addr, data)
        return bytearray(data)

    def mem_write(self, addr, data):
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        if self._traps:
            data = self._repatch(addr, data)
        n = len(data)
        c = self._find(addr)
        if c is not None and addr + n <= c[1]:
            ctypes.memmove(c[2] + (addr - c[0]), data, n)
            return
        a, off = addr, 0
        while off < n:
            c = self._find(a)
            if c is None:
                raise UcError(UC_ERR_WRITE_UNMAPPED)
            k = min(n - off, c[1] - a)
            ctypes.memmove(c[2] + (a - c[0]), data[off:off + k], k)
            a += k
            off += k

    def _add_region(self, addr, size, host):
        self._cut(addr, addr + size)
        bisect.insort(self._starts, addr)
        self._rec[addr] = [addr + size, host]
        self._last = None

    def _cut(self, lo, hi):
        """Remove [lo, hi) from the region records (splitting partial overlaps)."""
        i = max(bisect.bisect_right(self._starts, lo) - 1, 0)
        out = []
        while i < len(self._starts) and self._starts[i] < hi:
            s = self._starts[i]
            e, host = self._rec[s]
            if e <= lo:
                i += 1
                continue
            del self._rec[s]
            self._starts.pop(i)
            if s < lo:
                out.append((s, lo, host))
            if hi < e:
                out.append((hi, e, host + (hi - s)))
        for s, e, host in out:
            bisect.insort(self._starts, s)
            self._rec[s] = [e, host]
        self._last = None

    def mem_map_ptr(self, addr, size, prot, ptr):
        self.p.map_gpa(ptr, addr, size)
        self._add_region(addr, size, ptr)
        self._pt_fill(addr, size, prot)

    def mem_map(self, addr, size, prot=7):
        host = _valloc(size)
        self._keep.append(host)
        self.p.map_gpa(host, addr, size)
        self._add_region(addr, size, host)
        self._pt_fill(addr, size, prot)

    def mem_unmap(self, addr, size):
        self._pt_fill(addr, size, 0)
        self.p.unmap_gpa(addr, size)
        self._cut(addr, addr + size)

    def mem_protect(self, addr, size, prot):
        self._pt_fill(addr, size, prot)

    # ------------------------------------------------------------------ page tables
    def _alloc_table(self):
        i = self._pool_next
        if i >= POOL_PAGES:
            raise MemoryError("WHP page-table pool exhausted")
        self._pool_next += 1
        return POOL_GPA + i * PAGE, self._pool_page(i)

    def _get_pt(self, va):
        k = va >> 21
        pt = self._pt.get(k)
        if pt is None:
            k2 = va >> 30
            pd = self._pd.get(k2)
            if pd is None:
                k3 = (va >> 39) & 0x1FF
                pdpt = self._pdpt.get(k3)
                if pdpt is None:
                    gpa, pdpt = self._alloc_table()
                    self._pml4[k3] = gpa | 7
                    self._pdpt[k3] = pdpt
                gpa, pd = self._alloc_table()
                pdpt[(va >> 30) & 0x1FF] = gpa | 7
                self._pd[k2] = pd
            gpa, pt = self._alloc_table()
            pd[(va >> 21) & 0x1FF] = gpa | 7
            self._pt[k] = pt
        return pt

    def _pt_fill(self, va, size, prot):
        """Identity-map [va, va+size) (GPA == VA) with `prot` (0 = not present)."""
        flags = np.uint64(_pte_flags(prot))
        a = va & MASK48
        end = a + size
        while a < end:
            nxt = min(end, (a | 0x1FFFFF) + 1)
            pt = self._get_pt(a)
            i0 = (a >> 12) & 0x1FF
            n = (nxt - a) >> 12
            if flags:
                pt[i0:i0 + n] = np.arange(a, a + n * PAGE, PAGE, dtype=np.uint64) | flags
            else:
                pt[i0:i0 + n] = 0
            a = nxt
        self._tlb_dirty = True

    def _pt_set_pages(self, va, gpas, flags):
        a = va & MASK48
        pt = self._get_pt(a)
        i0 = (a >> 12) & 0x1FF
        for k, g in enumerate(gpas):
            pt[i0 + k] = np.uint64(g | flags)
        self._tlb_dirty = True

    # ------------------------------------------------------------------ HLE traps (int3)
    def hle_add(self, addr):
        if addr not in self._traps:
            self._traps_pending.add(addr)

    def hle_remove(self, addr):
        self._traps_pending.discard(addr)
        orig = self._traps.pop(addr, None)
        if orig is not None:
            c = self._find(addr)
            if c is not None:
                ctypes.memmove(c[2] + (addr - c[0]), bytes([orig]), 1)

    def _apply_traps(self):
        for addr in list(self._traps_pending):
            c = self._find(addr)
            if c is None:
                continue
            p = c[2] + (addr - c[0])
            self._traps[addr] = ctypes.string_at(p, 1)[0]
            ctypes.memmove(p, b"\xcc", 1)
            self._traps_pending.discard(addr)

    def _unpatch(self, addr, data):
        end = addr + len(data)
        for a, orig in self._traps.items():
            if addr <= a < end:
                b = bytearray(data)
                b[a - addr] = orig
                data = bytes(b)
        return data

    def _repatch(self, addr, data):
        end = addr + len(data)
        for a in list(self._traps):
            if addr <= a < end:
                b = bytearray(data)
                self._traps[a] = b[a - addr]
                b[a - addr] = 0xCC
                data = bytes(b)
        return data

    # ------------------------------------------------------------------ hooks
    def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0, aux1=0):
        entry = (callback, user_data)
        if htype == UC_HOOK_INSN:
            self._h_syscall.append(entry)
        elif htype == UC_HOOK_MEM_UNMAPPED:
            self._h_unmapped.append(entry)
        elif htype == UC_HOOK_INSN_INVALID:
            self._h_invalid.append(entry)
        elif htype == UC_HOOK_INTR:
            self._h_intr.append(entry)
        elif htype == UC_HOOK_MEM_WRITE_PROT:
            self._h_wprot.append(entry)
        elif htype == UC_HOOK_CODE:
            raise NotImplementedError("per-instruction hooks do not exist on the WHP backend")
        return 0

    def emu_stop(self):
        self._stop = True

    def ctl_set_cpu_model(self, *a):
        pass

    # ------------------------------------------------------------------ run loop
    def _start_timer(self):
        if self._timer is not None:
            return

        def loop():
            while not self._closed:
                time.sleep(self.slice_s)
                if self._in_guest:
                    try:
                        self.p.cancel()
                    except Exception:
                        pass
        self._timer = threading.Thread(target=loop, daemon=True)
        self._timer.start()

    def _count(self, key):
        self.exits[key] = self.exits.get(key, 0) + 1

    def emu_start(self, begin, until, timeout=0, count=0):
        self._stop = False
        self._r[I_RIP] = begin
        self._dirty = True
        self._start_timer()
        run = self._d.WHvRunVirtualProcessor
        ctx = self._ctx
        while True:
            self._flush()
            self._in_guest = True
            hr = run(self._h, 0, ctx, 256)
            self._in_guest = False
            if hr & 0xFFFFFFFF:
                raise whp.WhpError("WHvRunVirtualProcessor failed (hr=%#010x)" % (hr & 0xFFFFFFFF))
            self._pull()
            reason = struct.unpack_from("<I", ctx, 0)[0]
            if reason == whp.EXIT_HALT:
                self._on_halt()
            elif reason == whp.EXIT_CANCELED:
                self._count("cancel")
                cb = self.preempt_cb
                # never switch threads mid single-step: TF would travel with the saved context
                if cb is not None and self._step_addr is None and cb(self, self._r[I_RIP]):
                    self._stop = True
            elif reason == whp.EXIT_EXCEPTION:
                self._on_exception()
            elif reason == whp.EXIT_MEMORY:
                self._on_memory_exit()
            else:
                self._fatal(reason)
            if self.tick_cb is not None:
                self.tick_cb()
            if self._stop:
                return

    def _fatal(self, reason):
        r = self._r
        raise whp.WhpError("unexpected VM exit %#x at rip=%#x (rsp=%#x)" %
                           (reason, r[I_RIP], r[4]))

    # ---- HLT at the LSTAR stub == guest `syscall` ----
    def _on_halt(self):
        r = self._r
        rip = r[I_RIP]
        if not KSTUB_VA <= rip <= KSTUB_VA + 1:
            raise UcError(UC_ERR_INSN_INVALID)       # a real guest HLT
        self.n_syscalls += 1
        r[I_RIP] = r[I_RCX]                           # as after the `syscall` instruction ...
        r[I_RFLAGS] = r[I_R11]                        # ... with the caller's flags (CF = error)
        self._dirty = True
        for cb, ud in self._h_syscall:
            cb(self, ud)

    # ---- exceptions ----
    def _on_exception(self):
        ctx = self._ctx
        vec = ctx[72]
        err = struct.unpack_from("<I", ctx, 76)[0]
        param = struct.unpack_from("<Q", ctx, 80)[0]
        r = self._r
        rip = r[I_RIP]
        self._count("exc%d" % vec)
        if vec == 3:                                   # #BP: an HLE trap (or a guest int3)
            addr = rip if rip in self._traps else rip - 1
            if addr in self._traps:
                self._hle(addr)
                return
            self._intr(3, rip)
            return
        if vec == 1:                                   # #DB: end of a single-step
            if self._step_addr is not None:
                a, self._step_addr = self._step_addr, None
                r[I_RFLAGS] &= ~0x100
                self._dirty = True
                if a in self._traps:                   # still armed: put the int3 back
                    self._rearm(a)
                return
            self._report_exception(vec, err, param, rip)
            raise UcError(UC_ERR_EXCEPTION)
        if vec == 14:                                  # #PF
            self._page_fault(param, err)
            return
        if vec == 6:                                   # #UD
            if self._h_invalid:
                for cb, ud in self._h_invalid:
                    if cb(self, ud):
                        return
            raise UcError(UC_ERR_INSN_INVALID)
        if vec == 13:                                  # #GP: `int n` without an IDT lands here
            code = self.mem_read(rip, 2)
            if code[0] == 0xCD:
                r[I_RIP] = rip + 2
                self._dirty = True
                self._intr(code[1], rip)
                return
        self._report_exception(vec, err, param, rip)
        raise UcError(UC_ERR_EXCEPTION)

    def _report_exception(self, vec, err, param, rip):
        try:
            code = bytes(self.mem_read(rip, 16)).hex(" ")
        except Exception:
            code = "?"
        print("  [whp] unhandled exception #%d err=%#x param=%#x at rip=%#x bytes: %s"
              % (vec, err, param, rip, code))

    def _intr(self, intno, rip):
        if not self._h_intr:
            self._report_exception(-intno, 0, 0, rip)
            raise UcError(UC_ERR_EXCEPTION)
        for cb, ud in self._h_intr:
            cb(self, intno, ud)

    def _page_fault(self, addr, err):
        present, write, fetch = err & 1, err & 2, err & 16
        if present and write and not fetch:
            for cb, ud in self._h_wprot:
                if cb(self, ACC_WRITE_PROT, addr, 1, 0, ud):
                    return
            raise UcError(UC_ERR_WRITE_PROT)
        if present and fetch:
            raise UcError(UC_ERR_FETCH_PROT)
        acc = ACC_FETCH_UNMAPPED if fetch else ACC_WRITE_UNMAPPED if write else ACC_READ_UNMAPPED
        for cb, ud in self._h_unmapped:
            if cb(self, acc, addr, 1, 0, ud):
                return
        raise UcError(UC_ERR_FETCH_UNMAPPED if fetch else
                      UC_ERR_WRITE_UNMAPPED if write else UC_ERR_READ_UNMAPPED)

    def _on_memory_exit(self):
        ctx = self._ctx
        acc = struct.unpack_from("<I", ctx, 68)[0] & 3
        gva = struct.unpack_from("<Q", ctx, 80)[0]
        self._count("ept")
        a = (ACC_READ_UNMAPPED, ACC_WRITE_UNMAPPED, ACC_FETCH_UNMAPPED)[min(acc, 2)]
        for cb, ud in self._h_unmapped:
            if cb(self, a, gva, 1, 0, ud):
                return
        raise UcError((UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED, UC_ERR_FETCH_UNMAPPED)[min(acc, 2)])

    # ---- HLE hook trap ----
    def _hle(self, addr):
        self._count("hle")
        r = self._r
        r[I_RIP] = addr
        self._dirty = True
        redirected = self.hle_cb(self, addr) if self.hle_cb else False
        if redirected:
            return
        # 'fixup': let the real instruction run -- put the original byte back, single-step it,
        # then re-arm the int3 (if the hook was not removed meanwhile)
        if addr in self._traps:
            c = self._find(addr)
            ctypes.memmove(c[2] + (addr - c[0]), bytes([self._traps[addr]]), 1)
            self._step_addr = addr
            self._r[I_RIP] = addr
            self._r[I_RFLAGS] |= 0x100                  # TF
            self._dirty = True

    def _rearm(self, addr):
        c = self._find(addr)
        if c is not None:
            ctypes.memmove(c[2] + (addr - c[0]), b"\xcc", 1)

    # ------------------------------------------------------------------ lifecycle
    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.p.close()
        except Exception:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
