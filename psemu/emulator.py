"""Emulator core: build a Unicorn x86-64 CPU, map the ELF, set up a stack and
TLS, install the syscall + diagnostic hooks, and run.

This is intentionally a thin, legible core so new kernel services can be added
in syscalls.py without touching the CPU plumbing.
"""
import os
import struct
from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_64,
    UC_HOOK_INSN, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_INSN_INVALID,
    UC_HOOK_INTR, UC_HOOK_MEM_WRITE_PROT,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_ALL,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_INS_SYSCALL,
    UC_X86_REG_RSP, UC_X86_REG_RDI, UC_X86_REG_RIP,
    UC_X86_REG_FS_BASE, UC_X86_REG_CR0, UC_X86_REG_CR4,
    UC_CPU_X86_HASWELL,
)

from .hostvm import HostVM
from .loader import Elf64, PAGE, align_up
from .syscalls import SyscallDispatcher
from .avx_shim import AvxShim
from .hle import HleHooks

# Where we park the emulator-managed regions, well away from the module image
# (which lives around 0x400000-0x4a0000).
STACK_TOP = 0x0000_7fff_0000_0000
STACK_SIZE = 0x200000                      # 2 MiB
TLS_BASE = 0x0000_0000_1000_0000
TLS_SIZE = 0x10000
# bump-allocated region handed out by mmap()
# Below 1 TB so mmap'd memory is addressable by the PS4 GPU (40-bit VAs);
# see hostvm.py for how guest pages double as host pages.
MMAP_BASE = 0x0000_0020_0000_0000
MMAP_END = 0x0000_0020_8000_0000           # 2 GiB window
PAGE4K = 0x1000


def _align_up(x, a=PAGE4K):
    return (x + a - 1) & ~(a - 1)


# --- libthr `struct pthread` offsets used by this firmware ----------------
# (recovered from the mutex-enqueue path at 0x440240; firmware-specific)
CT_TID = 0x00       # owner id / lock word
CT_MQ1 = 0x1a0      # owned-mutex TAILQ #1 head (tqh_first, tqh_last)
CT_MQ2 = 0x1b0      # owned-mutex TAILQ #2 head
DEFAULT_TID = 0x10001


def _align_down(x, a=PAGE4K):
    return x & ~(a - 1)


IDLE = -1          # _run_segment result: every thread is waiting for another process


class Emulator:
    def __init__(self, path, trace=False, max_insns=2_000_000, verbose=True,
                 fw_root=None, backend=None, shared_machine=None, host_identity=True):
        import collections
        import time
        # CPU backend: "unicorn" (default: deterministic reference, instruction-counted clock)
        # or "whp" (hardware-virtualized guest on the Windows Hypervisor Platform; wall-clock
        # virtual time, see whp_uc.py). PSEMU_BACKEND=whp selects it from the environment.
        self.whp = (backend or os.environ.get("PSEMU_BACKEND") or "unicorn").lower() == "whp"
        self._t0 = time.perf_counter()
        # whp: wall seconds spent on the (parallel, on real hardware) GPU / compositor; excluded
        # from virtual time so the guest's 60 Hz world is not starved by our software renderer
        self._excl = 0.0
        self._time = time.perf_counter
        self.max_seconds = None        # whp: wall-clock budget (an instruction budget is meaningless)
        # --then: once the first process (SceSysCore) has brought its services up, chain-load this
        # one (the app, entered through libkernel as the interpreter); whp only
        self.then_path = None
        self.then_settle = 5.0         # seconds of SceSysCoreApp2 being up before the handoff
        self._then_seen = None
        self.path = path
        self.trace = trace
        # several processes on one WHP machine (see process.py / whp_uc.Machine): the partition they
        # share, and whether this process's guest memory is host memory at the same address (GPU-visible)
        self.shared_machine = shared_machine
        self.host_identity = host_identity
        self.max_insns = max_insns
        self.verbose = verbose
        # Firmware root used to resolve execve() paths like "/SceSysAvControl.elf".
        self.fw_root = fw_root or os.path.dirname(os.path.abspath(path))
        # /app0 = the directory of the launched application (its eboot.bin).
        self.app_root = os.path.dirname(os.path.abspath(path))

        # placeholders the helpers read at construction (set by _build_image)
        self.uc = None
        self.elf = None

        # --- "kernel" state: persists across execve() like a real process ---
        # native per-instruction hook (cpu_native.py); --trace keeps the
        # Python hook, which can log every instruction
        from .cpu_native import NativeCpu
        self.native = None if (trace or self.whp) else NativeCpu.load()
        self._insn_py = 0
        self._last_py = 0
        self.syscalls = SyscallDispatcher(self)   # fd table, handles, objects
        self.avx = AvxShim(self)                   # YMM shim (capstone decoder)
        self.hle = HleHooks(self)                  # function hooks (per image)
        self._insn_count = 0                       # cumulative across modules
        self.sched = None                          # threads.Scheduler, set by run()
        self.module_index = 0
        self.max_modules = 8                       # chain-load safety cap
        # process-spawn policy for execve() from an rfork'd child (see
        # SyscallDispatcher.sys_execve). None/"follow" = chain-load the child,
        # replacing the image (the default, and how boot handoffs work);
        # "stay" = keep running the parent process and retire the spawned
        # child; any other string = a path substring to follow (chain-load a
        # child whose path contains it, otherwise stay with the parent).
        self.spawn_mode = None
        self._rip_history = collections.deque(maxlen=24)

        # --- per-image state (reset by _build_image) ---
        self._hle_pending = False
        self._pending_fault = None  # (address, is_write) of a fault awaiting SIGSEGV delivery
        self._exec_next = None     # (path, argv) requested by execve()
        self._stop_reason = None
        self._last_rip = 0
        self._mmap_next = MMAP_BASE
        self._mapped = []
        self._relaxed = set()
        self._vex_cache = {}

        self._build_image(path)

    def _build_image(self, path):
        """Create a fresh address space (new Unicorn instance) and load `path`
        into it: segments, stack, TCB/curthread, hooks, and per-module HLE
        hooks. Used at startup and on every execve(). The kernel-side state
        (fd table, handles) is inherited, exactly as execve() does."""
        self.path = path
        self.elf = Elf64(path)
        self.dyn = None
        if self.elf.is_dynamic:
            self._build_dynamic(path)
            return
        self._dynamic_block = False
        self.uc = self._new_cpu()
        self.vm = HostVM(self.uc, log=self.log, identity=getattr(self.uc, 'identity', True))
        self._enable_avx()
        # re-point the helpers at the new CPU
        self.avx.uc = self.uc
        self.hle.uc = self.uc
        self.hle.table = {}
        self._vex_cache = {}
        # per-image memory bookkeeping
        self._mmap_next = MMAP_BASE
        self._mapped = []
        self._relaxed = set()
        self.log(f"\n== loading module #{self.module_index}: "
                 f"{os.path.basename(path)} (entry 0x{self.elf.entry:x}) ==")
        self.lo, self.hi = self.elf.map_into(self.uc, log=self.log, mapper=self.vm.map)
        rsp = self._map_stack_and_tls()
        self._setup_initial_stack(rsp)
        self._install_hooks()
        self._register_default_hle()
        self.entry_point = self.elf.entry

    def _build_dynamic(self, path):
        """Dynamically linked process: map the executable and all its
        libraries, relocate, and start in libkernel (the interpreter) like the
        PS4 kernel does. See dynproc.py."""
        from .dynproc import DynamicProcess
        self._dynamic_block = False
        self.uc = self._new_cpu()
        self.vm = HostVM(self.uc, log=self.log, identity=getattr(self.uc, 'identity', True))
        self._enable_avx()
        self.avx.uc = self.uc
        self.hle.uc = self.uc
        self.hle.table = {}
        self._vex_cache = {}
        self._mmap_next = MMAP_BASE
        self._mapped = []
        self._relaxed = set()
        self.log(f"\n== loading module #{self.module_index}: "
                 f"{os.path.basename(path)} (dynamic, interp {self.elf.interp}) ==")
        self.dyn = DynamicProcess(self, path).build()
        lk = self.dyn.libkernel
        self.lo, self.hi = lk.lo, lk.hi
        rsp = self._map_stack_and_tls()
        rsp = self.dyn.initial_stack(rsp, [self.dyn.path_guest()])
        # PS4 enters the interpreter as if it had been CALLed: rsp must be
        # 8 (mod 16) at the entry point, so that after libkernel's prologue
        # (`sub rsp,0x18`) the first `call` is made from a 16-aligned rsp and
        # every callee's `push rbp` yields a 16-aligned frame. initial_stack
        # returns a 16-aligned (0 mod 16) block pointer; entering with that as
        # rsp leaves the whole process 8 bytes misaligned (tolerated by most
        # code via unaligned moves, but it trips Mono AOT's deliberate stack-
        # alignment assertion deep in managed init). The argc/argv/auxv block
        # pointer is passed in rdi (libkernel reads it there: `mov r12,rdi`).
        self.uc.reg_write(UC_X86_REG_RSP, rsp - 8)
        self.uc.reg_write(UC_X86_REG_RDI, rsp)
        self._install_hooks()
        # libthr lives in libkernel: detect its hooks there
        self._scan_elf, self._scan_base = lk.mod.elf, lk.base
        self._register_default_hle()
        self._scan_elf = None
        self.entry_point = lk.entry
        self.log(f"  entry: libkernel @ {lk.entry:#x} (executable entry {self.dyn.exe.entry:#x})")

    def _new_cpu(self):
        """A fresh CPU for a new address space: Unicorn, or a WHP partition."""
        old = getattr(self, "uc", None)
        if self.whp:
            from .whp_uc import WhpUc
            if old is not None and hasattr(old, "close"):
                old.close()                     # execve: the previous partition is gone
            return WhpUc(machine=self.shared_machine, identity=self.host_identity)
        return Uc(UC_ARCH_X86, UC_MODE_64)

    # ---- cpu features ---------------------------------------------------
    def _enable_avx(self):
        """The module uses AVX (vxorps/vmovups ymm...). Unicorn's default CPU
        model rejects those, so select an AVX2-capable model and turn on the
        SSE/AVX enable bits so instructions don't #UD at runtime."""
        if getattr(self, "whp", False):
            return          # the vCPU is built with SSE/AVX on (whp_uc.CR4_VAL / XCR0_VAL)
        try:
            self.uc.ctl_set_cpu_model(UC_CPU_X86_HASWELL)
        except Exception as e:
            print(f"  (warning: could not set CPU model: {e})")
        # CR0: clear EM (bit2), set MP (bit1)  -> FPU present
        cr0 = self.uc.reg_read(UC_X86_REG_CR0)
        cr0 = (cr0 & ~(1 << 2)) | (1 << 1)
        self.uc.reg_write(UC_X86_REG_CR0, cr0)
        # CR4: OSFXSR (bit9) | OSXMMEXCPT (bit10) | OSXSAVE (bit18)
        cr4 = self.uc.reg_read(UC_X86_REG_CR4)
        cr4 |= (1 << 9) | (1 << 10) | (1 << 18)
        self.uc.reg_write(UC_X86_REG_CR4, cr4)
        # XCR0: x87(0) | SSE(1) | AVX(2).  Written via MSR index 0 if exposed.
        try:
            from unicorn.x86_const import UC_X86_REG_XCR0
            self.uc.reg_write(UC_X86_REG_XCR0, 0x7)
        except Exception:
            # No XCR0 register in this binding; Haswell model + CR4 is usually
            # enough for TCG to accept AVX. If a runtime #UD still occurs we
            # report it from the fault hook.
            pass

    # ---- logging --------------------------------------------------------
    def log(self, *a):
        if self.verbose:
            print(*a)

    def stop(self, reason):
        self._stop_reason = reason
        self.uc.emu_stop()

    # ---- guest memory management (used by mmap/munmap) ------------------
    def _is_mapped(self, start, size):
        for s, sz in self._mapped:
            if start < s + sz and s < start + size:
                return True
        return False

    def map_anon(self, size, addr_hint=0, prot=None, align=0):
        """Map `size` bytes of anonymous RWX memory, honouring addr_hint when
        it is free and page-aligned, otherwise bump-allocating. `align` (a power of two)
        forces the address to that alignment (an unaligned hint is ignored). Returns the
        guest address, or 0xFFFFFFFFFFFFFFFF (MAP_FAILED) on failure."""
        from unicorn import UC_PROT_ALL
        if prot is None:
            prot = UC_PROT_ALL
        size = _align_up(size)
        if size == 0:
            return 0xFFFFFFFFFFFFFFFF

        addr = 0
        if addr_hint:
            h = _align_down(addr_hint)
            if not self._is_mapped(h, size) and not (align and h % align):
                addr = h
        if addr == 0:
            # Natural alignment: allocators (notably Mono SGen's lock-free
            # allocator, which masks any address with ~(block_size-1) to find
            # the superblock header) assume a power-of-2-sized anonymous mapping
            # comes back aligned to its size - the usual OS behaviour. Our bump
            # allocator only 4K-aligns, so honour size alignment for power-of-2
            # requests (capped so a huge request can't waste the whole region).
            req_align = align
            align = PAGE4K
            if size and (size & (size - 1)) == 0 and size <= 0x0100_0000:
                align = size
            align = max(align, req_align)
            a = (self._mmap_next + align - 1) & ~(align - 1)
            while self._is_mapped(a, size):
                a += align
            if a + size > MMAP_END:
                return 0xFFFFFFFFFFFFFFFF
            addr = a
            self._mmap_next = a + size
        try:
            self.vm.map(addr, size, prot)
        except Exception as e:
            self.log(f"  [mmap] mem_map failed: {e}")
            return 0xFFFFFFFFFFFFFFFF
        self._mapped.append((addr, size))
        return addr

    def map_fixed(self, addr, size, prot=None):
        """MAP_FIXED: anonymous zero pages exactly at [addr, addr+size),
        replacing whatever was mapped there (libthr's stack guard pages are
        placed over the bottom of the stack mapping this way)."""
        from unicorn import UC_PROT_ALL
        if prot is None:
            prot = UC_PROT_ALL
        addr, size = _align_down(addr), _align_up(size)
        page = 0x1000
        # Split the range into runs of already-mapped / unmapped pages and
        # handle each run with one call: thousands of single-page Unicorn
        # regions make every guest memory access slow.
        runs = []
        for a in range(addr, addr + size, page):
            m = self._is_mapped(a, page)
            if runs and runs[-1][2] == m and runs[-1][0] + runs[-1][1] == a:
                runs[-1][1] += page
            else:
                runs.append([a, page, m])
        try:
            for a, n, mapped in runs:
                if mapped:
                    self.uc.mem_write(a, b"\x00" * n)
                    self.uc.mem_protect(a, n, prot)
                else:
                    self.vm.map(a, n, prot)
                    self._mapped.append((a, n))
        except Exception as e:
            self.log(f"  [mmap] MAP_FIXED {addr:#x}+{size:#x} failed: {e}")
            return 0xFFFFFFFFFFFFFFFF
        return addr

    def unmap_anon(self, addr, size):
        size = _align_up(size)
        try:
            self.vm.unmap(_align_down(addr), size)
        except Exception:
            return -1
        self._mapped = [(s, sz) for (s, sz) in self._mapped
                        if not (s == _align_down(addr))]
        return 0

    # ---- setup ----------------------------------------------------------
    def _map_stack_and_tls(self):
        import struct
        stack_base = STACK_TOP - STACK_SIZE
        self.vm.map(stack_base, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        rsp = STACK_TOP - 0x1000
        self.uc.reg_write(UC_X86_REG_RSP, rsp)

        # --- FreeBSD/amd64 TLS is Variant II -----------------------------
        # Layout in one mapping:
        #   [ .tdata/.tbss static block ][ TCB ][ struct pthread (curthread) ]
        # %fs points at the TCB. Static TLS variables live just BELOW %fs
        # (negative offsets). The TCB's self-pointer is at %fs:0 and the
        # current-thread pointer (curthread) is at %fs:0x10.
        self.vm.map(TLS_BASE, TLS_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        tdata_size = 0
        tcb_addr = TLS_BASE + 0x8000              # %fs base
        if getattr(self, "dyn", None):
            # one static block per module with PT_TLS, variant II offsets
            tdata_size = self.dyn.tls_static_size
            for lm in self.dyn.modules:
                if lm.tls_index:
                    t, e = lm.tls, lm.mod.elf
                    self.uc.mem_write(tcb_addr - lm.tls_offset,
                                      e.data[t.offset:t.offset + t.filesz])
        elif self.elf.tls:
            tdata_size = align_up(self.elf.tls.memsz, 64)
            t = self.elf.tls
            init = self.elf.data[t.offset:t.offset + t.filesz]
            self.uc.mem_write(tcb_addr - tdata_size, init)   # below %fs
        self.tcb_addr = tcb_addr

        # curthread: a minimal libthr `struct pthread`
        curthread = TLS_BASE + 0x9000
        self.curthread = curthread
        self.uc.mem_write(curthread, b"\x00" * 0x800)
        # owner id / lock word used as the mutex owner tid
        self.uc.mem_write(curthread + CT_TID, struct.pack("<I", DEFAULT_TID))
        # two owned-mutex TAILQs, initialised empty (tqh_last = &tqh_first)
        for head in (CT_MQ1, CT_MQ2):
            self.uc.mem_write(curthread + head, struct.pack("<Q", 0))
            self.uc.mem_write(curthread + head + 8,
                              struct.pack("<Q", curthread + head))

        # TCB fields
        self.uc.mem_write(tcb_addr + 0x00, struct.pack("<Q", tcb_addr))      # self
        self.uc.mem_write(tcb_addr + 0x10, struct.pack("<Q", curthread))     # curthread
        self.uc.reg_write(UC_X86_REG_FS_BASE, tcb_addr)

        self.log(f"  stack 0x{stack_base:012x}-0x{STACK_TOP:012x}, rsp=0x{rsp:x}")
        self.log(f"  tcb   0x{tcb_addr:012x} (fs_base), tdata 0x{tdata_size:x}")
        self.log(f"  curthread 0x{curthread:012x} (tid={DEFAULT_TID:#x})")
        return rsp

    def _setup_initial_stack(self, rsp):
        """Minimal SysV/FreeBSD process stack: argc, argv[0]=NULL-ish, envp,
        and an empty aux vector. Enough that a C runtime entry doesn't read
        off unmapped memory immediately."""
        # Build: [argc][argv0][0][envp0=0][auxv: AT_NULL(0),0]
        import struct
        blob = struct.pack("<QQQQQ Q",
                           1,            # argc
                           0,            # argv[0] (null for now)
                           0,            # argv terminator
                           0,            # envp terminator
                           0, 0)         # AT_NULL aux entry
        rsp = (rsp - len(blob)) & ~0xF
        self.uc.mem_write(rsp, blob)
        self.uc.reg_write(UC_X86_REG_RSP, rsp)
        # FreeBSD entry also gets a pointer to the stack base in rdi sometimes;
        # many crt0 variants read argc off the stack, so leave rdi = rsp.
        self.uc.reg_write(UC_X86_REG_RDI, rsp)
        return rsp

    # ---- diagnostics ----------------------------------------------------
    def dump_state(self):
        from unicorn.x86_const import (
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
            UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
            UC_X86_REG_RIP,
        )
        regs = [
            ("rax", UC_X86_REG_RAX), ("rbx", UC_X86_REG_RBX),
            ("rcx", UC_X86_REG_RCX), ("rdx", UC_X86_REG_RDX),
            ("rsi", UC_X86_REG_RSI), ("rdi", UC_X86_REG_RDI),
            ("rbp", UC_X86_REG_RBP), ("rsp", UC_X86_REG_RSP),
            ("r8", UC_X86_REG_R8), ("r9", UC_X86_REG_R9),
            ("r10", UC_X86_REG_R10), ("r11", UC_X86_REG_R11),
            ("r12", UC_X86_REG_R12), ("r13", UC_X86_REG_R13),
            ("r14", UC_X86_REG_R14), ("r15", UC_X86_REG_R15),
            ("rip", UC_X86_REG_RIP),
        ]
        self.log("  --- register state ---")
        line = []
        for i, (name, rid) in enumerate(regs):
            line.append(f"{name:>3}=0x{self.uc.reg_read(rid):016x}")
            if len(line) == 3:
                self.log("   " + "  ".join(line)); line = []
        if line:
            self.log("   " + "  ".join(line))
        hist = "  ".join(f"0x{a:x}" for a in self._recent_rips()[-12:])
        self.log(f"  recent rips: {hist}")
        # crude backtrace: scan the stack for values in the code range
        from unicorn.x86_const import UC_X86_REG_RSP
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        lo, hi = 0x400000, 0x481000
        found = []
        try:
            raw = bytes(self.uc.mem_read(rsp, 0x400))
            import struct
            for i in range(0, len(raw) - 8, 8):
                v = struct.unpack_from("<Q", raw, i)[0]
                if lo <= v < hi:
                    found.append(v)
        except Exception:
            pass
        self.log("  stack code-ptrs (return addrs): " +
                 "  ".join(f"0x{a:x}" for a in found[:12]))

    # ---- instruction clock -----------------------------------------------
    @property
    def _insn_count(self):
        if self.whp:
            # no instruction counter on hardware: virtual time follows the wall clock, expressed
            # in "instructions" at the scheduler's NS_PER_INSN so now_ns() stays one formula
            return int((self._time() - self._t0 - self._excl) * 1e9)
        n = self.native
        return n.s.count if n is not None else self._insn_py

    @_insn_count.setter
    def _insn_count(self, v):
        if self.whp:
            return
        if self.native is not None:
            self.native.s.count = v
        else:
            self._insn_py = v

    @property
    def _last_rip(self):
        n = self.native
        return n.s.last if n is not None else self._last_py

    @_last_rip.setter
    def _last_rip(self, v):
        if self.native is not None:
            self.native.s.last = v
        else:
            self._last_py = v

    def _recent_rips(self):
        if self.native is not None:
            return self.native.recent()
        return list(self._rip_history)

    # ---- hooks ----------------------------------------------------------
    def _hook_syscall(self, uc, user_data):
        self.syscalls.dispatch(uc)

    def _classify_vex(self, uc, address):
        """Decide once per code address whether the shim must run it."""
        from .avx_ops import needs_emulation
        res = None
        try:
            code = bytes(uc.mem_read(address, 15))
            if code[0] in (0xC4, 0xC5) or (code[0] in (0x66, 0xF2, 0xF3) and
                                           code[1] in (0xC4, 0xC5)):
                insn = next(self.avx.md.disasm(code, address, 1), None)
                if insn is not None and needs_emulation(insn, code):
                    res = insn
        except Exception:
            res = None
        self._vex_cache[address] = res
        return res

    def _hook_code(self, uc, address, size, user_data):
        # Threads: preempt at the end of the time slice (only when there is
        # someone else to run); the instruction at `address` runs on resume.
        sched = self.sched
        if sched is not None and len(sched.order) > 1 and sched.tick(uc, address):
            return
        # HLE: if this address is a hooked function entry, run the Python
        # implementation, return to the caller, and restart emulation there.
        if self.hle.has(address):
            redirect = self.hle.invoke(uc, address)
            if redirect:            # 'replace' hook: jump back to caller
                self._hle_pending = True
                uc.emu_stop()
                return
            # 'fixup' hook: fall through and run the real instruction
        # VEX three-operand SSE/AVX: QEMU runs these as legacy two-operand
        # forms (wrong when dst != src1), so execute them in the shim instead.
        vex = self._vex_cache.get(address, 0)
        if vex == 0:
            vex = self._classify_vex(uc, address)
        if vex is not None:
            self._last_rip = address
            self._insn_count += 1
            if not self.avx.emulate_vex(vex):
                return
            uc.reg_write(UC_X86_REG_RIP, address + vex.size)
            self._hle_pending = True
            uc.emu_stop()
            return
        self._last_rip = address
        self._rip_history.append(address)
        self._insn_count += 1
        if self.trace:
            try:
                code = uc.mem_read(address, size)
                self.log(f"    {address:#012x}: " + " ".join(f"{b:02x}" for b in code))
            except Exception:
                pass
        if self._insn_count >= self.max_insns:
            self.stop(f"instruction limit reached ({self.max_insns})")

    # ---- WHP backend callbacks (whp_uc.WhpUc) --------------------------------------------
    def _whp_hle(self, uc, addr):
        """An HLE int3 trap fired at `addr`; True when a 'replace' hook already returned to the
        caller, False when the real instruction must run (fixup / guard-None)."""
        return bool(self.hle.has(addr) and self.hle.invoke(uc, addr))

    def _whp_preempt(self, uc, rip):
        """End of a wall-clock time slice: True when another thread is runnable and a switch is
        now pending (the vCPU is stopped before `rip`)."""
        sched = self.sched
        if sched is None or len(sched.order) < 2:
            return False
        return sched.slice_expired(uc, rip)

    def _whp_tick(self):
        if self.max_seconds is not None and self._time() - self._t0 >= self.max_seconds:
            self.stop(f"wall-clock budget reached ({self.max_seconds:g} s)")
        if self.then_path is not None:
            self._check_then()

    def _check_then(self):
        """Core-initialized -> app handoff. SceSysCore is "initialized" once its SceSysCoreApp2 IPMI
        server exists (the last service its boot registers) and has had `then_settle` seconds to
        finish. Then the process image is replaced the way execve() does it -- fresh address
        space, the kernel-side state (fds, event flags, named objects) inherited -- by the app,
        which starts in libkernel acting as the interpreter."""
        servers = getattr(self.syscalls, "_ipmi_servers", {})
        if "SceSysCoreApp2" not in servers:
            return
        now = self._time()
        if self._then_seen is None:
            self._then_seen = now
            return
        if now - self._then_seen < self.then_settle:
            return
        path, self.then_path = self.then_path, None
        self.log(f"\n== core initialized after {now - self._t0:.1f} s "
                 f"({len(servers)} IPMI services up) -> linking into {path} ==")
        servers.clear()                     # the old process's services die with it
        self.app_root = os.path.dirname(os.path.abspath(path))
        self.exec_module(path, [path])

    def _native_stop(self):
        """The native hook stopped the CPU before the instruction at
        stop_addr: do the Python-side work and return where to resume (RIP is
        also written, so a thread switch saves the right context)."""
        from .cpu_native import R_LIMIT, R_PAGE, R_TRAP
        native, uc = self.native, self.uc
        s = native.s
        why, addr = s.reason, s.stop_addr
        s.reason = 0
        nxt = addr
        if why == R_LIMIT:
            if s.count >= self.max_insns:
                self.stop(f"instruction limit reached ({self.max_insns})")
            else:
                self.sched.slice_expired(uc, addr)
        elif why == R_PAGE:
            native.scan_page(uc, addr)
        elif why == R_TRAP:
            if self.hle.has(addr):
                if self.hle.invoke(uc, addr):          # 'replace': returned to caller
                    return uc.reg_read(UC_X86_REG_RIP)
                s.skip = addr                          # 'fixup': now run the real code
            else:
                vex = self._vex_cache.get(addr, 0)
                if vex == 0:
                    vex = self._classify_vex(uc, addr)
                if vex is None:                        # QEMU runs it correctly
                    native.trap_remove(addr)
                    native.vex_traps.discard(addr)
                elif self.avx.emulate_vex(vex):
                    s.count += 1
                    nxt = addr + vex.size
                else:
                    s.skip = addr
        uc.reg_write(UC_X86_REG_RIP, nxt)
        return nxt

    def _hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)
        kind = {16: "READ", 17: "WRITE", 18: "FETCH"}.get(access, str(access))
        # The guest installed a SIGSEGV handler (Mono turns null dereferences into
        # NullReferenceException this way): let _run_segment deliver the signal
        # instead of ending the run.
        if self.syscalls.can_deliver(self.syscalls.SIGSEGV):
            self._pending_fault = (address, access == 17)
            return False
        self.log(f"  [unmapped {kind}] addr=0x{address:x} size={size} "
                 f"at rip=0x{rip:x}")
        self.dump_state()
        # Returning False tells Unicorn we did NOT fix the fault -> it stops.
        self.stop(f"unmapped {kind} at 0x{address:x} (rip 0x{rip:x})")
        return False

    def _hook_write_prot(self, uc, access, address, size, value, user_data):
        # The module writes through pointers into pages we mapped read-only
        # (e.g. an internal table the runtime fixes up in place). For a
        # permissive scaffold we grant write access to that page and retry.
        page = _align_down(address)
        try:
            uc.mem_protect(page, PAGE4K, UC_PROT_ALL)
        except Exception as e:
            self.log(f"  [write-prot] could not relax 0x{page:x}: {e}")
            self.stop(f"write-protected 0x{address:x} (rip 0x{self._last_rip:x})")
            return False
        if page not in self._relaxed:
            self._relaxed.add(page)
            self.log(f"  [write-prot] granted write to page 0x{page:x} "
                     f"(write at 0x{address:x}, rip 0x{self._last_rip:x})")
        return True

    def _hook_intr(self, uc, intno, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)
        # On ORBIS some gates use `int`; but 0x44 in these modules fronts an
        # abort/panic stub (followed by ud2). Report the error code the stub
        # loads and stop cleanly instead of letting the CPU fault.
        self.log(f"  [int 0x{intno:x}] at rip=0x{rip:x} -> guest trap/abort")
        self.dump_state()
        self.stop(f"guest executed int 0x{intno:x} (abort stub) at 0x{rip:x}")

    def _install_hooks(self):
        self.uc.hook_add(UC_HOOK_INSN, self._hook_syscall,
                         begin=1, end=0, aux1=UC_X86_INS_SYSCALL)
        if self.whp:
            self.uc.hle_cb = self._whp_hle
            self.uc.preempt_cb = self._whp_preempt
            self.uc.tick_cb = self._whp_tick
            for a in self.hle.table:
                self.uc.hle_add(a)
        elif self.native is not None:
            self.native.attach(self.uc, self.hle.table.keys())
        else:
            self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_mem_unmapped)
        self.uc.hook_add(UC_HOOK_INSN_INVALID, self.avx.on_invalid)
        self.uc.hook_add(UC_HOOK_INTR, self._hook_intr)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_PROT, self._hook_write_prot)

    # ---- per-module libthr hook detection ------------------------------
    def _detect_libthr_hooks(self):
        """Find this module's libthr fatal-error reporter and its mutex
        lock-family function entries by scanning the code, so the HLE hooks
        work on any libkernel module, not just mini-syscore.

        Returns (fatal_addr_or_None, [lock_entry_addrs])."""
        import capstone
        import capstone.x86 as cx
        from capstone.x86 import X86_OP_MEM

        elf = getattr(self, "_scan_elf", None) or self.elf
        sbase = getattr(self, "_scan_base", 0)
        seg = next((s for s in elf.loadable() if s.flags & 1), None)
        if seg is None:
            return None, []
        base = seg.vaddr + sbase
        code = elf.data[seg.offset:seg.offset + seg.filesz]

        # string VAs for the panic message
        msg_vas = set()
        for s in (b"mutex is on list", b"static_thr_mutex.c"):
            start = 0
            while True:
                idx = elf.data.find(s, start)
                if idx < 0:
                    break
                va = self._file_off_to_va(idx)
                if va is not None:
                    msg_vas.add(va)
                start = idx + 1

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        insns = list(md.disasm(code, base))

        func_starts = []
        prev_term = True
        for i in insns:
            if prev_term and i.mnemonic == "push" and i.op_str == "rbp":
                func_starts.append(i.address)
            prev_term = i.mnemonic in ("ret", "ud2", "int3")
        import bisect

        def owner_func(addr):
            j = bisect.bisect_right(func_starts, addr) - 1
            return func_starts[j] if j >= 0 else None

        fatal_targets = {}
        lock_entries = set()
        for idx, i in enumerate(insns):
            for op in i.operands:
                if op.type == X86_OP_MEM and op.mem.base == cx.X86_REG_RIP:
                    tgt = i.address + i.size + op.mem.disp
                    if i.mnemonic == "lea" and tgt in msg_vas:
                        # the fatal reporter is called a few insns later
                        for k in range(idx, min(idx + 8, len(insns))):
                            if insns[k].mnemonic == "call":
                                ct = insns[k].operands[0]
                                if ct.type == cx.X86_OP_IMM:
                                    fatal_targets[ct.imm] = fatal_targets.get(ct.imm, 0) + 1
                                break
                # a function that touches curthread's owned-mutex TAILQ
                if op.type == X86_OP_MEM and op.mem.base == cx.X86_REG_R14 \
                        and op.mem.disp in (CT_MQ1, CT_MQ1 + 8, CT_MQ2, CT_MQ2 + 8):
                    f = owner_func(i.address)
                    if f is not None:
                        lock_entries.add(f)

        fatal = max(fatal_targets, key=fatal_targets.get) if fatal_targets else None
        return fatal, sorted(lock_entries)

    def _file_off_to_va(self, off):
        elf = getattr(self, "_scan_elf", None) or self.elf
        sbase = getattr(self, "_scan_base", 0)
        for s in elf.loadable():
            if s.offset <= off < s.offset + s.filesz:
                return sbase + s.vaddr + (off - s.offset)
        return None

    # ---- run ------------------------------------------------------------
    def _register_default_hle(self):
        """Auto-detect and register this module's libthr HLE hooks: the
        fatal-error reporter (clean diagnostics) and the mutex lock-family
        entries (owned-list fixup). Works on any libkernel module."""
        import struct

        def pthread_fatal(emu, uc):
            # void _thread_printf_panic(const char *file, int line, const char *msg)
            file_ptr, line, msg_ptr = self.hle.args(uc)[:3]
            msg = emu.syscalls._read_cstr(uc, msg_ptr, 96)
            fname = emu.syscalls._read_cstr(uc, file_ptr, 96)
            emu.log(f"  [pthread fatal] '{msg}'  ({fname}:{line})")
            emu.stop(f"ScePthread fatal: '{msg}' at {fname}:{line}")
            return 0

        MUTEX_WARMUP = 100_000

        def mutex_lock_fixup(emu, uc):
            # The owned-mutex TAILQ is only used for robust/PI mutexes, whose
            # unlock dequeues via _umtx_op in the kernel -- which we stub, so a
            # freed mutex can be left with a stale link (+0x40/+0x48), tripping
            # the 'mutex is on list' panic. Single-threaded we never need that
            # list: at lock entry clear the incoming mutex's link and reset
            # curthread's TAILQs, then let the real lock code run.
            #
            # This hook fires on EVERY mutex lock -- tens of thousands of times
            # in managed (Mono) code, each a native->Python round trip, which
            # profiling shows is the single biggest emulation cost. So it tracks
            # whether it ever has real work to do (a stale incoming link, or a
            # non-empty owned-mutex list), and once a process has locked
            # MUTEX_WARMUP times with none, it DISARMS itself (removes the trap):
            # that process uses no robust/PI mutexes, so the fixup is pure
            # overhead. If that guess is ever wrong, a later robust mutex trips
            # the pthread_fatal hook -- a clean stop, never silent corruption.
            # Count every lock and, once a process has locked MUTEX_WARMUP
            # times without the fixup ever doing real work, disarm. Most calls
            # early-return below (a libthr-managed thread, left alone), so the
            # counter lives here at the top, before any return.
            self._mutex_calls += 1
            if (not self._mutex_needed and (self.native is not None or self.whp)
                    and self._mutex_calls >= MUTEX_WARMUP):
                for ent in self._mutex_lock_entries:
                    try:
                        if self.whp:
                            uc.hle_remove(ent)
                        else:
                            self.native.trap_remove(ent)
                        self.hle.table.pop(ent, None)
                    except Exception:
                        pass
                self._mutex_lock_entries = []
                emu.log(f"  [perf] mutex_lock_fixup disarmed after "
                        f"{self._mutex_calls} locks (no robust/PI mutexes seen)")
                return None
            m = uc.reg_read(UC_X86_REG_RDI)
            try:
                # the live curthread (libthr installs its own TCB via sysarch)
                fsb0 = uc.reg_read(UC_X86_REG_FS_BASE)
                live = struct.unpack("<Q", bytes(uc.mem_read(fsb0 + 0x10, 8)))[0]
                if live and live != self.curthread:
                    # libthr runs on its own, fully initialised struct pthread:
                    # its owned-mutex lists are consistent, leave them alone
                    return None
                internal = struct.unpack("<Q", bytes(uc.mem_read(m, 8)))[0]
                if internal > 2:
                    tqe = struct.unpack("<Q", bytes(uc.mem_read(internal + 0x48, 8)))[0]
                    tqn = struct.unpack("<Q", bytes(uc.mem_read(internal + 0x40, 8)))[0]
                    if tqe or tqn:
                        uc.mem_write(internal + 0x40, b"\x00" * 16)
                        self._mutex_fixups += 1
                        self._mutex_needed = True
                ct = struct.unpack("<Q", bytes(uc.mem_read(fsb0 + 0x10, 8)))[0] or self.curthread
                if ct != self.curthread:
                    # libthr runs on its own, fully initialised struct pthread:
                    # its owned-mutex lists are consistent, leave them alone
                    return None
                # An empty TAILQ head is {first=0, last=&first}. Reset only a
                # head that is NOT already empty -- and remember that we did, so
                # a process that genuinely uses the list keeps the hook armed.
                for head in (CT_MQ1, CT_MQ2):
                    first = struct.unpack("<Q", bytes(uc.mem_read(ct + head, 8)))[0]
                    last = struct.unpack("<Q", bytes(uc.mem_read(ct + head + 8, 8)))[0]
                    if first != 0 or last != ct + head:
                        self._mutex_needed = True
                        uc.mem_write(ct + head, struct.pack("<Q", 0))
                        uc.mem_write(ct + head + 8, struct.pack("<Q", ct + head))
            except Exception:
                pass
            return None

        self._mutex_fixups = 0
        self._mutex_calls = 0
        self._mutex_needed = False
        self._mutex_lock_entries = []
        fatal, lock_entries = self._detect_libthr_hooks()
        if getattr(self, "dyn", None) is not None:
            # dynamic process: the lock functions are exported by name from
            # libkernel, so hook their real entries instead of scanned guesses
            from .sys_dynlib import nid
            exports = self.dyn.libkernel.mod.exports
            names = ("pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_timedlock",
                     "scePthreadMutexLock", "scePthreadMutexTrylock",
                     "scePthreadMutexTimedlock", "_pthread_mutex_lock",
                     "__pthread_mutex_lock", "_pthread_mutex_trylock",
                     "__pthread_mutex_trylock")
            lock_entries = sorted({exports[nid(n)] for n in names if nid(n) in exports})
        if fatal is not None:
            self.hle.register(fatal, pthread_fatal, name="pthread_fatal")
        self._mutex_lock_entries = list(lock_entries)
        for ent in lock_entries:
            self.hle.register(ent, mutex_lock_fixup,
                              name="mutex_lock_fixup", mode="fixup")
        self.log(f"  libthr hooks: fatal={'0x%x' % fatal if fatal else '?'}, "
                 f"mutex-lock entries={[hex(a) for a in lock_entries]}")

    def load(self):
        # image is built in __init__/_build_image; kept for API compatibility
        pass

    def exec_module(self, path, argv=None):
        """Requested by execve(): resolve `path` to a firmware file and queue a
        chain-load. The actual image rebuild happens in the run loop, after the
        current emu_start unwinds."""
        resolved = self.resolve_path(path)
        if resolved is None:
            self.log(f"  [execve] '{path}' not found under {self.fw_root}")
            self.stop(f"execve('{path}'): module not found")
            return False
        self._exec_next = (resolved, argv or [path])
        self.uc.emu_stop()
        return True

    def app0_file(self, guest_path):
        """'/app0/<rest>' -> the file inside the launched application's own
        directory, if it exists there (else None). Without this a basename
        search could pick another app's file of the same name (every PSM app
        has a psm/Application/app.exe.sprx)."""
        name = guest_path.replace("\\", "/").lstrip("/")
        if not name.startswith("app0/"):
            return None
        cand = os.path.join(getattr(self, "app_root", self.fw_root),
                            *name[len("app0/"):].split("/"))
        return cand if os.path.isfile(cand) else None

    def resolve_path(self, guest_path):
        """Map a guest path like '/SceSysAvControl.elf' to a real file under
        the firmware root (searching the tree for the basename)."""
        name = guest_path.replace("\\", "/").lstrip("/")
        cand = self.app0_file(name)
        if cand:
            return cand
        cand = os.path.join(self.fw_root, name)
        if os.path.isfile(cand):
            return cand
        base = os.path.basename(name)
        # basename index of the firmware tree, built once (first hit in walk order
        # wins, as before); falls back to a case-insensitive match because the
        # console's /system/common/font etc. are looked up without regard to case
        # (the dump has DFHEI5-SONY.ttf, PSM opens DFHEI5-SONY.TTF).
        idx = getattr(self, "_basename_index", None)
        if idx is None:
            idx, low = {}, {}
            for root, _dirs, files in os.walk(self.fw_root):
                for f in files:
                    p = os.path.join(root, f)
                    idx.setdefault(f, p)
                    low.setdefault(f.lower(), p)
            self._basename_index = idx
            self._basename_index_ci = low
        return idx.get(base) or self._basename_index_ci.get(base.lower())

    def run(self, start=None):
        """Single-process driver: start, step to completion, summarise. A
        ProcessManager interleaves several processes by calling begin_run once
        per process and then round-robining _run_segment (see MULTIPROCESS.md)."""
        if self._dynamic_block:
            self.log(f"\n== stopped: {self._stop_reason} ==")
            return self._stop_reason
        cur = self.begin_run(start)
        while cur is not None:
            cur = self._run_segment(cur)
        return self.end_run()

    def begin_run(self, start=None):
        """Prologue of a run: set up the thread scheduler and return the RIP to
        start stepping from, or None if there is nothing to run. Split out from
        run() so a ProcessManager can start several processes and then
        round-robin their _run_segment (see MULTIPROCESS.md)."""
        if self._dynamic_block:
            return None
        if start is None:
            start = self.entry_point
        self.log(f"\n== running module #{self.module_index} from 0x{start:x} "
                 f"(max {self.max_insns} insns) ==")
        from .threads import Scheduler
        self.sched = Scheduler(self)
        self.sched.adopt_main(DEFAULT_TID)
        return start

    def end_run(self):
        """Epilogue of a run: print the summaries and return the stop reason."""
        self.log(f"\n== stopped: {self._stop_reason or 'clean exit'} ==")
        self.log(f"   ran {self.module_index + 1} module(s), "
                 f"{self._insn_count} instructions total, "
                 f"last rip 0x{self._last_rip:x}")
        self.log("\n" + self.syscalls.summary())
        self.log(self.avx.summary())
        if self.native is not None:
            self.log(self.native.vex_summary())
        self.log(self.hle.summary())
        if self.whp:
            self.log(f"WHP: {self._time() - self._t0:.1f} s wall ({self.uc.t_run:.1f} s in the guest), "
                     f"{self.uc.n_syscalls} syscalls, "
                     f"VM exits {self.uc.exits}")
        self.log(self.sched.summary())
        return self._stop_reason

    def try_resume(self):
        """Retry a switch for a process that went idle waiting on another one: the RIP to run
        next, IDLE if still nothing is runnable, None when it has finished."""
        nxt = self.sched.switch()
        if nxt is not None:
            return nxt
        if all(t.state == "exited" for t in self.sched.threads.values()):
            self._stop_reason = "all threads exited"
            return None
        return IDLE

    def _run_segment(self, cur):
        """One scheduling segment: run the CPU from `cur` until the native/HLE
        hook, a thread switch, an execve, or a stop interrupts it, then do the
        corresponding bookkeeping. Returns the RIP to resume at next, or None
        when this process is finished (a stop reason has been set). Extracted
        from run()'s loop body unchanged so the behaviour is identical; it is
        the per-process step a multi-process ProcessManager drives (see
        MULTIPROCESS.md)."""
        from .threads import Scheduler
        native = self.native
        self._hle_pending = False
        if native is not None:
            ns = native.s
            ns.reason = 0
            before = ns.count
            # stop for the budget or the end of this thread's time slice
            ns.limit = min(self.max_insns, before + max(self.sched.slice_left, 1))
        try:
            self.uc.emu_start(cur, 0)
        except UcError as e:
            rip = self.uc.reg_read(UC_X86_REG_RIP)
            fault, self._pending_fault = self._pending_fault, None
            if fault is not None and self._stop_reason is None:
                handler = self.syscalls.deliver_signal(self.uc, self.syscalls.SIGSEGV,
                                                       fault[0], fault[1])
                if handler is not None:
                    return handler                  # run the guest's SIGSEGV handler
                self._stop_reason = (f"unmapped access at 0x{fault[0]:x} (rip 0x{rip:x}); "
                                     f"SIGSEGV handler could not run")
                return None
            if self._stop_reason is None:
                self._stop_reason = f"UcError: {e} at rip=0x{rip:x}"
            return None
        if native is not None:
            self.sched.slice_left -= ns.count - before
            if ns.reason:
                if (self._stop_reason is None and not self.sched.switch_pending
                        and not self._exec_next):
                    cur = self._native_stop()
                    if (self._stop_reason is None and not self.sched.switch_pending
                            and not self._exec_next):
                        return cur
                else:
                    ns.reason = 0
        if self.sched.switch_pending and self._stop_reason is None and not self._exec_next:
            nxt = self.sched.switch()
            if nxt is None:
                ts = self.sched.threads.values()
                mgr = getattr(self, "manager", None)
                if (mgr is not None and mgr.others_alive(self)
                        and not all(t.state == "exited" for t in ts)):
                    return IDLE          # waiting for another process to wake a thread
                if all(t.state == "exited" for t in ts):
                    self._stop_reason = "all threads exited"
                elif any(isinstance(t.wait, dict) and t.wait.get("kind") == "kevent"
                         for t in ts):
                    # every thread sleeps; at least one waits for events
                    # that nothing in the emulated system will produce
                    self._stop_reason = ("module booted; idle in event loop (no events "
                                         "to deliver) - " + self.sched.describe())
                else:
                    self._stop_reason = "deadlock: " + self.sched.describe()
                return None
            return nxt
        if self._exec_next and self._stop_reason is None:
            path, argv = self._exec_next
            self._exec_next = None
            if self.module_index + 1 >= self.max_modules:
                self._stop_reason = (f"reached max-modules={self.max_modules} "
                                     f"(next was {os.path.basename(path)})")
                return None
            self.module_index += 1
            self._build_image(path)   # fresh address space; fds inherited
            self.sched = Scheduler(self)          # a new process: one thread
            self.sched.adopt_main(DEFAULT_TID)
            if self._dynamic_block:   # next stage is dynamically linked
                return None
            return self.entry_point
        if self._hle_pending and self._stop_reason is None:
            return self.uc.reg_read(UC_X86_REG_RIP)
        return None
