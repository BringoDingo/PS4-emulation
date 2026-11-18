"""Windows Hypervisor Platform (WHP) binding + validation self-test.

This is the foundation of a hardware-virtualized CPU backend for psemu: run the PS4 guest's
x86-64 code directly on the host CPU inside a WHP partition, and take VM exits back to Python
for syscalls, HLE hooks and faults (see docs/whp-backend-plan.md). Profiling showed the guest
program itself is only ~7% of emulation time under Unicorn; the rest is the per-instruction
hook, the translator and AVX emulation, all of which this backend removes.

Requires the Windows Hypervisor Platform feature and firmware virtualization (SVM/VT-x) enabled.

    python -m psemu.whp          # self-test: hello-guest (real mode) + long-mode + I/O-exit

Register-name and error-code constants verified by probing on an AMD Ryzen (2026-11): the
control registers live at 0x1C-0x20 (after the table registers), not 0x40; EFER is 0x2001;
partition property ProcessorCount is 0x1FFF.
"""
import ctypes
import struct
from ctypes import wintypes

_whp = None


def dll():
    global _whp
    if _whp is None:
        _whp = ctypes.WinDLL("WinHvPlatform.dll")
        _set_argtypes(_whp)
    return _whp


# ---- register names (WHV_REGISTER_NAME) ---------------------------------
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(0x00, 0x08)
R8, R9, R10, R11, R12, R13, R14, R15 = range(0x08, 0x10)
RIP, RFLAGS = 0x10, 0x11
ES, CS, SS, DS, FS, GS, LDTR, TR = range(0x12, 0x1A)
IDTR, GDTR = 0x1A, 0x1B
CR0, CR2, CR3, CR4, CR8 = 0x1C, 0x1D, 0x1E, 0x1F, 0x20
# MSR register group
TSC = 0x2000
EFER = 0x2001
KERNEL_GS_BASE = 0x2002
STAR, LSTAR, CSTAR, SFMASK = 0x2008, 0x2009, 0x200A, 0x200B
FS_BASE, GS_BASE = 0x2010, 0x2011   # WHvX64RegisterFsBase / GsBase

# ---- exit reasons (WHV_RUN_VP_EXIT_REASON) ------------------------------
EXIT_NONE = 0x0
EXIT_MEMORY = 0x1
EXIT_IO = 0x2
EXIT_UNRECOVERABLE = 0x4
EXIT_INVALID_REGISTER = 0x5
EXIT_UNSUPPORTED = 0x6
EXIT_HALT = 0x8
EXIT_MSR = 0x1000
EXIT_CPUID = 0x1001
EXIT_EXCEPTION = 0x1002
EXIT_CANCELED = 0x2001

# ---- partition property codes (WHV_PARTITION_PROPERTY_CODE) --------------
PROP_EXTENDED_VM_EXITS = 0x1
PROP_EXCEPTION_EXIT_BITMAP = 0x2
PROP_PROCESSOR_COUNT = 0x1FFF

# ---- map flags (WHV_MAP_GPA_RANGE_FLAGS) --------------------------------
MAP_READ, MAP_WRITE, MAP_EXEC = 1, 2, 4
MAP_RWX = MAP_READ | MAP_WRITE | MAP_EXEC

# long-mode segment attribute presets (WHP Attributes layout:
# Type:4 S:1 DPL:2 P:1 _:4 AVL:1 L:1 DB:1 G:1)
ATTR_CODE64 = 0xA09B   # execute/read, present, L=1, G=1
ATTR_DATA = 0xC093     # read/write, present, DB=1, G=1


class WHV_REGISTER_VALUE(ctypes.Union):
    _fields_ = [("Reg128", ctypes.c_ubyte * 16),
                ("Reg64", ctypes.c_uint64),
                ("Reg32", ctypes.c_uint32),
                ("bytes", ctypes.c_ubyte * 16)]


class WHV_X64_SEGMENT_REGISTER(ctypes.Structure):
    _fields_ = [("Base", ctypes.c_uint64),
                ("Limit", ctypes.c_uint32),
                ("Selector", ctypes.c_uint16),
                ("Attributes", ctypes.c_uint16)]


class WhpError(OSError):
    pass


def _chk(hr, what):
    if hr & 0xFFFFFFFF:
        raise WhpError("%s failed (hr=%#010x)" % (what, hr & 0xFFFFFFFF))


def _set_argtypes(h):
    P = ctypes.c_void_p
    h.WHvGetCapability.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
                                   ctypes.POINTER(ctypes.c_uint32)]
    h.WHvCreatePartition.argtypes = [ctypes.POINTER(P)]
    h.WHvSetPartitionProperty.argtypes = [P, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    h.WHvSetupPartition.argtypes = [P]
    h.WHvCreateVirtualProcessor.argtypes = [P, ctypes.c_uint32, ctypes.c_uint32]
    h.WHvMapGpaRange.argtypes = [P, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64,
                                 ctypes.c_uint32]
    h.WHvUnmapGpaRange.argtypes = [P, ctypes.c_uint64, ctypes.c_uint64]
    h.WHvRunVirtualProcessor.argtypes = [P, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
    h.WHvCancelRunVirtualProcessor.argtypes = [P, ctypes.c_uint32, ctypes.c_uint32]
    # pass the arrays by explicit pointer so ctypes keeps them alive for the call
    h.WHvSetVirtualProcessorRegisters.argtypes = [P, ctypes.c_uint32,
                                                  ctypes.POINTER(ctypes.c_int), ctypes.c_uint32,
                                                  ctypes.POINTER(WHV_REGISTER_VALUE)]
    h.WHvGetVirtualProcessorRegisters.argtypes = [P, ctypes.c_uint32,
                                                  ctypes.POINTER(ctypes.c_int), ctypes.c_uint32,
                                                  ctypes.POINTER(WHV_REGISTER_VALUE)]
    h.WHvDeleteVirtualProcessor.argtypes = [P, ctypes.c_uint32]
    h.WHvDeletePartition.argtypes = [P]


def hypervisor_present():
    """True if the Windows Hypervisor Platform is available (feature + firmware virtualization)."""
    try:
        h = dll()
    except OSError:
        return False
    buf = (ctypes.c_uint32 * 1)()
    written = ctypes.c_uint32()
    hr = h.WHvGetCapability(0, buf, 4, ctypes.byref(written))  # WHvCapabilityCodeHypervisorPresent
    return hr == 0 and buf[0] == 1


def seg(base, selector, attributes, limit=0xFFFFFFFF):
    """A WHV_REGISTER_VALUE holding a segment register descriptor."""
    v = WHV_REGISTER_VALUE()
    s = WHV_X64_SEGMENT_REGISTER(base, limit, selector, attributes)
    ctypes.memmove(v.bytes, ctypes.byref(s), 16)
    return v


class Partition:
    """One WHP partition with a single vCPU. Memory is mapped from host buffers the caller owns."""

    def __init__(self, vcpus=1):
        self.h = ctypes.c_void_p()
        d = dll()
        _chk(d.WHvCreatePartition(ctypes.byref(self.h)), "WHvCreatePartition")
        count = ctypes.c_uint32(vcpus)
        _chk(d.WHvSetPartitionProperty(self.h, PROP_PROCESSOR_COUNT, ctypes.byref(count), 4),
             "SetPartitionProperty(ProcessorCount)")
        _chk(d.WHvSetupPartition(self.h), "WHvSetupPartition")
        for i in range(vcpus):
            _chk(d.WHvCreateVirtualProcessor(self.h, i, 0), "WHvCreateVirtualProcessor")
        self.vcpus = vcpus
        self._closed = False

    def map_gpa(self, host_addr, gpa, size, flags=MAP_RWX):
        """Map `size` bytes of host memory at `host_addr` (page-aligned) to guest physical `gpa`."""
        _chk(dll().WHvMapGpaRange(self.h, ctypes.c_void_p(host_addr), ctypes.c_uint64(gpa),
                                  ctypes.c_uint64(size), flags), "WHvMapGpaRange")

    def unmap_gpa(self, gpa, size):
        _chk(dll().WHvUnmapGpaRange(self.h, ctypes.c_uint64(gpa), ctypes.c_uint64(size)),
             "WHvUnmapGpaRange")

    def set_regs(self, pairs, vp=0):
        n = len(pairs)
        cap = max(n, 2)                 # WHP over-reads the arrays by an entry; pad to avoid a fault
        names = (ctypes.c_int * cap)(*[k for k, _ in pairs])
        vals = (WHV_REGISTER_VALUE * cap)()
        for i, (_, v) in enumerate(pairs):
            if isinstance(v, WHV_REGISTER_VALUE):
                vals[i] = v
            else:
                vals[i].Reg64 = v & 0xFFFFFFFFFFFFFFFF
        _chk(dll().WHvSetVirtualProcessorRegisters(self.h, vp, names, n, vals),
             "WHvSetVirtualProcessorRegisters")

    def get_regs(self, names, vp=0):
        n = len(names)
        cap = max(n, 2)
        arr = (ctypes.c_int * cap)(*names)
        vals = (WHV_REGISTER_VALUE * cap)()
        _chk(dll().WHvGetVirtualProcessorRegisters(self.h, vp, arr, n, vals),
             "WHvGetVirtualProcessorRegisters")
        return [vals[i].Reg64 for i in range(n)]

    def run(self, vp=0):
        """Run the vCPU until a VM exit; return the exit reason (EXIT_*)."""
        ctx = (ctypes.c_ubyte * 256)()
        _chk(dll().WHvRunVirtualProcessor(self.h, vp, ctx, 256), "WHvRunVirtualProcessor")
        return struct.unpack_from("<I", bytes(ctx), 0)[0]

    def cancel(self, vp=0):
        _chk(dll().WHvCancelRunVirtualProcessor(self.h, vp, 0), "WHvCancelRunVirtualProcessor")

    def close(self):
        if self._closed:
            return
        self._closed = True
        d = dll()
        for i in range(self.vcpus):
            d.WHvDeleteVirtualProcessor(self.h, i)
        d.WHvDeletePartition(self.h)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# ---- validation self-test ------------------------------------------------
def _alloc(size):
    k32 = ctypes.WinDLL("kernel32")
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    addr = k32.VirtualAlloc(None, size, 0x3000, 0x04)   # MEM_COMMIT|RESERVE, PAGE_READWRITE
    if not addr:
        raise OSError("VirtualAlloc failed")
    return addr


def _selftest():
    if not hypervisor_present():
        print("WHP self-test: hypervisor NOT present (enable firmware virtualization + the "
              "'Windows Hypervisor Platform' feature)")
        return 1

    # 1) hello-guest in real mode: mov ax,0x2a; mov bx,0x1234; hlt
    host = _alloc(0x1000)
    ctypes.memmove(ctypes.c_void_p(host), bytes.fromhex("b82a00bb3412f4"), 7)
    with Partition() as p:
        p.map_gpa(host, 0x1000, 0x1000)
        p.set_regs([(CS, seg(0, 0, 0x9b, 0xFFFF)), (RIP, 0x1000), (RFLAGS, 0x2)])
        r = p.run()
        rax, rbx = p.get_regs([RAX, RBX])
    ok1 = r == EXIT_HALT and (rax & 0xFFFF) == 0x2a and (rbx & 0xFFFF) == 0x1234
    print("  real-mode hello-guest: %s (exit=%#x rax=%#x rbx=%#x)"
          % ("PASS" if ok1 else "FAIL", r, rax & 0xFFFF, rbx & 0xFFFF))

    # 2) long mode + memory write + I/O-port exit (the syscall mechanism) + resume to HLT
    SIZE = 0x200000
    host = _alloc(SIZE)
    mem = (ctypes.c_ubyte * SIZE).from_address(host)

    def wrq(off, v):
        ctypes.memmove(host + off, struct.pack("<Q", v), 8)
    wrq(0x1000, 0x2000 | 0x3)             # PML4[0] -> PDPT
    wrq(0x2000, 0x3000 | 0x3)             # PDPT[0] -> PD
    wrq(0x3000, 0x0 | 0x83)               # PD[0] = 2 MB identity page (present|rw|PS)
    code = bytes.fromhex("48b8fecaefbeadde0000"   # mov rax, 0xdeadbeefcafe
                         "4889042500500000"       # mov [0x5000], rax
                         "488b1c2500500000"       # mov rbx, [0x5000]
                         "66ba1000"               # mov dx, 0x10
                         "ee"                      # out dx, al  -> I/O exit
                         "f4")                     # hlt
    ctypes.memmove(host + 0x4000, code, len(code))

    with Partition() as p:
        p.map_gpa(host, 0, SIZE)
        p.set_regs([(CR3, 0x1000), (CR4, 0x20), (CR0, 0x80000011), (EFER, 0x500),
                    (CS, seg(0, 0x08, ATTR_CODE64)), (SS, seg(0, 0x10, ATTR_DATA)),
                    (DS, seg(0, 0x10, ATTR_DATA)), (ES, seg(0, 0x10, ATTR_DATA)),
                    (RIP, 0x4000), (RFLAGS, 0x2)])
        r1 = p.run()
        rbx, rip = p.get_regs([RBX, RIP])
        wrote = struct.unpack_from("<Q", bytes(mem[0x5000:0x5008]))[0]
        p.set_regs([(RIP, rip + 1)])          # advance past the 1-byte OUT, like a syscall handler
        r2 = p.run()
    ok2 = (r1 == EXIT_IO and wrote == 0xdeadbeefcafe and rbx == 0xdeadbeefcafe and r2 == EXIT_HALT)
    print("  long-mode + mem + I/O exit: %s (io=%#x wrote=%#x rbx=%#x halt=%#x)"
          % ("PASS" if ok2 else "FAIL", r1, wrote, rbx, r2))

    ok3 = _test_syscall()
    ok4 = _test_umtx_fastpath()
    ok5 = _test_context()
    allok = ok1 and ok2 and ok3 and ok4 and ok5
    print("WHP self-test:", "PASS" if allok else "FAIL")
    return 0 if allok else 1


def _longmode_part(code_at_4000, stub_at_6000=None):
    """A 2 MB identity-mapped long-mode guest with `code` at 0x4000 (and an optional LSTAR stub
    at 0x6000). Returns (Partition, host_addr) with the vCPU set to enter at 0x4000."""
    SIZE = 0x200000
    host = _alloc(SIZE)
    for off, v in ((0x1000, 0x2003), (0x2000, 0x3003), (0x3000, 0x0083)):
        ctypes.memmove(host + off, struct.pack("<Q", v), 8)
    ctypes.memmove(host + 0x4000, code_at_4000, len(code_at_4000))
    if stub_at_6000:
        ctypes.memmove(host + 0x6000, stub_at_6000, len(stub_at_6000))
    p = Partition()
    p.map_gpa(host, 0, SIZE)
    return p, host


def _test_syscall():
    """Guest `syscall` -> our LSTAR stub -> host services it -> return to user (restore RIP from
    the saved RCX). psemu owns the syscall MSRs; the guest is ring3 with no guest kernel."""
    user = bytes.fromhex("b82a000000" "bf11110000" "0f05" "4889c3" "f4")  # eax=42;edi=0x1111;syscall;rbx=rax;hlt
    p, host = _longmode_part(user, stub_at_6000=b"\xf4")
    with p:
        p.set_regs([(CR3, 0x1000), (CR4, 0x20), (CR0, 0x80000011), (EFER, 0x501),  # EFER.SCE
                    (STAR, 0x0000000800000000), (LSTAR, 0x6000), (SFMASK, 0x0),
                    (CS, seg(0, 0x08, ATTR_CODE64)), (SS, seg(0, 0x10, ATTR_DATA)),
                    (DS, seg(0, 0x10, ATTR_DATA)), (ES, seg(0, 0x10, ATTR_DATA)),
                    (RIP, 0x4000), (RFLAGS, 0x2)])
        r1 = p.run()
        rax, rdi, rcx, rip = p.get_regs([RAX, RDI, RCX, RIP])
        in_stub = 0x6000 <= rip <= 0x6002
        p.set_regs([(RAX, rax * 2), (RIP, rcx)])    # service: result=nr*2, return to user
        r2 = p.run()
        rbx = p.get_regs([RBX])[0]
    ok = (r1 == EXIT_HALT and in_stub and rax == 42 and rdi == 0x1111 and r2 == EXIT_HALT and rbx == 84)
    print("  guest syscall -> host dispatch: %s (nr=%d arg0=%#x result=%d)"
          % ("PASS" if ok else "FAIL", rax, rdi, rbx))
    return ok


def _test_umtx_fastpath():
    """Uncontended mutex lock handled entirely in the LSTAR stub with an atomic CAS (no host
    exit); contention traps to the host. ~96% of PS4 syscalls are this uncontended case."""
    user = bytes.fromhex("b8c6010000" "bf00500000" "be05000000" "0f05" "4889c3" "f4")
    stub = bytes.fromhex("483dc6010000" "751b" "4883fe05" "7515" "448b042500700000" "31c0"
                         "f0440fb107" "7504" "31c0" "ffe1" "f4")
    trap_rip = 0x6000 + len(stub) - 1

    def run_case(mutex_init):
        p, host = _longmode_part(user, stub_at_6000=stub)
        ctypes.memmove(host + 0x5000, struct.pack("<I", mutex_init), 4)
        ctypes.memmove(host + 0x7000, struct.pack("<I", 0x1234), 4)   # host-maintained current tid
        with p:
            p.set_regs([(CR3, 0x1000), (CR4, 0x20), (CR0, 0x80000011), (EFER, 0x501),
                        (STAR, 0x0000000800000000), (LSTAR, 0x6000), (SFMASK, 0x0),
                        (CS, seg(0, 0x08, ATTR_CODE64)), (SS, seg(0, 0x10, ATTR_DATA)),
                        (DS, seg(0, 0x10, ATTR_DATA)), (ES, seg(0, 0x10, ATTR_DATA)),
                        (RIP, 0x4000), (RFLAGS, 0x2)])
            r = p.run()
            rbx, rdi, rip = p.get_regs([RBX, RDI, RIP])
            mutex = struct.unpack_from("<I", bytes((ctypes.c_ubyte * 4).from_address(host + 0x5000)))[0]
        return r, rbx, rdi, rip, mutex

    rA, rbxA, _, ripA, mutexA = run_case(0)            # uncontended
    fastA = rA == EXIT_HALT and ripA not in (trap_rip, trap_rip + 1) and rbxA == 0 and mutexA == 0x1234
    rB, _, rdiB, ripB, mutexB = run_case(0x9999)       # contended
    trapB = rB == EXIT_HALT and ripB in (trap_rip, trap_rip + 1) and rdiB == 0x5000 and mutexB == 0x9999
    ok = fastA and trapB
    print("  umtx fast path (in-guest CAS): %s (uncontended=no-exit, contended=trap)"
          % ("PASS" if ok else "FAIL"))
    return ok


def _test_context():
    """Full vCPU context (GP + RIP + RFLAGS + FS/GS base) save/restore -- the cooperative thread
    switch. FS base matters because the PS4 uses it for TLS."""
    gp = [RAX, RBX, RCX, RDX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15]
    ctxregs = gp + [RIP, RFLAGS, FS, GS]
    p, host = _longmode_part(bytes.fromhex("64488b042500000000") + b"\xf4")  # mov rax, fs:[0]; hlt
    ctypes.memmove(host + 0x5000, struct.pack("<Q", 0xAAAA0000AAAA), 8)
    with p:
        p.set_regs([(CR3, 0x1000), (CR4, 0x20), (CR0, 0x80000011), (EFER, 0x500),
                    (CS, seg(0, 0x08, ATTR_CODE64)), (SS, seg(0, 0x10, ATTR_DATA)),
                    (DS, seg(0, 0x10, ATTR_DATA)), (ES, seg(0, 0x10, ATTR_DATA)),
                    (FS, seg(0x5000, 0x10, ATTR_DATA)), (GS, seg(0, 0x10, ATTR_DATA)),
                    (RFLAGS, 0x2), (RIP, 0x4000), (R12, 0xCAFED00D)])
        r = p.run()
        tls = p.get_regs([RAX])[0]
        p.set_regs([(RIP, 0x4000)])
        ctx = dict(zip(ctxregs, p.get_regs(ctxregs)))                 # save
        p.set_regs([(n, 0) for n in gp] + [(FS, seg(0xDEAD000, 0x10, ATTR_DATA))])  # clobber
        p.set_regs([(n, seg(v, 0x10, ATTR_DATA) if n in (FS, GS) else v)            # restore
                    for n, v in ctx.items()])
        back = dict(zip(ctxregs, p.get_regs(ctxregs)))
    ok = (r == EXIT_HALT and tls == 0xAAAA0000AAAA and all(back[n] == ctx[n] for n in ctxregs)
          and back[R12] == 0xCAFED00D and back[FS] == 0x5000)
    print("  vCPU context save/restore: %s (TLS via FS base, full GP set)" % ("PASS" if ok else "FAIL"))
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
