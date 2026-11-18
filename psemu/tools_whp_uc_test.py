"""Self-test for psemu.whp_uc.WhpUc (the WHP-backed Unicorn stand-in).

    python -m psemu.tools_whp_uc_test
"""
import struct
import sys

import unicorn.x86_const as X
from unicorn import (UC_HOOK_INSN, UC_HOOK_INTR, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE_PROT,
                     UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UcError)

from . import hostvm, whp
from .whp_uc import WhpUc

CODE, DATA, STACK = 0x400000, 0x500000, 0x600000


def build():
    uc = WhpUc()
    vm = hostvm.HostVM(uc)
    vm.map(CODE, 0x2000, UC_PROT_ALL)
    vm.map(DATA, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
    vm.map(STACK, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
    uc.reg_write(X.UC_X86_REG_RSP, STACK + 0x1000)
    return uc, vm


def run(uc, code, at=CODE, hlt=True):
    uc.mem_write(at, code + (b"\xf4" if hlt else b""))
    try:
        uc.emu_start(at, 0)
    except UcError as e:
        return e
    return None


def main():
    if not whp.hypervisor_present():
        print("WHP not present")
        return 1
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print("  %-44s %s %s" % (name, "PASS" if cond else "FAIL", extra))

    uc, vm = build()
    print("WhpUc self-test")

    # 1) plain code + memory write + a real guest HLT is reported as an invalid insn
    e = run(uc, bytes.fromhex("48b82a00000000000000" "48a30000500000000000"))   # mov rax,42; mov [DATA],rax
    check("run to guest hlt", isinstance(e, UcError))
    check("guest store visible to host", struct.unpack("<Q", uc.mem_read(DATA, 8))[0] == 42)

    # 2) XCR0 / AVX are live: xgetbv; vxorps; vaddps; vmovups
    code = bytes.fromhex(
        "31c9" "0f01d0"                       # xor ecx,ecx; xgetbv  -> edx:eax
        "89042508005000"                      # mov [DATA+8], eax
        "c5fc57c0"                            # vxorps ymm0,ymm0,ymm0
        "b801000000" "c5f96ec0"               # mov eax,1; vmovd xmm0,eax
        "c5fc58c8"                            # vaddps ymm1,ymm0,ymm0 (ymm1 = 2*ymm0)
        "c5fc110c2510005000"                  # vmovups [DATA+0x10], ymm1
    )
    e = run(uc, code)
    xcr = struct.unpack("<I", uc.mem_read(DATA + 8, 4))[0]
    check("xgetbv reports AVX state enabled", (xcr & 7) == 7, "xcr0=%#x" % xcr)
    check("native AVX executed", struct.unpack("<I", uc.mem_read(DATA + 0x10, 4))[0] == 2)

    # 3) syscall -> hook -> resume with the hook's result; rcx/r11 as after a syscall
    seen = {}

    def on_syscall(u, ud):
        seen["rax"] = u.reg_read(X.UC_X86_REG_RAX)
        seen["rdi"] = u.reg_read(X.UC_X86_REG_RDI)
        seen["rip"] = u.reg_read(X.UC_X86_REG_RIP)
        u.reg_write(X.UC_X86_REG_RAX, seen["rax"] * 2)
    uc.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, X.UC_X86_INS_SYSCALL)
    code = bytes.fromhex("b82a000000" "bf11110000" "0f05" "4889c3")        # eax=42; edi=0x1111; syscall; rbx=rax
    e = run(uc, code)
    check("syscall hook sees rax/rdi", seen.get("rax") == 42 and seen.get("rdi") == 0x1111)
    check("syscall hook sees rip after the insn", seen.get("rip") == CODE + 12)
    check("guest resumes with hook's rax", uc.reg_read(X.UC_X86_REG_RBX) == 84)

    # 4) emu_stop from a syscall hook returns control; resume continues
    def stopper(u, ud):
        u.emu_stop()
    uc._h_syscall.clear()
    uc.hook_add(UC_HOOK_INSN, stopper, None, 1, 0, X.UC_X86_INS_SYSCALL)
    uc.mem_write(CODE, bytes.fromhex("0f05" "48c7c307000000" "f4"))          # syscall; mov rbx,7; hlt
    uc.reg_write(X.UC_X86_REG_RBX, 0)
    uc.emu_start(CODE, 0)
    check("emu_stop in syscall returns", uc.reg_read(X.UC_X86_REG_RBX) == 0
          and uc.reg_read(X.UC_X86_REG_RIP) == CODE + 2)
    uc._h_syscall.clear()
    e = None
    try:
        uc.emu_start(uc.reg_read(X.UC_X86_REG_RIP), 0)
    except UcError as ex:
        e = ex
    check("resume after stop runs on", uc.reg_read(X.UC_X86_REG_RBX) == 7)

    # 5) HLE 'replace' hook: int3 patch, handler redirects (returns to caller)
    FN = CODE + 0x100
    uc.mem_write(FN, bytes.fromhex("48c7c0ee000000" "c3"))                    # mov rax,0xee; ret
    uc.mem_write(CODE + 0x200, bytes.fromhex("e8" + struct.pack("<i", FN - (CODE + 0x205)).hex()
                                             + "4889c3" "f4"))                # call FN; mov rbx,rax; hlt
    calls = []

    def hle_cb(u, addr):
        calls.append(addr)
        rsp = u.reg_read(X.UC_X86_REG_RSP)
        ret = struct.unpack("<Q", bytes(u.mem_read(rsp, 8)))[0]
        u.reg_write(X.UC_X86_REG_RSP, rsp + 8)
        u.reg_write(X.UC_X86_REG_RIP, ret)
        u.reg_write(X.UC_X86_REG_RAX, 0x1234)
        return True
    uc.hle_cb = hle_cb
    uc.hle_add(FN)
    run(uc, b"", at=CODE + 0x200, hlt=False)
    check("HLE replace hook fired + returned", calls == [FN] and uc.reg_read(X.UC_X86_REG_RBX) == 0x1234)
    check("mem_read shows original bytes at a trap", bytes(uc.mem_read(FN, 1)) == b"\x48")

    # 6) HLE 'fixup' hook: handler runs, then the real function body executes
    calls.clear()
    hle_fix = lambda u, addr: calls.append(addr) or False
    uc.hle_cb = hle_fix
    run(uc, b"", at=CODE + 0x200, hlt=False)
    check("HLE fixup hook runs real body after", calls == [FN] and uc.reg_read(X.UC_X86_REG_RBX) == 0xEE)
    calls.clear()
    run(uc, b"", at=CODE + 0x200, hlt=False)                                    # trap re-armed?
    check("trap re-armed after single-step", calls == [FN])
    uc.hle_remove(FN)
    calls.clear()
    run(uc, b"", at=CODE + 0x200, hlt=False)
    check("hle_remove disarms", calls == [] and uc.reg_read(X.UC_X86_REG_RBX) == 0xEE)

    # 7) unmapped read -> UNMAPPED hook -> UcError (the Emulator turns this into SIGSEGV)
    faults = []

    def on_unmapped(u, access, addr, size, value, ud):
        faults.append((access, addr))
        return False
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    e = run(uc, bytes.fromhex("488b042500009000"))                              # mov rax,[0x900000]
    check("unmapped read faults", isinstance(e, UcError) and faults and faults[0][1] == 0x900000,
          "faults=%s" % faults)
    check("rip left at the faulting insn", uc.reg_read(X.UC_X86_REG_RIP) == CODE)

    # 8) write to a read-only page -> WRITE_PROT hook relaxes it -> retry succeeds
    vm.map(DATA + 0x10000, 0x1000, UC_PROT_READ)
    relaxed = []

    def on_wprot(u, access, addr, size, value, ud):
        u.mem_protect(addr & ~0xFFF, 0x1000, UC_PROT_ALL)
        relaxed.append(addr)
        return True
    uc.hook_add(UC_HOOK_MEM_WRITE_PROT, on_wprot)
    e = run(uc, bytes.fromhex("48c7042500005100" "55000000"))                   # mov qword [0x510000],0x55
    check("write-protect hook relaxes and retries", e is not None and relaxed == [0x510000]
          and struct.unpack("<I", uc.mem_read(0x510000, 4))[0] == 0x55, "relaxed=%s" % relaxed)

    # 9) `int 0x44` -> INTR hook
    ints = []

    def on_intr(u, no, ud):
        ints.append(no)
        u.emu_stop()
    uc.hook_add(UC_HOOK_INTR, on_intr)
    run(uc, bytes.fromhex("cd44" "f4"))
    check("int n reaches the INTR hook", ints == [0x44], "ints=%s" % ints)

    # 10) context save / restore incl. FS base + vector state
    uc.reg_write(X.UC_X86_REG_FS_BASE, DATA)
    uc.mem_write(DATA + 0x100, struct.pack("<Q", 0xAAAABBBBCCCC))
    code = bytes.fromhex("64488b042500010000")                                  # mov rax, fs:[0x100]
    run(uc, code)
    check("FS base reaches the guest", uc.reg_read(X.UC_X86_REG_RAX) == 0xAAAABBBBCCCC)
    ctx = uc.context_save()
    uc.reg_write(X.UC_X86_REG_FS_BASE, 0)
    uc.reg_write(X.UC_X86_REG_R12, 99)
    uc.context_restore(ctx)
    check("context restore", uc.reg_read(X.UC_X86_REG_FS_BASE) == DATA and uc.reg_read(X.UC_X86_REG_R12) == 0)

    # 11) memory above 2^43 (stack-like addresses) works as GPA == VA
    HI = 0x7FFEFF000000
    vm.map(HI, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(HI, struct.pack("<Q", 0x77))
    code = bytes.fromhex("48b8" + struct.pack("<Q", HI).hex() + "488b00")      # mov rax, HI; mov rax,[rax]
    run(uc, code)
    check("guest reads memory at 0x7ffeff000000", uc.reg_read(X.UC_X86_REG_RAX) == 0x77)

    # 12) unmap -> access faults again; remap -> works (TLB is flushed)
    faults.clear()
    uc.reg_write(X.UC_X86_REG_RAX, 0)
    vm.unmap(HI, 0x2000)
    e = run(uc, code)
    check("access after unmap faults", isinstance(e, UcError) and faults and faults[0][1] == HI)

    # 13) watched pages (lazy GPU write-back): a guest access traps once, the callback runs with the
    #     PTEs already restored, and the access then retries and succeeds
    # (same partition as above)
    W = 0x700000
    vm.map(W, 0x4000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(W + 0x1000, struct.pack("<Q", 0x1111))
    fired = []

    def on_watch(start, size):
        fired.append((start, size))
        uc.mem_write(W + 0x1000, struct.pack("<Q", 0x2222))         # "write the surface back"
    uc.watch_add(W + 0x1000, 0x2000, on_watch)
    code = bytes.fromhex("488b042500107000" "4889c3" "f4")           # mov rax,[W+0x1000]; mov rbx,rax; hlt
    e = run(uc, code)
    check("guest read of a watched page traps", fired == [(W + 0x1000, 0x2000)], "fired=%s" % fired)
    check("callback's write is what the guest reads", uc.reg_read(X.UC_X86_REG_RBX) == 0x2222)
    fired.clear()
    uc.reg_write(X.UC_X86_REG_RBX, 0)
    run(uc, code)
    check("watch is one-shot (no trap after)", fired == [] and uc.reg_read(X.UC_X86_REG_RBX) == 0x2222)

    uc.watch_add(W, 0x1000, on_watch)
    e = run(uc, bytes.fromhex("48c7042500007000" "07000000"))         # mov qword [W],7  (guest write)
    check("guest write to a watched page traps", fired == [(W, 0x1000)]
          and struct.unpack("<I", uc.mem_read(W, 4))[0] == 7, "fired=%s" % fired)

    fired.clear()
    uc.watch_add(W + 0x2000, 0x1000, on_watch)
    uc.mem_read(W + 0x2010, 8)
    check("host mem_read of a watched page fires the callback", fired == [(W + 0x2000, 0x1000)])
    fired.clear()
    uc.watch_add(W + 0x2000, 0x1000, on_watch)
    uc.mem_write(W + 0x2ff8, b"" * 8)
    check("host mem_write of a watched page fires the callback", fired == [(W + 0x2000, 0x1000)])
    fired.clear()
    uc.mem_read(W + 0x3000, 8)
    check("pages outside a watch are untouched", fired == [])

    uc.watch_add(W, 0x1000, on_watch)
    uc.watch_remove(W)
    e = run(uc, bytes.fromhex("488b042500007000" "f4"))
    check("watch_remove restores without a callback", fired == [] and isinstance(e, UcError)
          and uc.n_watch_hits >= 4)
    uc.watch_add(W, 0x2000, on_watch)
    uc.watch_add(W + 0x1000, 0x1000, on_watch)                       # overlaps: old one is settled
    check("overlapping watch settles the old one", fired == [(W, 0x2000)], "fired=%s" % fired)

    # 14) more watch cases: an access straddling a page boundary, a partial guest write over the
    #     callback's write-back, several disjoint watches, a remap under a watch
    uc.watch_remove(W + 0x1000)
    fired.clear()
    uc.watch_add(W + 0x1000, 0x1000, on_watch)
    e = run(uc, bytes.fromhex("488b0425fc0f7000" "f4"))                # mov rax,[W+0xFFC]: 8 bytes over 2 pages
    check("access straddling into a watched page traps", fired == [(W + 0x1000, 0x1000)],
          "fired=%s" % fired)

    fired.clear()

    def fill_aa(start, size):
        fired.append((start, size))
        uc.mem_write(start, b"\xaa" * size)                           # "the write-back"
    uc.watch_add(W + 0x2000, 0x1000, fill_aa)
    run(uc, bytes.fromhex("c7042508207000" "44332211" "f4"))           # mov dword [W+0x2008], 0x11223344
    page = bytes(uc.mem_read(W + 0x2000, 0x1000))
    check("partial guest write lands on top of the write-back",
          fired == [(W + 0x2000, 0x1000)] and page[8:12] == bytes.fromhex("44332211")
          and page[:8] == b"\xaa" * 8 and page[12:] == b"\xaa" * (0x1000 - 12))

    fired.clear()
    uc.watch_add(W, 0x1000, on_watch)
    uc.watch_add(W + 0x3000, 0x1000, on_watch)
    uc.mem_read(W + 0x3008, 8)
    check("disjoint watches fire independently",
          fired == [(W + 0x3000, 0x1000)] and sorted(uc._watch) == [W], "fired=%s" % fired)
    uc.watch_remove(W)

    fired.clear()
    uc.watch_add(W + 0x3000, 0x1000, on_watch)
    uc.mem_protect(W + 0x3000, 0x1000, UC_PROT_READ)                   # remap under a watch
    check("remapping a watched range settles the watch first",
          fired == [(W + 0x3000, 0x1000)] and not uc._watch, "fired=%s" % fired)

    print("WhpUc self-test:", "PASS" if ok else "FAIL", "exits=%s" % uc.exits)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
