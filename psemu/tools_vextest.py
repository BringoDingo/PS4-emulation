"""Differential test: native VEX execution (native/vex.c) vs the Python shim.

    python -m psemu.tools_vextest [--per-bucket N] [--trials K] [libs...]

Harvests real VEX instructions from firmware libraries, then runs each one
from identical random CPU/memory states twice: once through the native hook
(a real emu_start, so the RIP-write-from-hook path is exercised too) and once
through the Python AVX shim. Registers (all YMM, GPRs, RIP) and memory must
match. Instructions vex.c does not execute natively are skipped.
"""
import argparse
import os
import random
import re
import struct
import sys

import capstone
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
from unicorn import x86_const as xc

from .cpu_native import NativeCpu
from .loader import Elf64

FW = os.environ.get("PSEMU_FW", r"D:\Ps4Tools\ps4kernel\firmware")
DEFAULT_LIBS = ["system/common/lib/libSceLibcInternal.sprx",
                "system/common/lib/libkernel.sprx",
                "system/common/lib/libSceGnmDriver.sprx",
                "system/common/lib/libScePlayerInvitationDialog.sprx",
                "system/common/lib/libSceVideoCoreInterface.sprx",
                "system/common/lib/libSceAudio3d.sprx",
                "system/common/lib/libSceNgs2.sprx",
                "system/common/lib/libSceFiber.sprx",
                "system/common/lib/libSceJson.sprx",
                "system/sys/GnmCompositor.elf"]

CODE = 0x100000
DATA = 0x4000000
DATA_SIZE = 0x200000
GPRS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def vex_key(code):
    """(map, opcode, pp, L, is_mem) bucket of a VEX instruction."""
    if code[0] == 0xC5:
        m, b2, i = 1, code[1], 2
    else:
        m, b2, i = code[1] & 0x1F, code[2], 3
    return (m, code[i], b2 & 3, (b2 >> 2) & 1, (code[i + 1] >> 6) != 3)


def harvest(paths, per_bucket):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    buckets = {}
    for p in paths:
        if not os.path.exists(p):
            continue
        elf = Elf64(p)
        for seg in elf.loadable():
            if not seg.flags & 1:
                continue
            code = elf.data[seg.offset:seg.offset + seg.filesz]
            for m in re.finditer(rb"[\xc4\xc5]", code):
                i = m.start()
                chunk = code[i:i + 15]
                if len(chunk) < 6:
                    continue
                insn = next(md.disasm(chunk, 0, 1), None)
                if insn is None:
                    continue
                k = vex_key(chunk)
                lst = buckets.setdefault(k, {})
                if len(lst) < per_bucket and bytes(insn.bytes) not in lst:
                    lst[bytes(insn.bytes)] = insn.mnemonic + " " + insn.op_str
    return buckets


class _Emu:
    """The bits of Emulator the AVX shim touches."""
    def __init__(self, uc):
        self.uc = uc
        self.trace = False
        self._last_rip = CODE
        self.stopped = None
        self.native = None

    def log(self, msg):
        pass

    def stop(self, reason):
        self.stopped = reason


def make_uc(code, state, native):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    from .emulator import Emulator
    Emulator._enable_avx(type("X", (), {"uc": uc})())      # before any mapping
    uc.mem_map(CODE, 0x2000, UC_PROT_ALL)
    uc.mem_map(DATA, DATA_SIZE, UC_PROT_ALL)
    uc.mem_write(CODE, code + b"\x90" * 16)
    uc.mem_write(DATA, state["mem"])
    for r, v in state["gpr"].items():
        uc.reg_write(getattr(xc, "UC_X86_REG_" + r.upper()), v)
    for i, v in enumerate(state["ymm"]):
        uc.reg_write(xc.UC_X86_REG_YMM0 + i, v)
    if native is not None:
        native.attach(uc)
    return uc


def snapshot(uc):
    regs = [uc.reg_read(xc.UC_X86_REG_YMM0 + i) for i in range(16)]
    gp = [uc.reg_read(getattr(xc, "UC_X86_REG_" + r.upper())) for r in GPRS]
    return regs, gp, uc.reg_read(xc.UC_X86_REG_RIP), bytes(uc.mem_read(DATA, DATA_SIZE))


def random_state(rng, kind):
    def vec():
        if kind == 0:
            return int.from_bytes(rng.randbytes(32), "little")
        if kind == 1:
            return int.from_bytes(struct.pack("<8f", *[rng.uniform(-100, 100) for _ in range(8)]),
                                  "little")
        return int.from_bytes(struct.pack("<4d", *[rng.uniform(-1e6, 1e6) for _ in range(4)]),
                              "little")
    gpr = {r: DATA + 0x80000 + rng.randrange(0, 0x100) * 16 for r in GPRS}
    for r in ("rax", "rcx", "rdx"):                 # some plain integers too
        if rng.random() < 0.5:
            gpr[r] = rng.randrange(0, 1 << 32) if rng.random() < 0.5 else rng.randrange(0, 64)
    return {"gpr": gpr, "ymm": [vec() for _ in range(16)], "mem": rng.randbytes(DATA_SIZE)}


def run_native(native, code, st):
    uc = make_uc(code, st, native)
    from .cpu_native import R_PAGE, R_TRAP
    passed = native.s.vex_passed
    cur = CODE
    for _ in range(4):
        s = native.s
        s.reason = 0
        s.limit = s.count + 10
        try:
            uc.emu_start(cur, CODE + len(code), 0, 0)
        except Exception as e:
            return None, f"fault: {e}"
        if s.reason == R_PAGE:
            native.scan_page(uc, s.stop_addr)
            cur = s.stop_addr
            continue
        if s.reason == R_TRAP:
            return None, "python"                     # not executed natively
        break
    if native.s.vex_passed != passed:
        return None, "python"                         # left to QEMU, as before
    return snapshot(uc), None


def run_python(code, st):
    uc = make_uc(code, st, None)
    emu = _Emu(uc)
    from .avx_shim import AvxShim
    shim = AvxShim(emu)
    insn = next(shim.md.disasm(code, CODE, 1))
    try:
        ok = shim.emulate_vex(insn)
    except Exception as e:
        return None, f"python error {e!r}"
    if not ok or emu.stopped:
        return None, "python unhandled"
    uc.reg_write(xc.UC_X86_REG_RIP, CODE + insn.size)
    return snapshot(uc), None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("libs", nargs="*")
    ap.add_argument("--per-bucket", type=int, default=6)
    ap.add_argument("--trials", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args(argv)
    native = NativeCpu.load()
    if native is None:
        sys.exit("psemu_cpu.dll not available")
    paths = a.libs or [os.path.join(FW, p) for p in DEFAULT_LIBS]
    buckets = harvest(paths, a.per_bucket)
    rng = random.Random(a.seed)
    tested = mism = skipped = 0
    bad = {}
    seen = {}
    for key in sorted(buckets):
        for code, text in buckets[key].items():
            for t in range(a.trials):
                st = random_state(rng, t % 3)
                n, why = run_native(native, code, st)
                if n is None:
                    skipped += 1
                    if a.v and why != "python":
                        print(f"  skip {text}: {why}")
                    break
                p, why = run_python(code, st)
                if p is None:
                    skipped += 1
                    if a.v:
                        print(f"  skip {text}: {why}")
                    break
                tested += 1
                seen[text.split()[0]] = seen.get(text.split()[0], 0) + 1
                if n != p:
                    mism += 1
                    diffs = [f"ymm{i}" for i in range(16) if n[0][i] != p[0][i]]
                    diffs += [GPRS[i] for i in range(16) if n[1][i] != p[1][i]]
                    if n[2] != p[2]:
                        diffs.append(f"rip {n[2]:#x}/{p[2]:#x}")
                    if n[3] != p[3]:
                        diffs.append("mem")
                    bad.setdefault(text.split()[0], []).append((text, diffs, code.hex()))
    print(f"buckets {len(buckets)}, compared {tested}, mismatches {mism}, skipped {skipped}")
    print("compared: " + ", ".join(f"{k} x{v}" for k, v in sorted(seen.items())))
    for mn, lst in sorted(bad.items()):
        text, diffs, hx = lst[0]
        print(f"  {mn:<14} x{len(lst)}  e.g. {text}  [{hx}]  differs: {', '.join(diffs)}")
    return 1 if mism else 0


if __name__ == "__main__":
    sys.exit(main())
