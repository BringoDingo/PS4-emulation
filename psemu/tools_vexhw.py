"""Check native VEX execution (native/vex.c) against the host CPU.

    python -m psemu.tools_vexhw [--per-bucket N] [--trials K]

The ground truth for an AVX instruction is an AVX CPU, and the host is one.
Each harvested firmware instruction that vex.c executes is run twice from the
same state: on the host (a generated stub loads YMM0-15 and the GPRs, runs
the instruction bytes, stores everything back) and in Unicorn through the
native hook. Registers and the memory buffer must match bit for bit.

Only instructions whose memory operand (if any) is [base + index*scale +
disp] with a non-RSP base are run, with the base pointing into a private
buffer, so the host never touches anything else.
"""
import argparse
import ctypes
import random
import struct
import sys

import capstone
from capstone.x86 import X86_OP_MEM

from .cpu_native import NativeCpu
from . import tools_vextest as vt

DATA_SIZE = 0x10000
BASE_OFF = 0x8000

# capstone register name -> modrm number
GPR_NUM = {n: i for i, n in enumerate(["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"])}
CTX_GPR = 512


def _vex3(R, B, L, pp, op, modrm_reg, base, disp):
    """vmovdqu-style VEX.0F op with [base + disp32] operand."""
    b1 = ((not R) << 7) | (1 << 6) | ((not B) << 5) | 1
    b2 = (0xF << 3) | (L << 2) | pp
    m = 0x80 | ((modrm_reg & 7) << 3) | (base & 7)
    out = bytes([0xC4, b1, b2, op, m])
    if base & 7 == 4:
        out += b"\x24"
    return out + struct.pack("<i", disp)


def vmov_store_x(n, base, disp):   # vmovdqu [base+disp], xmmN
    return _vex3(n >= 8, base >= 8, 0, 2, 0x7F, n, base, disp)


def vmov_load_x(n, base, disp):    # vmovdqu xmmN, [base+disp]
    return _vex3(n >= 8, base >= 8, 0, 2, 0x6F, n, base, disp)


def vmov_store_y(n, base, disp):
    return _vex3(n >= 8, base >= 8, 1, 2, 0x7F, n, base, disp)


def vmov_load_y(n, base, disp):
    return _vex3(n >= 8, base >= 8, 1, 2, 0x6F, n, base, disp)


def mov_load(reg, base, disp):     # mov reg, [base+disp32]
    rex = 0x48 | ((reg >= 8) << 2) | (base >= 8)
    m = 0x80 | ((reg & 7) << 3) | (base & 7)
    out = bytes([rex, 0x8B, m]) + (b"\x24" if base & 7 == 4 else b"")
    return out + struct.pack("<i", disp)


def mov_store(reg, base, disp):    # mov [base+disp32], reg
    rex = 0x48 | ((reg >= 8) << 2) | (base >= 8)
    m = 0x80 | ((reg & 7) << 3) | (base & 7)
    out = bytes([rex, 0x89, m]) + (b"\x24" if base & 7 == 4 else b"")
    return out + struct.pack("<i", disp)


def push(r):
    return (b"\x41" if r >= 8 else b"") + bytes([0x50 + (r & 7)])


def pop(r):
    return (b"\x41" if r >= 8 else b"") + bytes([0x58 + (r & 7)])


SAVED = [3, 5, 6, 7, 12, 13, 14, 15]           # rbx rbp rsi rdi r12-r15 (Windows callee-saved)
RSP, RAX, RCX = 4, 0, 1


def build_stub(insn):
    c = b""
    for r in SAVED:
        c += push(r)
    c += b"\x48\x81\xEC" + struct.pack("<I", 0xA8)        # sub rsp, 0xa8
    for k in range(10):                                    # save xmm6-15
        c += vmov_store_x(6 + k, RSP, 16 * k)
    c += push(RCX)                                         # ctx
    for n in range(16):
        c += vmov_load_y(n, RCX, 32 * n)
    for r in range(16):
        if r not in (RSP, RCX):
            c += mov_load(r, RCX, CTX_GPR + 8 * r)
    c += mov_load(RCX, RCX, CTX_GPR + 8 * RCX)
    c += insn
    c += push(RAX)
    c += b"\x48\x8B\x44\x24\x08"                           # mov rax, [rsp+8]
    for n in range(16):
        c += vmov_store_y(n, RAX, 32 * n)
    for r in range(16):
        if r not in (RSP, RAX):
            c += mov_store(r, RAX, CTX_GPR + 8 * r)
    c += pop(RCX) + mov_store(RCX, RAX, CTX_GPR)           # guest rax
    c += pop(RCX)                                          # ctx (discard)
    for k in range(10):
        c += vmov_load_x(6 + k, RSP, 16 * k)
    c += b"\x48\x81\xC4" + struct.pack("<I", 0xA8)        # add rsp, 0xa8
    for r in reversed(SAVED):
        c += pop(r)
    c += b"\xC5\xF8\x77\xC3"                               # vzeroupper; ret
    return c


class HostRunner:
    def __init__(self):
        k = ctypes.windll.kernel32
        k.VirtualAlloc.restype = ctypes.c_void_p
        k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
                                   ctypes.c_uint32]
        self.code = k.VirtualAlloc(None, 0x1000, 0x3000, 0x40)   # RWX
        self.ctx = (ctypes.c_uint8 * (512 + 128))()
        self.data = (ctypes.c_uint8 * DATA_SIZE)()
        self.fn = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self.code)

    @property
    def data_addr(self):
        return ctypes.addressof(self.data)

    def run(self, insn, ymm, gpr, mem):
        stub = build_stub(insn)
        ctypes.memmove(self.code, stub, len(stub))
        for n in range(16):
            ctypes.memmove(ctypes.addressof(self.ctx) + 32 * n, ymm[n].to_bytes(32, "little"), 32)
        for r in range(16):
            ctypes.memmove(ctypes.addressof(self.ctx) + CTX_GPR + 8 * r,
                           struct.pack("<Q", gpr[r] & (2**64 - 1)), 8)
        ctypes.memmove(self.data, mem, DATA_SIZE)
        self.fn(ctypes.addressof(self.ctx))
        raw = bytes(self.ctx)
        y = [int.from_bytes(raw[32 * n:32 * n + 32], "little") for n in range(16)]
        g = list(struct.unpack_from("<16Q", raw, CTX_GPR))
        return y, g, bytes(self.data)


def plan(insn):
    """Registers used for addressing -> (base, index) numbers, or None to skip."""
    for op in insn.operands:
        if op.type == X86_OP_MEM:
            m = op.mem
            if m.base == 0 or m.segment != 0:
                return None
            b = insn.reg_name(m.base)
            if b not in GPR_NUM or b == "rsp":
                return None
            idx = insn.reg_name(m.index) if m.index else None
            if idx is not None and (idx not in GPR_NUM or idx == b):
                return None
            if not -0x4000 < m.disp < 0x4000:
                return None
            return GPR_NUM[b], (GPR_NUM[idx] if idx else None)
    return (None, None)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("libs", nargs="*")
    ap.add_argument("--per-bucket", type=int, default=6)
    ap.add_argument("--trials", type=int, default=4)
    ap.add_argument("--seed", type=int, default=2)
    a = ap.parse_args(argv)
    k = ctypes.windll.kernel32
    if not (k.IsProcessorFeaturePresent(39) and k.IsProcessorFeaturePresent(40)):
        sys.exit("host CPU lacks AVX/AVX2")
    native = NativeCpu.load()
    if native is None:
        sys.exit("psemu_cpu.dll not available")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    host = HostRunner()
    import os
    paths = a.libs or [os.path.join(vt.FW, p) for p in vt.DEFAULT_LIBS]
    buckets = vt.harvest(paths, a.per_bucket)
    rng = random.Random(a.seed)
    tested = mism = 0
    seen, bad = {}, {}
    probe_len = ctypes.c_int()
    for key in sorted(buckets):
        for code, text in buckets[key].items():
            insn = next(md.disasm(code, vt.CODE, 1), None)
            if insn is None or insn.size != len(code):
                continue
            p = plan(insn)
            if p is None:
                continue
            base, index = p
            for t in range(a.trials):
                kind = t % 3
                st = vt.random_state(rng, kind)
                st["mem"] = rng.randbytes(DATA_SIZE)
                gvals = [rng.randrange(0, 1 << 32) if rng.random() < 0.5 else rng.randrange(0, 64)
                         for _ in range(16)]
                gvals[4] = 0
                if index is not None:
                    gvals[index] = rng.randrange(0, 16)
                host_g = list(gvals)
                guest_g = list(gvals)
                if base is not None:
                    host_g[base] = host.data_addr + BASE_OFF
                    guest_g[base] = vt.DATA + BASE_OFF
                names = list(GPR_NUM)
                st["gpr"] = {names[r]: guest_g[r] for r in range(16) if r != 4}
                guest_mem = st["mem"] + bytes(vt.DATA_SIZE - DATA_SIZE)
                st_full = dict(st, mem=guest_mem)
                n, why = vt.run_native(native, code, st_full)
                if n is None:
                    break                       # not executed natively
                hy, hg, hmem = host.run(code, st["ymm"], host_g, st["mem"])
                tested += 1
                mn = text.split()[0]
                seen[mn] = seen.get(mn, 0) + 1
                ny, ngp, _rip, nmem = n
                gp_names = vt.GPRS
                diffs = [f"ymm{i}" for i in range(16) if ny[i] != hy[i]]
                for i, nm in enumerate(gp_names):
                    r = GPR_NUM[nm]
                    if r == 4 or r == base:
                        continue
                    if ngp[i] != hg[r]:
                        diffs.append(nm)
                if nmem[:DATA_SIZE] != hmem:
                    diffs.append("mem")
                if diffs:
                    mism += 1
                    bad.setdefault(mn, []).append((text, diffs, code.hex(), kind))
    print(f"compared {tested} executions against the host CPU, mismatches {mism}")
    print("compared: " + ", ".join(f"{k} x{v}" for k, v in sorted(seen.items())))
    for mn, lst in sorted(bad.items()):
        text, diffs, hx, kind = lst[0]
        print(f"  {mn:<14} x{len(lst)}  e.g. {text}  [{hx}] state={kind}  differs: {', '.join(diffs)}")
    return 1 if mism else 0


if __name__ == "__main__":
    sys.exit(main())
