"""Small reverse-engineering helpers for firmware modules (developer use).

    python -m psemu.tools_re callers libkernel.sprx 649       # call sites of syscall 649's wrapper
    python -m psemu.tools_re dis libkernel.sprx 0x27d00 0x80   # disassemble at a module offset
    python -m psemu.tools_re imm libSceVideoOut.sprx 0xc0308203 # code using a 32-bit constant
"""
import glob
import os
import struct
import sys

import capstone

from .loader import Elf64

FW = r"D:\Ps4Tools\ps4kernel\firmware"


def find_module(name):
    if os.path.isfile(name):
        return name
    hits = glob.glob(os.path.join(FW, "**", name), recursive=True)
    if not hits:
        raise SystemExit("module not found: " + name)
    return hits[0]


def text(elf):
    seg = next(s for s in elf.segments if s.type == 1 and s.flags & 1)
    return seg, elf.data[seg.offset:seg.offset + seg.filesz]


def disasm(elf, off, n, base=0):
    seg, code = text(elf)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    start = off - seg.vaddr
    for i in md.disasm(code[start:start + n], base + off):
        print("  %x: %-8s %s" % (i.address, i.mnemonic, i.op_str))


def aligned_disasm(elf, target, back=0x80, fwd=0x60):
    """Disassemble around `target`, choosing a start that decodes onto it."""
    seg, code = text(elf)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    t = target - seg.vaddr
    for b in range(back, 0, -1):
        ins = list(md.disasm(code[t - b:t + fwd], target - b))
        if any(i.address == target for i in ins):
            for i in ins:
                mark = "  <==" if i.address == target else ""
                print("  %x: %-8s %s%s" % (i.address, i.mnemonic, i.op_str, mark))
            return
    disasm(elf, target, fwd)


def syscall_wrappers(elf, num):
    """Offsets of `mov eax, num ... syscall` wrapper functions."""
    seg, code = text(elf)
    out = []
    for pat in (b"\xb8" + struct.pack("<I", num), b"\x48\xc7\xc0" + struct.pack("<I", num)):
        i = 0
        while True:
            i = code.find(pat, i)
            if i < 0:
                break
            if b"\x0f\x05" in code[i + len(pat):i + len(pat) + 8]:
                out.append(seg.vaddr + i)
            i += 1
    return out


def callers(elf, target):
    seg, code = text(elf)
    res = []
    for i in range(len(code) - 5):
        if code[i] == 0xE8:
            rel = struct.unpack_from("<i", code, i + 1)[0]
            if seg.vaddr + i + 5 + rel == target:
                res.append(seg.vaddr + i)
    return res


def imm_refs(elf, value):
    """Addresses of instructions whose bytes contain the 32-bit immediate."""
    seg, code = text(elf)
    pat = struct.pack("<I", value & 0xFFFFFFFF)
    out, i = [], 0
    while True:
        i = code.find(pat, i)
        if i < 0:
            return out
        out.append(seg.vaddr + i)
        i += 1


def main():
    cmd, mod = sys.argv[1], sys.argv[2]
    elf = Elf64(find_module(mod))
    if cmd == "dis":
        disasm(elf, int(sys.argv[3], 0), int(sys.argv[4], 0))
    elif cmd == "callers":
        num = int(sys.argv[3], 0)
        ctx = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x30
        for w in syscall_wrappers(elf, num):
            print("wrapper @%#x" % w)
            for c in callers(elf, w):
                print(" call site @%#x" % c)
                aligned_disasm(elf, c, ctx, 0x40)
                print()
    elif cmd == "imm":
        value = int(sys.argv[3], 0)
        for a in imm_refs(elf, value):
            print("== constant at %#x" % a)
            # the instruction starts a few bytes before the immediate
            for back in range(1, 8):
                seg, code = text(elf)
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                ins = next(md.disasm(code[a - back - seg.vaddr:a - back - seg.vaddr + 15],
                                     a - back), None)
                if ins and ins.address + ins.size >= a + 4:
                    aligned_disasm(elf, ins.address, int(sys.argv[4], 0) if len(sys.argv) > 4
                                   else 0x40, 0x80)
                    break
            print()


if __name__ == "__main__":
    main()
