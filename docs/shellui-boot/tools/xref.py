"""Segment-aware static xref scanner for the PS4 eboot (PIE, x86-64). Maps file offsets to vaddrs
via the ELF program headers (code seg: file 0x4000 -> vaddr 0, so abs = 0x100000000 + foff - 0x4000),
then finds RIP-relative `lea`/`mov` references to a target string/function vaddr.

    python xref.py str "SELECT count(*) FROM sqlite_master"     # xref a string by content
    python xref.py addr 0x1008d4cb6                              # xref a given absolute vaddr
"""
import struct
import sys

EBOOT = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
BASE = 0x100000000
b = open(EBOOT, "rb").read()
e_phoff = struct.unpack("<Q", b[32:40])[0]
e_phnum = struct.unpack("<H", b[56:58])[0]
segs = []  # (file_off, vaddr, filesz)
for i in range(e_phnum):
    o = e_phoff + i * 56
    if struct.unpack("<I", b[o:o+4])[0] == 1:
        off, va, _pa, fsz = struct.unpack("<QQQQ", b[o+8:o+40])
        segs.append((off, va, fsz))


def foff_to_vaddr(foff):
    for off, va, fsz in segs:
        if off <= foff < off + fsz:
            return BASE + va + (foff - off)
    return None


def vaddr_to_foff(vaddr):
    v = vaddr - BASE
    for off, va, fsz in segs:
        if va <= v < va + fsz:
            return off + (v - va)
    return None


mode, arg = sys.argv[1], sys.argv[2]
if mode == "str":
    foff = b.find(arg.encode())
    if foff < 0:
        print("string not found"); sys.exit()
    target = foff_to_vaddr(foff)
    print(f"string at file {foff:#x} -> vaddr {target:#x}: {b[foff:foff+70].split(bytes([0]))[0]!r}")
else:
    target = int(arg, 16)
    print(f"target vaddr {target:#x}")

# scan the code segment for rip-relative lea/mov referencing `target`
hits = []
code_off, code_va, code_sz = segs[0]
for i in range(code_off, code_off + code_sz - 7):
    c0, c1, c2 = b[i], b[i+1], b[i+2]
    # lea r64,[rip+d]  (48/4c 8d /r mod=00 rm=101) ; mov r64,[rip+d] (48/4c 8b /r) ; also 32-bit forms
    is_lea = c0 in (0x48, 0x4c) and c1 == 0x8d and (c2 & 0xc7) == 0x05
    is_mov = c0 in (0x48, 0x4c) and c1 == 0x8b and (c2 & 0xc7) == 0x05
    if is_lea or is_mov:
        disp = struct.unpack("<i", b[i+3:i+7])[0]
        insn_va = foff_to_vaddr(i)
        if insn_va is not None and insn_va + 7 + disp == target:
            hits.append((insn_va, "lea" if is_lea else "mov"))
print(f"{len(hits)} rip-relative refs:")
for va, kind in hits[:40]:
    print(f"   {kind} @ {va:#x}")
