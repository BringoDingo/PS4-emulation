"""For PLT thunks of a module: the imported symbol NID and (if the module is loaded in a run) where it
resolves. Static part prints the NIDs, matching them against psemu/nid_candidates.txt.

    python plt_targets.py libScePsm.sprx 0x1868 0x1898 0x18a8
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2\PS4-emulation\docs\shellui-boot\tools")
sys.path.insert(0, r"D:\CLAUDEGODOT2")
import elfsyms

lib = sys.argv[1]
P = lib if ("/" in lib or "\\" in lib) else r"D:/Ps4Tools/ps4kernel/firmware/system/common/lib/" + lib
d, segs, dyn, v2f = elfsyms.load(P)
code_off, code_va, _ = segs[0]
phoff = struct.unpack_from("<Q", d, 0x20)[0]
phnum = struct.unpack_from("<H", d, 0x38)[0]
phes = struct.unpack_from("<H", d, 0x36)[0]
base = None
for i in range(phnum):
    t, fl, o2, va2, pa, fs2, ms, al = struct.unpack_from("<IIQQQQQQ", d, phoff + i * phes)
    if t == 0x61000000:
        base = o2
o, sz = dyn
tags = {}
for i in range(sz // 16):
    t, v = struct.unpack_from("<qQ", d, o + i * 16)
    tags[t & 0xFFFFFFFF] = v
st, strt = base + tags[0x61000039], base + tags[0x61000035]
ro, rs = base + tags[0x61000029], tags[0x6100002D]
slot_sym = {}
for i in range(rs // 24):
    r_off, r_info, r_add = struct.unpack_from("<QQq", d, ro + i * 24)
    nm = struct.unpack_from("<I", d, st + (r_info >> 32) * 24)[0]
    e = d.index(b"\0", strt + nm)
    slot_sym[r_off] = d[strt + nm:e].decode()
names = [l.strip() for l in open(r"D:\CLAUDEGODOT2\psemu\nid_candidates.txt", encoding="utf-8")
         if l.strip() and not l.startswith("#")]
byid = {elfsyms.nid(n): n for n in names}
for a in sys.argv[2:]:
    t = int(a, 0)
    fo = code_off + t - code_va
    rel = struct.unpack_from("<i", d, fo + 2)[0]
    slot = t + 6 + rel
    sym = slot_sym.get(slot, "?")
    print(f"thunk {t:#x}: GOT {slot:#x} -> {sym}  {byid.get(sym.split('#')[0], '')}")
