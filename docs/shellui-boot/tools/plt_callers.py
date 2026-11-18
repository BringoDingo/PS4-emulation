"""Find the call sites of an imported function in a firmware module (by symbol NID prefix or name).

    python plt_callers.py libScePsm.sprx scePadOpen
"""
import re
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2\PS4-emulation\docs\shellui-boot\tools")
import elfsyms

lib, want = sys.argv[1], sys.argv[2]
P = lib if ("/" in lib or "\\" in lib) else r"D:/Ps4Tools/ps4kernel/firmware/system/common/lib/" + lib
d, segs, dyn, v2f = elfsyms.load(P)
phoff = struct.unpack_from("<Q", d, 0x20)[0]
phnum = struct.unpack_from("<H", d, 0x38)[0]
phes = struct.unpack_from("<H", d, 0x36)[0]
base = None
for i in range(phnum):
    t, fl, off, va, pa, fs, ms, al = struct.unpack_from("<IIQQQQQQ", d, phoff + i * phes)
    if t == 0x61000000:
        base = off
o, sz = dyn
tags = {}
for i in range(sz // 16):
    t, v = struct.unpack_from("<qQ", d, o + i * 16)
    tags[t & 0xFFFFFFFF] = v
st = base + tags[0x61000039]
nsym = tags[0x6100003F] // 24
strt = base + tags[0x61000035]
nid = elfsyms.nid(want)
idx = None
for i in range(nsym):
    nm, info, oth, shn, val, size = struct.unpack_from("<IBBHQQ", d, st + i * 24)
    e = d.index(b"\0", strt + nm)
    name = d[strt + nm:e].decode()
    if name.split("#")[0] == nid:
        idx = i
        break
print("symbol index of", want, ":", idx)
# relocations: JMPREL (0x61000029 offset, 0x6100002b size?) and RELA (0x6100002f, 0x61000031)
slots = []
for ot, st_ in ((0x61000029, 0x6100002D), (0x6100002F, 0x61000031)):
    if ot in tags and st_ in tags:
        ro, rs = base + tags[ot], tags[st_]
        for i in range(rs // 24):
            r_off, r_info, r_add = struct.unpack_from("<QQq", d, ro + i * 24)
            if (r_info >> 32) == idx:
                slots.append(r_off)
print("GOT slots:", [hex(s) for s in slots])
code_off, code_va, code_fs = segs[0]
code = d[code_off:code_off + code_fs]
thunks = []
for m in re.finditer(rb"\xff\x25(....)", code, re.S):
    i = m.start()
    tgt = code_va + i + 6 + struct.unpack("<i", m.group(1))[0]
    if tgt in slots:
        thunks.append(code_va + i)
print("PLT thunks:", [hex(t) for t in thunks])
sites = []
for t in thunks:
    for m in re.finditer(rb"\xe8(....)", code, re.S):
        i = m.start()
        if code_va + i + 5 + struct.unpack("<i", m.group(1))[0] == t:
            sites.append(code_va + i)
    for m in re.finditer(rb"\xe9(....)", code, re.S):          # tail calls
        i = m.start()
        if code_va + i + 5 + struct.unpack("<i", m.group(1))[0] == t:
            sites.append(code_va + i)
print("call sites:", [hex(s) for s in sorted(sites)])
