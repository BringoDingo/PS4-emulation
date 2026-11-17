"""Minimal ECMA-335 metadata reader: list methods that call chosen BCL members."""
import sys, struct
sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.syscalls import _embedded_cil

U16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
U32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

CODED = {  # name: (tag bits, [tables by tag])
 "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
 "HasConstant": (2, [0x04, 0x08, 0x17]),
 "HasCustomAttribute": (5, [0x06,0x04,0x01,0x02,0x08,0x09,0x0A,0x00,0x0E,0x17,0x14,0x11,0x1A,0x1B,0x20,0x23,0x26,0x27,0x28,0x2A,0x2C,0x2B]),
 "HasFieldMarshal": (1, [0x04, 0x08]),
 "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
 "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
 "HasSemantics": (1, [0x14, 0x17]),
 "MethodDefOrRef": (1, [0x06, 0x0A]),
 "MemberForwarded": (1, [0x04, 0x06]),
 "Implementation": (2, [0x26, 0x23, 0x27]),
 "CustomAttributeType": (3, [None, None, 0x06, 0x0A, None]),
 "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
 "TypeOrMethodDef": (1, [0x02, 0x06]),
}
# column kinds: 2=u16, 4=u32, S=string, G=guid, B=blob, ('c',name)=coded, ('t',table)=simple index
SCHEMA = {
 0x00: [2,'S','G','G','G'], 0x01: [('c','ResolutionScope'),'S','S'],
 0x02: [4,'S','S',('c','TypeDefOrRef'),('t',0x04),('t',0x06)], 0x03: [('t',0x04)],
 0x04: [2,'S','B'], 0x05: [('t',0x06)], 0x06: [4,2,2,'S','B',('t',0x08)], 0x07: [('t',0x08)],
 0x08: [2,2,'S'], 0x09: [('t',0x02),('c','TypeDefOrRef')], 0x0A: [('c','MemberRefParent'),'S','B'],
 0x0B: [2,('c','HasConstant'),'B'], 0x0C: [('c','HasCustomAttribute'),('c','CustomAttributeType'),'B'],
 0x0D: [('c','HasFieldMarshal'),'B'], 0x0E: [2,('c','HasDeclSecurity'),'B'], 0x0F: [2,4,('t',0x02)],
 0x10: [4,('t',0x04)], 0x11: ['B'], 0x12: [('t',0x02),('t',0x14)], 0x13: [('t',0x14)],
 0x14: [2,'S',('c','TypeDefOrRef')], 0x15: [('t',0x02),('t',0x17)], 0x16: [('t',0x17)], 0x17: [2,'S','B'],
 0x18: [2,('t',0x06),('c','HasSemantics')], 0x19: [('t',0x02),('c','MethodDefOrRef'),('c','MethodDefOrRef')],
 0x1A: ['S'], 0x1B: ['B'], 0x1C: [2,('c','MemberForwarded'),'S',('t',0x1A)], 0x1D: [4,('t',0x04)],
 0x1E: [4,4], 0x1F: [4], 0x20: [4,2,2,2,2,4,'B','S','S'], 0x21: [4], 0x22: [4,4,4],
 0x23: [2,2,2,2,4,'B','S','S','B'], 0x24: [4,('t',0x23)], 0x25: [4,4,4,('t',0x23)],
 0x26: [4,'S','B'], 0x27: [4,4,'S','S',('c','Implementation')], 0x28: [4,4,'S',('c','Implementation')],
 0x29: [('t',0x02),('t',0x02)], 0x2A: [2,2,('c','TypeOrMethodDef'),'S'], 0x2B: [('c','MethodDefOrRef'),'B'],
 0x2C: [('t',0x2A),('c','TypeDefOrRef')],
}

class Asm:
    def __init__(self, pe):
        self.pe = pe
        po = U32(pe, 0x3C)
        nsec = U16(pe, po + 6); optsz = U16(pe, po + 20)
        opt = po + 24
        magic = U16(pe, opt)
        ddoff = opt + (0x70 if magic == 0x20B else 0x60)
        self.secs = []
        so = opt + optsz
        for i in range(nsec):
            o = so + 40 * i
            vsz, va, rsz, rptr = U32(pe, o+8), U32(pe, o+12), U32(pe, o+16), U32(pe, o+20)
            self.secs.append((va, max(vsz, rsz), rptr))
        clr_rva = U32(pe, ddoff + 14 * 8)
        clr = self.off(clr_rva)
        md_rva, md_sz = U32(pe, clr + 8), U32(pe, clr + 12)
        md = self.off(md_rva)
        assert U32(pe, md) == 0x424A5342, "no BSJB"
        vlen = U32(pe, md + 12)
        p = md + 16 + vlen
        nstreams = U16(pe, p + 2); p += 4
        self.streams = {}
        for _ in range(nstreams):
            so_, ssz = U32(pe, p), U32(pe, p + 4)
            name = bytes(pe[p+8:p+8+32]).split(b"\0")[0].decode()
            self.streams[name] = (md + so_, ssz)
            p += 8 + ((len(name) + 1 + 3) & ~3)
        self._parse_tables()

    def off(self, rva):
        for va, sz, ptr in self.secs:
            if va <= rva < va + sz:
                return ptr + rva - va
        raise ValueError(hex(rva))

    def string(self, idx):
        base, _ = self.streams["#Strings"]
        e = self.pe.index(b"\0", base + idx)
        return self.pe[base+idx:e].decode("utf8", "replace")

    def _parse_tables(self):
        pe = self.pe
        base, size = self.streams.get("#~", self.streams.get("#-"))
        heap = pe[base + 6]
        self.ss = 4 if heap & 1 else 2; self.gs = 4 if heap & 2 else 2; self.bs = 4 if heap & 4 else 2
        valid = struct.unpack_from("<Q", pe, base + 8)[0]
        p = base + 24
        self.rows = {}
        for t in range(64):
            if valid >> t & 1:
                self.rows[t] = U32(pe, p); p += 4
        def tsz(t): return 4 if self.rows.get(t, 0) >= 65536 else 2
        def csz(name):
            bits, tabs = CODED[name]
            m = max([self.rows.get(t, 0) for t in tabs if t is not None] + [0])
            return 4 if m >= (1 << (16 - bits)) else 2
        def colsize(c):
            if c == 2: return 2
            if c == 4: return 4
            if c == 'S': return self.ss
            if c == 'G': return self.gs
            if c == 'B': return self.bs
            if c[0] == 'c': return csz(c[1])
            return tsz(c[1])
        self.tab = {}
        for t in sorted(self.rows):
            cols = SCHEMA[t]
            sizes = [colsize(c) for c in cols]
            rsz = sum(sizes)
            self.tab[t] = (p, rsz, sizes)
            p += rsz * self.rows[t]

    def row(self, t, i):  # 1-based
        p, rsz, sizes = self.tab[t]
        o = p + rsz * (i - 1); out = []
        for s in sizes:
            out.append(U16(self.pe, o) if s == 2 else U32(self.pe, o)); o += s
        return out

    def coded(self, name, v):
        bits, tabs = CODED[name]
        return tabs[v & ((1 << bits) - 1)], v >> bits

    def typename(self, t, i):
        if t == 0x01:
            r = self.row(0x01, i); return (self.string(r[2]) + "." if self.string(r[2]) else "") + self.string(r[1])
        if t == 0x02:
            r = self.row(0x02, i); return (self.string(r[2]) + "." if self.string(r[2]) else "") + self.string(r[1])
        return f"<{t:#x}:{i}>"

def build(pe):
    return Asm(bytearray(pe))

def method_bodies(a):
    """yield (typename, methodname, il bytes) for each MethodDef with a body"""
    n = a.rows.get(0x06, 0)
    ntypes = a.rows.get(0x02, 0)
    # type owning each method via MethodList ranges
    starts = [(a.row(0x02, i)[5], i) for i in range(1, ntypes + 1)]
    owner = {}
    for k, (ms, ti) in enumerate(starts):
        me = starts[k+1][0] if k + 1 < len(starts) else n + 1
        for m in range(ms, me): owner[m] = ti
    for m in range(1, n + 1):
        r = a.row(0x06, m)
        rva = r[0]
        if not rva: continue
        try: o = a.off(rva)
        except Exception: continue
        b = a.pe[o]
        if b & 3 == 2: size = b >> 2; il = o + 1
        elif b & 3 == 3:
            hdr = (U16(a.pe, o) >> 12) * 4; size = U32(a.pe, o + 4); il = o + hdr
        else: continue
        yield a.typename(0x02, owner.get(m, 1)), a.string(r[3]), bytes(a.pe[il:il+size])

def memberref_target(a, i):
    r = a.row(0x0A, i)
    t, idx = a.coded("MemberRefParent", r[0])
    return a.typename(t, idx) if t in (0x01, 0x02) else f"<{t}>", a.string(r[1])

if __name__ == "__main__":
    sprx, wants = sys.argv[1], sys.argv[2:]
    a = build(_embedded_cil(open(sprx, "rb").read()))
    print(f"{sprx.split(chr(92))[-1]}: {a.rows.get(0x02,0)} types, {a.rows.get(0x06,0)} methods, {a.rows.get(0x0A,0)} memberrefs")
    # memberrefs we are looking for
    targets = {}
    for i in range(1, a.rows.get(0x0A, 0) + 1):
        tn, mn = memberref_target(a, i)
        key = f"{tn}::{mn}"
        if any(w in key for w in wants): targets[0x0A000000 | i] = key
    print("memberrefs matched:", sorted(set(targets.values()))[:12])
    hits = {}
    for tn, mn, il in method_bodies(a):
        for pos in range(len(il) - 4):
            if il[pos] in (0x28, 0x6F, 0x73):
                tok = struct.unpack_from("<I", il, pos + 1)[0]
                if tok in targets:
                    hits.setdefault((tn, mn), []).append(targets[tok])
    print(f"\nmethods calling the targets: {len(hits)}")
    for (tn, mn), l in sorted(hits.items()):
        print(f"  {tn}::{mn}   -> {sorted(set(l))}")
