"""A small CIL disassembler for the managed assemblies embedded in the firmware's .dll.sprx files.

The ShellUI's logic is managed code (AOT-compiled, but the original IL is embedded in the .sprx).
This reads that IL so a method seen in a managed stack (aotsym / stack scans) can be read instead of
guessed at.

    python cil.py app.exe.sprx list Launch            # methods whose Type::Name contains 'Launch'
    python cil.py app.exe.sprx dis AppLauncher::Start # disassemble (substring match, first 6 hits)
    python cil.py app.exe.sprx dis "LaunchTargetInfo::.ctor"

The first argument is a file under the firmware's NPXS20001/psm/Application, system/common/lib or a
full path. Metadata tokens are resolved to names (MethodDef/MemberRef/TypeRef/Field/#US strings).
Only what is needed to read the code is implemented (no generics signatures, no custom attributes).
"""
import os
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
FW = r"D:\Ps4Tools\ps4kernel\firmware"
SEARCH = (FW + r"\system_ex\app\NPXS20001\psm\Application", FW + r"\system\common\lib")

# ---- ECMA-335 metadata layout -------------------------------------------------------------------
CODED = {
    "TypeDefOrRef": (2, ["TypeDef", "TypeRef", "TypeSpec"]),
    "HasConstant": (2, ["Field", "Param", "Property"]),
    "HasCustomAttribute": (5, ["MethodDef", "Field", "TypeRef", "TypeDef", "Param", "InterfaceImpl", "MemberRef",
                               "Module", "DeclSecurity", "Property", "Event", "StandAloneSig", "ModuleRef",
                               "TypeSpec", "Assembly", "AssemblyRef", "File", "ExportedType",
                               "ManifestResource", "GenericParam", "GenericParamConstraint", "MethodSpec"]),
    "HasFieldMarshal": (1, ["Field", "Param"]),
    "HasDeclSecurity": (2, ["TypeDef", "MethodDef", "Assembly"]),
    "MemberRefParent": (3, ["TypeDef", "TypeRef", "ModuleRef", "MethodDef", "TypeSpec"]),
    "HasSemantics": (1, ["Event", "Property"]),
    "MethodDefOrRef": (1, ["MethodDef", "MemberRef"]),
    "MemberForwarded": (1, ["Field", "MethodDef"]),
    "Implementation": (2, ["File", "AssemblyRef", "ExportedType"]),
    "CustomAttributeType": (3, [None, None, "MethodDef", "MemberRef", None]),
    "ResolutionScope": (2, ["Module", "ModuleRef", "AssemblyRef", "TypeRef"]),
    "TypeOrMethodDef": (1, ["TypeDef", "MethodDef"]),
}
# column kinds: number = fixed bytes, "S" string idx, "G" guid idx, "B" blob idx, ("T", table) table idx,
# ("C", codedname)
TABLES = {
    0x00: ("Module", [2, "S", "G", "G", "G"]),
    0x01: ("TypeRef", [("C", "ResolutionScope"), "S", "S"]),
    0x02: ("TypeDef", [4, "S", "S", ("C", "TypeDefOrRef"), ("T", "Field"), ("T", "MethodDef")]),
    0x03: ("FieldPtr", [("T", "Field")]),
    0x04: ("Field", [2, "S", "B"]),
    0x05: ("MethodPtr", [("T", "MethodDef")]),
    0x06: ("MethodDef", [4, 2, 2, "S", "B", ("T", "Param")]),
    0x07: ("ParamPtr", [("T", "Param")]),
    0x08: ("Param", [2, 2, "S"]),
    0x09: ("InterfaceImpl", [("T", "TypeDef"), ("C", "TypeDefOrRef")]),
    0x0A: ("MemberRef", [("C", "MemberRefParent"), "S", "B"]),
    0x0B: ("Constant", [2, ("C", "HasConstant"), "B"]),
    0x0C: ("CustomAttribute", [("C", "HasCustomAttribute"), ("C", "CustomAttributeType"), "B"]),
    0x0D: ("FieldMarshal", [("C", "HasFieldMarshal"), "B"]),
    0x0E: ("DeclSecurity", [2, ("C", "HasDeclSecurity"), "B"]),
    0x0F: ("ClassLayout", [2, 4, ("T", "TypeDef")]),
    0x10: ("FieldLayout", [4, ("T", "Field")]),
    0x11: ("StandAloneSig", ["B"]),
    0x12: ("EventMap", [("T", "TypeDef"), ("T", "Event")]),
    0x13: ("EventPtr", [("T", "Event")]),
    0x14: ("Event", [2, "S", ("C", "TypeDefOrRef")]),
    0x15: ("PropertyMap", [("T", "TypeDef"), ("T", "Property")]),
    0x16: ("PropertyPtr", [("T", "Property")]),
    0x17: ("Property", [2, "S", "B"]),
    0x18: ("MethodSemantics", [2, ("T", "MethodDef"), ("C", "HasSemantics")]),
    0x19: ("MethodImpl", [("T", "TypeDef"), ("C", "MethodDefOrRef"), ("C", "MethodDefOrRef")]),
    0x1A: ("ModuleRef", ["S"]),
    0x1B: ("TypeSpec", ["B"]),
    0x1C: ("ImplMap", [2, ("C", "MemberForwarded"), "S", ("T", "ModuleRef")]),
    0x1D: ("FieldRVA", [4, ("T", "Field")]),
    0x20: ("Assembly", [4, 2, 2, 2, 2, 4, "B", "S", "S"]),
    0x21: ("AssemblyProcessor", [4]),
    0x22: ("AssemblyOS", [4, 4, 4]),
    0x23: ("AssemblyRef", [2, 2, 2, 2, 4, "B", "S", "S", "B"]),
    0x24: ("AssemblyRefProcessor", [4, ("T", "AssemblyRef")]),
    0x25: ("AssemblyRefOS", [4, 4, 4, ("T", "AssemblyRef")]),
    0x26: ("File", [4, "S", "B"]),
    0x27: ("ExportedType", [4, 4, "S", "S", ("C", "Implementation")]),
    0x28: ("ManifestResource", [4, 4, "S", ("C", "Implementation")]),
    0x29: ("NestedClass", [("T", "TypeDef"), ("T", "TypeDef")]),
    0x2A: ("GenericParam", [2, 2, ("C", "TypeOrMethodDef"), "S"]),
    0x2B: ("MethodSpec", [("C", "MethodDefOrRef"), "B"]),
    0x2C: ("GenericParamConstraint", [("T", "GenericParam"), ("C", "TypeDefOrRef")]),
}
NAME2ID = {v[0]: k for k, v in TABLES.items()}

# ---- IL opcodes ----------------------------------------------------------------------------------
# operand kinds: "" none, "i1","u1","i2","u2","i4","i8","r4","r8","tok","br1","br4","sw"
OPS = {}


def _op(code, name, kind=""):
    OPS[code] = (name, kind)


for c, n in enumerate("nop break ldarg.0 ldarg.1 ldarg.2 ldarg.3 ldloc.0 ldloc.1 ldloc.2 ldloc.3 stloc.0 stloc.1 "
                      "stloc.2 stloc.3".split()):
    _op(c, n)
_op(0x0E, "ldarg.s", "u1"); _op(0x0F, "ldarga.s", "u1"); _op(0x10, "starg.s", "u1")
_op(0x11, "ldloc.s", "u1"); _op(0x12, "ldloca.s", "u1"); _op(0x13, "stloc.s", "u1")
_op(0x14, "ldnull"); _op(0x15, "ldc.i4.m1")
for i in range(9):
    _op(0x16 + i, "ldc.i4.%d" % i)
_op(0x1F, "ldc.i4.s", "i1"); _op(0x20, "ldc.i4", "i4"); _op(0x21, "ldc.i8", "i8")
_op(0x22, "ldc.r4", "r4"); _op(0x23, "ldc.r8", "r8")
_op(0x25, "dup"); _op(0x26, "pop"); _op(0x27, "jmp", "tok"); _op(0x28, "call", "tok")
_op(0x29, "calli", "tok"); _op(0x2A, "ret")
for i, n in enumerate("br.s brfalse.s brtrue.s beq.s bge.s bgt.s ble.s blt.s bne.un.s bge.un.s bgt.un.s ble.un.s "
                      "blt.un.s".split()):
    _op(0x2B + i, n, "br1")
for i, n in enumerate("br brfalse brtrue beq bge bgt ble blt bne.un bge.un bgt.un ble.un blt.un".split()):
    _op(0x38 + i, n, "br4")
_op(0x45, "switch", "sw")
for i, n in enumerate("ldind.i1 ldind.u1 ldind.i2 ldind.u2 ldind.i4 ldind.u4 ldind.i8 ldind.i ldind.r4 ldind.r8 "
                      "ldind.ref stind.ref stind.i1 stind.i2 stind.i4 stind.i8 stind.r4 stind.r8 add sub mul div "
                      "div.un rem rem.un and or xor shl shr shr.un neg not conv.i1 conv.i2 conv.i4 conv.i8 conv.r4 "
                      "conv.r8 conv.u4 conv.u8".split()):
    _op(0x46 + i, n)
_op(0x6F, "callvirt", "tok"); _op(0x70, "cpobj", "tok"); _op(0x71, "ldobj", "tok"); _op(0x72, "ldstr", "tok")
_op(0x73, "newobj", "tok"); _op(0x74, "castclass", "tok"); _op(0x75, "isinst", "tok"); _op(0x76, "conv.r.un")
_op(0x79, "unbox", "tok"); _op(0x7A, "throw")
for i, n in enumerate("ldfld ldflda stfld ldsfld ldsflda stsfld stobj".split()):
    _op(0x7B + i, n, "tok")
for i, n in enumerate("conv.ovf.i1.un conv.ovf.i2.un conv.ovf.i4.un conv.ovf.i8.un conv.ovf.u1.un conv.ovf.u2.un "
                      "conv.ovf.u4.un conv.ovf.u8.un conv.ovf.i.un conv.ovf.u.un".split()):
    _op(0x82 + i, n)
_op(0x8C, "box", "tok"); _op(0x8D, "newarr", "tok"); _op(0x8E, "ldlen"); _op(0x8F, "ldelema", "tok")
for i, n in enumerate("ldelem.i1 ldelem.u1 ldelem.i2 ldelem.u2 ldelem.i4 ldelem.u4 ldelem.i8 ldelem.i ldelem.r4 "
                      "ldelem.r8 ldelem.ref stelem.i stelem.i1 stelem.i2 stelem.i4 stelem.i8 stelem.r4 stelem.r8 "
                      "stelem.ref".split()):
    _op(0x90 + i, n)
_op(0xA3, "ldelem", "tok"); _op(0xA4, "stelem", "tok"); _op(0xA5, "unbox.any", "tok")
for i, n in enumerate("conv.ovf.i1 conv.ovf.u1 conv.ovf.i2 conv.ovf.u2 conv.ovf.i4 conv.ovf.u4 conv.ovf.i8 "
                      "conv.ovf.u8".split()):
    _op(0xB3 + i, n)
_op(0xC2, "refanyval", "tok"); _op(0xC3, "ckfinite"); _op(0xC6, "mkrefany", "tok"); _op(0xD0, "ldtoken", "tok")
for i, n in enumerate("conv.u2 conv.u1 conv.i conv.ovf.i conv.ovf.u add.ovf add.ovf.un mul.ovf mul.ovf.un sub.ovf "
                      "sub.ovf.un endfinally".split()):
    _op(0xD1 + i, n)
_op(0xDD, "leave", "br4"); _op(0xDE, "leave.s", "br1"); _op(0xDF, "stind.i"); _op(0xE0, "conv.u")
OPS2 = {0x00: ("arglist", ""), 0x01: ("ceq", ""), 0x02: ("cgt", ""), 0x03: ("cgt.un", ""), 0x04: ("clt", ""),
        0x05: ("clt.un", ""), 0x06: ("ldftn", "tok"), 0x07: ("ldvirtftn", "tok"), 0x09: ("ldarg", "u2"),
        0x0A: ("ldarga", "u2"), 0x0B: ("starg", "u2"), 0x0C: ("ldloc", "u2"), 0x0D: ("ldloca", "u2"),
        0x0E: ("stloc", "u2"), 0x0F: ("localloc", ""), 0x11: ("endfilter", ""), 0x12: ("unaligned.", "u1"),
        0x13: ("volatile.", ""), 0x14: ("tail.", ""), 0x15: ("initobj", "tok"), 0x16: ("constrained.", "tok"),
        0x17: ("cpblk", ""), 0x18: ("initblk", ""), 0x1A: ("rethrow", ""), 0x1C: ("sizeof", "tok"),
        0x1D: ("refanytype", ""), 0x1E: ("readonly.", "")}


def embedded_pe(path):
    """The managed PE inside a .dll.sprx (cached next to the temp dir: the scan of a multi-MB blob takes
    a while)."""
    import hashlib
    import tempfile
    from psemu.syscalls import _embedded_cil
    data = open(path, "rb").read()
    if data[:2] == b"MZ":
        return data
    key = hashlib.sha1(path.encode() + str(len(data)).encode()).hexdigest()[:16]
    cache = os.path.join(tempfile.gettempdir(), "psemu_cil_" + key + ".bin")
    if os.path.isfile(cache):
        return open(cache, "rb").read()
    pe = _embedded_cil(data)
    if pe:
        with open(cache, "wb") as fh:
            fh.write(pe)
    return pe


class Assembly:
    def __init__(self, pe):
        self.pe = pe
        pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
        nsec = struct.unpack_from("<H", pe, pe_off + 6)[0]
        optsz = struct.unpack_from("<H", pe, pe_off + 20)[0]
        opt = pe_off + 24
        magic = struct.unpack_from("<H", pe, opt)[0]
        dd = opt + (96 if magic == 0x10B else 112)
        self.sections = []
        sh = opt + optsz
        for i in range(nsec):
            vsz, va, rsz, raw = struct.unpack_from("<IIII", pe, sh + 8 + i * 40)
            self.sections.append((va, max(vsz, rsz), raw))
        cli_rva = struct.unpack_from("<I", pe, dd + 14 * 8)[0]
        cli = self.off(cli_rva)
        md_rva = struct.unpack_from("<I", pe, cli + 8)[0]
        self.md = self.off(md_rva)
        self._parse_streams()
        self._parse_tables()

    def off(self, rva):
        for va, sz, raw in self.sections:
            if va <= rva < va + sz:
                return raw + rva - va
        raise ValueError("rva %#x" % rva)

    def _parse_streams(self):
        pe, md = self.pe, self.md
        assert pe[md:md + 4] == b"BSJB"
        vlen = struct.unpack_from("<I", pe, md + 12)[0]
        p = md + 16 + vlen + 2
        n = struct.unpack_from("<H", pe, p)[0]
        p += 2
        self.streams = {}
        for _ in range(n):
            o, s = struct.unpack_from("<II", pe, p)
            p += 8
            e = pe.index(b"\0", p)
            name = pe[p:e].decode()
            p = (e + 4) & ~3
            self.streams[name] = (md + o, s)

    def string(self, i):
        o, s = self.streams["#Strings"]
        e = self.pe.index(b"\0", o + i)
        return self.pe[o + i:e].decode("utf-8", "replace")

    def user_string(self, i):
        o, s = self.streams["#US"]
        p = o + i
        b = self.pe[p]
        if b & 0x80 == 0:
            n, p = b, p + 1
        elif b & 0xC0 == 0x80:
            n, p = ((b & 0x3F) << 8) | self.pe[p + 1], p + 2
        else:
            n, p = struct.unpack_from(">I", self.pe, p)[0] & 0x1FFFFFFF, p + 4
        return self.pe[p:p + max(0, n - 1)].decode("utf-16-le", "replace")

    def _parse_tables(self):
        pe = self.pe
        o, s = self.streams["#~"]
        heap = pe[o + 6]
        self.big = {"S": heap & 1, "G": heap & 2, "B": heap & 4}
        valid = struct.unpack_from("<Q", pe, o + 8)[0]
        p = o + 24
        self.rows = {}
        for t in range(64):
            if valid >> t & 1:
                self.rows[t] = struct.unpack_from("<I", pe, p)[0]
                p += 4

        def tsize(t):
            return 4 if self.rows.get(t, 0) >= 0x10000 else 2

        def csize(name):
            bits, tabs = CODED[name]
            mx = max(self.rows.get(NAME2ID[x], 0) for x in tabs if x)
            return 4 if mx >= (1 << (16 - bits)) else 2

        def width(col):
            if isinstance(col, int):
                return col
            if col == "S":
                return 4 if self.big["S"] else 2
            if col == "G":
                return 4 if self.big["G"] else 2
            if col == "B":
                return 4 if self.big["B"] else 2
            if col[0] == "T":
                return tsize(NAME2ID[col[1]])
            return csize(col[1])
        self.table = {}
        for t in sorted(self.rows):
            name, cols = TABLES[t]
            widths = [width(c) for c in cols]
            rowsz = sum(widths)
            rows = []
            for r in range(self.rows[t]):
                vals = []
                q = p
                for w in widths:
                    vals.append(int.from_bytes(pe[q:q + w], "little"))
                    q += w
                rows.append(vals)
                p += rowsz
            self.table[t] = rows

    # --- name resolution
    def coded(self, kind, v):
        bits, tabs = CODED[kind]
        t = tabs[v & ((1 << bits) - 1)]
        return t, (v >> bits)

    def type_name(self, tok):
        t, i = tok >> 24, (tok & 0xFFFFFF)
        if t == 0x02:
            r = self.table[0x02][i - 1]
            ns, nm = self.string(r[2]), self.string(r[1])
            return (ns + "." if ns else "") + nm
        if t == 0x01:
            r = self.table[0x01][i - 1]
            ns, nm = self.string(r[2]), self.string(r[1])
            return (ns + "." if ns else "") + nm
        if t == 0x1B:
            return "<typespec %d>" % i
        return "<type %#x>" % tok

    def method_owner(self, rid):
        tds = self.table[0x02]
        owner = None
        for k, r in enumerate(tds):
            if r[5] <= rid:
                owner = k + 1
            else:
                break
        return owner

    def method_name(self, tok):
        t, i = tok >> 24, tok & 0xFFFFFF
        if t == 0x06:
            r = self.table[0x06][i - 1]
            return "%s::%s" % (self.type_name(0x02000000 | self.method_owner(i)), self.string(r[3]))
        if t == 0x0A:
            r = self.table[0x0A][i - 1]
            kind, idx = self.coded("MemberRefParent", r[0])
            if kind == "TypeRef":
                owner = self.type_name(0x01000000 | idx)
            elif kind == "TypeDef":
                owner = self.type_name(0x02000000 | idx)
            elif kind == "TypeSpec":
                owner = "<spec>"
            else:
                owner = kind
            return "%s::%s" % (owner, self.string(r[1]))
        if t == 0x2B:
            r = self.table[0x2B][i - 1]
            kind, idx = self.coded("MethodDefOrRef", r[0])
            return self.method_name(((0x06 if kind == "MethodDef" else 0x0A) << 24) | idx) + "<>"
        return "<method %#x>" % tok

    def field_name(self, tok):
        i = tok & 0xFFFFFF
        r = self.table[0x04][i - 1]
        owner = None
        for k, td in enumerate(self.table[0x02]):
            if td[4] <= i:
                owner = k + 1
            else:
                break
        return "%s::%s" % (self.type_name(0x02000000 | owner), self.string(r[1]))

    def tok_name(self, tok):
        t = tok >> 24
        if t == 0x70:
            return '"%s"' % self.user_string(tok & 0xFFFFFF).replace("\n", "\\n")
        if t in (0x06, 0x0A, 0x2B):
            return self.method_name(tok)
        if t == 0x04:
            return self.field_name(tok)
        if t in (0x01, 0x02, 0x1B):
            return self.type_name(tok)
        return "tok(%#x)" % tok

    def methods(self):
        """Yield (rid, 'Type::Name', rva) for every MethodDef."""
        for rid, r in enumerate(self.table[0x06], 1):
            yield rid, "%s::%s" % (self.type_name(0x02000000 | self.method_owner(rid)), self.string(r[3])), r[0]

    def disassemble(self, rva):
        pe = self.pe
        p = self.off(rva)
        b = pe[p]
        if b & 3 == 2:
            size, p = b >> 2, p + 1
        else:
            size = struct.unpack_from("<I", pe, p + 4)[0]
            hdr = (struct.unpack_from("<H", pe, p)[0] >> 12) * 4
            p += hdr
        code = pe[p:p + size]
        out, i = [], 0
        while i < len(code):
            start = i
            op = code[i]
            i += 1
            if op == 0xFE:
                name, kind = OPS2.get(code[i], ("fe.%02x" % code[i], ""))
                i += 1
            else:
                name, kind = OPS.get(op, ("op.%02x" % op, ""))
            arg = ""
            if kind in ("u1", "i1", "br1"):
                v = code[i] if kind == "u1" else struct.unpack_from("<b", code, i)[0]
                i += 1
                arg = ("IL_%04x" % (i + v)) if kind == "br1" else str(v)
            elif kind in ("u2",):
                arg = str(struct.unpack_from("<H", code, i)[0]); i += 2
            elif kind in ("i4", "br4"):
                v = struct.unpack_from("<i", code, i)[0]
                i += 4
                arg = ("IL_%04x" % (i + v)) if kind == "br4" else str(v)
            elif kind == "i8":
                arg = str(struct.unpack_from("<q", code, i)[0]); i += 8
            elif kind == "r4":
                arg = str(struct.unpack_from("<f", code, i)[0]); i += 4
            elif kind == "r8":
                arg = str(struct.unpack_from("<d", code, i)[0]); i += 8
            elif kind == "tok":
                arg = self.tok_name(struct.unpack_from("<I", code, i)[0]); i += 4
            elif kind == "sw":
                n = struct.unpack_from("<I", code, i)[0]
                base = i + 4 + 4 * n
                tg = [struct.unpack_from("<i", code, i + 4 + 4 * k)[0] + base for k in range(n)]
                i = base
                arg = "(" + ", ".join("IL_%04x" % t for t in tg) + ")"
            out.append("  IL_%04x: %-12s %s" % (start, name, arg))
        return out


def find_file(name):
    if os.path.isfile(name):
        return name
    for d in SEARCH:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    raise SystemExit("not found: " + name)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return
    asm = Assembly(embedded_pe(find_file(sys.argv[1])))
    cmd, pat = sys.argv[2], sys.argv[3]
    hits = [(rid, n, rva) for rid, n, rva in asm.methods() if pat in n]
    if cmd == "list":
        for rid, n, rva in hits:
            print("%-6d %s%s" % (rid, n, "" if rva else "  (no body)"))
        print(len(hits), "methods")
        return
    for rid, n, rva in hits[:int(sys.argv[4]) if len(sys.argv) > 4 else 6]:
        print("== %s (MethodDef %d)" % (n, rid))
        if rva:
            print("\n".join(asm.disassemble(rva)))


if __name__ == "__main__":
    main()
