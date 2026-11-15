"""Minimal ORBIS/SCE dynamic linker.

PS4 dynamic modules (SCE_DYNAMIC) import/export functions by **NID** -- a hash
of the symbol name, encoded in the dynamic string table as "<nid>#<lib>#<mod>".
This linker:

  1. loads a module and, recursively, its DT_NEEDED .sprx/.prx (searching the
     firmware's lib directories),
  2. assigns each a load base and builds its image bytes,
  3. collects every module's exported NIDs -> address,
  4. resolves the RELA + JMPREL relocations against that global export map.

It works on the decrypted .sprx in the firmware tree (all plain ELF). It does
NOT yet execute the linked image under the CPU -- that is the next step; this
is the link stage, reported standalone so the resolution can be verified.

Usage:
    python -m psemu.dynld system/sys/fs_cleaner.elf --fw-root <firmware>
"""
import argparse
import os
import struct

from .loader import Elf64, PT_LOAD, PT_SCE_RELRO, PT_SCE_DYNLIBDATA, \
    PT_SCE_DYNLIBDATA2, PT_DYNAMIC

# SCE dynamic tags
DT_NEEDED = 1
SCE = {
    "JMPREL": 0x61000029, "PLTRELSZ": 0x6100002d,
    "RELA": 0x6100002f, "RELASZ": 0x61000031,
    "STRTAB": 0x61000035, "SYMTAB": 0x61000039, "SYMTABSZ": 0x6100003f,
    "PLTGOT": 0x61000027,
}

# x86-64 relocation types
R_X86_64_64 = 1
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8

PAGE = 0x1000


def _align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


class Module:
    def __init__(self, name, path, elf, base):
        self.name = name
        self.path = path
        self.elf = elf
        self.base = base
        self.exports = {}      # NID -> absolute address
        self.imports_unresolved = []
        self._parse_dynamic()

    def _parse_dynamic(self):
        d = self.elf.data
        dyn = next((s for s in self.elf.segments if s.type == PT_DYNAMIC), None)
        dlibs = [s for s in self.elf.segments
                 if s.type in (PT_SCE_DYNLIBDATA, PT_SCE_DYNLIBDATA2)]
        self.dlib = max(dlibs, key=lambda s: s.filesz) if dlibs else None
        self.dyn_vals = {}
        self.needed = []
        if dyn is None or self.dlib is None:
            return
        for i in range(0, dyn.filesz, 16):
            tag, val = struct.unpack_from("<QQ", d, dyn.offset + i)
            if tag == 0:
                break
            if tag == DT_NEEDED:
                self.needed.append(val)
            elif tag == 0x0C:                 # DT_INIT
                self.dyn_vals["INIT"] = val
            elif tag == 0x0D:                 # DT_FINI
                self.dyn_vals["FINI"] = val
            for k, t in SCE.items():
                if tag == t:
                    self.dyn_vals[k] = val
        self._do = self.dlib.offset           # dynlibdata file offset
        self._collect_exports()

    def _sym(self, idx):
        name, st_value, st_info, _shndx = self._sym_full(idx)
        return name, st_value, st_info

    def _sym_full(self, idx):
        d = self.elf.data
        base = self._do + self.dyn_vals["SYMTAB"]
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", d, base + idx * 24)
        p = self._do + self.dyn_vals["STRTAB"] + st_name
        end = d.find(b"\x00", p)
        name = d[p:end].decode("latin1", "replace")
        return name, st_value, st_info, st_shndx

    def _nid(self, name):
        return name.split("#", 1)[0] if name else name

    def _collect_exports(self):
        # Walk symbols referenced by relocations to bound the table, plus scan
        # the symtab region up to STRTAB-adjacent end for defined symbols.
        if "SYMTAB" not in self.dyn_vals:
            return
        # symtab runs from SYMTAB offset; bound it by the dynlibdata size.
        start = self.dyn_vals["SYMTAB"]
        if "SYMTABSZ" in self.dyn_vals:       # exact size of the symbol table
            max_syms = self.dyn_vals["SYMTABSZ"] // 24
        else:
            max_syms = max(0, (self.dlib.filesz - start) // 24)
        for i in range(max_syms):
            name, val, info, shndx = self._sym_full(i)
            if not name:
                continue
            bind = info >> 4
            if shndx != 0 and val != 0 and bind in (1, 2):   # defined GLOBAL/WEAK -> export
                self.exports[self._nid(name)] = self.base + val

    def needed_names(self):
        d = self.elf.data
        out = []
        for n in self.needed:
            p = self._do + self.dyn_vals.get("STRTAB", 0) + n
            end = d.find(b"\x00", p)
            out.append(d[p:end].decode("latin1", "replace"))
        return out

    def relocations(self):
        """Yield (reloc_table, offset, info, addend) for RELA then JMPREL."""
        d = self.elf.data
        for tbl, szk in (("RELA", "RELASZ"), ("JMPREL", "PLTRELSZ")):
            if tbl not in self.dyn_vals or szk not in self.dyn_vals:
                continue
            off = self._do + self.dyn_vals[tbl]
            for i in range(0, self.dyn_vals[szk], 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", d, off + i)
                yield tbl, r_off, r_info, r_add


class DynamicLinker:
    def __init__(self, fw_root, log=print):
        self.fw_root = fw_root
        self.log = log
        self.modules = []          # in load order
        self.by_name = {}
        self.global_exports = {}   # NID -> addr
        self._next_base = 0x0000_0001_0000_0000   # 4 GiB, spaced per module
        self._index = self._index_libs()

    def _index_libs(self):
        idx = {}
        for dp, _dirs, files in os.walk(self.fw_root):
            for f in files:
                if f.lower().endswith((".sprx", ".prx")):
                    idx.setdefault(f, os.path.join(dp, f))
        return idx

    def _resolve_lib_file(self, need):
        for cand in (need, need.replace(".prx", ".sprx"),
                     need.replace(".sprx", ".prx")):
            if cand in self._index:
                return self._index[cand]
        return None

    def _image_span(self, elf):
        hi = 0
        for s in elf.segments:
            if s.type in (PT_LOAD, PT_SCE_RELRO) and s.memsz:
                hi = max(hi, s.vaddr + s.memsz)
        return _align_up(hi)

    def load(self, path, name=None):
        name = name or os.path.basename(path)
        if name in self.by_name:
            return self.by_name[name]
        elf = Elf64(path)
        base = self._next_base
        self._next_base += _align_up(self._image_span(elf), 0x10000) + 0x10000
        mod = Module(name, path, elf, base)
        self.modules.append(mod)
        self.by_name[name] = mod
        self.log(f"  loaded {name:<28} base=0x{base:x} "
                 f"exports={len(mod.exports)} needs={len(mod.needed_names())}")
        # recurse into dependencies
        for dep in mod.needed_names():
            f = self._resolve_lib_file(dep)
            if f is None:
                self.log(f"    ! missing dependency: {dep}")
                continue
            self.load(f, dep)
        return mod

    def link(self):
        # global export map
        for m in self.modules:
            for nid, addr in m.exports.items():
                self.global_exports.setdefault(nid, addr)
        resolved = unresolved = relative = 0
        unresolved_nids = set()
        for m in self.modules:
            for tbl, r_off, r_info, r_add in m.relocations():
                rtype = r_info & 0xFFFFFFFF
                sidx = r_info >> 32
                if rtype == R_X86_64_RELATIVE:
                    relative += 1
                    continue
                if rtype in (R_X86_64_JUMP_SLOT, R_X86_64_GLOB_DAT, R_X86_64_64):
                    name, _val, _info = m._sym(sidx)
                    nid = m._nid(name)
                    if nid in self.global_exports:
                        resolved += 1
                    else:
                        unresolved += 1
                        unresolved_nids.add(nid)
        return {
            "modules": len(self.modules),
            "relative": relative,
            "resolved": resolved,
            "unresolved": unresolved,
            "unresolved_nids": sorted(unresolved_nids)[:12],
            "exports_total": len(self.global_exports),
        }


def main():
    ap = argparse.ArgumentParser(description="SCE dynamic linker (link stage).")
    ap.add_argument("module")
    ap.add_argument("--fw-root", required=True)
    args = ap.parse_args()
    path = args.module
    if not os.path.isfile(path):
        path = os.path.join(args.fw_root, args.module)
    ld = DynamicLinker(args.fw_root)
    print(f"== linking {os.path.basename(path)} ==")
    ld.load(path)
    r = ld.link()
    print(f"\n== link result ==")
    print(f"  modules loaded     : {r['modules']}")
    print(f"  total exports (NID): {r['exports_total']}")
    print(f"  RELATIVE relocs    : {r['relative']}")
    print(f"  symbol relocs      : {r['resolved']} resolved, "
          f"{r['unresolved']} unresolved")
    if r["unresolved_nids"]:
        print(f"  sample unresolved  : {', '.join(r['unresolved_nids'])}")


if __name__ == "__main__":
    main()
