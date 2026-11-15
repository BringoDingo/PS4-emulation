"""ELF loader: parse a 64-bit FreeBSD/ORBIS ELF and map its segments into a
Unicorn memory space.

Only the pieces the emulator needs live here (header + program headers). It is
deliberately independent of decode_elf.py so psemu stands on its own.
"""
import struct
from unicorn import (
    UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
)

PAGE = 0x1000


def align_down(x, a=PAGE):
    return x & ~(a - 1)


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


PT_LOAD = 0x00000001
PT_DYNAMIC = 0x00000002
PT_INTERP = 0x00000003
PT_TLS = 0x00000007

# PS4/SCE segment types we might see; treated like PT_LOAD if they carry a
# vaddr + file bytes, otherwise ignored for mapping.
PT_SCE_RELRO = 0x61000010
PT_SCE_DYNLIBDATA = 0x61000000
PT_SCE_PROCPARAM = 0x61000001       # sceProcParam (executables)
PT_SCE_MODULE_PARAM = 0x61000002    # sceModuleParam (libraries)
PT_SCE_DYNLIBDATA2 = PT_SCE_PROCPARAM   # old (wrong) name kept for imports

# ELF e_type values of interest
ET_EXEC = 0x0002
ET_SCE_DYNAMIC = 0xFE10

# dynamic tags
DT_NEEDED = 1
DT_SCE_STRTAB = 0x61000035


class Segment:
    def __init__(self, p_type, flags, offset, vaddr, filesz, memsz, align):
        self.type = p_type
        self.flags = flags            # ELF p_flags (1=X 2=W 4=R)
        self.offset = offset
        self.vaddr = vaddr
        self.filesz = filesz
        self.memsz = memsz
        self.align = align

    def uc_prot(self):
        prot = UC_PROT_NONE
        if self.flags & 4:
            prot |= UC_PROT_READ
        if self.flags & 2:
            prot |= UC_PROT_WRITE
        if self.flags & 1:
            prot |= UC_PROT_EXEC
        # Unicorn needs at least READ to fetch/execute; be permissive on RX/R.
        if prot == UC_PROT_NONE:
            prot = UC_PROT_READ
        return prot

    def prot_str(self):
        return ("r" if self.flags & 4 else "-") + \
               ("w" if self.flags & 2 else "-") + \
               ("x" if self.flags & 1 else "-")


class Elf64:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if d[4] != 2:
            raise ValueError("not 64-bit ELF")

        (self.e_type, self.e_machine, _ver, self.entry, self.phoff, self.shoff,
         self.flags, self.ehsize, self.phentsize, self.phnum,
         self.shentsize, self.shnum, self.shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", d, 16)

        if self.e_machine not in (0x3E, 0x3F):
            raise ValueError(f"not x86-64 (machine=0x{self.e_machine:x})")

        self.segments = []
        self.tls = None
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            (p_type, p_flags, p_offset, p_vaddr, p_paddr,
             p_filesz, p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", d, off)
            seg = Segment(p_type, p_flags, p_offset, p_vaddr,
                          p_filesz, p_memsz, p_align)
            if p_type == PT_TLS:
                self.tls = seg
            self.segments.append(seg)

        self.is_dynamic = any(s.type in (PT_DYNAMIC, PT_INTERP) for s in self.segments) \
            or self.e_type == ET_SCE_DYNAMIC
        self.interp = self._read_interp()

    def _read_interp(self):
        for s in self.segments:
            if s.type == PT_INTERP:
                return self.data[s.offset:s.offset + s.filesz].split(b"\x00")[0]\
                    .decode("latin1", "replace")
        return None

    def needed_libraries(self):
        """Parse DT_NEEDED entries (names live in the SCE dynlib string table)."""
        dyn = next((s for s in self.segments if s.type == PT_DYNAMIC), None)
        if dyn is None:
            return []
        dynlib = [s for s in self.segments
                  if s.type in (PT_SCE_DYNLIBDATA, PT_SCE_DYNLIBDATA2)]
        if not dynlib:
            return []
        strseg = max(dynlib, key=lambda s: s.filesz)
        needed_offs, strtab = [], 0
        for i in range(0, dyn.filesz, 16):
            tag, val = struct.unpack_from("<QQ", self.data, dyn.offset + i)
            if tag == 0:
                break
            if tag == DT_NEEDED:
                needed_offs.append(val)
            elif tag == DT_SCE_STRTAB:
                strtab = val
        base = strseg.offset + strtab
        out = []
        for n in needed_offs:
            p = base + n
            end = self.data.find(b"\x00", p)
            out.append(self.data[p:end].decode("latin1", "replace"))
        return out

    def loadable(self):
        for s in self.segments:
            # map PT_LOAD / SCE_RELRO; allow vaddr 0 (position-dependent at base 0)
            if s.type in (PT_LOAD, PT_SCE_RELRO) and s.memsz > 0:
                yield s

    def map_into(self, uc, log=print, mapper=None):
        """Map every loadable segment into the Unicorn instance `uc`
        (through `mapper(start, size, prot)` when given, e.g. HostVM.map).

        Returns (lo, hi) virtual-address bounds of the loaded image.
        """
        lo = None
        hi = 0
        # First pass: map page-aligned regions (merging is unnecessary for this
        # module since segments are 0x4000-aligned and don't overlap pages).
        for s in self.loadable():
            start = align_down(s.vaddr)
            end = align_up(s.vaddr + s.memsz)
            size = end - start
            (mapper or uc.mem_map)(start, size, s.uc_prot())
            chunk = self.data[s.offset:s.offset + s.filesz]
            uc.mem_write(s.vaddr, chunk)
            log(f"  map 0x{start:012x}-0x{end:012x} {s.prot_str()}  "
                f"(vaddr 0x{s.vaddr:x}, filesz 0x{s.filesz:x}, memsz 0x{s.memsz:x})")
            lo = start if lo is None else min(lo, start)
            hi = max(hi, end)
        return lo, hi
