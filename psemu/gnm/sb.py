"""PS4 shader binaries: standalone `.sb` files and shaders embedded in ELFs.

Every compiled GNM shader ends with a 28-byte `ShaderBinaryInfo` footer that
starts with the signature "OrbShdr". Just before the footer sit the input
usage slots (how user-data SGPRs are filled: T#, S#, V#, table pointers...).
The machine code starts with the marker `s_mov_b32 vcc_hi, #imm`
(0xBEEB03FF), which is how code is found from a footer.

A standalone `.sb` file also carries a "Shdr" header holding the Gnm stage
registers (SPI_SHADER_PGM_RSRC1/2, SPI_PS_INPUT_ENA, ...).
"""
import os
import struct

from . import isa

SIGNATURE = b"OrbShdr"
CODE_MARKER = 0xBEEB03FF
FOOTER_SIZE = 28

USAGE_TYPES = {
    0x00: "ImmResource", 0x01: "ImmSampler", 0x02: "ImmConstBuffer",
    0x03: "ImmVertexBuffer", 0x04: "ImmRwResource", 0x05: "ImmAluFloatConst",
    0x06: "ImmAluBool32Const", 0x07: "ImmGdsCounterRange", 0x08: "ImmGdsMemoryRange",
    0x09: "ImmGwsBase", 0x0A: "ImmShaderResourceTable", 0x0D: "ImmLdsEsGsSize",
    0x12: "SubPtrFetchShader", 0x13: "PtrResourceTable", 0x14: "PtrInternalResourceTable",
    0x15: "PtrSamplerTable", 0x16: "PtrConstBufferTable", 0x17: "PtrVertexBufferTable",
    0x18: "PtrSoBufferTable", 0x19: "PtrRwResourceTable", 0x1A: "PtrInternalGlobalTable",
    0x1B: "PtrExtendedUserData", 0x1C: "PtrIndirectResourceTable",
    0x1D: "PtrIndirectInternalResourceTable", 0x1E: "PtrIndirectRwResourceTable",
}

# The footer's 4-bit `type` field is not a stage number (compute shaders in
# libSceDepth carry both 0 and 4), and shadPS4 ignores it too. The stage is
# therefore classified from the code itself, see `classify_stage`.


def classify_stage(prog):
    """vs: exports a position; ps: exports colour/depth or interpolates;
    gs: emits vertices with s_sendmsg; cs: everything else (no exports).
    ES/LS/HS stages also have no exports and are reported as cs."""
    pos = mrt = interp = gs_msg = False
    for ins in prog.values():
        if ins.enc == "EXP":
            t = ins.f["tgt"]
            pos |= 12 <= t <= 15
            mrt |= t <= 9          # mrt0-7, mrtz, and null (PS that only stores)
        elif ins.enc == "VINTRP":
            interp = True
        elif ins.name == "s_sendmsg" and (ins.f["simm16"] & 0xF) == 2:   # MSG_GS
            gs_msg = True
    if pos:
        return "vs"
    if mrt or interp:
        return "ps"
    if gs_msg:
        return "gs"
    return "cs"


def _vgpr_inputs(prog):
    """VGPRs read before any write, in linear code order: the hardware-loaded
    PS inputs (barycentrics, position...). Approximate but good enough to pick
    SPI_PS_INPUT_ENA for shaders that come without registers."""
    written, inputs = set(), set()

    def read(r, n=1):
        for k in range(r, r + n):
            if k not in written:
                inputs.add(k)

    for off in sorted(prog):
        ins = prog[off]
        f, e = ins.f, ins.enc
        if e in ("VOP1", "VOP2", "VOPC", "VOP3"):
            for k in ("src0", "src1", "src2"):
                c = f.get(k)
                if c is not None and c >= 256:
                    read(c - 256)
            if e != "VOPC" and not (e == "VOP3" and ins.op < 256):
                written.add(f["vdst"])
        elif e == "VINTRP":
            if ins.op != 2:
                read(f["vsrc"])
            written.add(f["vdst"])
        elif e in ("MIMG", "MUBUF", "MTBUF"):
            read(f["vaddr"], 2 if e == "MIMG" else 1)
            if ins.name and "store" in ins.name:
                read(f["vdata"])
            else:
                written.update(range(f["vdata"], f["vdata"] + 4))
        elif e == "EXP":
            for i in range(4):
                if f["en"] >> i & 1:
                    read(f["vsrc"][i])
        elif e == "DS":
            read(f["addr"])
            written.add(f["vdst"])
    return inputs


def infer_ps_regs(prog):
    """Best-effort PS registers for shaders that come without them (embedded
    in ELFs): interpolant count from v_interp attrs, colour export format from
    the exports, and SPI_PS_INPUT_ENA from which input VGPRs the code reads
    (perspective-centre I/J in v0/v1, then POS_X/Y/Z/W)."""
    nattr = 0
    col = 0
    for ins in prog.values():
        if ins.enc == "VINTRP":
            nattr = max(nattr, ins.f["attr"] + 1)
        elif ins.enc == "EXP" and ins.f["tgt"] < 8:
            fmt = 4 if ins.f["compr"] else 9          # FP16_ABGR or 32_ABGR
            col |= fmt << (4 * ins.f["tgt"])
    ins_used = _vgpr_inputs(prog)
    top = max(ins_used) if ins_used else -1
    ena = 0x2                                    # PERSP_CENTER -> v0, v1
    for i in range(4):                           # POS_X..POS_W -> v2..v5
        if top >= 2 + i:
            ena |= 1 << (8 + i)
    return {"ps_input_ena": ena, "ps_input_addr": ena, "ps_in_control": nattr,
            "col_format": col}


class UsageSlot:
    __slots__ = ("usage", "api_slot", "start_reg", "flags")

    def __init__(self, b):
        self.usage, self.api_slot, self.start_reg, self.flags = b[0], b[1], b[2], b[3]

    @property
    def name(self):
        return USAGE_TYPES.get(self.usage, "Usage%#x" % self.usage)

    @property
    def reg_count(self):
        if self.usage in (0x00, 0x04):          # T# : 4 or 8 dwords
            return 8 if self.flags & 1 else 4
        if self.usage in (0x01, 0x02, 0x03):     # S#, V# : 4 dwords
            return 4
        if self.usage >= 0x12:                   # 64-bit pointers
            return 2
        return 1

    def __repr__(self):
        return "%s(api=%d, s%d..s%d)" % (self.name, self.api_slot, self.start_reg,
                                         self.start_reg + self.reg_count - 1)


class Shader:
    """One shader found in a file. `blob` is the whole containing file so
    pc-relative data (s_getpc_b64 tables) stays addressable."""

    def __init__(self, path, blob, code_off, footer_off):
        self.path = path
        self.blob = blob
        self.code_off = code_off
        self.footer_off = footer_off
        f = blob[footer_off:footer_off + FOOTER_SIZE]
        self.version = f[7]
        bits = struct.unpack_from("<I", f, 8)[0]
        self.pssl = bits & 1
        self.cached = (bits >> 1) & 1
        self.type = (bits >> 2) & 0xF
        self.source_type = (bits >> 6) & 3
        self.length = bits >> 8
        self.usage_off_dw = f[12]
        self.num_slots = f[13]
        self.srt_flags = f[14]
        self.hash0, self.hash1, self.crc32 = struct.unpack_from("<III", f, 16)
        masks_at = footer_off - self.usage_off_dw * 4
        slots_at = masks_at - self.num_slots * 4
        self.slots = [UsageSlot(blob[slots_at + 4 * i: slots_at + 4 * i + 4])
                      for i in range(self.num_slots)] if slots_at >= code_off else []
        self.regs = {}           # stage registers (standalone .sb only)
        self._prog = None
        self._stage = None

    @property
    def code(self):
        return self.blob[self.code_off:self.code_off + self.length]

    @property
    def stage(self):
        if self._stage is None:
            try:
                self._stage = classify_stage(self.program)
            except isa.DecodeError:
                self._stage = "unknown"
        return self._stage

    def default_regs(self):
        """Stage registers to use when running the shader: the .sb header's
        values when present, otherwise inferred from the code."""
        regs = {}
        if self.stage == "ps":
            regs.update(infer_ps_regs(self.program))
        regs.update(self.regs)
        return regs

    @property
    def program(self):
        """{offset: Insn}; decoded lazily over the declared code length."""
        if self._prog is None:
            self._prog = isa.decode_program(self.blob, self.code_off,
                                            max_bytes=self.length)
        return self._prog

    def disassemble(self):
        return isa.disassemble(self.program)

    def user_sgpr_count(self):
        if "rsrc2" in self.regs:
            return (self.regs["rsrc2"] >> 1) & 0x1F
        return max((s.start_reg + s.reg_count for s in self.slots if s.start_reg < 16),
                   default=0)

    def describe(self):
        out = ["%s @code+%#x len=%d stage=%s(type %d) hash=%08x%08x" % (
            os.path.basename(self.path), self.code_off, self.length, self.stage,
            self.type, self.hash1, self.hash0)]
        for s in self.slots:
            out.append("   slot %r" % s)
        for k, v in self.regs.items():
            out.append("   %-16s = %#010x" % (k, v))
        return "\n".join(out)


def _find_code_start(blob, footer_off, length):
    """Walk back from the footer to the code marker."""
    latest = footer_off - length
    for start in range(latest - (latest % 4), max(-1, latest - 2048), -4):
        if start < 0:
            break
        if struct.unpack_from("<I", blob, start)[0] == CODE_MARKER:
            return start
    # unaligned files: try byte granularity
    for start in range(latest, max(-1, latest - 2048), -1):
        if start >= 0 and blob[start:start + 4] == b"\xff\x03\xeb\xbe":
            return start
    return None


def find_shaders(blob, path="<mem>"):
    """Yield every Shader embedded in `blob`."""
    pos = 0
    while True:
        at = blob.find(SIGNATURE, pos)
        if at < 0:
            return
        pos = at + 1
        if at + FOOTER_SIZE > len(blob):
            continue
        length = struct.unpack_from("<I", blob, at + 8)[0] >> 8
        if not (4 <= length <= 0x100000):
            continue
        start = _find_code_start(blob, at, length)
        if start is None:
            continue
        yield Shader(path, blob, start, at)


# Field order of the Gnm stage-register structs that follow the "Shdr" header.
_STAGE_REGS = {
    "vs": ("pgm_lo", "pgm_hi", "rsrc1", "rsrc2", "vs_out_config", "pos_format",
           "pa_cl_vs_out_cntl"),
    "ps": ("pgm_lo", "pgm_hi", "rsrc1", "rsrc2", "z_format", "col_format",
           "ps_input_ena", "ps_input_addr", "ps_in_control", "baryc_cntl",
           "db_shader_control", "cb_shader_mask"),
    "cs": ("pgm_lo", "pgm_hi", "rsrc1", "rsrc2", "num_thread_x", "num_thread_y",
           "num_thread_z"),
}


def load_sb(path):
    """Load a standalone .sb file (the shader plus its stage registers)."""
    with open(path, "rb") as fh:
        blob = fh.read()
    shaders = list(find_shaders(blob, path))
    if not shaders:
        raise ValueError("%s: no OrbShdr footer" % path)
    sh = shaders[0]
    hdr = blob.find(b"Shdr")
    if 0 <= hdr < sh.code_off:
        base = hdr + 0x10           # ShaderCommonData, then the stage registers
        regs_at = base + 8
        names = _STAGE_REGS.get(sh.stage, ("pgm_lo", "pgm_hi", "rsrc1", "rsrc2"))
        for i, n in enumerate(names):
            if regs_at + 4 * i + 4 <= sh.code_off:
                sh.regs[n] = struct.unpack_from("<I", blob, regs_at + 4 * i)[0]
    return sh


def scan_tree(root, exts=None):
    """Yield (path, [Shader]) for every file under `root` containing shaders."""
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            p = os.path.join(dp, fn)
            if exts and not fn.lower().endswith(exts):
                continue
            try:
                with open(p, "rb") as fh:
                    blob = fh.read()
            except OSError:
                continue
            if SIGNATURE not in blob:
                continue
            found = list(find_shaders(blob, p))
            if found:
                yield p, found
