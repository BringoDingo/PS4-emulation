"""Build GNM PM4 command buffers in Python.

Emits the same kinds of packets libSceGnmDriver writes (sce::Gnm::DrawCommandBuffer
setVsShader / setPsShader / setUserData / setRenderTarget / drawIndexAuto ...),
so command streams can be produced for tests, or decoded/compared against
streams captured from the firmware. Register numbers are dword indices into the
GFX7 register space; the ones used here are the offsets shadPS4's AmdGpu::Regs
verifies with static_asserts.

    cb = pm4.CommandBuffer()
    cb.set_vs_shader(addr, rsrc1, rsrc2)
    ...
    cb.draw_index_auto(4)
    backend.submit(cb.words())
"""
import struct

import numpy as np

# register spaces (dword index bases)
SH_BASE, CONTEXT_BASE, UCONFIG_BASE, CONFIG_BASE = 0x2C00, 0xA000, 0xC000, 0x2000

# ---- SH registers
SPI_SHADER_PGM_LO_PS = 0x2C08          # LO, HI, RSRC1, RSRC2, USER_DATA_0..15
SPI_SHADER_PGM_LO_VS = 0x2C48
SPI_SHADER_USER_DATA_PS_0 = 0x2C0C
SPI_SHADER_USER_DATA_VS_0 = 0x2C4C
COMPUTE_DISPATCH_INITIATOR = 0x2E00
COMPUTE_NUM_THREAD_X = 0x2E07
COMPUTE_PGM_LO = 0x2E0C
COMPUTE_PGM_RSRC1 = 0x2E12
COMPUTE_USER_DATA_0 = 0x2E40

# ---- context registers
CB_TARGET_MASK = 0xA08E
CB_SHADER_MASK = 0xA08F
PA_SC_SCREEN_SCISSOR_TL = 0xA00C
PA_SC_GENERIC_SCISSOR_TL = 0xA090
PA_CL_VPORT_XSCALE = 0xA10F            # XSCALE XOFFSET YSCALE YOFFSET ZSCALE ZOFFSET
SPI_PS_INPUT_CNTL_0 = 0xA191
SPI_VS_OUT_CONFIG = 0xA1B1
SPI_PS_INPUT_ENA = 0xA1B3
SPI_PS_INPUT_ADDR = 0xA1B4
SPI_PS_IN_CONTROL = 0xA1B6
SPI_BARYC_CNTL = 0xA1B8
SPI_SHADER_POS_FORMAT = 0xA1C3
SPI_SHADER_Z_FORMAT = 0xA1C4
SPI_SHADER_COL_FORMAT = 0xA1C5
CB_BLEND0_CONTROL = 0xA1E0
DB_SHADER_CONTROL = 0xA203
DB_RENDER_CONTROL = 0xA000
DB_DEPTH_VIEW = 0xA002
DB_STENCIL_CLEAR = 0xA00A                # then DB_DEPTH_CLEAR (float)
DB_Z_INFO = 0xA010                       # Z_INFO STENCIL_INFO Z/S_READ Z/S_WRITE SIZE SLICE
DB_STENCIL_CONTROL = 0xA10B
DB_STENCILREFMASK = 0xA10C               # then _BF
DB_DEPTH_CONTROL = 0xA200
Z_16, Z_32_FLOAT = 1, 3
CMP_NEVER, CMP_LESS, CMP_EQUAL, CMP_LEQUAL, CMP_GREATER, CMP_NOTEQUAL, CMP_GEQUAL, CMP_ALWAYS = \
    range(8)
STENCIL_KEEP, STENCIL_ZERO, STENCIL_REPLACE_TEST = 0, 1, 3
PA_CL_CLIP_CNTL = 0xA204
PA_CL_VTE_CNTL = 0xA206
PA_CL_VS_OUT_CNTL = 0xA207
VGT_SHADER_STAGES_EN = 0xA2D5
CB_COLOR0_BASE = 0xA318                # BASE PITCH SLICE VIEW INFO ATTRIB (+15 per target)
CB_COLOR_STRIDE = 15

# ---- uconfig registers
VGT_PRIMITIVE_TYPE = 0xC242
VGT_NUM_INSTANCES = 0xC24D

# ---- type-3 opcodes
IT_NOP, IT_CLEAR_STATE, IT_DISPATCH_DIRECT = 0x10, 0x12, 0x15
IT_INDEX_BASE, IT_DRAW_INDEX_2, IT_CONTEXT_CONTROL, IT_INDEX_TYPE = 0x26, 0x27, 0x28, 0x2A
IT_DRAW_INDEX_AUTO, IT_NUM_INSTANCES, IT_WRITE_DATA = 0x2D, 0x2F, 0x37
IT_WAIT_REG_MEM, IT_INDIRECT_BUFFER = 0x3C, 0x3F
IT_EVENT_WRITE, IT_EVENT_WRITE_EOP, IT_EVENT_WRITE_EOS = 0x46, 0x47, 0x48
IT_DMA_DATA, IT_ACQUIRE_MEM = 0x50, 0x58
IT_SET_CONFIG_REG, IT_SET_CONTEXT_REG = 0x68, 0x69
IT_SET_SH_REG, IT_SET_UCONFIG_REG = 0x76, 0x79

OPCODE_NAMES = {v: k[3:] for k, v in list(globals().items()) if k.startswith("IT_")}

PRIM_TRILIST, PRIM_TRIFAN, PRIM_TRISTRIP, PRIM_RECTLIST = 4, 5, 6, 0x11
TILE_LINEAR_ALIGNED = 8


def f32(x):
    return struct.unpack("<I", struct.pack("<f", float(x)))[0]


class CommandBuffer:
    def __init__(self):
        self._w = []

    def words(self):
        return np.array(self._w, dtype=np.uint32)

    def __len__(self):
        return len(self._w)

    # ------------------------------------------------------------ packets
    def type3(self, opcode, body, compute=False):
        body = [int(x) & 0xFFFFFFFF for x in body]
        if not body:
            body = [0]
        self._w.append((3 << 30) | ((len(body) - 1) << 16) | (opcode << 8) | (int(compute) << 1))
        self._w.extend(body)
        return self

    def _set(self, opcode, base, reg, values):
        if not (base <= reg < base + 0x1000):
            raise ValueError("register %#x outside its space %#x" % (reg, base))
        return self.type3(opcode, [reg - base] + list(values))

    def set_sh_reg(self, reg, *values):
        return self._set(IT_SET_SH_REG, SH_BASE, reg, values)

    def set_context_reg(self, reg, *values):
        return self._set(IT_SET_CONTEXT_REG, CONTEXT_BASE, reg, values)

    def set_uconfig_reg(self, reg, *values):
        return self._set(IT_SET_UCONFIG_REG, UCONFIG_BASE, reg, values)

    def nop(self, n=1):
        return self.type3(IT_NOP, [0] * n)

    def context_control(self):
        return self.type3(IT_CONTEXT_CONTROL, [0x80000000, 0x80000000])

    def clear_state(self):
        return self.type3(IT_CLEAR_STATE, [0])

    def index_type(self, is32):
        return self.type3(IT_INDEX_TYPE, [1 if is32 else 0])

    def num_instances(self, n):
        return self.type3(IT_NUM_INSTANCES, [n])

    def draw_index_auto(self, count):
        return self.type3(IT_DRAW_INDEX_AUTO, [count, 2])          # DI_SRC_SEL_AUTO_INDEX

    def draw_index(self, count, index_addr):
        return self.type3(IT_DRAW_INDEX_2, [count, index_addr & 0xFFFFFFFF,
                                            (index_addr >> 32) & 0xFF, count, 0])

    def dispatch_direct(self, x, y=1, z=1):
        return self.type3(IT_DISPATCH_DIRECT, [x, y, z, 1], compute=True)

    def event_write_eop(self, addr, value, data_sel=1):
        """Write `value` to `addr` when everything before it has finished."""
        return self.type3(IT_EVENT_WRITE_EOP, [
            0x28 | (5 << 8),                                 # CACHE_FLUSH_AND_INV_TS_EVENT
            addr & 0xFFFFFFFF, ((addr >> 32) & 0xFFFF) | (data_sel << 29),
            value & 0xFFFFFFFF, (value >> 32) & 0xFFFFFFFF])

    def write_data(self, addr, values):
        return self.type3(IT_WRITE_DATA, [5 << 8, addr & 0xFFFFFFFF, addr >> 32] + list(values))

    def dma_fill(self, dst, value, nbytes):
        return self.type3(IT_DMA_DATA, [(2 << 29), value, 0, dst & 0xFFFFFFFF, dst >> 32,
                                        nbytes & 0x1FFFFF])

    def indirect_buffer(self, addr, dwords):
        return self.type3(IT_INDIRECT_BUFFER, [addr & 0xFFFFFFFC, (addr >> 32) & 0xFFFF,
                                               dwords & 0xFFFFF])

    # ------------------------------------------------- Gnm-style helpers
    def set_vs_shader(self, code_addr, rsrc1, rsrc2, vs_out_config=0, pos_format=4,
                      out_cntl=0):
        if code_addr & 0xFF:
            raise ValueError("shader code must be 256-byte aligned for SPI_SHADER_PGM_LO")
        a = code_addr >> 8
        self.set_sh_reg(SPI_SHADER_PGM_LO_VS, a & 0xFFFFFFFF, (a >> 32) & 0xFF, rsrc1, rsrc2)
        self.set_context_reg(SPI_VS_OUT_CONFIG, vs_out_config)
        self.set_context_reg(SPI_SHADER_POS_FORMAT, pos_format)
        self.set_context_reg(PA_CL_VS_OUT_CNTL, out_cntl)
        return self

    def set_ps_shader(self, code_addr, rsrc1, rsrc2, input_ena, input_addr, num_interp,
                      col_format, z_format=0, db_shader_control=0x10, cb_shader_mask=0xF):
        if code_addr & 0xFF:
            raise ValueError("shader code must be 256-byte aligned for SPI_SHADER_PGM_LO")
        a = code_addr >> 8
        self.set_sh_reg(SPI_SHADER_PGM_LO_PS, a & 0xFFFFFFFF, (a >> 32) & 0xFF, rsrc1, rsrc2)
        self.set_context_reg(SPI_SHADER_Z_FORMAT, z_format, col_format)
        self.set_context_reg(SPI_PS_INPUT_ENA, input_ena, input_addr)
        self.set_context_reg(SPI_PS_IN_CONTROL, num_interp)
        self.set_context_reg(SPI_BARYC_CNTL, 0)
        self.set_context_reg(DB_SHADER_CONTROL, db_shader_control)
        self.set_context_reg(CB_SHADER_MASK, cb_shader_mask)
        if num_interp:
            # attribute i <- VS param i
            self.set_context_reg(SPI_PS_INPUT_CNTL_0, *range(num_interp))
        return self

    def set_cs_shader(self, code_addr, rsrc1, rsrc2, threads=(64, 1, 1)):
        a = code_addr >> 8
        self.set_sh_reg(COMPUTE_NUM_THREAD_X, *threads)
        self.set_sh_reg(COMPUTE_PGM_LO, a & 0xFFFFFFFF, (a >> 32) & 0xFF)
        self.set_sh_reg(COMPUTE_PGM_RSRC1, rsrc1, rsrc2)
        return self

    def set_user_data(self, stage, values, start=0):
        base = {"vs": SPI_SHADER_USER_DATA_VS_0, "ps": SPI_SHADER_USER_DATA_PS_0,
                "cs": COMPUTE_USER_DATA_0}[stage]
        if values:
            self.set_sh_reg(base + start, *values)
        return self

    def set_render_target(self, slot, addr, pitch, height, fmt=10, number_type=0,
                          tile_mode=TILE_LINEAR_ALIGNED, comp_swap=0):
        """CB_COLORn_* for a colour surface. `pitch` (elements) must be a
        multiple of 8, `pitch * height` a multiple of 64 (the CB tile units)."""
        if addr & 0xFF:
            raise ValueError("render target must be 256-byte aligned")
        if pitch % 8 or (pitch * height) % 64:
            raise ValueError("pitch must be a multiple of 8 and pitch*height of 64")
        info = (fmt << 2) | (number_type << 8) | (comp_swap << 11)
        self.set_context_reg(CB_COLOR0_BASE + CB_COLOR_STRIDE * slot,
                             addr >> 8,                              # BASE
                             pitch // 8 - 1,                         # PITCH.TILE_MAX
                             pitch * height // 64 - 1,               # SLICE.TILE_MAX
                             0,                                      # VIEW
                             info,                                   # INFO
                             tile_mode)                              # ATTRIB
        return self

    def set_viewport(self, width, height, x=0, y=0):
        """Full-target viewport the way GNM sets it: Y flipped (negative yscale)."""
        self.set_context_reg(PA_CL_VPORT_XSCALE, f32(width / 2), f32(x + width / 2),
                             f32(-height / 2), f32(y + height / 2), f32(0.5), f32(0.5))
        self.set_context_reg(PA_CL_VTE_CNTL, 0x43F)
        self.set_context_reg(PA_CL_CLIP_CNTL, 0x00080000)
        scissor = ((x & 0x7FFF) | (y & 0x7FFF) << 16, ((x + width) & 0x7FFF) |
                   ((y + height) & 0x7FFF) << 16)
        self.set_context_reg(PA_SC_SCREEN_SCISSOR_TL, *scissor)
        self.set_context_reg(PA_SC_GENERIC_SCISSOR_TL, *scissor)
        return self

    def set_primitive_type(self, prim):
        return self.set_uconfig_reg(VGT_PRIMITIVE_TYPE, prim)

    # ---- depth / stencil (DB_*)
    def set_depth_target(self, z_addr, s_addr, pitch, height, z_format=Z_32_FLOAT, tile_mode=0):
        """DB_Z_INFO .. DB_DEPTH_SLICE: Z plane at z_addr (0 = none), 8-bit
        stencil plane at s_addr (0 = none), both in `tile_mode` (0-7)."""
        if (z_addr | s_addr) & 0xFF:
            raise ValueError("depth/stencil planes must be 256-byte aligned")
        z_info = (z_format if z_addr else 0) | (tile_mode << 20)
        s_info = (1 if s_addr else 0) | (tile_mode << 20)
        self.set_context_reg(DB_Z_INFO, z_info, s_info,
                             z_addr >> 8, s_addr >> 8,           # READ bases
                             z_addr >> 8, s_addr >> 8,           # WRITE bases
                             (pitch // 8 - 1) | ((height // 8 - 1) << 11),   # DEPTH_SIZE
                             pitch * height // 64 - 1)           # DEPTH_SLICE
        self.set_context_reg(DB_DEPTH_VIEW, 0)
        return self

    def set_depth_control(self, z_enable=False, z_write=False, z_func=CMP_ALWAYS,
                          stencil_enable=False, s_func=CMP_ALWAYS):
        return self.set_context_reg(DB_DEPTH_CONTROL,
                                    int(stencil_enable) | int(z_enable) << 1 |
                                    int(z_write) << 2 | z_func << 4 | s_func << 8)

    def set_stencil(self, ref=0, mask=0xFF, write_mask=0xFF, op_val=1,
                    fail=STENCIL_KEEP, zpass=STENCIL_KEEP, zfail=STENCIL_KEEP):
        ops = fail | zpass << 4 | zfail << 8
        self.set_context_reg(DB_STENCIL_CONTROL, ops | ops << 12)
        rm = ref | mask << 8 | write_mask << 16 | op_val << 24
        return self.set_context_reg(DB_STENCILREFMASK, rm, rm)

    def set_depth_clear(self, depth=None, stencil=None):
        """DB_RENDER_CONTROL clear enables + values: the next draw clears."""
        self.set_context_reg(DB_STENCIL_CLEAR, stencil or 0, f32(depth if depth is not None
                                                                  else 1.0))
        return self.set_context_reg(DB_RENDER_CONTROL,
                                    int(depth is not None) | int(stencil is not None) << 1)


def decode(words, limit=None):
    """List PM4 packets: [(dword_offset, type, opcode_name, body_words)]."""
    words = [int(w) for w in words]
    out, i = [], 0
    while i < len(words) and (limit is None or len(out) < limit):
        h = words[i]
        t = h >> 30
        if t == 2:
            out.append((i, 2, "FILLER", []))
            i += 1
        elif t == 3:
            n = ((h >> 16) & 0x3FFF) + 1
            op = (h >> 8) & 0xFF
            out.append((i, 3, OPCODE_NAMES.get(op, "OP_%02X" % op), words[i + 1:i + 1 + n]))
            i += 1 + n
        elif t == 0:
            n = ((h >> 16) & 0x3FFF) + 1
            out.append((i, 0, "REG_WRITE@%#x" % (h & 0xFFFF), words[i + 1:i + 1 + n]))
            i += 1 + n
        else:
            out.append((i, t, "BAD", []))
            break
    return out
