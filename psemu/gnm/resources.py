"""GNM resource descriptors (V#, T#, S#), data formats and texture sampling.

Descriptors are the 4/8-dword records shaders load into SGPRs:
  V#  buffer   (4 dwords)  - vertex/constant/structured buffers
  T#  texture  (8 dwords)  - images
  S#  sampler  (4 dwords)  - filtering and addressing
Field layouts follow the GFX7 (Sea Islands) register spec.
"""
import numpy as np

# ------------------------------------------------------------- formats
# data_format -> (component bit widths) for the plain (non-block) formats
DATA_FORMATS = {
    1: (8,), 2: (16,), 3: (8, 8), 4: (32,), 5: (16, 16), 6: (10, 11, 11),
    7: (11, 11, 10), 8: (10, 10, 10, 2), 9: (2, 10, 10, 10), 10: (8, 8, 8, 8),
    11: (32, 32), 12: (16, 16, 16, 16), 13: (32, 32, 32), 14: (32, 32, 32, 32),
    16: (5, 6, 5), 17: (1, 5, 5, 5), 18: (5, 5, 5, 1), 19: (4, 4, 4, 4),
    20: (8, 24), 21: (24, 8),
}
DATA_FORMAT_NAMES = {
    0: "INVALID", 1: "8", 2: "16", 3: "8_8", 4: "32", 5: "16_16", 6: "10_11_11",
    7: "11_11_10", 8: "10_10_10_2", 9: "2_10_10_10", 10: "8_8_8_8", 11: "32_32",
    12: "16_16_16_16", 13: "32_32_32", 14: "32_32_32_32", 16: "5_6_5", 17: "1_5_5_5",
    18: "5_5_5_1", 19: "4_4_4_4", 20: "8_24", 21: "24_8", 22: "X24_8_32", 32: "GB_GR",
    33: "BG_RG", 34: "5_9_9_9", 35: "BC1", 36: "BC2", 37: "BC3", 38: "BC4",
    39: "BC5", 40: "BC6", 41: "BC7",
}
NUM_FORMAT_NAMES = {0: "UNORM", 1: "SNORM", 2: "USCALED", 3: "SSCALED", 4: "UINT",
                    5: "SINT", 6: "SNORM_OGL", 7: "FLOAT", 9: "SRGB"}
BLOCK_FORMATS = {35: 8, 36: 16, 37: 16, 38: 8, 39: 16}   # bytes per 4x4 block

# AMD packed-format names list components from MSB to LSB, so X (red) is the
# *last* number: "2_10_10_10" is R10 G10 B10 A2 with R at bit 0.
# Component widths starting from bit 0 (X first):
_PACKED_ORDER = {6: (11, 11, 10), 7: (10, 11, 11), 8: (2, 10, 10, 10),
                 9: (10, 10, 10, 2), 16: (5, 6, 5), 17: (5, 5, 5, 1),
                 18: (1, 5, 5, 5), 19: (4, 4, 4, 4), 20: (24, 8), 21: (8, 24)}


def bytes_per_element(dfmt):
    if dfmt in BLOCK_FORMATS:
        return BLOCK_FORMATS[dfmt]
    return sum(DATA_FORMATS.get(dfmt, (32,))) // 8


def _f16(bits):
    return bits.astype(np.uint16).view(np.float16).astype(np.float32)


def _f11(bits, mbits):
    """Unsigned small float (11-bit: 6m5e, 10-bit: 5m5e)."""
    bits = bits.astype(np.uint32)
    m = bits & ((1 << mbits) - 1)
    e = (bits >> mbits) & 0x1F
    out = np.where(e == 0, m / float(1 << mbits) * 2.0 ** -14,
                   (1 + m / float(1 << mbits)) * np.exp2(e.astype(np.float32) - 15))
    out = np.where(e == 31, np.where(m == 0, np.inf, np.nan), out)
    return out.astype(np.float32)


def convert_components(raw, widths, nfmt, dfmt=None):
    """raw: uint32 array [..., n] of component bit patterns (each already
    shifted down), widths: bits per component. Returns float32 or the raw
    integers reinterpreted as uint32 (for UINT/SINT/FLOAT32)."""
    out = []
    for i, w in enumerate(widths):
        c = raw[..., i].astype(np.uint32)
        if nfmt == 7:  # FLOAT
            if w == 32:
                out.append(c)
                continue
            if w == 16:
                v = _f16(c)
            elif w in (11, 10):
                v = _f11(c, w - 5)
            else:
                v = c.astype(np.float32)
        elif nfmt in (0, 9):  # UNORM / SRGB
            v = c.astype(np.float32) / float((1 << w) - 1)
            if nfmt == 9 and i < 3:
                v = np.where(v <= 0.04045, v / 12.92, ((v + 0.055) / 1.055) ** 2.4).astype(np.float32)
        elif nfmt in (1, 6):  # SNORM
            s = (c.astype(np.int64) ^ (1 << (w - 1))) - (1 << (w - 1))
            v = np.maximum(s.astype(np.float32) / float((1 << (w - 1)) - 1), -1.0)
        elif nfmt == 2:
            v = c.astype(np.float32)
        elif nfmt == 3:
            s = (c.astype(np.int64) ^ (1 << (w - 1))) - (1 << (w - 1))
            v = s.astype(np.float32)
        elif nfmt == 4:
            out.append(c)
            continue
        elif nfmt == 5:
            s = (c.astype(np.int64) ^ (1 << (w - 1))) - (1 << (w - 1))
            out.append(s.astype(np.int32).view(np.uint32))
            continue
        else:
            v = c.astype(np.float32)
        out.append(v.astype(np.float32).view(np.uint32))
    return np.stack(out, axis=-1)


def decode_elements(raw_bytes, dfmt, nfmt):
    """raw_bytes: uint8 [..., bpe]. Returns uint32 bit patterns [..., ncomp]
    (floats are stored as their bit patterns, ints as ints)."""
    widths = DATA_FORMATS.get(dfmt)
    if widths is None:
        raise NotImplementedError("data format %s" % DATA_FORMAT_NAMES.get(dfmt, dfmt))
    bpe = sum(widths) // 8
    if dfmt in _PACKED_ORDER:
        order = _PACKED_ORDER[dfmt]
        word = np.zeros(raw_bytes.shape[:-1], dtype=np.uint64)
        for b in range(bpe):
            word |= raw_bytes[..., b].astype(np.uint64) << np.uint64(8 * b)
        comps, sh = [], 0
        for w in order:
            comps.append(((word >> np.uint64(sh)) & np.uint64((1 << w) - 1)).astype(np.uint32))
            sh += w
        return convert_components(np.stack(comps, -1), order, nfmt, dfmt)
    comps, off = [], 0
    for w in widths:
        nb = w // 8
        c = np.zeros(raw_bytes.shape[:-1], dtype=np.uint32)
        for b in range(nb):
            c |= raw_bytes[..., off + b].astype(np.uint32) << np.uint32(8 * b)
        comps.append(c)
        off += nb
    return convert_components(np.stack(comps, -1), widths, nfmt, dfmt)


def encode_elements(values, dfmt, nfmt):
    """Inverse of decode_elements for stores. values: uint32 bit patterns
    [..., ncomp] (floats as bits). Returns uint8 [..., bpe]."""
    widths = DATA_FORMATS.get(dfmt)
    if widths is None:
        raise NotImplementedError("store format %s" % DATA_FORMAT_NAMES.get(dfmt, dfmt))
    order = _PACKED_ORDER.get(dfmt, widths)
    word = np.zeros(values.shape[:-1], dtype=np.uint64)
    sh = 0
    for i, w in enumerate(order):
        c = values[..., i] if i < values.shape[-1] else np.zeros(values.shape[:-1], np.uint32)
        if nfmt == 7 and w == 32:
            bits = c.astype(np.uint64)
        elif nfmt == 7 and w == 16:
            bits = c.view(np.float32).astype(np.float16).view(np.uint16).astype(np.uint64)
        elif nfmt in (0, 9):
            f = np.clip(c.view(np.float32), 0, 1)
            bits = np.rint(f * ((1 << w) - 1)).astype(np.uint64)
        elif nfmt in (1, 6):
            f = np.clip(c.view(np.float32), -1, 1)
            bits = (np.rint(f * ((1 << (w - 1)) - 1)).astype(np.int64) & ((1 << w) - 1)).astype(np.uint64)
        else:
            bits = c.astype(np.uint64) & np.uint64((1 << w) - 1)
        word |= (bits & np.uint64((1 << w) - 1)) << np.uint64(sh)
        sh += w
    nb = sh // 8
    return np.stack([((word >> np.uint64(8 * b)) & np.uint64(0xFF)).astype(np.uint8)
                     for b in range(nb)], -1)


# ------------------------------------------------------------- descriptors

def _b(v, lo, n):
    return (int(v) >> lo) & ((1 << n) - 1)


class VSharp:
    """Buffer resource (4 dwords)."""

    def __init__(self, d):
        d = [int(x) for x in d]
        self.raw = tuple(d)
        self.base = d[0] | (_b(d[1], 0, 16) << 32)
        self.stride = _b(d[1], 16, 14)
        self.swizzle = _b(d[1], 31, 1)
        self.num_records = d[2]
        self.dst_sel = tuple(_b(d[3], 3 * i, 3) for i in range(4))
        self.nfmt = _b(d[3], 12, 3)
        self.dfmt = _b(d[3], 15, 4)
        self.element_size = _b(d[3], 19, 2)
        self.index_stride = _b(d[3], 21, 2)
        self.add_tid = _b(d[3], 23, 1)

    def __repr__(self):
        return "V#(base=%#x stride=%d records=%d fmt=%s/%s)" % (
            self.base, self.stride, self.num_records,
            DATA_FORMAT_NAMES.get(self.dfmt), NUM_FORMAT_NAMES.get(self.nfmt))


def make_vsharp(base, num_records, stride=0, dfmt=14, nfmt=7, dst_sel=(4, 5, 6, 7)):
    d3 = (dst_sel[0] | dst_sel[1] << 3 | dst_sel[2] << 6 | dst_sel[3] << 9 |
          nfmt << 12 | dfmt << 15)
    return [base & 0xFFFFFFFF, ((base >> 32) & 0xFFFF) | (stride << 16), num_records, d3]


TEX_TYPES = {8: "1d", 9: "2d", 10: "3d", 11: "cube", 12: "1d_array", 13: "2d_array",
             14: "2d_msaa", 15: "2d_msaa_array"}
TILE_LINEAR = 8   # Gnm kTileModeDisplay_LinearAligned


class TSharp:
    """Texture resource (8 dwords; first 4 for buffer-like 128-bit use)."""

    def __init__(self, d):
        d = [int(x) for x in d] + [0] * (8 - len(d))
        self.raw = tuple(d)
        self.base = (d[0] | (_b(d[1], 0, 8) << 32)) << 8
        self.min_lod = _b(d[1], 8, 12)
        self.dfmt = _b(d[1], 20, 6)
        self.nfmt = _b(d[1], 26, 4)
        self.width = _b(d[2], 0, 14) + 1
        self.height = _b(d[2], 14, 14) + 1
        self.dst_sel = tuple(_b(d[3], 3 * i, 3) for i in range(4))
        self.base_level = _b(d[3], 12, 4)
        self.last_level = _b(d[3], 16, 4)
        self.tiling = _b(d[3], 20, 5)
        self.pow2pad = _b(d[3], 25, 1)
        self.type = _b(d[3], 28, 4)
        self.depth = _b(d[4], 0, 13) + 1
        self.pitch = _b(d[4], 13, 14) + 1
        self.base_array = _b(d[5], 0, 13)
        self.last_array = _b(d[5], 13, 13)

    @property
    def coord_count(self):
        return {8: 1, 9: 2, 10: 3, 11: 3, 12: 2, 13: 3, 14: 2, 15: 3}.get(self.type, 2)

    def __repr__(self):
        return "T#(%#x %dx%d %s %s/%s tile=%d)" % (
            self.base, self.width, self.height, TEX_TYPES.get(self.type, self.type),
            DATA_FORMAT_NAMES.get(self.dfmt), NUM_FORMAT_NAMES.get(self.nfmt), self.tiling)


def make_tsharp(base, width, height, dfmt, nfmt, pitch=None, dst_sel=(4, 5, 6, 7),
                tiling=TILE_LINEAR, ttype=9):
    pitch = pitch or width
    a = base >> 8
    d = [a & 0xFFFFFFFF, ((a >> 32) & 0xFF) | (dfmt << 20) | (nfmt << 26),
         (width - 1) | ((height - 1) << 14),
         dst_sel[0] | dst_sel[1] << 3 | dst_sel[2] << 6 | dst_sel[3] << 9 |
         (tiling << 20) | (ttype << 28),
         (pitch - 1) << 13, 0, 0, 0]
    return d


class SSharp:
    """Sampler (4 dwords)."""

    def __init__(self, d):
        d = [int(x) for x in d]
        self.raw = tuple(d)
        self.clamp = (_b(d[0], 0, 3), _b(d[0], 3, 3), _b(d[0], 6, 3))
        self.depth_compare = _b(d[0], 12, 3)
        self.force_unnorm = _b(d[0], 15, 1)
        self.mag = _b(d[2], 20, 2)
        self.min = _b(d[2], 22, 2)
        self.mip = _b(d[2], 26, 2)
        self.border = _b(d[3], 30, 2)

    def __repr__(self):
        return "S#(clamp=%s mag=%d min=%d)" % (self.clamp, self.mag, self.min)


def make_ssharp(clamp=2, filt=1):
    return [clamp | clamp << 3 | clamp << 6, 0, (filt << 20) | (filt << 22), 0]


# ------------------------------------------------------------- textures

def _bc_color_block(blk):
    """blk: uint8 [N, 8] BC1 colour block -> float32 [N, 16, 4]."""
    c0 = blk[:, 0].astype(np.uint32) | blk[:, 1].astype(np.uint32) << 8
    c1 = blk[:, 2].astype(np.uint32) | blk[:, 3].astype(np.uint32) << 8
    idx = (blk[:, 4].astype(np.uint32) | blk[:, 5].astype(np.uint32) << 8 |
           blk[:, 6].astype(np.uint32) << 16 | blk[:, 7].astype(np.uint32) << 24)

    def rgb(c):
        return np.stack([((c >> 11) & 31) / 31.0, ((c >> 5) & 63) / 63.0, (c & 31) / 31.0], -1)
    p0, p1 = rgb(c0), rgb(c1)
    four = (c0 > c1)[:, None]
    p2 = np.where(four, (2 * p0 + p1) / 3, (p0 + p1) / 2)
    p3 = np.where(four, (p0 + 2 * p1) / 3, 0)
    pal = np.stack([p0, p1, p2, p3], 1)                         # N,4,3
    alpha = np.ones((len(blk), 4), np.float32)
    alpha[:, 3] = np.where(four[:, 0], 1.0, 0.0)
    sel = (idx[:, None] >> (2 * np.arange(16, dtype=np.uint32))) & 3   # N,16
    n = np.arange(len(blk))[:, None]
    col = pal[n, sel]
    a = alpha[n, sel]
    return np.concatenate([col, a[..., None]], -1).astype(np.float32)


def _bc_alpha_block(blk):
    """BC4-style 8-byte block -> float32 [N, 16]."""
    a0 = blk[:, 0].astype(np.float32) / 255
    a1 = blk[:, 1].astype(np.float32) / 255
    bits = np.zeros(len(blk), np.uint64)
    for i in range(6):
        bits |= blk[:, 2 + i].astype(np.uint64) << np.uint64(8 * i)
    sel = ((bits[:, None] >> (3 * np.arange(16, dtype=np.uint64))) & np.uint64(7)).astype(np.int64)
    pal = np.zeros((len(blk), 8), np.float32)
    pal[:, 0], pal[:, 1] = a0, a1
    eight = (a0 > a1)
    for i in range(1, 7):
        pal[:, 1 + i] = np.where(eight, ((7 - i) * a0 + i * a1) / 7, pal[:, 1 + i])
    for i in range(1, 5):
        pal[:, 1 + i] = np.where(~eight, ((5 - i) * a0 + i * a1) / 5, pal[:, 1 + i])
    pal[:, 6] = np.where(~eight, 0.0, pal[:, 6])
    pal[:, 7] = np.where(~eight, 1.0, pal[:, 7])
    return pal[np.arange(len(blk))[:, None], sel]


def decode_block_texture(data, width, height, dfmt, pitch_blocks):
    bw, bh = (width + 3) // 4, (height + 3) // 4
    bpb = BLOCK_FORMATS[dfmt]
    rows = data[:bh * pitch_blocks * bpb].reshape(bh, pitch_blocks, bpb)[:, :bw].reshape(-1, bpb)
    if dfmt == 35:
        px = _bc_color_block(rows)
    elif dfmt == 36:
        px = _bc_color_block(rows[:, 8:])
        a4 = np.zeros((len(rows), 16), np.float32)
        for i in range(8):
            a4[:, 2 * i] = (rows[:, i] & 15) / 15.0
            a4[:, 2 * i + 1] = (rows[:, i] >> 4) / 15.0
        px[..., 3] = a4
    elif dfmt == 37:
        px = _bc_color_block(rows[:, 8:])
        px[..., 3] = _bc_alpha_block(rows[:, :8])
    elif dfmt == 38:
        r = _bc_alpha_block(rows)
        px = np.stack([r, np.zeros_like(r), np.zeros_like(r), np.ones_like(r)], -1)
    else:  # 39 BC5
        r, g = _bc_alpha_block(rows[:, :8]), _bc_alpha_block(rows[:, 8:])
        px = np.stack([r, g, np.zeros_like(r), np.ones_like(r)], -1)
    img = px.reshape(bh, bw, 4, 4, 4).transpose(0, 2, 1, 3, 4).reshape(bh * 4, bw * 4, 4)
    return img[:height, :width]


class TextureCache:
    """Decodes T# images to float32 RGBA arrays (before dst_sel swizzle)."""

    def __init__(self, mem):
        self.mem = mem
        self._cache = {}
        self.warnings = set()

    def invalidate(self):
        self._cache.clear()

    def texels(self, t):
        key = t.raw
        img = self._cache.get(key)
        if img is not None:
            return img
        if t.tiling != TILE_LINEAR:
            self.warnings.add("tile mode %d read as linear (detiling not implemented)" % t.tiling)
        bpe = bytes_per_element(t.dfmt)
        if t.dfmt in BLOCK_FORMATS:
            pitch_blocks = max(1, (t.pitch + 3) // 4)
            size = ((t.height + 3) // 4) * pitch_blocks * bpe
            raw = np.frombuffer(self.mem.read(t.base, size), dtype=np.uint8)
            img = decode_block_texture(raw, t.width, t.height, t.dfmt, pitch_blocks)
            img = img.astype(np.float32).view(np.uint32)
        else:
            size = t.pitch * t.height * bpe
            raw = np.frombuffer(self.mem.read(t.base, size), dtype=np.uint8)
            raw = raw.reshape(t.height, t.pitch, bpe)[:, :t.width]
            img = decode_elements(raw, t.dfmt, t.nfmt)
        if img.shape[-1] < 4:   # missing components: 0 for rgb, 1 for alpha
            pad = np.zeros(img.shape[:-1] + (4 - img.shape[-1],), np.uint32)
            if img.shape[-1] < 4:
                one = np.float32(1.0).view(np.uint32) if t.nfmt not in (4, 5) else 1
                pad[..., -1] = one
            img = np.concatenate([img, pad], -1)
        self._cache[key] = img
        return img


def apply_dst_sel(texel_bits, dst_sel, integer=False):
    """texel_bits: uint32 [..., 4]; dst_sel codes 0=0 1=1 4..7=x..w."""
    one = np.uint32(1) if integer else np.float32(1.0).view(np.uint32)
    outs = []
    for s in dst_sel:
        if s >= 4:
            outs.append(texel_bits[..., s - 4])
        elif s == 1:
            outs.append(np.full(texel_bits.shape[:-1], one, np.uint32))
        else:
            outs.append(np.zeros(texel_bits.shape[:-1], np.uint32))
    return np.stack(outs, -1)


def _wrap(i, n, mode):
    if mode == 0:    # wrap
        return np.mod(i, n)
    if mode == 1:    # mirror
        period = 2 * n
        m = np.mod(i, period)
        return np.where(m >= n, period - 1 - m, m)
    if mode == 3:    # mirror once
        a = np.where(i < 0, -1 - i, i)
        return np.clip(a, 0, n - 1)
    return np.clip(i, 0, n - 1)   # clamp-to-edge / border (border colour not modelled)


def sample_2d(img_bits, s, u, v, integer=False, unnorm=False):
    """Bilinear/point sample. img_bits uint32 [H, W, 4]; u, v float arrays.
    Returns uint32 [..., 4]."""
    H, W = img_bits.shape[:2]
    if integer:
        x = _wrap(np.floor(u if unnorm else u * W).astype(np.int64), W, s.clamp[0])
        y = _wrap(np.floor(v if unnorm else v * H).astype(np.int64), H, s.clamp[1])
        return img_bits[y, x]
    img = img_bits.view(np.float32)
    fx = (u if unnorm else u * W) - 0.5
    fy = (v if unnorm else v * H) - 0.5
    if s.mag == 0 and s.min == 0:   # point
        x = _wrap(np.floor(fx + 0.5).astype(np.int64), W, s.clamp[0])
        y = _wrap(np.floor(fy + 0.5).astype(np.int64), H, s.clamp[1])
        return img_bits[y, x]
    x0 = np.floor(fx)
    y0 = np.floor(fy)
    ax = (fx - x0)[..., None].astype(np.float32)
    ay = (fy - y0)[..., None].astype(np.float32)
    x0 = x0.astype(np.int64)
    y0 = y0.astype(np.int64)
    xa, xb = _wrap(x0, W, s.clamp[0]), _wrap(x0 + 1, W, s.clamp[0])
    ya, yb = _wrap(y0, H, s.clamp[1]), _wrap(y0 + 1, H, s.clamp[1])
    top = img[ya, xa] * (1 - ax) + img[ya, xb] * ax
    bot = img[yb, xa] * (1 - ax) + img[yb, xb] * ax
    return (top * (1 - ay) + bot * ay).astype(np.float32).view(np.uint32)
