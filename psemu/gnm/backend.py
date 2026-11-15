"""Python side of the native GNM backend (psemu/gnm/native/gnm_native.dll).

The DLL holds shadPS4's shader recompiler (GCN -> SPIR-V) and a Vulkan
runner. Guest pointers handed to it are *host* addresses, so resources live
in `HostHeap` buffers whose real addresses are written into descriptors.

    from psemu.gnm import backend, sb
    vs = sb.load_sb("yuv_vv.sb")
    spirv, summary = backend.translate(vs)
"""
import ctypes as C
import os

import numpy as np

from . import resources

HERE = os.path.dirname(os.path.abspath(__file__))
DLL_CANDIDATES = [os.path.join(HERE, "native", "build", "release", "gnm_native.dll"),
                  os.path.join(HERE, "native", "build", "debug", "gnm_native.dll")]

STAGES = {"ps": 0, "vs": 1, "gs": 2, "es": 3, "hs": 4, "ls": 5, "cs": 6}
PRIM_TRILIST, PRIM_TRIFAN, PRIM_TRISTRIP = 4, 5, 6


class ShaderDesc(C.Structure):
    _fields_ = [("stage", C.c_uint32), ("code_dwords", C.c_uint32),
                ("code", C.POINTER(C.c_uint32)), ("hash", C.c_uint64),
                ("rsrc1", C.c_uint32), ("rsrc2", C.c_uint32),
                ("user_data", C.c_uint32 * 16),
                ("ps_input_ena", C.c_uint32), ("ps_input_addr", C.c_uint32),
                ("num_interp", C.c_uint32), ("col_format", C.c_uint32),
                ("z_format", C.c_uint32), ("vs_out_cntl", C.c_uint32)]


class DrawDesc(C.Structure):
    _fields_ = [("vs", ShaderDesc), ("ps", ShaderDesc), ("prim_type", C.c_uint32),
                ("vertex_count", C.c_uint32), ("instance_count", C.c_uint32),
                ("width", C.c_uint32), ("height", C.c_uint32),
                ("vp_xscale", C.c_float), ("vp_xoffset", C.c_float),
                ("vp_yscale", C.c_float), ("vp_yoffset", C.c_float),
                ("clear_color", C.c_float * 4)]


class SubmitStats(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in (
        "packets", "draws", "dispatches", "failed", "skipped_packets",
        "first_skipped_opcode", "fences", "waits_unsatisfied", "interrupts")]

    def as_dict(self):
        return {n: getattr(self, n) for n, _ in self._fields_}


class GnmError(RuntimeError):
    pass


_dll = None


def dll():
    global _dll
    if _dll is None:
        path = next((p for p in DLL_CANDIDATES if os.path.exists(p)), None)
        if path is None:
            raise GnmError("gnm_native.dll not built; run: python psemu/gnm/native/build.py")
        _dll = C.CDLL(path)
        _dll.gnm_init.argtypes = [C.c_char_p, C.c_int]
        _dll.gnm_device_name.argtypes = [C.c_char_p, C.c_int]
        _dll.gnm_set_log_level.argtypes = [C.c_int]
        _dll.gnm_translate.argtypes = [C.POINTER(ShaderDesc), C.POINTER(C.c_uint32), C.c_uint32,
                                       C.POINTER(C.c_uint32), C.c_char_p, C.c_int,
                                       C.c_char_p, C.c_int]
        _dll.gnm_draw.argtypes = [C.POINTER(DrawDesc), C.POINTER(C.c_uint8), C.c_char_p, C.c_int]
        _dll.gnm_submit.argtypes = [C.POINTER(C.c_uint32), C.c_uint32, C.POINTER(SubmitStats),
                                    C.c_char_p, C.c_int]
        _dll.gnm_read_reg.argtypes = [C.c_uint32, C.POINTER(C.c_uint32)]
        _dll.gnm_profile.argtypes = [C.c_char_p, C.c_int, C.c_int]
        _dll.gnm_tiling.argtypes = [C.c_uint32, C.c_uint32, C.c_uint32, C.c_uint32, C.c_int,
                                    C.c_void_p, C.c_void_p, C.POINTER(C.c_uint64),
                                    C.POINTER(C.c_uint32), C.POINTER(C.c_uint32),
                                    C.c_char_p, C.c_int]
    return _dll


def profile(reset=True):
    """Per-phase time of graphics jobs since the last reset, as a string."""
    buf = C.create_string_buffer(512)
    dll().gnm_profile(buf, len(buf), 1 if reset else 0)
    return buf.value.decode(errors="replace")


def tiling_info(mode, bpp, pitch, height):
    """(tiled_bytes, padded_pitch, padded_height) of a tiled surface layout."""
    tb, pp, ph = C.c_uint64(), C.c_uint32(), C.c_uint32()
    err = C.create_string_buffer(512)
    if dll().gnm_tiling(mode, bpp, pitch, height, 0, None, None, C.byref(tb), C.byref(pp),
                        C.byref(ph), err, len(err)):
        raise GnmError(err.value.decode(errors="replace"))
    return tb.value, pp.value, ph.value


def tile(mode, linear, bpp):
    """Tile a linear (height, pitch[, ...]) array; returns the tiled bytes."""
    lin = np.ascontiguousarray(linear)
    h, p = lin.shape[0], lin.shape[1]
    tb, _, _ = tiling_info(mode, bpp, p, h)
    out = np.zeros(tb, np.uint8)
    err = C.create_string_buffer(512)
    if dll().gnm_tiling(mode, bpp, p, h, 1, lin.ctypes.data, out.ctypes.data, None, None, None,
                        err, len(err)):
        raise GnmError(err.value.decode(errors="replace"))
    return out


def detile(mode, tiled, bpp, pitch, height):
    """Detile `tiled` bytes into a (height, pitch, bpp) uint8 array."""
    t = np.ascontiguousarray(tiled, np.uint8)
    tb, _, _ = tiling_info(mode, bpp, pitch, height)
    if t.size < tb:
        raise GnmError("tiled buffer too small: %d < %d" % (t.size, tb))
    out = np.zeros((height, pitch, bpp), np.uint8)
    err = C.create_string_buffer(512)
    if dll().gnm_tiling(mode, bpp, pitch, height, 0, t.ctypes.data, out.ctypes.data, None, None,
                        None, err, len(err)):
        raise GnmError(err.value.decode(errors="replace"))
    return out


def set_log_level(level):
    dll().gnm_set_log_level(level)


def init():
    err = C.create_string_buffer(1024)
    if dll().gnm_init(err, len(err)):
        raise GnmError(err.value.decode(errors="replace"))
    name = C.create_string_buffer(256)
    dll().gnm_device_name(name, len(name))
    return name.value.decode(errors="replace")


# ------------------------------------------------------------ host memory

class GuestArena:
    """Guest GPU memory: a region reserved with VirtualAlloc *below 1 TB*.

    PS4 GPU virtual addresses are 40 bits wide and several registers hold
    them shifted into 32-bit fields (CB_COLORn_BASE, SPI_SHADER_PGM_LO/HI...),
    so ordinary Python allocations (around 2^42 on Windows) do not fit.
    Everything handed to the GPU path lives here instead. The same range can
    later be mapped into the Unicorn CPU at identical addresses."""

    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE = 0x1000, 0x2000, 0x04
    CANDIDATE_BASES = (0x10_0000_0000, 0x20_0000_0000, 0x40_0000_0000, 0x80_0000_0000)

    def __init__(self, size=4 << 30):
        k32 = C.WinDLL("kernel32", use_last_error=True)
        self._valloc = k32.VirtualAlloc
        self._valloc.restype = C.c_void_p
        self._valloc.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32]
        self.base = None
        for b in self.CANDIDATE_BASES:
            got = self._valloc(C.c_void_p(b), size, self.MEM_RESERVE, self.PAGE_READWRITE)
            if got:
                self.base = got
                break
        if self.base is None:
            raise GnmError("could not reserve guest memory below 1 TB")
        self.size = size
        self.top = self.base
        self.committed = self.base

    def alloc(self, nbytes, align=256):
        start = (self.top + align - 1) & ~(align - 1)
        end = start + max(nbytes, 1)
        if end > self.base + self.size:
            raise GnmError("guest arena exhausted (%d MiB)" % (self.size >> 20))
        if end > self.committed:
            grow = ((end - self.committed) + 0xFFFF) & ~0xFFFF
            if not self._valloc(C.c_void_p(self.committed), grow, self.MEM_COMMIT,
                                self.PAGE_READWRITE):
                raise GnmError("VirtualAlloc commit failed (%d)" % C.get_last_error())
            self.committed += grow
        self.top = end
        arr = np.frombuffer((C.c_uint8 * nbytes).from_address(start), dtype=np.uint8)
        arr[:] = 0
        return arr

    def mark(self):
        return self.top

    def release(self, mark):
        """Free everything allocated after `mark` (stack discipline)."""
        if self.base <= mark <= self.top:
            self.top = mark


_arena = None


def arena():
    global _arena
    if _arena is None:
        _arena = GuestArena()
    return _arena


class HostHeap:
    """Hands out aligned buffers in guest memory (see GuestArena); their
    addresses go into descriptors and GPU registers. Use as a context manager
    (or call release()) to give the memory back when done; heaps must be
    released in reverse order of creation."""

    def __init__(self):
        self._arena = arena()
        self._mark = self._arena.mark()

    def release(self):
        self._arena.release(self._mark)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()

    def alloc(self, nbytes, align=256):
        return self._arena.alloc(nbytes, align)

    def put(self, data, align=256):
        data = np.ascontiguousarray(data)
        buf = self.alloc(data.nbytes, align)
        buf[:] = data.view(np.uint8).reshape(-1)
        return buf

    @staticmethod
    def addr(buf):
        return buf.ctypes.data


CODE_TAIL = 0x10000   # bytes kept after the shader for pc-relative tables


def _code_bytes(shader, start):
    end = min(len(shader.blob), shader.footer_off + 32 + CODE_TAIL)
    return np.frombuffer(shader.blob, dtype=np.uint8)[start:end]


def _code_view(heap, shader):
    """Copy the shader's containing blob to aligned memory so pc-relative
    tables after the code stay readable. Returns (blob_view, code_address)."""
    start = shader.code_off & ~3
    view = heap.put(_code_bytes(shader, start), align=256)
    addr = view.ctypes.data + (shader.code_off - start)
    if addr & 3:
        # misaligned code start inside an ELF: realign the code itself
        view = heap.put(_code_bytes(shader, shader.code_off), align=256)
        addr = view.ctypes.data
    return view, addr


def place_code(shader, heap):
    """Copy a shader (and everything after it in its file, so pc-relative
    tables come along) to a 256-byte aligned address, as SPI_SHADER_PGM_LO
    requires. Returns that address."""
    view = heap.put(_code_bytes(shader, shader.code_off), align=256)
    return view.ctypes.data


def shader_desc(shader, heap, user_data=None, regs=None):
    regs = dict(shader.default_regs(), **(regs or {}))
    _, addr = _code_view(heap, shader)
    d = ShaderDesc()
    if shader.stage not in STAGES:
        raise GnmError("cannot classify shader stage (%s)" % shader.stage)
    d.stage = STAGES[shader.stage]
    d.code_dwords = shader.length // 4
    d.code = C.cast(C.c_void_p(addr), C.POINTER(C.c_uint32))
    d.hash = (shader.hash1 << 32) | shader.hash0
    d.rsrc1 = regs.get("rsrc1", 0)
    d.rsrc2 = regs.get("rsrc2", (shader.user_sgpr_count() & 0x1F) << 1)
    for i, v in enumerate((user_data or [])[:16]):
        d.user_data[i] = int(v) & 0xFFFFFFFF
    d.ps_input_ena = regs.get("ps_input_ena", 0)
    d.ps_input_addr = regs.get("ps_input_addr", d.ps_input_ena)
    d.num_interp = regs.get("ps_in_control", 0) & 0x3F
    d.col_format = regs.get("col_format", 0)
    d.z_format = regs.get("z_format", 0)
    d.vs_out_cntl = regs.get("pa_cl_vs_out_cntl", 0)
    return d


def translate(shader, user_data=None, regs=None, heap=None):
    """Recompile one shader to SPIR-V. Returns (spirv uint32 array, summary)."""
    own = heap is None
    heap = heap or HostHeap()
    try:
        return _translate(shader, user_data, regs, heap)
    finally:
        if own:
            heap.release()


def _translate(shader, user_data, regs, heap):
    if user_data is None:
        user_data = synth_user_data(shader, heap)
    d = shader_desc(shader, heap, user_data, regs)
    n = C.c_uint32()
    summ = C.create_string_buffer(4096)
    err = C.create_string_buffer(4096)
    if dll().gnm_translate(C.byref(d), None, 0, C.byref(n), summ, len(summ), err, len(err)):
        raise GnmError(err.value.decode(errors="replace"))
    out = (C.c_uint32 * n.value)()
    if dll().gnm_translate(C.byref(d), out, n.value, C.byref(n), summ, len(summ), err, len(err)):
        raise GnmError(err.value.decode(errors="replace"))
    return np.frombuffer(out, dtype=np.uint32).copy(), summ.value.decode(errors="replace")


def draw(vs, ps, width, height, heap, vs_user=None, ps_user=None, prim=PRIM_TRISTRIP,
         vertex_count=4, clear=(0, 0, 0, 1), vs_regs=None, ps_regs=None):
    """Draw once with a GNM VS/PS pair; returns an (H, W, 4) uint8 image."""
    d = DrawDesc()
    d.vs = shader_desc(vs, heap, vs_user, vs_regs)
    d.ps = shader_desc(ps, heap, ps_user, ps_regs)
    d.prim_type = prim
    d.vertex_count = vertex_count
    d.instance_count = 1
    d.width, d.height = width, height
    # what the GNM driver programs for a full-target viewport (Y flipped)
    d.vp_xscale, d.vp_xoffset = width / 2.0, width / 2.0
    d.vp_yscale, d.vp_yoffset = -height / 2.0, height / 2.0
    for i, c in enumerate(clear):
        d.clear_color[i] = c
    out = np.zeros((height, width, 4), dtype=np.uint8)
    err = C.create_string_buffer(4096)
    if dll().gnm_draw(C.byref(d), out.ctypes.data_as(C.POINTER(C.c_uint8)), err, len(err)):
        raise GnmError(err.value.decode(errors="replace"))
    return out


def reset_gpu():
    """Forget all register state (a fresh graphics queue)."""
    dll().gnm_pm4_reset()


def submit(words):
    """Run a PM4 command buffer (uint32 array). Returns SubmitStats as a dict
    plus the first error message ("" if every draw/dispatch ran)."""
    words = np.ascontiguousarray(words, dtype=np.uint32)
    st = SubmitStats()
    err = C.create_string_buffer(4096)
    rc = dll().gnm_submit(words.ctypes.data_as(C.POINTER(C.c_uint32)), len(words),
                          C.byref(st), err, len(err))
    msg = err.value.decode(errors="replace")
    if rc:
        raise GnmError("malformed command buffer: " + msg)
    return st.as_dict(), msg


def submit_at(addr, dwords):
    """Run a command buffer that already sits in host memory at `addr`
    (guest memory of a running psemu process). Same result as submit()."""
    st = SubmitStats()
    err = C.create_string_buffer(4096)
    rc = dll().gnm_submit(C.cast(C.c_void_p(addr), C.POINTER(C.c_uint32)), dwords,
                          C.byref(st), err, len(err))
    msg = err.value.decode(errors="replace")
    if rc:
        raise GnmError("malformed command buffer: " + msg)
    return st.as_dict(), msg


def read_reg(index):
    v = C.c_uint32()
    if dll().gnm_read_reg(index, C.byref(v)):
        raise GnmError("bad register index %#x" % index)
    return v.value


# ------------------------------------------------------------ descriptors

def tsharp(heap_buf, width, height, dfmt, nfmt, pitch=None, dst_sel=(4, 5, 6, 7)):
    return resources.make_tsharp(HostHeap.addr(heap_buf), width, height, dfmt, nfmt,
                                 pitch=pitch, dst_sel=dst_sel)


def ssharp(clamp=2, bilinear=True):
    return resources.make_ssharp(clamp=clamp, filt=1 if bilinear else 0)


# Slot usage types (see sb.USAGE_TYPES) grouped by what they hold.
_T_SLOTS = {0x00, 0x04}                        # ImmResource / ImmRwResource (T#)
_S_SLOTS = {0x01}                              # ImmSampler (S#)
_V_SLOTS = {0x02, 0x03}                        # ImmConstBuffer / ImmVertexBuffer (V#)
_PTR_TABLES = {0x13: "t", 0x14: "t", 0x15: "s", 0x16: "v", 0x17: "v", 0x18: "v",
               0x19: "t", 0x1A: "v", 0x1C: "t", 0x1D: "t", 0x1E: "t"}


def synth_user_data(shader, heap, tex_size=(64, 64)):
    """Fill the shader's user SGPRs from its input-usage slots with valid
    placeholder resources (a small RGBA8 texture, a sampler, zeroed buffers,
    tables of those). Lets any firmware shader be recompiled or run without
    the original application having set it up."""
    w, h = tex_size
    tex = heap.alloc(w * h * 4)
    tex[:] = 0x80
    t = tsharp(tex, w, h, dfmt=10, nfmt=0)
    s = ssharp()
    buf = heap.alloc(1 << 16)
    v = resources.make_vsharp(heap.addr(buf), num_records=(1 << 16) // 16, stride=16)

    def table(kind):
        rec = {"t": t, "s": s + [0] * 4, "v": v + [0] * 4}[kind]   # 8-dword records
        return heap.put(np.array(rec * 64, np.uint32))

    ud = [0] * 16
    eud = np.zeros(256, np.uint32)          # extended user data (regs >= 16)
    has_eud = False

    def put(reg, words):
        nonlocal has_eud
        for i, wv in enumerate(words):
            r = reg + i
            if r < 16:
                ud[r] = wv
            elif r - 16 < len(eud):
                eud[r - 16] = wv
                has_eud = True

    eud_slot = None
    for slot in shader.slots:
        n = slot.reg_count
        if slot.usage in _T_SLOTS:
            # a 4-dword resource slot is a buffer (V#) unless it's a 128-bit T#
            put(slot.start_reg, t if n == 8 else v)
        elif slot.usage in _S_SLOTS:
            put(slot.start_reg, s)
        elif slot.usage in _V_SLOTS:
            put(slot.start_reg, v)
        elif slot.usage in _PTR_TABLES:
            a = heap.addr(table(_PTR_TABLES[slot.usage]))
            put(slot.start_reg, [a & 0xFFFFFFFF, a >> 32])
        elif slot.usage == 0x1B:            # PtrExtendedUserData
            eud_slot = slot
    if eud_slot is not None or has_eud:
        e = heap.put(eud)
        a = heap.addr(e)
        reg = eud_slot.start_reg if eud_slot is not None else 14
        put(reg, [a & 0xFFFFFFFF, a >> 32])
    return ud
