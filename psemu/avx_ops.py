"""Correct execution of VEX three-operand SSE/AVX instructions.

Unicorn's QEMU core executes many VEX.128 instructions as if they were the
legacy two-operand SSE form, ignoring VEX.vvvv: `vpcmpeqb xmm0, xmm2, xmm1`
runs as `pcmpeqb xmm0, xmm1` and silently computes garbage whenever the
destination is not also the first source. Sony's libc/libkernel are built
with AVX, so e.g. strncpy truncates strings.

The emulator calls `needs_emulation()` once per code address; instructions it
flags are executed here instead (see Emulator._hook_code). The engine works on
numpy views of the 128/256-bit values.
"""
import struct

import numpy as np
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

U8, I8, U16, I16, U32, I32, U64, I64 = (np.uint8, np.int8, np.uint16, np.int16, np.uint32,
                                        np.int32, np.uint64, np.int64)
F32, F64 = np.float32, np.float64


def vex_vvvv(code):
    """(used, register index) for a VEX-encoded instruction, else None.
    vvvv is stored inverted; 1111 means 'unused'."""
    i = 0
    while i < 4 and code[i] in (0x66, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x67):
        i += 1
    b = code[i]
    if b == 0xC5:
        v = (~code[i + 1] >> 3) & 0xF
    elif b == 0xC4:
        v = (~code[i + 2] >> 3) & 0xF
    else:
        return None
    return v != 0, v


def needs_emulation(insn, code):
    """True when QEMU's legacy-form execution would give a wrong result."""
    vv = vex_vvvv(code)
    if vv is None:
        return False
    ops = insn.operands
    if len(ops) < 2:
        return False
    if not vv[0]:
        # vvvv reads as "unused", but it is also how xmm0/ymm0 is encoded:
        # in a three-register form (dst, src1=vvvv, src2) the source is xmm0
        if not (len(ops) >= 3 and ops[2].type != X86_OP_IMM and ops[1].type == X86_OP_REG
                and insn.reg_name(ops[1].reg) in ("xmm0", "ymm0")):
            return False
    # BMI1/BMI2 (andn, bextr, shlx...) are VEX-encoded GPR ops QEMU handles
    # correctly; only vector instructions are affected.
    if not any(o.type == X86_OP_REG and insn.reg_name(o.reg).startswith(("xmm", "ymm"))
               for o in ops):
        return False
    a, b = ops[0], ops[1]
    if a.type == X86_OP_REG and b.type == X86_OP_REG and a.reg == b.reg and len(ops) == 3 \
            and ops[2].type != X86_OP_IMM:
        return False            # dst == src1: legacy semantics coincide
    return True


# --------------------------------------------------------------- helpers

def _np(value_bytes, dt):
    return np.frombuffer(value_bytes, dtype=dt).copy()


def _sat(x, dt):
    info = np.iinfo(dt)
    return np.clip(x, info.min, info.max).astype(dt)


def _cmp(fn, dt):
    ones = np.array(-1, dtype=np.int64).astype(dt)

    def f(a, b):
        return np.where(fn(a, b), ones, np.zeros_like(a)).astype(dt)
    return f


INT = {
    # name: (dtype, fn(a, b))
    "vpcmpeqb": (U8, _cmp(np.equal, U8)), "vpcmpeqw": (U16, _cmp(np.equal, U16)),
    "vpcmpeqd": (U32, _cmp(np.equal, U32)), "vpcmpeqq": (U64, _cmp(np.equal, U64)),
    "vpcmpgtb": (I8, _cmp(np.greater, I8)), "vpcmpgtw": (I16, _cmp(np.greater, I16)),
    "vpcmpgtd": (I32, _cmp(np.greater, I32)), "vpcmpgtq": (I64, _cmp(np.greater, I64)),
    "vpaddb": (U8, np.add), "vpaddw": (U16, np.add), "vpaddd": (U32, np.add),
    "vpaddq": (U64, np.add), "vpsubb": (U8, np.subtract), "vpsubw": (U16, np.subtract),
    "vpsubd": (U32, np.subtract), "vpsubq": (U64, np.subtract),
    "vpaddusb": (U8, lambda a, b: _sat(a.astype(np.int32) + b, U8)),
    "vpaddusw": (U16, lambda a, b: _sat(a.astype(np.int32) + b, U16)),
    "vpaddsb": (I8, lambda a, b: _sat(a.astype(np.int32) + b, I8)),
    "vpaddsw": (I16, lambda a, b: _sat(a.astype(np.int32) + b, I16)),
    "vpsubusb": (U8, lambda a, b: _sat(a.astype(np.int32) - b, U8)),
    "vpsubusw": (U16, lambda a, b: _sat(a.astype(np.int32) - b, U16)),
    "vpsubsb": (I8, lambda a, b: _sat(a.astype(np.int32) - b, I8)),
    "vpsubsw": (I16, lambda a, b: _sat(a.astype(np.int32) - b, I16)),
    "vpminub": (U8, np.minimum), "vpminuw": (U16, np.minimum), "vpminud": (U32, np.minimum),
    "vpmaxub": (U8, np.maximum), "vpmaxuw": (U16, np.maximum), "vpmaxud": (U32, np.maximum),
    "vpminsb": (I8, np.minimum), "vpminsw": (I16, np.minimum), "vpminsd": (I32, np.minimum),
    "vpmaxsb": (I8, np.maximum), "vpmaxsw": (I16, np.maximum), "vpmaxsd": (I32, np.maximum),
    "vpand": (U64, np.bitwise_and), "vpor": (U64, np.bitwise_or),
    "vpxor": (U64, np.bitwise_xor), "vpandn": (U64, lambda a, b: ~a & b),
    "vandps": (U64, np.bitwise_and), "vandpd": (U64, np.bitwise_and),
    "vorps": (U64, np.bitwise_or), "vorpd": (U64, np.bitwise_or),
    "vxorps": (U64, np.bitwise_xor), "vxorpd": (U64, np.bitwise_xor),
    "vandnps": (U64, lambda a, b: ~a & b), "vandnpd": (U64, lambda a, b: ~a & b),
    "vpmullw": (U16, lambda a, b: (a.astype(np.uint32) * b).astype(U16)),
    "vpmulld": (U32, lambda a, b: (a.astype(np.uint64) * b).astype(U32)),
    "vpmulhw": (I16, lambda a, b: ((a.astype(np.int32) * b) >> 16).astype(I16)),
    "vpmulhuw": (U16, lambda a, b: ((a.astype(np.uint32) * b) >> 16).astype(U16)),
    "vpavgb": (U8, lambda a, b: ((a.astype(np.uint16) + b + 1) >> 1).astype(U8)),
    "vpavgw": (U16, lambda a, b: ((a.astype(np.uint32) + b + 1) >> 1).astype(U16)),
    "vpsignb": (I8, lambda a, b: np.sign(b).astype(I8) * a),
    "vpsignw": (I16, lambda a, b: np.sign(b).astype(I16) * a),
    "vpsignd": (I32, lambda a, b: np.sign(b).astype(I32) * a),
}

FLOAT = {"add": np.add, "sub": np.subtract, "mul": np.multiply, "div": np.divide,
         "min": lambda a, b: np.where(a < b, a, b), "max": lambda a, b: np.where(a > b, a, b)}

# vcmp predicates (imm8 low 3 bits for the SSE set; capstone also spells them)
CMP_PRED = {"eq": np.equal, "lt": np.less, "le": np.less_equal,
            "unord": lambda a, b: np.isnan(a) | np.isnan(b),
            "neq": lambda a, b: ~np.equal(a, b), "nlt": lambda a, b: ~np.less(a, b),
            "nle": lambda a, b: ~np.less_equal(a, b),
            "ord": lambda a, b: ~(np.isnan(a) | np.isnan(b)),
            "gt": np.greater, "ge": np.greater_equal, "ngt": lambda a, b: ~np.greater(a, b),
            "nge": lambda a, b: ~np.greater_equal(a, b), "false": lambda a, b: np.zeros(a.shape, bool),
            "true": lambda a, b: np.ones(a.shape, bool)}
CMP_IMM = ["eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord", "eq", "nge", "ngt", "false",
           "neq", "ge", "gt", "true"]


class VexEngine:
    def __init__(self, shim):
        self.s = shim

    # operand access as bytes --------------------------------------------
    def width(self, insn):
        r = insn.operands[0]
        if r.type == X86_OP_REG and insn.reg_name(r.reg).startswith("ymm"):
            return 32
        return 16

    def get(self, insn, op, width):
        s = self.s
        if op.type == X86_OP_REG:
            name = insn.reg_name(op.reg)
            v = s._read_reg(name)
            if name.startswith(("xmm", "ymm")):
                return (v & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
            return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        if op.type == X86_OP_MEM:
            ea = s._mem_ea(insn, op)
            return bytes(s.uc.mem_read(ea, op.size))
        raise NotImplementedError

    def put(self, insn, op, data):
        v = int.from_bytes(bytes(data), "little")
        self.s._put(insn, op, v)

    @staticmethod
    def pad(b, width):
        return b + bytes(width - len(b)) if len(b) < width else b[:width]

    # dispatch -------------------------------------------------------------
    def emulate(self, insn):
        mn = insn.mnemonic
        ops = insn.operands
        w = self.width(insn)
        if mn in INT:
            dt, fn = INT[mn]
            a = _np(self.pad(self.get(insn, ops[1], w), w), dt)
            b = _np(self.pad(self.get(insn, ops[2], w), w), dt)
            with np.errstate(all="ignore"):
                self.put(insn, ops[0], fn(a, b).astype(dt).tobytes())
            return True
        for suffix, dt in (("ps", F32), ("pd", F64), ("ss", F32), ("sd", F64)):
            if not mn.endswith(suffix):
                continue
            core = mn[1:-2]
            scalar = suffix[0] == "s"
            if core in FLOAT or core.startswith("cmp") or core in ("sqrt", "addsub", "hadd",
                                                                    "hsub", "unpckl", "unpckh",
                                                                    "shuf", "blend", "blendv",
                                                                    "mov", "rcp", "rsqrt",
                                                                    "round"):
                return self._float(insn, core, dt, scalar, w)
        h = getattr(self, "op_" + mn, None)
        if h is not None:
            h(insn, w)
            return True
        return False

    def _float(self, insn, core, dt, scalar, w):
        ops = insn.operands
        a_b = self.pad(self.get(insn, ops[1], w), w)
        a = _np(a_b, dt)
        b_raw = self.get(insn, ops[2], w) if len(ops) > 2 else a_b
        b = _np(self.pad(b_raw, w), dt)
        imm = ops[-1].imm if ops[-1].type == X86_OP_IMM else None
        with np.errstate(all="ignore"):
            if core in FLOAT:
                r = FLOAT[core](a, b).astype(dt)
            elif core.startswith("cmp"):
                pred = core[3:] or CMP_IMM[imm & 0xF]
                fn = CMP_PRED[pred.replace("_oq", "").replace("_uq", "").replace("_os", "")
                              .replace("_us", "")]
                mask = fn(a, b)
                r = np.where(mask, np.array(-1).astype(np.int64), 0).astype(
                    I32 if dt == F32 else I64).view(dt)
            elif core == "sqrt":
                r = np.sqrt(b).astype(dt)
            elif core == "rcp":
                r = (1.0 / b).astype(dt)
            elif core == "rsqrt":
                r = (1.0 / np.sqrt(b)).astype(dt)
            elif core == "round":
                mode = imm & 3 if not (imm & 4) else 0
                r = [np.rint, np.floor, np.ceil, np.trunc][mode](b).astype(dt)
            elif core == "addsub":
                r = a.copy()
                r[0::2] = a[0::2] - b[0::2]
                r[1::2] = a[1::2] + b[1::2]
            elif core in ("hadd", "hsub"):
                f = np.add if core == "hadd" else np.subtract
                lanes = []
                n = 16 // a.itemsize
                for l in range(w // 16):
                    aa, bb = a[l * n:(l + 1) * n], b[l * n:(l + 1) * n]
                    lanes += [f(aa[0::2], aa[1::2]), f(bb[0::2], bb[1::2])]
                r = np.concatenate(lanes).astype(dt)
            elif core in ("unpckl", "unpckh"):
                r = self._unpack(a, b, core == "unpckh", w)
            elif core == "shuf":
                r = self._shuf(a, b, imm, dt, w)
            elif core == "blend":
                n = len(a)
                r = np.array([b[i] if imm >> i & 1 else a[i] for i in range(n)], dt)
            elif core == "blendv":
                m = _np(self.pad(self.get(insn, ops[3], w), w), I32 if dt == F32 else I64)
                r = np.where(m < 0, b, a).astype(dt)
            elif core == "mov":       # vmovss/vmovsd xmm, xmm, xmm (reg-reg 3-op form)
                r = a.copy()
                r[0] = b[0]
                scalar = False
            else:
                return False
        if scalar:                     # only the low element changes
            out = a.copy()
            out[0] = r[0]
            r = out
            if w == 16:
                pass
        self.put(insn, ops[0], np.asarray(r).tobytes())
        return True

    @staticmethod
    def _unpack(a, b, high, w):
        n = 16 // a.itemsize
        res = []
        for l in range(w // 16):
            aa, bb = a[l * n:(l + 1) * n], b[l * n:(l + 1) * n]
            half = slice(n // 2, n) if high else slice(0, n // 2)
            res.append(np.ravel(np.column_stack([aa[half], bb[half]])))
        return np.concatenate(res).astype(a.dtype)

    @staticmethod
    def _shuf(a, b, imm, dt, w):
        if dt == F32:
            out = []
            for l in range(w // 16):
                aa, bb = a[4 * l:4 * l + 4], b[4 * l:4 * l + 4]
                out += [aa[imm & 3], aa[(imm >> 2) & 3], bb[(imm >> 4) & 3], bb[(imm >> 6) & 3]]
            return np.array(out, dt)
        out = []
        for l in range(w // 16):
            aa, bb = a[2 * l:2 * l + 2], b[2 * l:2 * l + 2]
            k = imm >> (2 * l)
            out += [aa[k & 1], bb[(k >> 1) & 1]]
        return np.array(out, dt)

    # integer specials -----------------------------------------------------
    def _ab(self, insn, w, dt):
        ops = insn.operands
        return (_np(self.pad(self.get(insn, ops[1], w), w), dt),
                _np(self.pad(self.get(insn, ops[2], w), w), dt))

    def _unpk(self, insn, w, dt, high):
        a, b = self._ab(insn, w, dt)
        self.put(insn, insn.operands[0], self._unpack(a, b, high, w).tobytes())

    def op_vpunpcklbw(self, i, w): self._unpk(i, w, U8, False)
    def op_vpunpckhbw(self, i, w): self._unpk(i, w, U8, True)
    def op_vpunpcklwd(self, i, w): self._unpk(i, w, U16, False)
    def op_vpunpckhwd(self, i, w): self._unpk(i, w, U16, True)
    def op_vpunpckldq(self, i, w): self._unpk(i, w, U32, False)
    def op_vpunpckhdq(self, i, w): self._unpk(i, w, U32, True)
    def op_vpunpcklqdq(self, i, w): self._unpk(i, w, U64, False)
    def op_vpunpckhqdq(self, i, w): self._unpk(i, w, U64, True)

    def _pack(self, insn, w, src, dst):
        a, b = self._ab(insn, w, src)
        n = 16 // a.itemsize
        res = []
        for l in range(w // 16):
            res += [_sat(a[l * n:(l + 1) * n], dst), _sat(b[l * n:(l + 1) * n], dst)]
        self.put(insn, insn.operands[0], np.concatenate(res).tobytes())

    def op_vpacksswb(self, i, w): self._pack(i, w, I16, I8)
    def op_vpackuswb(self, i, w): self._pack(i, w, I16, U8)
    def op_vpackssdw(self, i, w): self._pack(i, w, I32, I16)
    def op_vpackusdw(self, i, w): self._pack(i, w, I32, U16)

    def op_vpshufb(self, insn, w):
        a, b = self._ab(insn, w, U8)
        out = np.zeros_like(a)
        for l in range(w // 16):
            for k in range(16):
                m = b[16 * l + k]
                out[16 * l + k] = 0 if m & 0x80 else a[16 * l + (m & 15)]
        self.put(insn, insn.operands[0], out.tobytes())

    def op_vpalignr(self, insn, w):
        a, b = self._ab(insn, w, U8)
        imm = insn.operands[3].imm
        out = []
        for l in range(w // 16):
            cat = np.concatenate([b[16 * l:16 * l + 16], a[16 * l:16 * l + 16], np.zeros(32, U8)])
            out.append(cat[imm:imm + 16])
        self.put(insn, insn.operands[0], np.concatenate(out).tobytes())

    def op_vpmuludq(self, insn, w):
        a, b = self._ab(insn, w, U32)
        r = a[0::2].astype(np.uint64) * b[0::2].astype(np.uint64)
        self.put(insn, insn.operands[0], r.tobytes())

    def op_vpmuldq(self, insn, w):
        a, b = self._ab(insn, w, I32)
        r = a[0::2].astype(np.int64) * b[0::2].astype(np.int64)
        self.put(insn, insn.operands[0], r.tobytes())

    def op_vpmaddwd(self, insn, w):
        a, b = self._ab(insn, w, I16)
        p = a.astype(np.int64) * b
        r = (p[0::2] + p[1::2]).astype(np.int64).astype(np.int32)
        self.put(insn, insn.operands[0], r.tobytes())

    def op_vpsadbw(self, insn, w):
        a, b = self._ab(insn, w, U8)
        d = np.abs(a.astype(np.int32) - b)
        r = np.array([d[8 * k:8 * k + 8].sum() for k in range(w // 8)], np.uint64)
        self.put(insn, insn.operands[0], r.tobytes())

    def op_vpblendw(self, insn, w):
        a, b = self._ab(insn, w, U16)
        imm = insn.operands[3].imm
        r = np.array([b[k] if imm >> (k % 8) & 1 else a[k] for k in range(len(a))], U16)
        self.put(insn, insn.operands[0], r.tobytes())

    def op_vpblendvb(self, insn, w):
        a, b = self._ab(insn, w, U8)
        m = _np(self.pad(self.get(insn, insn.operands[3], w), w), U8)
        self.put(insn, insn.operands[0], np.where(m & 0x80, b, a).astype(U8).tobytes())

    # shifts: by imm (NDD form: dst=vvvv, src=rm) or by xmm count ------------
    def _shift(self, insn, w, dt, kind):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], w), w), dt)
        if ops[2].type == X86_OP_IMM:
            cnt = ops[2].imm
        else:
            cnt = struct.unpack_from("<Q", self.pad(self.get(insn, ops[2], 16), 16))[0]
        bits = a.itemsize * 8
        if kind == "ll":
            r = np.zeros_like(a) if cnt >= bits else (a << dt(cnt)).astype(dt)
        elif kind == "rl":
            r = np.zeros_like(a) if cnt >= bits else (a >> dt(cnt)).astype(dt)
        else:
            sd = {U16: I16, U32: I32, U64: I64}[dt]
            r = (a.view(sd) >> min(cnt, bits - 1)).view(dt)
        self.put(insn, ops[0], r.tobytes())

    def op_vpsllw(self, i, w): self._shift(i, w, U16, "ll")
    def op_vpslld(self, i, w): self._shift(i, w, U32, "ll")
    def op_vpsllq(self, i, w): self._shift(i, w, U64, "ll")
    def op_vpsrlw(self, i, w): self._shift(i, w, U16, "rl")
    def op_vpsrld(self, i, w): self._shift(i, w, U32, "rl")
    def op_vpsrlq(self, i, w): self._shift(i, w, U64, "rl")
    def op_vpsraw(self, i, w): self._shift(i, w, U16, "ra")
    def op_vpsrad(self, i, w): self._shift(i, w, U32, "ra")

    def op_vpslldq(self, insn, w):
        a = _np(self.pad(self.get(insn, insn.operands[1], w), w), U8)
        n = min(insn.operands[2].imm, 16)
        out = np.zeros_like(a)
        for l in range(w // 16):
            out[16 * l + n:16 * l + 16] = a[16 * l:16 * l + 16 - n]
        self.put(insn, insn.operands[0], out.tobytes())

    def op_vpsrldq(self, insn, w):
        a = _np(self.pad(self.get(insn, insn.operands[1], w), w), U8)
        n = min(insn.operands[2].imm, 16)
        out = np.zeros_like(a)
        for l in range(w // 16):
            out[16 * l:16 * l + 16 - n] = a[16 * l + n:16 * l + 16]
        self.put(insn, insn.operands[0], out.tobytes())

    # inserts / conversions (3-operand scalar forms) ---------------------------
    def _insert(self, insn, w, dt):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), dt)
        v = int.from_bytes(self.get(insn, ops[2], 16)[:np.dtype(dt).itemsize].ljust(
            np.dtype(dt).itemsize, b"\0"), "little")
        n = len(a)
        a[ops[3].imm % n] = v & ((1 << (8 * a.itemsize)) - 1)
        self.put(insn, ops[0], a.tobytes())

    def op_vpinsrb(self, i, w): self._insert(i, w, U8)
    def op_vpinsrw(self, i, w): self._insert(i, w, U16)
    def op_vpinsrd(self, i, w): self._insert(i, w, U32)
    def op_vpinsrq(self, i, w): self._insert(i, w, U64)

    def op_vinsertps(self, insn, w):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), F32)
        imm = ops[3].imm
        src = self.get(insn, ops[2], 16)
        if ops[2].type == X86_OP_MEM:
            val = _np(src[:4], F32)[0]
        else:
            val = _np(self.pad(src, 16), F32)[(imm >> 6) & 3]
        a[(imm >> 4) & 3] = val
        for k in range(4):
            if imm >> k & 1:
                a[k] = 0
        self.put(insn, ops[0], a.tobytes())

    def _cvt_int(self, insn, dt):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), dt)
        raw = self.get(insn, ops[2], 16)
        size = ops[2].size
        v = int.from_bytes(raw[:size], "little", signed=True)
        a[0] = dt(v)
        self.put(insn, ops[0], a.tobytes())

    def op_vcvtsi2ss(self, i, w): self._cvt_int(i, F32)
    def op_vcvtsi2sd(self, i, w): self._cvt_int(i, F64)

    def op_vcvtss2sd(self, insn, w):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), F64)
        b = _np(self.pad(self.get(insn, ops[2], 16), 16), F32)
        a[0] = F64(b[0])
        self.put(insn, ops[0], a.tobytes())

    def op_vcvtsd2ss(self, insn, w):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), F32)
        b = _np(self.pad(self.get(insn, ops[2], 16), 16), F64)
        a[0] = F32(b[0])
        self.put(insn, ops[0], a.tobytes())

    def op_vmovhlps(self, insn, w):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), U64)
        b = _np(self.pad(self.get(insn, ops[2], 16), 16), U64)
        self.put(insn, ops[0], np.array([b[1], a[1]], U64).tobytes())

    def op_vmovlhps(self, insn, w):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), U64)
        b = _np(self.pad(self.get(insn, ops[2], 16), 16), U64)
        self.put(insn, ops[0], np.array([a[0], b[0]], U64).tobytes())

    def _movlh_mem(self, insn, high):
        ops = insn.operands
        a = _np(self.pad(self.get(insn, ops[1], 16), 16), U64)
        m = _np(self.get(insn, ops[2], 8)[:8], U64)[0]
        a[1 if high else 0] = m
        self.put(insn, ops[0], a.tobytes())

    def op_vmovlps(self, i, w): self._movlh_mem(i, False)
    def op_vmovlpd(self, i, w): self._movlh_mem(i, False)
    def op_vmovhps(self, i, w): self._movlh_mem(i, True)
    def op_vmovhpd(self, i, w): self._movlh_mem(i, True)
