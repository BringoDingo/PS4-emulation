"""AVX software shim.

The stock Unicorn wheel's TCG does not decode VEX-encoded (AVX) instructions,
so they raise UC_ERR_INSN_INVALID. This module catches that via the
UC_HOOK_INSN_INVALID hook, decodes the instruction with capstone, emulates its
effect against Unicorn's YMM/XMM register file and guest memory, advances RIP
past it, and lets execution continue.

It implements the common data-movement / logical AVX ops that system modules
hit during C-runtime and struct initialisation. Anything not yet handled is
logged by mnemonic with its bytes, so the set is easy to extend: add a method
`op_<mnemonic>(self, insn)`.
"""
import capstone
from capstone.x86 import (
    X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
)

MASK256 = (1 << 256) - 1
MASK128 = (1 << 128) - 1


class AvxShim:
    def __init__(self, emu):
        self.emu = emu
        self.uc = emu.uc
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.handled = {}       # mnemonic -> count
        self._reg_cache = {}

    # -- unicorn register id lookup by capstone register name --------------
    def _uc_reg(self, name):
        name = name.lower()
        if name in self._reg_cache:
            return self._reg_cache[name]
        from unicorn import x86_const as xc
        rid = getattr(xc, f"UC_X86_REG_{name.upper()}", None)
        self._reg_cache[name] = rid
        return rid

    def _read_reg(self, name):
        return self.uc.reg_read(self._uc_reg(name))

    def _write_reg(self, name, value):
        self.uc.reg_write(self._uc_reg(name), value)

    # -- effective address for a memory operand ---------------------------
    def _mem_ea(self, insn, op):
        m = op.mem
        ea = m.disp
        if m.base != 0:
            bname = insn.reg_name(m.base)
            if bname == "rip":
                ea += insn.address + insn.size
            else:
                ea += self._read_reg(bname)
        if m.index != 0:
            ea += self._read_reg(insn.reg_name(m.index)) * m.scale
        return ea & 0xFFFFFFFFFFFFFFFF

    # -- read/write a vector operand (reg or mem) as an int ----------------
    def _get(self, insn, op):
        if op.type == X86_OP_REG:
            name = insn.reg_name(op.reg)
            val = self._read_reg(name)
            return val & (MASK256 if name.startswith("ymm") else MASK128), name
        if op.type == X86_OP_MEM:
            ea = self._mem_ea(insn, op)
            data = self.uc.mem_read(ea, op.size)
            return int.from_bytes(bytes(data), "little"), None
        if op.type == X86_OP_IMM:
            return op.imm, None
        raise NotImplementedError("operand type")

    def _put(self, insn, op, value):
        if op.type == X86_OP_REG:
            name = insn.reg_name(op.reg)
            if name.startswith("ymm"):
                self._write_reg(name, value & MASK256)
            else:
                # writing xmm via VEX zeroes the upper 128 bits of the ymm
                yname = "ymm" + name[3:]
                self._write_reg(yname, value & MASK128)
            return
        if op.type == X86_OP_MEM:
            ea = self._mem_ea(insn, op)
            self.uc.mem_write(ea, (value & ((1 << (op.size * 8)) - 1))
                              .to_bytes(op.size, "little"))
            return
        raise NotImplementedError("dest operand type")

    # -- the hook ---------------------------------------------------------
    def on_invalid(self, uc, user_data=None):
        rip = self.emu._last_rip or uc.reg_read(self._uc_reg("rip"))
        try:
            code = bytes(uc.mem_read(rip, 15))
        except Exception:
            return False
        insn = next(self.md.disasm(code, rip, 1), None)
        if insn is None:
            self.emu.log(f"  [avx] cannot decode bytes at 0x{rip:x}")
            return False

        mn = insn.mnemonic
        handler = getattr(self, f"op_{mn}", None)
        if handler is None:
            # Not one of this shim's own ops - try the VexEngine (avx_ops),
            # which covers the wide VEX form set (vpermilps, ...).
            from .avx_ops import VexEngine
            if not hasattr(self, "_vex"):
                self._vex = VexEngine(self)
            self.uc = uc
            try:
                if self._vex.emulate(insn):
                    self.handled[mn] = self.handled.get(mn, 0) + 1
                    uc.reg_write(self._uc_reg("rip"), rip + insn.size)
                    return True
            except Exception as e:
                self.emu.log(f"  [avx] 0x{rip:x}: {mn} {insn.op_str} via VexEngine failed: {e!r}")
            raw = " ".join(f"{b:02x}" for b in insn.bytes)
            self.emu.log(f"  [avx UNHANDLED] 0x{rip:x}: {raw}  {mn} {insn.op_str}")
            self.emu.stop(f"unhandled AVX insn '{mn}' at 0x{rip:x}")
            return False

        if self.emu.trace:
            self.emu.log(f"  [avx] 0x{rip:x}: {mn} {insn.op_str}")
        handler(insn)
        self.handled[mn] = self.handled.get(mn, 0) + 1
        # advance past the instruction and resume
        uc.reg_write(self._uc_reg("rip"), rip + insn.size)
        return True

    # ---- instruction implementations -----------------------------------
    # logical: dst = src1 OP src2
    def _binop(self, insn, fn):
        ops = insn.operands
        dst = ops[0]
        a, _ = self._get(insn, ops[1])
        b, _ = self._get(insn, ops[2])
        self._put(insn, dst, fn(a, b))

    def op_vxorps(self, insn):
        self._binop(insn, lambda a, b: a ^ b)

    def op_vxorpd(self, insn):
        self._binop(insn, lambda a, b: a ^ b)

    def op_vpxor(self, insn):
        self._binop(insn, lambda a, b: a ^ b)

    def op_vandps(self, insn):
        self._binop(insn, lambda a, b: a & b)

    def op_vandpd(self, insn):
        self._binop(insn, lambda a, b: a & b)

    def op_vpand(self, insn):
        self._binop(insn, lambda a, b: a & b)

    def op_vorps(self, insn):
        self._binop(insn, lambda a, b: a | b)

    def op_vpor(self, insn):
        self._binop(insn, lambda a, b: a | b)

    # moves: dst = src  (reg/mem both directions)
    def _mov(self, insn):
        ops = insn.operands
        src, _ = self._get(insn, ops[1])
        self._put(insn, ops[0], src)

    op_vmovups = _mov
    op_vmovupd = _mov
    op_vmovaps = _mov
    op_vmovapd = _mov
    op_vmovdqu = _mov
    op_vmovdqa = _mov
    op_vmovq = _mov
    op_vmovd = _mov

    def op_vinsertf128(self, insn):
        # vinsertf128 dst(ymm), src1(ymm), src2(xmm/m128), imm8
        ops = insn.operands
        src1, _ = self._get(insn, ops[1])
        src2, _ = self._get(insn, ops[2])
        imm = ops[3].imm & 1
        src2 &= MASK128
        lo = src1 & MASK128
        hi = (src1 >> 128) & MASK128
        if imm:
            hi = src2
        else:
            lo = src2
        self._put(insn, ops[0], (hi << 128) | lo)

    op_vinserti128 = op_vinsertf128

    def op_vextractf128(self, insn):
        # vextractf128 dst(xmm/m128), src(ymm), imm8
        ops = insn.operands
        src, _ = self._get(insn, ops[1])
        imm = ops[2].imm & 1
        half = (src >> 128) & MASK128 if imm else src & MASK128
        self._put(insn, ops[0], half)

    op_vextracti128 = op_vextractf128

    def op_vperm2f128(self, insn):
        # vperm2f128 dst, src1, src2, imm8: select 128-bit lanes
        ops = insn.operands
        a, _ = self._get(insn, ops[1])
        b, _ = self._get(insn, ops[2])
        imm = ops[3].imm
        lanes = [a & MASK128, (a >> 128) & MASK128, b & MASK128, (b >> 128) & MASK128]
        lo = 0 if (imm & 0x08) else lanes[imm & 3]
        hi = 0 if (imm & 0x80) else lanes[(imm >> 4) & 3]
        self._put(insn, ops[0], (hi << 128) | lo)

    op_vperm2i128 = op_vperm2f128

    def op_vzeroupper(self, insn):
        # clear bits 128..255 of ymm0..ymm15
        for i in range(16):
            name = f"ymm{i}"
            v = self._read_reg(name) & MASK128
            self._write_reg(name, v)

    def op_vzeroall(self, insn):
        for i in range(16):
            self._write_reg(f"ymm{i}", 0)

    def emulate_vex(self, insn):
        """Run a VEX three-operand instruction that QEMU would mis-execute
        (see avx_ops.py). Returns False (and stops the emulator) if the
        instruction is not implemented yet."""
        from .avx_ops import VexEngine
        if not hasattr(self, "_vex"):
            self._vex = VexEngine(self)
        self.uc = self.emu.uc
        mn = insn.mnemonic
        if self.emu.trace:
            self.emu.log(f"  [vex] 0x{insn.address:x}: {mn} {insn.op_str}")
        try:
            ok = self._vex.emulate(insn)
            if not ok and hasattr(self, "op_" + mn):   # 256-bit ops the shim already has
                getattr(self, "op_" + mn)(insn)
                ok = True
        except Exception as e:
            ok = False
            self.emu.log(f"  [vex] 0x{insn.address:x}: {mn} {insn.op_str} failed: {e!r}")
        if not ok:
            raw = " ".join(f"{b:02x}" for b in insn.bytes)
            self.emu.log(f"  [vex UNHANDLED] 0x{insn.address:x}: {raw}  {mn} {insn.op_str}")
            self.emu.stop(f"unhandled VEX insn '{mn}' at 0x{insn.address:x}")
            return False
        key = mn + "*"
        self.handled[key] = self.handled.get(key, 0) + 1
        return True

    def summary(self):
        if not self.handled:
            return "no AVX instructions were emulated."
        parts = ", ".join(f"{k} x{v}" for k, v in sorted(self.handled.items()))
        return f"AVX emulated: {parts}"
