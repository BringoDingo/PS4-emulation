"""Hardware check of the native VEX ops that firmware harvesting rarely hits.

    python -m psemu.tools_vexhw_synth [TRIALS]

tools_vexhw runs instructions harvested from firmware on the host CPU and through
native/vex.c and demands bit-identical results. This driver feeds it a synthetic
set instead: every VCVTPS2PH form (imm8 0..7, 128/256-bit source, register and
memory destination, several registers) and VPERMILPS/VPERMILPD in both their
immediate and variable encodings, so the F16C conversion and the in-lane
permutes are checked against the real instruction.
"""
import sys

from . import tools_vexhw as hw
from . import tools_vextest as vt


def synthetic_codes():
    codes = {}
    for L in (0, 1):
        b2 = 0x79 | (L << 2)
        vec = "ymm" if L else "xmm"
        for imm in range(8):
            for src in (0, 3, 7):
                for dst in (1, 5):          # register destination: modrm mod=3, reg=src, rm=dst
                    codes[bytes([0xC4, 0xE3, b2, 0x1D, 0xC0 | (src << 3) | dst, imm])] = \
                        f"vcvtps2ph xmm{dst}, {vec}{src}, {imm}"
                # memory destination [rax + 0x10]
                codes[bytes([0xC4, 0xE3, b2, 0x1D, 0x40 | (src << 3), 0x10, imm])] = \
                    f"vcvtps2ph xmmword ptr [rax + 0x10], {vec}{src}, {imm}"
    for L in (0, 1):
        vec = "ymm" if L else "xmm"
        b2 = 0x79 | (L << 2)
        for imm in (0x00, 0x1B, 0xE4, 0xB1, 0xFF, 0x55, 0xAA, 0x93):
            # VEX.66.0F3A 04/05 /r ib: source = r/m, vvvv unused (1111)
            for op, mn in ((0x04, "vpermilps"), (0x05, "vpermilpd")):
                codes[bytes([0xC4, 0xE3, b2, op, 0xC0 | (2 << 3) | 6, imm])] = \
                    f"{mn} {vec}2, {vec}6, {imm}"
                codes[bytes([0xC4, 0xE3, b2, op, 0x40 | (2 << 3), 0x20, imm])] = \
                    f"{mn} {vec}2, ptr [rax + 0x20], {imm}"
        for op, mn in ((0x0C, "vpermilps"), (0x0D, "vpermilpd")):
            # VEX.NDS.66.0F38 0C/0D /r: source = vvvv, control = r/m
            for vv in (1, 4):
                b2v = (((~vv) & 15) << 3) | (L << 2) | 0x01
                codes[bytes([0xC4, 0xE2, b2v, op, 0xC0 | (2 << 3) | 6])] = \
                    f"{mn} {vec}2, {vec}{vv}, {vec}6"
                codes[bytes([0xC4, 0xE2, b2v, op, 0x40 | (2 << 3), 0x20])] = \
                    f"{mn} {vec}2, {vec}{vv}, ptr [rax + 0x20]"
    return codes


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    trials = args[0] if args else "60"
    codes = synthetic_codes()
    vt.harvest = lambda paths, per: {("synthetic", "new"): codes}
    hw.main(["--per-bucket", "999", "--trials", trials, "x"])


if __name__ == "__main__":
    main()
