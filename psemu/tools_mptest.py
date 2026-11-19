"""Unit test of several address spaces on one WHP machine (whp_uc.Machine): the same guest address
holds different memory in each, and each space runs its own code on the shared vCPU.

    python -m psemu.tools_mptest
"""
import sys
import unicorn.x86_const as X

from .whp_uc import Machine, WhpUc


def main():
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print("  %-70s %s %s" % (name, "PASS" if cond else "FAIL", extra))

    m = Machine()
    a = WhpUc(machine=m, identity=True)
    b = WhpUc(machine=m, identity=False)
    check("first space is identity-mapped, the second is not", a.identity and not b.identity)
    CODE, DATA = 0x400000, 0x500000
    # mov dword [DATA], imm ; mov eax, [DATA] ; add eax, 1 ; hlt (the HLT exit stands in for the end)
    def prog(value):
        return (b"\xc7\x04\x25" + DATA.to_bytes(4, "little") + value.to_bytes(4, "little")
                + b"\x8b\x04\x25" + DATA.to_bytes(4, "little") + b"\x83\xc0\x01" + b"\xf4")
    for uc, v in ((a, 0x1111), (b, 0x2222)):
        uc.mem_map(CODE, 0x1000, 5)
        uc.mem_map(DATA, 0x1000, 3)
        uc.mem_write(CODE, prog(v))
    check("the same guest address holds different memory per space",
          bytes(a.mem_read(CODE, 4)) == bytes(a.mem_read(CODE, 4)) and a.mem_read(CODE, 12) != b.mem_read(CODE, 12))
    for uc, v in ((a, 0x1111), (b, 0x2222), (a, 0x1111)):
        uc.reg_write(X.UC_X86_REG_RSP, 0x500800)
        try:
            uc.emu_start(CODE, 0)
        except Exception:
            pass                                        # the stray HLT raises; the registers are what we read
        check("space runs its own code on the shared vCPU: eax = %#x" % (v + 1),
              uc.reg_read(X.UC_X86_REG_RAX) & 0xFFFFFFFF == v + 1)
    check("each space wrote only its own data page",
          int.from_bytes(a.mem_read(DATA, 4), "little") == 0x1111
          and int.from_bytes(b.mem_read(DATA, 4), "little") == 0x2222)
    rs = [r for r in b._rec.values()]
    check("the second space's guest-physical memory is above 2**47 (clear of the identity space)",
          all(r[2] >= Machine.GPA_BUMP_BASE for r in rs))
    print("multi-space machine:", "PASS" if ok else "FAIL")
    a.close()
    b.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
