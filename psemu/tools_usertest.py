"""Unit test of the SceUserService per-user string method (0x30004): the name, and that other kinds
(the theme entitlement id) stay empty.

    python -m psemu.tools_usertest
"""
import os
import struct
import sys

from .syscalls import SyscallDispatcher


class Mem:
    def __init__(self):
        self.m = {}

    def mem_write(self, a, d):
        for i, b in enumerate(bytes(d)):
            self.m[a + i] = b

    def mem_read(self, a, n):
        return bytearray(self.m.get(a + i, 0) for i in range(n))


class Sc(SyscallDispatcher):
    def __init__(self, uc):
        self.emu = type("E", (), {"uc": uc})()


def main():
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print("  %-70s %s %s" % (name, "PASS" if cond else "FAIL", extra))

    uc = Mem()
    sc = Sc(uc)
    saved = os.environ.pop("PSEMU_USER_NAME", None)

    def ask(uid, kind):
        uc.mem_write(0x1000, struct.pack("<II", uid, kind))
        uc.mem_write(0x2000, b"\xee" * 32)
        uc.mem_write(0x3000, bytes(32))
        res = sc._ipmi_user_name(uc, {"in": [(0x1000, 8)], "out": [(0x2000, 17, 0x3000)]})
        return res, bytes(uc.mem_read(0x2000, 17)), struct.unpack("<Q", bytes(uc.mem_read(0x3010, 8)))[0]

    res, out, n = ask(sc.USER_ID, 1)
    check("kind 1 (GetUserName) returns the placeholder name, NUL-terminated", res == 0 and out[:8] == b"Player1\0", repr(out[:8]))
    check("the reported size covers the string and its NUL", n == 8)
    res, out, n = ask(sc.USER_ID, 0x800)
    check("kind 0x800 (theme entitlement id) is empty (no packaged theme)", res == 0 and out[:1] == b"\0")
    res, out, n = ask(0x10000002, 1)
    check("an unknown user id is an error", res == 0x80960005)
    os.environ["PSEMU_USER_NAME"] = "A-very-long-user-name-here"
    res, out, n = ask(sc.USER_ID, 1)
    check("PSEMU_USER_NAME overrides it; names are cut at 16 characters",
          out == b"A-very-long-user" + b"\0", repr(out))
    if saved is None:
        del os.environ["PSEMU_USER_NAME"]
    else:
        os.environ["PSEMU_USER_NAME"] = saved
    print("user service:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
