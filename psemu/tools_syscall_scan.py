"""Rebuild psemu's syscall table straight from a decrypted libkernel.sprx.

    python -m psemu.tools_syscall_scan path/to/libkernel.sprx [-o syscalls.csv]
                                       [--names extra_names.txt]

libkernel's syscall wrappers all look like `mov eax/rax, N ; mov r10, rcx ;
syscall`. This scans the text segment for them, then names a number when an
export whose NID matches a known function name contains the stub. NIDs are
computed (base64 of the first 8 bytes of SHA-1(name + salt)), not looked up:
supply more candidate names with --names (one per line) to name more numbers.
Writes the CSV psemu reads via PSEMU_SYSCALLS_CSV (or ./syscalls.csv beside
syscalls.py), plus a `psemu_handler` column showing which numbers psemu
implements; the rest hit the "unimplemented: pretend success" path.
"""
import argparse
import base64
import csv
import hashlib
import os
import re
import struct
import sys

SALT = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
STUB = re.compile(rb"(?:\x48\xc7\xc0(....)|\xb8(....))\x49\x89\xca\x0f\x05", re.S)
SYSCALL_IN_EXPORT = re.compile(rb"(?:\x48\xc7\xc0(....)|\xb8(....))", re.S)


def nid(name):
    h = hashlib.sha1(name.encode() + SALT).digest()
    v = struct.unpack("<Q", h[:8])[0]
    return base64.b64encode(struct.pack(">Q", v)).decode().replace("/", "-").rstrip("=")


class Sprx:
    def __init__(self, data):
        d = self.d = data
        if d[:4] != b"\x7fELF":
            raise SystemExit("not a decrypted ELF/SPRX (still a SELF?)")
        phoff = struct.unpack_from("<Q", d, 32)[0]
        phnum = struct.unpack_from("<H", d, 56)[0]
        self.ph = [struct.unpack_from("<IIQQQQQQ", d, phoff + i * 56) for i in range(phnum)]
        self.loads = [(p[3], p[2], p[5]) for p in self.ph if p[0] == 1]
        self.text = next(p for p in self.ph if p[0] == 1 and p[1] & 1)

    def va2off(self, va):
        for v, o, fs in self.loads:
            if v <= va < v + fs:
                return o + va - v
        return None

    def exports(self):
        d = self.d
        dyn = next(p for p in self.ph if p[0] == 2)
        tags = {}
        for i in range(0, dyn[5], 16):
            t, v = struct.unpack_from("<qQ", d, dyn[2] + i)
            if t == 0:
                break
            tags.setdefault(t, v)
        sce = next(p for p in self.ph if p[0] == 0x61000000)
        symtab, strtab = sce[2] + tags[0x61000039], sce[2] + tags[0x61000035]
        for i in range(tags[0x6100003F] // 24):
            n, info, oth, shn, val, sz = struct.unpack_from("<IBBHQQ", d, symtab + i * 24)
            if shn and val and n:
                e = d.index(b"\0", strtab + n)
                yield d[strtab + n:e].decode("latin1"), val

    def stubs(self):
        """{number: [text offsets]} of every standard syscall wrapper."""
        o, n = self.text[2], self.text[5]
        out = {}
        for m in STUB.finditer(self.d[o:o + n]):
            out.setdefault(struct.unpack("<I", m.group(1) or m.group(2))[0], []).append(m.start())
        return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("sprx")
    ap.add_argument("-o", "--out", default="syscalls.csv")
    ap.add_argument("--names", help="extra candidate function names, one per line")
    a = ap.parse_args()
    sp = Sprx(open(a.sprx, "rb").read())

    cands = set()
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "nid_candidates.txt"), a.names):
        if path and os.path.isfile(path):
            cands |= {l.strip() for l in open(path, encoding="utf-8")
                      if l.strip() and not l.startswith("#")}
    nid2name = {}
    for c in sorted(cands):
        nid2name.setdefault(nid(c), c)

    per_num = {}                                   # number -> [(name or None, nid)]
    for sym, va in sp.exports():
        o = sp.va2off(va)
        code = sp.d[o:o + 32] if o is not None else b""
        k = code.find(b"\x0f\x05")
        if k < 0 or k > 16:
            continue
        m = SYSCALL_IN_EXPORT.search(code[:k])
        if m:
            num = struct.unpack("<I", m.group(1) or m.group(2))[0]
            n = sym.split("#")[0]
            per_num.setdefault(num, []).append((nid2name.get(n), n))

    handled = set()
    try:
        from .syscalls import SYSCALLS, SyscallDispatcher
        handled = {n for n, nm in SYSCALLS.items() if hasattr(SyscallDispatcher, "sys_" + nm)}
    except Exception as e:                         # run standalone without unicorn
        print(f"(psemu_handler column left blank: {e})", file=sys.stderr)

    stubs = sp.stubs()
    nums = sorted(set(stubs) | set(per_num))
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["number", "ps4_exported_names", "freebsd9_name", "freebsd9_status",
                    "called_by", "psemu_handler"])
        for n in nums:
            ex = per_num.get(n, [])
            names = " ".join(sorted({x[0] for x in ex if x[0]}))
            nids = " ".join(sorted({x[1] for x in ex}))
            w.writerow([n, names, "", "", nids, int(n in handled) if handled else ""])
    named = sum(1 for n in nums if any(x[0] for x in per_num.get(n, [])))
    print(f"{len(nums)} syscall numbers ({named} named from NIDs) -> {a.out}")
    if handled:
        miss = [n for n in nums if n not in handled]
        print(f"psemu implements {len(nums) - len(miss)}; {len(miss)} fall back to fake success")


if __name__ == "__main__":
    main()
