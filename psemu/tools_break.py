"""Run a dynamic module with code breakpoints (developer use).

    python -m psemu.tools_break GnmCompositor.elf libSceVideoOut.sprx+0xf82 [more...]
        [--max N] [--count K] [--no-gpu]

Each breakpoint is ``module+offset`` (module file name, offset relative to the
module's load base). When hit it prints rip, the argument registers and a
frame-pointer backtrace symbolised as module+offset. Hooks are installed when
the module is mapped, so runtime-loaded libraries work too.
"""
import argparse
import struct

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RAX,
                               UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                               UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RBX)

from . import dynproc
from .emulator import Emulator
from .tools_re import find_module


def symbolize(emu, addr):
    lm = emu.dyn.module_at(addr) if emu.dyn else None
    return f"{lm.name}+{addr - lm.base:#x}" if lm else f"{addr:#x}"


def backtrace(emu, uc, depth=12):
    out = []
    rbp = uc.reg_read(UC_X86_REG_RBP)
    # the word at rsp is the return address when stopped on a function entry
    try:
        ret0 = struct.unpack("<Q", bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8)))[0]
        out.append("[rsp] " + symbolize(emu, ret0))
    except Exception:
        pass
    for _ in range(depth):
        try:
            nxt, ret = struct.unpack("<QQ", bytes(uc.mem_read(rbp, 16)))
        except Exception:
            break
        if not ret:
            break
        out.append(symbolize(emu, ret))
        if nxt <= rbp:
            break
        rbp = nxt
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("bps", nargs="+", help="module+offset")
    ap.add_argument("--max", type=int, default=20_000_000)
    ap.add_argument("--count", type=int, default=4, help="reports per breakpoint")
    ap.add_argument("--no-gpu", action="store_true")
    ap.add_argument("--dump", action="append", default=[],
                    help="REG:LEN - hex-dump memory at a register on every report")
    args = ap.parse_args()

    def key(name):                       # libFoo.sprx == libFoo.prx == libFoo
        n = name.lower()
        for ext in (".sprx", ".prx", ".elf", ".self"):
            if n.endswith(ext):
                return n[:-len(ext)]
        return n

    want = {}
    for bp in args.bps:
        mod, off = bp.rsplit("+", 1)
        want.setdefault(key(mod), []).append(int(off, 0))
    hits = {}

    orig_map = dynproc.DynamicProcess._map

    def _map(self, lm):
        orig_map(self, lm)
        for off in want.get(key(lm.name), ()):
            addr = lm.base + off

            def hook(uc, address, size, user, off=off, name=lm.name):
                k = (name, off)
                hits[k] = hits.get(k, 0) + 1
                if hits[k] > args.count:
                    return
                regs = {n: uc.reg_read(r) for n, r in (
                    ("rdi", UC_X86_REG_RDI), ("rsi", UC_X86_REG_RSI), ("rdx", UC_X86_REG_RDX),
                    ("rcx", UC_X86_REG_RCX), ("r8", UC_X86_REG_R8), ("r9", UC_X86_REG_R9),
                    ("rax", UC_X86_REG_RAX), ("rbx", UC_X86_REG_RBX))}
                print(f"*** break {name}+{off:#x} (hit {hits[k]}) "
                      + " ".join(f"{n}={v:#x}" for n, v in regs.items()))
                for f in backtrace(self.emu, uc):
                    print("      <- " + f)
                for spec in args.dump:
                    reg, n = spec.split(":")
                    a = regs.get(reg, 0)
                    try:
                        data = bytes(uc.mem_read(a, int(n, 0)))
                    except Exception:
                        print(f"      [{reg}={a:#x}] unreadable")
                        continue
                    for i in range(0, len(data), 32):
                        print(f"      [{reg}+{i:#05x}] {data[i:i + 32].hex(' ', 4)}")
            self.emu.uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr)
            print(f"[break] {lm.name}+{off:#x} armed at {addr:#x}")

    dynproc.DynamicProcess._map = _map
    path = find_module(args.file)
    emu = Emulator(path, max_insns=args.max)
    emu.gpu_enabled = not args.no_gpu
    emu.run()
    print("breakpoint hits:", {f"{n}+{o:#x}": c for (n, o), c in hits.items()})


if __name__ == "__main__":
    main()
