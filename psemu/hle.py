"""High-Level Emulation (HLE) function hooks.

Sometimes the cleanest way past a wall is not to emulate an internal routine
instruction-by-instruction but to *replace* it: intercept the call at the
function's entry address, run a Python implementation, and return to the
caller. This is how console emulators stub libc/pthread internals they don't
want to (or can't yet) run faithfully.

Register a hook with:

    emu.hle.register(0x440240, my_handler, name="pthread_mutex_lock")

`my_handler(emu, uc)` runs with the guest about to execute the function's first
instruction. It reads arguments from the SysV registers (rdi, rsi, rdx, rcx,
r8, r9), does whatever it likes, and returns an integer which becomes the
function's return value (rax). The shim then performs the `ret` itself (pops the
return address, restores rsp), so the native function body never executes.
"""
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)
import struct


class HleHooks:
    def __init__(self, emu):
        self.emu = emu
        self.uc = emu.uc
        self.table = {}       # addr -> (name, handler)
        self.hits = {}        # addr -> count

    def register(self, addr, handler, name=None, mode="replace"):
        """mode='replace': handler returns rax; the shim performs `ret` so the
        native body never runs. mode='fixup': handler patches memory/regs at
        the entry, then the native function executes normally. mode='guard':
        a handler returning None lets the native function run; any other value
        returns it immediately (like 'replace')."""
        self.table[addr] = (name or f"hle_{addr:x}", handler, mode)
        native = getattr(self.emu, "native", None)
        if native is not None:
            native.hle_add(addr)

    def has(self, addr):
        return addr in self.table

    def mode(self, addr):
        return self.table[addr][2]

    @staticmethod
    def args(uc):
        return (
            uc.reg_read(UC_X86_REG_RDI), uc.reg_read(UC_X86_REG_RSI),
            uc.reg_read(UC_X86_REG_RDX), uc.reg_read(UC_X86_REG_RCX),
            uc.reg_read(UC_X86_REG_R8), uc.reg_read(UC_X86_REG_R9),
        )

    def invoke(self, uc, addr):
        """Run the handler for `addr`.

        For a 'replace' hook, simulate `ret` and return True (caller restarts
        emulation at the return address). For a 'fixup' hook, run the handler
        and return False so the native function executes normally."""
        name, handler, mode = self.table[addr]
        self.hits[addr] = self.hits.get(addr, 0) + 1
        if self.emu.trace:
            a = self.args(uc)
            self.emu.log(f"  [hle {name}/{mode}] args=({a[0]:#x}, {a[1]:#x}, {a[2]:#x})")
        ret = handler(self.emu, uc)
        if mode == "fixup" or (mode == "guard" and ret is None):
            return False     # guard: None = let the native function run
        # replace: perform the ret: pop return address
        rsp = uc.reg_read(UC_X86_REG_RSP)
        retaddr = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, retaddr)
        if ret is not None:
            uc.reg_write(UC_X86_REG_RAX, ret & 0xFFFFFFFFFFFFFFFF)
        return True

    def summary(self):
        if not self.hits:
            return "no HLE hooks fired."
        # hits survive an execve; their hooks belonged to the previous module
        parts = ", ".join(f"{self.table[a][0] if a in self.table else f'{a:#x}'} x{n}"
                          for a, n in self.hits.items())
        return f"HLE hooks: {parts}"
