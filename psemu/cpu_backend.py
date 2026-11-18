"""CpuBackend: the interface that lets psemu swap execution engines (Unicorn <-> WHP) without
rewriting the kernel/syscall HLE, the GNM renderer or the firmware loader.

Everything above the CPU (syscalls.py, sys_sync, devices, unixsock, the GPU backend, the
scheduler) touches the engine only through a small surface: read/write registers and guest
memory, map/protect memory, run until an event (syscall, fault, HLE hook, time-slice end), and
save/restore a thread's register context. An audit of the current code counts ~72 mem_read,
~109 mem_write, ~43 reg_read, ~49 reg_write, 7 hook_add, 6 context_save, 3 context_restore and
2 emu_start on the Unicorn `uc` object -- a narrow, stable surface.

This module defines that surface and the Unicorn<->WHP register-name mapping. The existing
Emulator is the reference `UnicornBackend`; `psemu.whp` has proved every piece a `WhpBackend`
needs (long mode, identity-mapped guest memory, guest syscall -> host dispatch, the in-guest
umtx fast path, and full context save/restore). Wiring the Emulator's direct `self.uc.*` calls
through this interface is the remaining mechanical step; it is intentionally not done here so
this commit changes no behaviour.

See docs/whp-backend-plan.md for the full design (memory model, syscall stub, exception exits,
scheduler, the determinism trade-off).
"""
from __future__ import annotations

import unicorn.x86_const as UC

from . import whp


# ---- Unicorn register id  ->  WHP register name -------------------------
# Only the registers psemu actually reads/writes. FS_BASE/GS_BASE are the segment-register Base
# fields in WHP (and the TLS pointers the PS4 depends on).
UC_TO_WHP = {
    UC.UC_X86_REG_RAX: whp.RAX, UC.UC_X86_REG_RBX: whp.RBX, UC.UC_X86_REG_RCX: whp.RCX,
    UC.UC_X86_REG_RDX: whp.RDX, UC.UC_X86_REG_RSP: whp.RSP, UC.UC_X86_REG_RBP: whp.RBP,
    UC.UC_X86_REG_RSI: whp.RSI, UC.UC_X86_REG_RDI: whp.RDI,
    UC.UC_X86_REG_R8: whp.R8, UC.UC_X86_REG_R9: whp.R9, UC.UC_X86_REG_R10: whp.R10,
    UC.UC_X86_REG_R11: whp.R11, UC.UC_X86_REG_R12: whp.R12, UC.UC_X86_REG_R13: whp.R13,
    UC.UC_X86_REG_R14: whp.R14, UC.UC_X86_REG_R15: whp.R15,
    UC.UC_X86_REG_RIP: whp.RIP, UC.UC_X86_REG_RFLAGS: whp.RFLAGS,
    UC.UC_X86_REG_CS: whp.CS, UC.UC_X86_REG_SS: whp.SS, UC.UC_X86_REG_DS: whp.DS,
    UC.UC_X86_REG_ES: whp.ES, UC.UC_X86_REG_FS: whp.FS, UC.UC_X86_REG_GS: whp.GS,
    UC.UC_X86_REG_CR0: whp.CR0, UC.UC_X86_REG_CR2: whp.CR2, UC.UC_X86_REG_CR3: whp.CR3,
    UC.UC_X86_REG_CR4: whp.CR4, UC.UC_X86_REG_CR8: whp.CR8,
    UC.UC_X86_REG_FS_BASE: whp.FS, UC.UC_X86_REG_GS_BASE: whp.GS,
}

# The architectural registers that make up one guest thread's saved context (a cooperative
# thread switch saves these and restores the next thread's). RIP/RFLAGS/RSP + the GP file +
# FS/GS base cover what psemu's scheduler needs; CR3 is shared (one address space).
THREAD_CONTEXT_REGS = [
    UC.UC_X86_REG_RAX, UC.UC_X86_REG_RBX, UC.UC_X86_REG_RCX, UC.UC_X86_REG_RDX,
    UC.UC_X86_REG_RSP, UC.UC_X86_REG_RBP, UC.UC_X86_REG_RSI, UC.UC_X86_REG_RDI,
    UC.UC_X86_REG_R8, UC.UC_X86_REG_R9, UC.UC_X86_REG_R10, UC.UC_X86_REG_R11,
    UC.UC_X86_REG_R12, UC.UC_X86_REG_R13, UC.UC_X86_REG_R14, UC.UC_X86_REG_R15,
    UC.UC_X86_REG_RIP, UC.UC_X86_REG_RFLAGS, UC.UC_X86_REG_FS_BASE, UC.UC_X86_REG_GS_BASE,
]

# what a run() returns -- why the vCPU stopped
EV_SYSCALL = "syscall"    # guest executed `syscall` (WHP: HLT at the LSTAR stub)
EV_FAULT = "fault"        # page fault / #GP / #UD  (WHP: memory or exception exit)
EV_HLE = "hle"            # execution reached an HLE-hooked address (WHP: int3 breakpoint)
EV_TIMESLICE = "timeslice"  # cooperative preemption point (WHP: WHvCancelRunVirtualProcessor)
EV_HALT = "halt"          # a real guest HLT
EV_STOPPED = "stopped"    # the host asked the CPU to stop


class CpuBackend:
    """The execution-engine interface. `UnicornBackend` wraps today's Emulator; `WhpBackend`
    (to come) drives a `psemu.whp.Partition`. Methods raise NotImplementedError here; the point
    of this class is the documented contract and the register maps above."""

    # --- memory ---
    def mem_read(self, addr, size):           raise NotImplementedError
    def mem_write(self, addr, data):          raise NotImplementedError
    def mem_map(self, addr, size, prot):      raise NotImplementedError
    def mem_unmap(self, addr, size):          raise NotImplementedError
    def mem_protect(self, addr, size, prot):  raise NotImplementedError

    # --- registers (keyed by UC_X86_REG_* so call sites don't change) ---
    def reg_read(self, uc_reg):               raise NotImplementedError
    def reg_write(self, uc_reg, value):       raise NotImplementedError

    # --- execution: run the current thread until an event; return one of EV_* ---
    def run(self):                            raise NotImplementedError
    def stop(self):                           raise NotImplementedError

    # --- cooperative thread switch: full register context ---
    def context_save(self):
        """Return an opaque snapshot of THREAD_CONTEXT_REGS for the running thread."""
        raise NotImplementedError

    def context_restore(self, ctx):
        """Make `ctx` (from context_save) the running thread's register state."""
        raise NotImplementedError

    # --- HLE hooks / traps (addresses that should return control to Python) ---
    def hook_add(self, addr):                 raise NotImplementedError
    def hook_remove(self, addr):              raise NotImplementedError


def whp_available():
    """True if a WhpBackend could run here (hypervisor present)."""
    return whp.hypervisor_present()
