"""FreeBSD / ORBIS syscall layer.

The PS4 kernel ABI is FreeBSD 9-ish with Sony extensions. User code invokes it
with the `syscall` instruction:

    rax = syscall number
    args: rdi, rsi, rdx, r10, r8, r9   (note r10, not rcx: syscall clobbers rcx)
    return value in rax, carry flag set on error (errno in rax)

This module provides a number->name table and a handful of real handlers
(write, exit, and friends). Everything else is stubbed: logged and returned as
success(0) or ENOSYS, so the module keeps running and we learn what it needs.
"""
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RFLAGS,
)

# --- errno values we care about -------------------------------------------
EPERM = 1
ENOENT = 2
EBADF = 9
EEXIST = 17
ENOMEM = 12
EACCES = 13
EFAULT = 14
EINVAL = 22
ENOSYS = 78


def _embedded_cil(sprx):
    """Extract the embedded managed (.NET CIL) assembly PE from a PS4 AOT
    `<name>.dll.sprx`. PS4 ships managed assemblies only as AOT modules that
    embed the original assembly image; Mono opens `<name>.dll` to read the CIL
    metadata. Scans for a valid managed PE (MZ + PE header + a CLI 'BSJB'
    metadata root) and returns its bytes (computed from the section table), or
    None if there is no embedded CIL."""
    import struct
    n = len(sprx)
    i = 0
    while True:
        i = sprx.find(b"MZ", i)
        if i < 0:
            return None
        start = i
        i += 2
        if start + 0x40 > n:
            continue
        e_lfanew = struct.unpack_from("<I", sprx, start + 0x3C)[0]
        pe = start + e_lfanew
        if not (0 < e_lfanew < 0x400 and pe + 24 <= n and sprx[pe:pe + 4] == b"PE\x00\x00"):
            continue
        machine, nsec = struct.unpack_from("<HH", sprx, pe + 4)
        optsz = struct.unpack_from("<H", sprx, pe + 20)[0]
        if machine not in (0x14C, 0x8664) or not (0 < nsec <= 96):
            continue
        sect = pe + 24 + optsz
        end = 0
        ok = True
        for s in range(nsec):
            base = sect + s * 40
            if base + 40 > n:
                ok = False
                break
            rawsz, rawptr = struct.unpack_from("<II", sprx, base + 16)
            if rawptr + rawsz > end:
                end = rawptr + rawsz
        if not ok or end == 0 or start + end > n:
            continue
        pe_bytes = sprx[start:start + end]
        if b"BSJB" in pe_bytes:        # a managed (CLI) image, not a native stub
            return pe_bytes


# IPMI result codes. NOT_EXIST: the client exists but its service process is not
# emulated, so a method call cannot be answered. NO_PACKET: the receive pump
# found no packet pending (the kernel's "would block" for a receive).
IPMI_METHOD_NOT_EXIST = 0x80020003
IPMI_NO_PACKET = 0x80020004
IPMI_TIMED_OUT = 0x8002003C        # ETIMEDOUT: an event-flag wait ran out
IPMI_EVF_NOT_SET = 0x80020010      # EBUSY: polled event flag pattern not set

# --- a partial FreeBSD syscall table (numbers that commonly show up) ------
# Full table: FreeBSD sys/kern/syscalls.master. Sony renumbers some and adds
# sce-specific ones in the 500+ range; those are logged by number.
SYSCALLS = {
    0: "syscall", 1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open",
    6: "close", 9: "dup", 59: "execve", 90: "dup2",
    20: "getpid", 23: "setuid", 24: "getuid", 33: "access",
    34: "chflags", 37: "kill", 39: "getppid", 41: "dup", 42: "pipe",
    54: "ioctl", 58: "readlink", 362: "kqueue", 363: "kevent",
    73: "munmap", 74: "mprotect",
    75: "madvise", 97: "socket", 98: "connect", 105: "setsockopt",
    118: "getsockopt", 202: "sysctl", 232: "clock_gettime",
    253: "issetugid", 272: "getdents", 324: "mlockall", 325: "munlockall",
    340: "sigprocmask", 416: "sigaction", 417: "sigreturn",
    431: "thr_exit", 432: "thr_self", 433: "thr_set_name", 165: "sysarch",
    454: "_umtx_op", 477: "mmap", 478: "lseek",
    # Sony / ORBIS specific (names best-effort; numbers vary by firmware)
    532: "regmgr_call", 572: "virtual_query", 533: "rtprio_thread", 557: "namedobj_create",
    587: "get_authinfo", 652: "terminate_process", 599: "mdbg_service", 603: "rdup",
}


from .sys_dynlib import DYNLIB_SYSCALLS, DynlibSyscalls
from .devices import BLOCKED, DceDevice, DmemDevice, open_device
from .sys_sync import SYNC_SYSCALLS, SyncSyscalls

import os
import struct as _struct
_TID_COUNTS = bool(os.environ.get("PSEMU_TID_COUNTS"))

# sysctls looked up by name (sysctl.name2oid). Values as the PS4 kernel
# (FreeBSD 9 based, 8 CPU cores) reports them.
NAMED_SYSCTLS = {
    "kern.sched.cpusetsize": _struct.pack("<i", 8),     # sizeof(cpuset_t)
    "kern.smp.cpus": _struct.pack("<i", 8),
    "hw.ncpu": _struct.pack("<i", 8),
    "machdep.tsc_freq": _struct.pack("<Q", 1_600_000_000),   # Jaguar @ 1.6 GHz
    "kern.sdk_version": _struct.pack("<I", 0x05050001),      # system software 5.05
    # sceKernelGetCpumode() (libkernel +0x14520) ignores sysctlbyname's return
    # value and returns its out variable, so an unknown name leaves stack garbage;
    # libSceSystemService then reports is_cpu_mode_7_cpu_normal = (mode == 5).
    # The console runs in the normal 7-CPU mode (5), and the shell polls this
    # every frame.
    "kern.cpumode": _struct.pack("<i", 5),
    # The console's own OpenPSID (16 bytes). The ShellUI reads it at launch
    # (LoginMgrProxy GetOpenPsIdForSystem) and hashes it into a GUID for system
    # logging; a missing sysctl made PsmNativeException(-1) end AppMain.Main.
    # A fixed dummy value (not any real console's id).
    "machdep.openpsid_for_sys": bytes(range(0xA0, 0xB0)),
    # SceSysCore (mini and full) and ShellCore's sceDataTransferInitialize read it at start-up; a missing
    # name made ShellCore abort its init ("*CRITICAL ERROR* Failed to initialize DataTransfer") and shut down.
    # 0 = the console is not in backup/restore mode.
    "kern.backup_restore_mode": _struct.pack("<i", 0),
    # SceSysCore's spawn path (sysctlbyname) asks for the pid the kernel reserved for the process about to be
    # forked ("[SceSysCore] sysctlbyname: failed -1" without it); 0 = none reserved.
    "debug.tentativeppid": _struct.pack("<i", 0),
    # The ShellUI's initializeSystemAfterPsm reads both (the shell's own init failed with 0x80f61308 when they were
    # missing): the current manufacturing mode (0 = a normal retail unit) and the console IDPS (16 bytes; a fixed
    # dummy value, not any real console's).
    "machdep.curr_manumode": _struct.pack("<i", 0),
    "machdep.idps": bytes(range(0xC0, 0xD0)),
}

SYSCALLS.update(DYNLIB_SYSCALLS)
SYSCALLS.update(SYNC_SYSCALLS)
SYSCALLS[548] = "batch_map"          # sceKernelBatchMap (else labelled "(sceKernelBatchMap)")
SYSCALLS[638] = "convert_utc_to_localtime"    # sceKernelConvertUtcToLocaltime
SYSCALLS[639] = "convert_localtime_to_utc"    # sceKernelConvertLocaltimeToUtc
# libkernel's pthread_{suspend,resume,get,set}_user_context_np: stop another
# thread and read/write its registers (Mono's stop-the-world uses them)
SYSCALLS.update({632: "thr_suspend_ucontext", 633: "thr_resume_ucontext",
                 634: "thr_get_ucontext", 635: "thr_set_ucontext"})
ESRCH = 3

# Names for every other syscall libkernel makes, from the table decoded out of
# libkernel.sprx / libkernel_sys.sprx (D:\Ps4Tools\ps4kernel\analysis\syscalls.csv;
# override with PSEMU_SYSCALLS_CSV). Only fills numbers psemu has no name for,
# so handler lookup (sys_<name>) is unchanged; unnamed Sony calls are labelled
# with the libkernel function that issues them, e.g. "(sceKernelSetEventFlag)".
SYSCALLS_CSV = r"D:\Ps4Tools\ps4kernel\analysis\syscalls.csv"

# Calls that wait on a real kernel. They don't count as progress for the
# idle-event-loop detector, and the plain waits hand the CPU to another
# runnable thread (kevent and _umtx_op decide that themselves).
WAIT_SYSCALLS = {240, 331, 363, 454, 542, 553}   # nanosleep, sched_yield, kevent,
#                                                  _umtx_op, WaitEventFlag, WaitSema
YIELD_SYSCALLS = {331}               # the other waits block on their own


def _load_syscall_names():
    import csv
    import os
    path = os.environ.get("PSEMU_SYSCALLS_CSV", SYSCALLS_CSV)
    if not os.path.isfile(path):
        # fall back to a table generated next to this file:
        #   python -m psemu.tools_syscall_scan libkernel.sprx -o psemu/syscalls.csv
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "syscalls.csv")
        if not os.path.isfile(path):
            return 0
    added = 0
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            try:
                num = int(row.get("number", ""))
            except ValueError:
                continue
            if num in SYSCALLS:
                continue
            exported = (row.get("ps4_exported_names") or "").split()
            fb = (row.get("freebsd9_name") or "").strip()
            if fb.startswith("sys_"):
                fb = fb[4:]
            if fb and (row.get("freebsd9_status") or "").strip() == "STD":
                name = fb
            elif exported:
                name = exported[0].lstrip("_")
                name = name[4:] if name.startswith("sys_") else name
            else:
                callers = (row.get("called_by") or "").split()
                name = f"({callers[0]})" if callers else ""
            if name:
                SYSCALLS[num] = name
                added += 1
    return added


_load_syscall_names()


_TRACE_TID = int(__import__('os').environ.get('PSEMU_TRACE_TID', '0'), 0)
_TRACE_PROC = __import__('os').environ.get('PSEMU_TRACE_PROC', '')

class SyscallDispatcher(DynlibSyscalls, SyncSyscalls):
    def __init__(self, emu):
        self.emu = emu            # back-reference for memory + stdout + stop
        self.counts = {}          # number -> times called
        self.tid_counts = {}      # (tid, number) -> times (PSEMU_TID_COUNTS=1)
        self.trace = emu.trace
        # Sony kernel-object model: hand out unique ids for created objects.
        self.children = {}          # child pid -> None (running) or its exit status (waiting to be reaped)
        self._next_handle = 0x100
        self._next_pid = 1001                 # children of rfork(RFPROC|RFMEM)
        self.objects = {}         # handle -> dict(kind, name, ...)
        # File-descriptor table: 0,1,2 are std streams; dup/open hand out the
        # lowest free fd, which is what the module's fd-setup code expects.
        self.fds = {0: "stdin", 1: "stdout", 2: "stderr"}
        self.kqueues = set()
        self.sig_actions = {}     # signal -> (handler, flags, mask bytes): sigaction()
        self.sig_altstack = {}    # tid -> (sp, size, flags): sigaltstack()
        self._sigtramp = None     # guest address of the sigreturn trampoline page
        self._sig_streak = {}     # (signal, rip, addr) -> deliveries, to catch fault loops
        self.devs = {}            # fd -> devices.Device (/dev/gc, /dev/dce, ...)
        # AF_UNIX endpoints served in-process (see unixsock.py): the system
        # processes that would own the listening end are not emulated.
        self.unix_servers = {}
        from .unixsock import install_default_servers
        install_default_servers(self)
        self.files = {}           # fd -> {"data": bytearray, "pos", "append", "path"} open files
        # Writable file layer: guest path -> contents. Firmware files are copied
        # in on first open, so writes never touch the dump on disk; files the
        # guest creates (databases, journals, flags) live here for the run.
        self.vfs = {}
        # the SQLite temp-file directory (osStat("//sqlite") in the engine's orbis VFS) exists on a
        # console; without it the managed SQLite layer logs orbisTempFileDir ERROR at every open
        self.vdirs = {"/sqlite"}  # directories the guest created (plus system dirs that must exist)
        self.vgone = set()        # firmware paths the guest deleted
        self.dirfds = set()       # fds opened on a directory
        self._cil_cache = {}      # .dll path -> CIL bytes extracted from .dll.sprx
        self.shms = {}            # fd -> shared-memory object (shm_open)
        self._shm_local = {}      # name -> {"name", "size", ...} POSIX shm objects (single process; see shm_objs)
        self.shm_maps = {}        # name -> (addr, span): where THIS process mapped each object
        self.vmas = []            # mmapped ranges (see _add_vma), for virtual_query
        self.knotes = {}          # kq fd -> {(ident, filter): knote dict}
        self.kq_pending = {}      # kq fd -> [(ident, filter)] triggered, not yet returned
        self._kq_wait_logged = set()
        self._ioctl_seen = set()  # (fd, req) of unmodelled ioctls already logged
        self._idle_waits = 0      # consecutive empty event-waits (idle detect)
        self.idle_limit = 512

    def _alloc_fd(self, desc="", base=3):
        # The real kernel hands mini-syscore a process with more than 0/1/2
        # open, so `open()` of a device lands at a high fd and leaves 3,4,5…
        # free for the module's rdup/dup bring-up (which expects exactly those).
        fd = base
        while fd in self.fds:
            fd += 1
        self.fds[fd] = desc or f"fd{fd}"
        return fd

    def _new_handle(self, kind, name=""):
        system = getattr(self.emu, "system", None)
        if system is not None:                      # one handle space for all processes
            h = system.alloc_handle()
        else:
            h = self._next_handle
            self._next_handle += 1
        self.objects[h] = {"kind": kind, "name": name}
        return h

    def _read_cstr(self, uc, ptr, maxlen=64):
        """NUL-terminated guest string, at most maxlen bytes. Reads page by page
        up to the terminator: a fixed maxlen-byte read faults whenever a short
        string sits within maxlen bytes of the end of its mapping (a 1024-byte
        read of a path 0x160 bytes below a page boundary killed the whole run),
        and returning "" on that fault would silently turn it into a wrong path."""
        if not ptr:
            return ""
        out = bytearray()
        while len(out) < maxlen:
            a = ptr + len(out)
            n = min(maxlen - len(out), 0x1000 - (a & 0xFFF))
            try:
                chunk = bytes(uc.mem_read(a, n))
            except Exception:
                break
            end = chunk.find(b"\x00")
            if end >= 0:
                out += chunk[:end]
                break
            out += chunk
        return out.decode("latin1", "replace")

    _ARG_REGS = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                 UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9)

    def _args(self, uc):
        # The six syscall argument registers are read on every syscall. Unicorn's
        # Python wrapper spends ~2us per register choosing a register class; calling
        # its batched C entry point with preallocated buffers reads all six in ~2us.
        sa = getattr(uc, "syscall_args", None)       # WHP backend: registers are cached
        if sa is not None:
            return sa()
        rd = self.__dict__.get("_argrd")
        if rd is None or rd[0] is not uc:
            try:
                import ctypes
                n = len(self._ARG_REGS)
                ids = (ctypes.c_int * n)(*self._ARG_REGS)
                vals = (ctypes.c_uint64 * n)()
                ptrs = (ctypes.c_void_p * n)(
                    *[ctypes.addressof(vals) + 8 * k for k in range(n)])
                rd = self._argrd = (uc, uc._do_reg_read_batch, ids, ptrs,
                                    ctypes.c_int(n), vals)
            except Exception:
                rd = self._argrd = (uc, None, None, None, None, None)
        if rd[1] is not None and rd[1](rd[2], rd[3], rd[4]) == 0:
            return tuple(rd[5])
        return tuple(uc.reg_read(r) for r in self._ARG_REGS)

    def _ret(self, uc, value, error=False):
        uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        fl = uc.reg_read(UC_X86_REG_RFLAGS)
        if error:
            fl |= 1          # set carry = error, FreeBSD convention
        else:
            fl &= ~1
        uc.reg_write(UC_X86_REG_RFLAGS, fl)

    # ---- the hook Unicorn calls on every `syscall` instruction ----------
    def dispatch(self, uc, user_data=None):
        num = uc.reg_read(UC_X86_REG_RAX)
        name = SYSCALLS.get(num, f"sys_{num}")
        self.counts[num] = self.counts.get(num, 0) + 1
        if _TID_COUNTS:                       # PSEMU_TID_COUNTS=1: per-thread syscall histogram in the summary
            _t = self.emu.sched.current.tid if self.emu.sched and self.emu.sched.current else 0
            self.tid_counts[(_t, num)] = self.tid_counts.get((_t, num), 0) + 1
        if num not in WAIT_SYSCALLS:  # real progress (not another wait) resets idle detection
            self._idle_waits = 0
        handler = getattr(self, f"sys_{name}", None)
        if _TRACE_TID and _TRACE_PROC in self.emu.path and self.emu.sched is not None and self.emu.sched.current is not None and (self.emu.sched.current.tid == _TRACE_TID or _TRACE_TID < 0):
            a = self._args(uc)
            self.emu.log(f'  [tt {num} {name}] ' + ' '.join(f'{x:#x}' for x in a[:6]))

        if handler is None:
            handler = getattr(self, "sys_" + SYSCALLS.get(num, ""), None)

        if self.trace or handler is None:
            a = self._args(uc)
            self.emu.log(f"  [syscall {num:>3} {name}] "
                         f"args=({a[0]:#x}, {a[1]:#x}, {a[2]:#x}, "
                         f"{a[3]:#x}, {a[4]:#x}, {a[5]:#x})")

        if handler is not None:
            handler(uc)
        else:
            # unknown/unimplemented: pretend success so we keep moving
            self._ret(uc, 0)
        if num in YIELD_SYSCALLS:
            self.yield_cpu()

    # ---- threads ------------------------------------------------------
    def yield_cpu(self):
        """A call that only gives up the CPU (sched_yield, polls that would
        spin): let another runnable thread run."""
        sched = self.emu.sched
        if sched is not None and any(t.state == "ready" for t in sched.threads.values()):
            sched.request_switch()

    # ---- registry (regmgr_call, syscall 532) -----------------------------
    # libSceRegMgr: sceRegMgrGetInt(key, int *out) = regmgr_call(2, key, &work, out, 4).
    # The registry itself lives in the (not emulated) kernel; a factory-default
    # value is returned for each known key and 0 for the rest.
    REGMGR_INT_DEFAULTS = {
        0x02020000: 1,      # SYSTEM_language = English (US)
        # SYSTEM_initialize: BootManager.IsInitialSetupRequired() is true when this
        # is 0, i.e. a never-set-up console takes the first-boot flow. A configured
        # console has it set.
        0x02040000: 1,
        0x020b0000: 1,      # SYSTEM_button_assign
        0x05020000: 2,      # DATE_date_format = MM/DD/YYYY
    }

    def sys_regmgr_call(self, uc):
        op, key, _work, out, size = self._args(uc)[:5]
        seen = self.__dict__.setdefault("_regmgr_seen", set())
        if (op, key) not in seen and len(seen) < 400:
            seen.add((op, key))
            self.emu.log(f"  [regmgr] op={op} key={key:#010x}"
                         + (f" -> {self.REGMGR_INT_DEFAULTS.get(key, 0)}" if op == 2 else ""))
        if op == 2 and out:                       # get int
            val = self.REGMGR_INT_DEFAULTS.get(key, 0)
            try:
                uc.mem_write(out, _struct.pack("<I", val)[:max(1, min(size or 4, 4))])
            except Exception:
                pass
        self._ret(uc, 0)

    # ---- real-ish handlers ---------------------------------------------
    def sys_exit(self, uc):
        code = self._args(uc)[0]
        signed = code - 0x100000000 if code >= 0x80000000 else code
        self.emu.log(f"  [exit] code={code} ({signed})")
        self.emu.stop(f"module called exit({signed})")

    def sys_thr_exit(self, uc):
        # thr_exit(long *state): the kernel stores 1 to *state and wakes
        # umtx waiters on it (pthread_join waits there), then the thread ends.
        import struct
        state = self._args(uc)[0]
        sched = self.emu.sched
        t = sched.current if sched else None
        if state:
            try:
                uc.mem_write(state, struct.pack("<q", 1))
            except Exception:
                pass
            self.umtx_wake(state, 1 << 30)
        self.emu.log(f"  [thr_exit] thread {t.tid if t else 0:#x}")
        if sched is None or not sched.multi:
            self.emu.stop("last thread called thr_exit")
            return
        sched.exit_current()

    def sys_thr_new(self, uc):
        # thr_new(struct thr_param *param, int size) - amd64 FreeBSD 9:
        #   0 start_func  8 arg  0x10 stack_base  0x18 stack_size  0x20 tls_base
        #   0x28 tls_size  0x30 long *child_tid  0x38 long *parent_tid
        #   0x40 int flags  0x48 struct rtprio *rtp
        import struct
        param, size = self._args(uc)[:2]
        try:
            raw = bytes(uc.mem_read(param, 0x50))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        start, arg, stack_base, stack_size, tls_base, _tls_size, ctid, ptid = \
            struct.unpack_from("<8Q", raw, 0)
        sched = self.emu.sched
        dyn = getattr(self.emu, "dyn", None)
        lm = dyn.module_at(start) if dyn else None
        if dyn is not None:
            # The new thread's static TLS block of the main executable (module 1, the one closest to
            # %fs, whose offset the linker fixed in its code): .tdata image, zeroed .tbss. The guest
            # allocates the block from its heap and only fills in libkernel's own, so without this
            # the executable sees whatever the heap held (SceSysCore's lock-order checker lives in
            # .tbss and aborts on it).
            for m in dyn.modules:
                if m.tls_index == 1 and m.tls_offset and m.tls_offset <= tls_base:
                    img = m.mod.elf.data[m.tls.offset:m.tls.offset + m.tls.filesz]
                    try:
                        uc.mem_write(tls_base - m.tls_offset, img + bytes(max(m.tls.memsz - len(img), 0)))
                    except Exception:
                        pass
        t = sched.spawn(start, arg, stack_base + stack_size, tls_base,
                        name=f"{lm.name}+{start - lm.base:#x}" if lm else "")
        for p in (ctid, ptid):
            if p:
                try:
                    uc.mem_write(p, struct.pack("<q", t.tid))
                except Exception:
                    pass
        self.emu.log(f"  [thr_new] thread {t.tid:#x} at {start:#x} ({t.name}) "
                     f"stack {stack_base:#x}+{stack_size:#x} tls {tls_base:#x} size {_tls_size:#x}")
        self._ret(uc, 0)

    def sys_rfork(self, uc):
        # rfork(flags). RFPROC|RFMEM (vfork-style, what sceKernelSpawn and
        # rfork_thread use) makes a child that shares memory: psemu runs it as
        # another thread, so the parent keeps going too (it may signal the
        # child, as mini-syscore's spawn semaphore does). A child that execve()s
        # replaces the whole image, as psemu runs one process.
        # FreeBSD returns rax = pid, rdx = 0 in the parent; rdx = 1 in the child.
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDX, UC_X86_REG_RFLAGS, UC_X86_REG_RIP
        RFPROC, RFMEM = 0x10, 0x20
        flags = self._args(uc)[0] & 0xFFFFFFFF
        if not flags & RFPROC:                 # resource-sharing changes only
            return self._ret(uc, 0)
        sched = self.emu.sched
        if not flags & RFMEM or sched is None:
            # a separate address space isn't modelled: continue as the child
            self.emu.log(f"  [rfork] flags={flags:#x}: no RFMEM - continuing as the child")
            uc.reg_write(UC_X86_REG_RDX, 1)
            return self._ret(uc, self.PID)
        try:
            a1 = self._args(uc)[1]
            if a1 > 0x10000 and os.environ.get('PSEMU_IPMI_TRACE'):
                self.emu.log('  [rfork] arg1 struct: ' + bytes(uc.mem_read(a1, 0x80)).hex())
        except Exception:
            pass
        sysm = getattr(self.emu, 'system', None)
        if sysm is not None:                           # one pid space for the whole machine
            pid = sysm.alloc_pid()
        else:
            pid = self._next_pid
            self._next_pid += 1
        rip = uc.reg_read(UC_X86_REG_RIP) + 2          # past the syscall instruction
        fl = uc.reg_read(UC_X86_REG_RFLAGS) & ~1
        t = sched.fork_current(rip, {UC_X86_REG_RAX: self.PID, UC_X86_REG_RDX: 1,
                                     UC_X86_REG_RFLAGS: fl}, name=f"pid{pid}")
        t.spawn_child = True                           # an execve() here spawns a process
        t.child_pid = pid
        self._rdup_next = 3                            # the child's own fd table starts after stdio
        self.children[pid] = None                      # alive (None) until it exits: status
        self.emu.log(f"  [rfork] flags={flags:#x} -> child pid {pid} (thread {t.tid:#x}, "
                     f"shares memory)")
        uc.reg_write(UC_X86_REG_RDX, 0)
        self._ret(uc, pid)

    def sys_write(self, uc):
        fd, buf, n, *_ = self._args(uc)
        try:
            data = uc.mem_read(buf, n) if n else b""
        except Exception:
            self._ret(uc, EBADF, error=True)
            return
        raw = bytes(data)
        dev = self.devs.get(fd & 0xFFFFFFFF)
        if dev is not None and hasattr(dev, "write"):
            # a device that takes writes (UNIX sockets); plain devices have no
            # write() and fall through to the logging path below
            try:
                rv = dev.write(uc, buf, n)
            except Exception as e:
                self.emu.log(f"  [write] {dev.path}: {e} -> EINVAL")
                return self._ret(uc, EINVAL, error=True)
            return self._ret(uc, n if rv is None else rv)
        f = self.files.get(fd & 0xFFFFFFFF)
        if f is not None:
            pos = len(f["data"]) if f.get("append") else f["pos"]
            self._vwrite(f["data"], pos, raw)
            f["pos"] = pos + len(raw)
            self.emu.log(f"  [write] '{f.get('path', fd)}' +{len(raw):#x} @ {pos:#x}")
            return self._ret(uc, n)
        if fd > 2 and n > 160:
            # binary device writes (notifications...): show the readable part
            words = [w for w in raw.replace(b"\n", b" ").split(b"\x00") if len(w) >= 4]
            text = (" | ".join(w.decode("latin1", "replace") for w in words))[:200]
            self.emu.log(f"  [write fd={fd} len={n}] (binary) {text!r}")
        else:
            text = raw.decode("latin1", "replace")
            self.emu.log(f"  [write fd={fd} len={n}] {text!r}")
        self._ret(uc, n)

    def sys_read(self, uc):
        fd, buf, n, *_ = self._args(uc)
        fd &= 0xFFFFFFFF
        dev = self.devs.get(fd)
        if dev is not None:
            try:
                rv = dev.read(uc, buf, n)
            except Exception as e:
                self.emu.log(f"  [read] {dev.path}: {e} -> EINVAL")
                return self._ret(uc, EINVAL, error=True)
            if rv is BLOCKED:
                return                                  # parked; the wake delivers the return value
            if rv is not None and rv < 0:
                return self._ret(uc, -rv, error=True)   # e.g. EAGAIN: no data pending
            return self._ret(uc, rv or 0)
        f = self.files.get(fd)
        if f is not None:
            chunk = bytes(f["data"][f["pos"]:f["pos"] + (n & 0xFFFFFFFF)])
            try:
                if chunk:
                    uc.mem_write(buf, chunk)
            except Exception:
                return self._ret(uc, EFAULT, error=True)
            if os.environ.get("PSEMU_TRACE_READ") and str(f.get("path", "")).endswith(os.environ["PSEMU_TRACE_READ"]):
                self.emu.log(f"  [read-trace] fd {fd} pos {f['pos']:#x} n {n & 0xFFFFFFFF:#x} -> {chunk[:24].hex()}")
            f["pos"] += len(chunk)
            return self._ret(uc, len(chunk))
        # no real input source yet -> EOF
        k = self.__dict__.setdefault("_eof_reads", {})
        k[fd] = k.get(fd, 0) + 1
        if k[fd] in (1, 1000):
            tid = self.emu.sched.current.tid if self.emu.sched and self.emu.sched.current else 0
            self.emu.log(f"  [read] fd {fd:#x} is not open: EOF (tid {tid:#x}, {k[fd]} time(s), n={n & 0xFFFFFFFF:#x})")
        if fd > 2 and os.environ.get("PSEMU_READ_EBADF", "1") != "0":
            return self._ret(uc, 9, error=True)        # EBADF: the descriptor is not open (the kernel's answer)
        self._ret(uc, 0)

    # ---- sockets -------------------------------------------------------
    AF_UNIX = 1

    def sys_socket(self, uc):
        # socket(domain, type, protocol). AF_UNIX gets a real endpoint served
        # in-process (unixsock.py); every other family keeps the old behaviour
        # of the generic stub (return 0) so SceNet and friends are unchanged.
        domain = self._args(uc)[0] & 0xFFFFFFFF
        if domain != self.AF_UNIX:
            return self._ret(uc, 0)
        from .unixsock import UnixSocket
        fd = self._alloc_fd("unix-socket", base=16)
        self.devs[fd] = UnixSocket(self)
        self.emu.log(f"  [socket] AF_UNIX -> fd {fd}")
        self._ret(uc, fd)

    EAGAIN = 35
    MSG_DONTWAIT = 0x80

    def sys_recvfrom(self, uc):
        """recvfrom(fd, buf, len, flags, from, fromlen). The only real sockets are the in-process
        AF_UNIX endpoints; every other family is a stub that "succeeds" (socket() returns 0). With
        no network a real receive never completes, but the stub used to return 0 bytes at once:
        the shell's managed network listener (System.dll -> libSceNet, recvfrom(0, buf, 0x300,
        0x40000000) in a loop with setsockopt/netcontrol) then spun at ~6000 iterations/s and took
        45-75% of all guest CPU time, starving the render and input threads (vblank gaps, a low
        frame rate). A blocking receive now parks the thread (as on a console that never hears
        anything); MSG_DONTWAIT polls get EAGAIN after a short pause on the virtual clock."""
        fd, buf, n, flags = self._args(uc)[:4]
        fd &= 0xFFFFFFFF
        dev = self.devs.get(fd)
        if dev is not None and hasattr(dev, "recvfrom"):
            return dev.recvfrom(uc, buf, n, flags)
        sched = self.emu.sched
        if sched is None or getattr(sched, "current", None) is None:
            return self._ret(uc, self.EAGAIN, error=True)
        if flags & self.MSG_DONTWAIT:
            self._ret(uc, self.EAGAIN, error=True)
            sched.block({"kind": "sleep", "ns": 5_000_000}, deadline_ns=sched.now_ns() + 5_000_000,
                        timeout_ret=(self.EAGAIN, True))
            return
        self._ret(uc, self.EAGAIN, error=True)
        sched.block({"kind": "net_recv", "fd": fd})          # no deadline: parked for good

    def sys_connect(self, uc):
        # connect(fd, sockaddr *, len): FreeBSD sockaddr_un = {u8 len; u8 family;
        # char path[104]}.
        fd, addr, alen = self._args(uc)[:3]
        sock = self.devs.get(fd & 0xFFFFFFFF)
        if not hasattr(sock, "connect"):
            return self._ret(uc, 0)
        path = self._read_cstr(uc, addr + 2, 104)
        err = sock.connect(path)
        if err:
            return self._ret(uc, err, error=True)
        self._ret(uc, 0)

    _ipmi_kid = 0x100           # next IPMI client/session handle to hand out
    IPMI_CREATE_SERVER = 0x0    # ipmimgr_call cmd: this process hosts a service
    IPMI_CREATE_CLIENT = 0x2    # ipmimgr_call cmd: create a client for a service
    IPMI_CONNECT = 0x400        # ipmimgr_call cmd: client connects to its service
    IPMI_DISCONNECT = 0x310     # ipmimgr_call cmd: client drops its session
    IPMI_INVOKE_SYNC = 0x320    # ipmimgr_call cmd: client invokes a sync method
    IPMI_WAIT_EVF = 0x490       # ipmimgr_call cmd: client waits on a service event flag
    IPMI_POLL_EVF = 0x491       # ipmimgr_call cmd: client polls a service event flag
    IPMI_RECEIVE = 0x201        # ipmimgr_call cmd: receive-pump reads the next packet
    IPMI_USER_GET_EVENT = 0x252 # ipmimgr_call cmd: getEvent try-receive
    # Client "try-receive an event" ipmimgr_call cmds that must report "no event"
    # (0x80020023) instead of empty-success, or their drain loops spin forever
    # (SceUserService getEvent 0x252, SceVideoCoreServer 0x252, SceAppDbIpc 0x251).
    IPMI_TRY_RECEIVE = frozenset({0x251, 0x252})
    # Service event flags (cmd 0x490 waitEventFlag) satisfied immediately instead
    # of parking: the compositor fires a vblank/flip event every frame on a
    # console, so the UI render thread's wait must complete for frames to flow.
    # SceAvSettingIpc: the AV-settings service answers requests (e.g. the shell's
    # SetVideoOutputColorEffect at boot) by signalling its event flag; unsignalled,
    # that boot task never finishes and BootManager's background-init join, and
    # with it the scene start-up, waits forever.
    # SceShellCoreUtil: ShellCore answers requests such as ChangeRunLevel (issued by
    # BootManager.BackgroundInitDaemons) by signalling completion on its event flag;
    # unsignalled, that thread parks forever and never sets boot flag 0x8000000, which
    # ResetSurfaceRect and the remote-play controller wait for.
    IPMI_EVF_SATISFY = frozenset({"SceVideoCoreServer", "SceAvSettingIpc", "SceShellCoreUtil"})

    def _ipmi_service_name(self, uc, in_ptr, size):
        import struct
        if not in_ptr:
            return ""
        try:
            for off in range(8, min(size, 0x18), 8):
                v = struct.unpack("<Q", bytes(uc.mem_read(in_ptr + off, 8)))[0]
                if 0x10000 < v < 0x7FFFFFFFFFFF:
                    s = self._read_cstr(uc, v, 48)
                    if s and s.isprintable() and s[:3] == "Sce":
                        return s
        except Exception:
            pass
        return ""

    # Response-delivery framework for IPMI sync methods (cmd 0x320).
    #
    # libSceIpmi's invokeSyncMethod(method, in[], numIn, out[], numOut, *result,
    # flags) passes the kernel this struct:
    #   {u32 method@0; u32 numIn@4; u32 numOut@8; u64 *inInfo@0x10;
    #    u64 *outInfo@0x18; u64 *methodResult@0x20; u32 flags@0x28}
    # with inInfo/outInfo arrays of {u64 data; u64 size} (out entries carry a
    # third u64: the size actually returned). The method's own return value is
    # stored through *methodResult; the syscall result is the transport status.
    #
    # Nothing answers these calls yet when the service is hosted by a process
    # psemu does not run (or by this program's own server threads - the
    # request/response loopback is not implemented). Until a method is modelled
    # in IPMI_METHODS it gets an EMPTY SUCCESS: method result 0, out buffers
    # zeroed, returned sizes 0. That reads as "nothing to report", which is
    # what most init-time query/notify methods need to proceed.
    #
    # IPMI_METHODS maps (service, method) -> name of a handler method
    # handler(uc, call) returning the method result;
    # call = {"in": [(ptr, size)], "out": [(ptr, size, info)]}.
    IPMI_METHODS = {
        ("SceSysCoreApp", 0xAA110002): "_ipmi_syscore_app_info",
        ("SceSysCoreApp2", 0xAA120009): "_ipmi_syscore_my_app_id",
        ("SceUserService", 0x3000F): "_ipmi_user_id_list",
        ("SceUserService", 0x3000C): "_ipmi_user_id_one",      # GetForegroundUser
        ("SceUserService", 0x30011): "_ipmi_user_id_one",      # GetInitialUser
        ("SceUserService", 0x30004): "_ipmi_user_name",        # GetUserName
        ("SceMbusIpc", 0xCE110028): "_ipmi_mbus_device_list",  # GetDeviceList (pads for libScePsm)
    }

    # An empty reply zeroes each small out buffer the caller declares, because the declared size
    # is a CAPACITY: some clients declare more than their real buffer holds (a real server only
    # writes what it returns). For those, cap how many bytes the empty reply may touch per out
    # buffer. SceAutoMounterIpc 0x30023 declares out=[64, 4] but the 64-byte one is smaller on
    # the caller's stack; zeroing all 64 bytes smashed the canary (guest abort in the stack-check
    # tail) once boot got far enough to make the call.
    IPMI_EMPTY_ZERO_CAP = {
        ("SceAutoMounterIpc", 0x30023): 4,
    }

    # The one registered/logged-in user. Real console user ids are 0x1xxxxxxx
    # values (the VSH's IsValidUserIdNative accepts only a high nibble of 1, 2
    # or 3), not small indexes.
    USER_ID = 0x10000001
    USER_ID_INVALID = 0xFFFFFFFF  # SCE_USER_SERVICE_USER_ID_INVALID (-1)

    def _ipmi_user_id_list(self, uc, call):
        """SceUserService 0x3000f: out[0] = 0x50 bytes = 20 x i32 user ids,
        unused slots -1. The shell's per-user setup walks it:
        `if (GetUserIdList(ids) == 0) for (i < 20) if (ids[i] != -1)
        createPerUserTables(ids[i])` (eboot+0x478669). Left as an unfilled
        reply buffer it was stale stack -- stack-pointer halves and a string
        fragment -- so the notification thread built a full set of tables,
        indexes and triggers (~130M instructions each) for up to 20 bogus
        users and ate ~90% of the CPU for billions of instructions, starving
        the UI thread. Report the single registered user."""
        import struct
        if call["out"]:
            ids = [self.USER_ID] + [self.USER_ID_INVALID] * 19
            self._ipmi_out(uc, call, 0, struct.pack("<20I", *ids))
        return 0

    # The registered user's name. A placeholder (a console shows the name typed at first-time setup);
    # PSEMU_USER_NAME overrides it. User names are at most 16 characters.
    USER_NAME = "Player1"

    # SceUserService 0x30004 is libSceUserService's generic "get a per-user string": every
    # sceUserServiceGet*(userId, char *buf, size_t size) built on libSceUserService+0x630 sends
    # {u32 user id; u32 kind}. kind 1 = the user name (sceUserServiceGetUserName), 0x800 = the theme
    # entitlement id (sceUserServiceGetThemeEntitlementId, +0x8110). Answering every kind with the
    # name made the theme manager see an entitlement id "Player1", try to mount a packaged theme
    # and die on an empty mount path.
    USER_STRING_NAME = 1

    def _ipmi_user_name(self, uc, call):
        """SceUserService 0x30004: in[0] = {u32 user id; u32 kind}, out[0] = the NUL-terminated string
        (capacity 17 for the name). Kind 1 is the registered user's name (placeholder, see USER_NAME);
        every other kind is not set for the user: an empty string. The method result is 0, or 0x80960005
        (INVALID_ARGUMENT, the code libSceUserService itself uses for a bad argument) for an id that is
        not the registered user (the exact USER_NOT_FOUND code is not confirmed)."""
        import os
        import struct
        kind = self.USER_STRING_NAME
        if call["in"]:
            uid, kind = struct.unpack("<II", bytes(self.emu.uc.mem_read(call["in"][0][0], 8)))
            if uid != self.USER_ID:
                return 0x80960005
        text = b""
        if kind == self.USER_STRING_NAME:
            name = os.environ.get("PSEMU_USER_NAME")
            text = (self.USER_NAME if name is None else name).encode("utf-8")[:16]
        if call["out"]:
            self._ipmi_out(uc, call, 0, text + bytes(1))
        return 0

    def _ipmi_user_id_one(self, uc, call):
        """SceUserService 0x3000c (GetForegroundUser) / 0x30011 (GetInitialUser):
        out[0] = u32 user id. With the default empty reply the shell read 0 --
        an invalid id -- and InputManager.SetDeviceIndexBehavior(SpecificUser, 0)
        threw ArgumentException, ending AppMain.Main."""
        import struct
        if call["out"]:
            self._ipmi_out(uc, call, 0, struct.pack("<I", self.USER_ID))
        return 0

    def _ipmi_mbus_device_list(self, uc, call):
        """SceMbusIpc 0xce110028 (GetDeviceList): in[0] = 0x110 bytes (a 0x100 filter + 0x10), out =
        [entries (0x100 each, <= 16), u32 count, u32 count]. libScePsm asks for each device class it
        can drive as a pad; the emulated DualShock 4 (mbus.py) is reported only when PSEMU_PAD is set to
        something other than 'off' (the default: with a pad registered the shell's main thread later
        parks on a libScePsm semaphore that nothing posts, see docs/shellui-boot/README.md). The method
        RESULT code is the number of entries (libSceMbus hands it back as the count)."""
        import os
        import struct
        from . import mbus
        flt = b""
        if call["in"]:
            d, sz = call["in"][0]
            flt = bytes(uc.mem_read(d, min(sz, 0x100))) if d and sz else b""
        devices = [] if os.environ.get("PSEMU_PAD", "off").lower() == "off"             else [mbus.pad_entry(0, self.USER_ID)]
        cap = (call["out"][0][1] // mbus.ENTRY_SIZE) if call["out"] else 0
        found = mbus.device_list(devices, flt, cap)
        if call["out"]:
            self._ipmi_out(uc, call, 0, b"".join(found))
        for i in (1, 2):
            if len(call["out"]) > i:
                self._ipmi_out(uc, call, i, struct.pack("<I", len(found)))
        seen = self.__dict__.setdefault("_mbus_logged", set())
        key = (struct.unpack_from("<I", flt.ljust(0x10, b"\xff"), 0xC)[0], len(found))
        if key not in seen:
            seen.add(key)
            self.emu.log(f"  [ipmi] SceMbusIpc GetDeviceList class={key[0]:#x} -> {len(found)} device(s)")
        return len(found)       # libSceMbus returns the method result code as the device count

    def _ipmi_syscore_my_app_id(self, uc, call):
        """SceSysCoreApp2 0xAA120009: out[0] = u32 app id of the calling
        process. Launch Control registers its own app entry under this id
        (SceLncUtilAppStatus%08x ...), and later looks the shell up by the id
        the kernel's AppInfo reports - the two must agree."""
        import struct
        if call["out"]:
            self._ipmi_out(uc, call, 0, struct.pack("<I", (getattr(self.emu, 'app_id', None) or self.APP_ID)))
        return 0

    def _ipmi_out(self, uc, call, i, data):
        """Store `data` as out-argument i of a sync method (and its size)."""
        import struct
        d, cap, info = call["out"][i]
        data = bytes(data)[:cap]
        uc.mem_write(d, data)
        uc.mem_write(info + 16, struct.pack("<Q", len(data)))

    def _ipmi_syscore_app_info(self, uc, call):
        """SceSysCoreApp 0xAA110002: app info for an app id. in[0] = u32 app
        id, out[0] = the kernel's 0x48-byte AppInfo (app id first). SceSysCore
        tracks every launched app; Launch Control asks it about its own
        process at start-up (waitUntilAppFound) and gives up - taking PSN
        core init down with it - if the app is unknown. We report the asked
        app as a plain running system process."""
        import struct
        app_id = self.APP_ID
        if call["in"] and call["in"][0][1] >= 4:
            app_id = struct.unpack("<I", bytes(uc.mem_read(call["in"][0][0], 4)))[0]
        if not call["out"]:
            return 0
        info = bytearray(call["out"][0][1])
        struct.pack_into("<I", info, 0, app_id)
        self._ipmi_out(uc, call, 0, info)
        self.emu.log(f"  [ipmi] SceSysCoreApp app info for app {app_id:#x}")
        return 0

    def _ipmi_invoke(self, uc, name, in_ptr, size):
        import struct
        try:
            a = bytes(uc.mem_read(in_ptr, 0x30))
        except Exception:
            return IPMI_METHOD_NOT_EXIST
        method, n_in, n_out = struct.unpack_from("<III", a, 0)
        p_in, p_out, p_res = struct.unpack_from("<QQQ", a, 0x10)
        n_in, n_out = min(n_in, 16), min(n_out, 16)
        call = {"in": [], "out": []}
        try:
            for i in range(n_in):
                d, sz = struct.unpack("<QQ", bytes(uc.mem_read(p_in + i * 16, 16)))
                call["in"].append((d, sz))
            for i in range(n_out):
                info = p_out + i * 24
                d, sz = struct.unpack("<QQ", bytes(uc.mem_read(info, 16)))
                call["out"].append((d, sz, info))
        except Exception:
            pass
        handler = self.IPMI_METHODS.get((name, method))
        if handler is not None:
            try:
                res = getattr(self, handler)(uc, call)
            except Exception as e:
                self.emu.log(f"  [ipmi] {name}.method{method:#x} handler failed: {e}")
                res = IPMI_METHOD_NOT_EXIST
        else:
            # Unmodelled method: an empty reply. Zero only small out fields
            # (counts, results). The out size is the caller's declared
            # capacity, not the real buffer size: SceShellCore passes a
            # 0x500-byte stack array as 2048, so filling it all overwrote the
            # stack canary (__stack_chk_fail after SceNpMgrIpc method 0x22).
            res = 0
            cap = self.IPMI_EMPTY_ZERO_CAP.get((name, method), 0x40)
            for d, sz, info in call["out"]:
                try:
                    if d and 0 < sz <= 0x40:
                        uc.mem_write(d, bytes(min(sz, cap)))
                    uc.mem_write(info + 16, struct.pack("<Q", 0))   # bytes returned
                except Exception:
                    pass
        try:
            if p_res:
                uc.mem_write(p_res, struct.pack("<I", res & 0xFFFFFFFF))
        except Exception:
            pass
        mc = self.__dict__.setdefault("_ipmi_method_counts", {})
        mc[(name, method)] = mc.get((name, method), 0) + 1
        seen = self.__dict__.setdefault("_ipmi_methods_seen", set())
        if (name, method) not in seen:
            seen.add((name, method))
            self.emu.log(f"  [ipmi] invoke {name}.method{method:#x} "
                         f"in={[sz for _, sz in call['in']]} "
                         f"out={[sz for _, sz, _ in call['out']]} -> "
                         + ("modelled" if handler else "empty success"))
        return 0

    def _ipmi_wait_evf(self, uc, kid, name, result_ptr, in_ptr):
        """Client waitEventFlag: {u32 index@0; u64 pattern@8; u32 mode@0x10;
        u64 *result@0x18; u32 *timeout_us@0x20}. Nothing sets these service
        event flags yet, so the wait runs out: the thread sleeps for the
        timeout on the virtual clock and gets ETIMEDOUT (or parks forever when
        no timeout was given), exactly as against an idle service."""
        import struct
        timeout_us = None
        p_to = 0
        try:
            p_to = struct.unpack("<Q", bytes(uc.mem_read(in_ptr + 0x20, 8)))[0]
            if p_to:
                timeout_us = struct.unpack("<I", bytes(uc.mem_read(p_to, 4)))[0]
        except Exception:
            pass
        sched = self.emu.sched
        if sched is None or getattr(sched, "current", None) is None:
            return IPMI_TIMED_OUT
        # SceVideoCoreServer is the compositor: the UI's render thread waits on
        # its event flag (idx 0, pattern 0xff, OR|CLEAR) for a vblank/flip/
        # composite-done event. On a console the compositor sets these bits
        # every vblank; nothing does here, so the thread just keeps timing out
        # and the render loop never advances. Deliver a SUCCESS wake with the
        # requested bits set, paced at one frame (~16.7ms, 60Hz) - this still
        # BLOCKS (so the scheduler runs the init/render threads and the thread
        # does not hog the CPU) but wakes as if a vblank fired instead of
        # ETIMEDOUT. {u32 idx@0; u64 pattern@8; u32 mode@0x10; u64 *result@0x18;
        # u32 *timeout@0x20}.
        if name in self.IPMI_EVF_SATISFY:
            try:
                pattern = struct.unpack("<Q", bytes(uc.mem_read(in_ptr + 8, 8)))[0]
            except Exception:
                pattern = 0xff
            try:
                p_bits = struct.unpack("<Q", bytes(uc.mem_read(in_ptr + 0x18, 8)))[0]
            except Exception:
                p_bits = 0
            frame_ns = 16_666_667           # 60 Hz vblank
            if timeout_us is not None:
                frame_ns = min(frame_ns, timeout_us * 1000)

            def on_frame(th, result_ptr=result_ptr, p_to=p_to,
                         p_bits=p_bits, pattern=(pattern or 0xff)):
                # each vblank the GnmCompositor stand-in drains whatever the
                # client queued in the shared command ring
                srv = self.unix_servers.get("GnmCompositor")
                if srv is not None:
                    _t = self.emu._time() if self.emu.whp else 0.0
                    srv.ring.service(self.emu.uc)
                    if self.emu.whp:
                        self.emu._excl += self.emu._time() - _t     # GPU time is not guest time
                try:
                    if result_ptr:
                        self.emu.uc.mem_write(result_ptr, struct.pack("<I", 0))
                    if p_bits:
                        self.emu.uc.mem_write(p_bits, struct.pack("<Q", pattern))
                    if p_to:
                        self.emu.uc.mem_write(p_to, struct.pack("<I", 0))
                except Exception:
                    pass

            seen = self.__dict__.setdefault("_ipmi_evf_sat_seen", set())
            if name not in seen:
                seen.add(name)
                self.emu.log(f"  [ipmi] wait_evf {name}: driving at 60Hz "
                             "(compositor vblank fired on wake)")
            sched.block({"kind": "ipmi_wait_evf", "kid": kid, "name": name,
                         "on_timeout": on_frame},
                        deadline_ns=sched.now_ns() + frame_ns,
                        timeout_ret=(0, False))
            return None                     # blocked; on_frame delivers success

        def on_timeout(th, result_ptr=result_ptr, p_to=p_to):
            try:
                if result_ptr:
                    self.emu.uc.mem_write(result_ptr, struct.pack("<I", IPMI_TIMED_OUT))
                if p_to:
                    self.emu.uc.mem_write(p_to, struct.pack("<I", 0))
            except Exception:
                pass

        sched.block({"kind": "ipmi_wait_evf", "kid": kid, "name": name,
                     "on_timeout": on_timeout},
                    deadline_ns=None if timeout_us is None
                    else sched.now_ns() + timeout_us * 1000,
                    timeout_ret=(0, False))
        return None                     # blocked: the wake-up supplies the result

    @staticmethod
    def _has_cstring(data, needle):
        """`needle` + NUL occurs in `data` not preceded by [A-Za-z0-9_]. A plain
        find() loop: the equivalent lookbehind regex was ~100x slower on a large image."""
        pat = needle + b"\x00"
        pos = data.find(pat)
        while pos >= 0:
            if pos == 0:
                return True
            c = data[pos - 1]
            if not (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c == 95):
                return True
            pos = data.find(pat, pos + 1)
        return False

    def _ipmi_hosted_here(self, name):
        """True if the running program itself hosts IPMI service `name`: its
        name appears as a string in the main executable (a program that only
        uses a service gets the name from the client library instead)."""
        cache = self.__dict__.setdefault("_ipmi_hosted_cache", {})
        key = (self.emu.path, name)
        if key not in cache:
            img = self.__dict__.get("_ipmi_main_image")
            if img is None or img[0] != self.emu.path:
                try:
                    with open(self.emu.path, "rb") as f:
                        img = (self.emu.path, f.read())
                except Exception:
                    img = (self.emu.path, b"")
                self._ipmi_main_image = img
            cache[key] = bool(name) and self._has_cstring(img[1], name.encode())
        return cache[key]

    def _ipmi_route(self, uc, cmd, kid, result_ptr, in_ptr, size):
        """Cross-process IPMI (ipmikernel.py). Returns True when the call was handled (or parked)."""
        import struct
        system = getattr(self.emu, "system", None)
        k = getattr(system, "ipmi", None) if system is not None else None
        if k is None:
            return False
        emu = self.emu
        if __import__('os').environ.get('PSEMU_IPMI_TRACE') == '2' and cmd not in (0x10,):
            try:
                hx = bytes(uc.mem_read(in_ptr, min(size, 0x30))).hex() if in_ptr and size else ''
            except Exception:
                hx = '?'
            k.log(f'  [ipmi-t] {emu.path.rsplit(chr(92), 1)[-1]} tid {emu.sched.current.tid:#x} cmd {cmd:#x} kid {kid:#x} size {size:#x} {hx}')
        if cmd == 0x10 and in_ptr:
            k._once(("c10", id(emu), kid), f"  [ipmi-k] {emu.path.rsplit(chr(92), 1)[-1]} cmd 0x10 kid {kid:#x}: " + bytes(uc.mem_read(in_ptr, 0x40)).hex())
        if cmd == 0x202 and __import__("os").environ.get("PSEMU_IPMI_TRACE"):
            import struct as _s
            rsp = uc.reg_read(__import__('unicorn.x86_const', fromlist=['x']).UC_X86_REG_RSP)
            q = _s.unpack('<24Q', bytes(uc.mem_read(rsp, 192)))
            lm = lambda a: (lambda m: f'{m.name}+{a-m.base:#x}' if m else '')(emu.dyn.module_at(a) if emu.dyn else None)
            from unicorn.x86_const import UC_X86_REG_RBP as _RBP
            bp = uc.reg_read(_RBP); chain = []
            for _ in range(10):
                try: nb, ra = _s.unpack('<QQ', bytes(uc.mem_read(bp, 16)))
                except Exception: break
                chain.append(lm(ra) or hex(ra)); bp = nb
            k.log('  [ipmi-k] 0x202 rbp chain: ' + ' <- '.join(chain))
            k.log(f'  [ipmi-k] 0x202 by thread {emu.sched.current.tid:#x} kid {kid:#x} stack: ' + ' '.join(x for x in (lm(a) for a in q) if x))
        if cmd == 0x4 and (kid & 0xFFFFFFFF) == 0xFFFFFFFF and k.create_session_handle(emu, uc, in_ptr, result_ptr):
            self._ret(uc, 0)
            return True
        if cmd == 0x468 and k.client_info(emu, uc, kid, in_ptr):
            if result_ptr:
                uc.mem_write(result_ptr, struct.pack('<I', 0))
            self._ret(uc, 0)
            return True
        if cmd == 0x302 and k.client_pid(emu, uc, kid, in_ptr):
            if result_ptr:
                uc.mem_write(result_ptr, struct.pack('<I', 0))
            self._ret(uc, 0)
            return True
        if cmd == 0x232 and k.reply(emu, uc, kid, in_ptr, size, result_ptr):
            self._ret(uc, 0)
            return True
        # server side: a kid that belongs to a registered server in this process
        srv = k.server_of(emu, kid)
        if srv is not None and cmd != self.IPMI_CREATE_SERVER:
            if cmd == self.IPMI_RECEIVE:
                if k.receive(emu, uc, srv, in_ptr, result_ptr):
                    self._ret(uc, 0)
                return True
            if k.server_call(emu, uc, srv, cmd, kid, in_ptr, size, result_ptr, self._args(uc)[5]):
                self._ret(uc, 0)
                return True
        # server answers carry the session id as kid
        if cmd in (0x222, 0x212, 0x444, 0x232) and kid in k.sessions and k.sessions[kid].server.emu is emu:
            k.server_call(emu, uc, k.sessions[kid].server, cmd, kid, in_ptr, size, result_ptr, self._args(uc)[5])
            self._ret(uc, 0)
            return True
        name = getattr(self, "_ipmi_names", {}).get(kid)
        if cmd == self.IPMI_CONNECT and name and k.is_routed(name) and k.servers[name].emu is not emu:
            k.connect(emu, uc, kid, name, result_ptr, in_ptr)
            return True
        if cmd == self.IPMI_INVOKE_SYNC and name:
            r = k.invoke_sync(emu, uc, kid, name, in_ptr, result_ptr)
            if r is False:
                return True
        if srv is not None:
            k._once(("srvcmd", srv.name, cmd),
                    f"  [ipmi-k] server '{srv.name}' cmd {cmd:#x} kid {kid:#x} size {size:#x}: "
                    + bytes(uc.mem_read(in_ptr, min(size, 0x40)) if in_ptr and size else b"").hex())
        return False

    def sys_ipmimgr_call(self, uc):
        # IPMI (Sony IPC): SceShellCore creates a client per system service and
        # then invokes methods on it. The services are separate processes we do
        # not run, so there is nobody to answer; we hand back a valid client
        # handle so client creation stops failing, and report success.
        import struct
        cmd, kid, result_ptr, in_ptr, size = self._args(uc)[:5]
        if not hasattr(self, "_ipmi_names"):
            self._ipmi_names = {}
        if self._ipmi_route(uc, cmd, kid, result_ptr, in_ptr, size):
            return
        counts = self.__dict__.setdefault("_ipmi_counts", {})
        ckey = (cmd, self._ipmi_names.get(kid, "") if cmd != self.IPMI_CREATE_CLIENT else "")
        counts[ckey] = counts.get(ckey, 0) + 1
        if cmd == self.IPMI_CREATE_CLIENT:
            name = self._ipmi_service_name(uc, in_ptr, size)
            h = self._ipmi_kid
            self._ipmi_kid += 1
            self._ipmi_names[h] = name
            if result_ptr:
                try:
                    uc.mem_write(result_ptr, struct.pack("<i", h))   # the new client kid
                except Exception:
                    pass
            self.emu.log(f"  [ipmi] create client '{name}' -> kid {h:#x}")
            return self._ret(uc, 0)
        if cmd == self.IPMI_CREATE_SERVER:
            # {u64 server_obj; u64 *service_name; u64 params}: a service hosted
            # by this process. Remember it: clients can only connect to servers
            # that exist.
            name = self._ipmi_service_name(uc, in_ptr, size)
            h = self._ipmi_kid
            self._ipmi_kid += 1
            self._ipmi_names[h] = name
            self._ipmi_servers = getattr(self, "_ipmi_servers", {})
            self._ipmi_servers[name] = h
            k = getattr(getattr(self.emu, "system", None), "ipmi", None)
            if k is not None:
                try:
                    obj = struct.unpack("<Q", bytes(uc.mem_read(in_ptr, 8)))[0]
                except Exception:
                    obj = 0
                if __import__('os').environ.get('PSEMU_IPMI_TRACE'):
                    q = struct.unpack('<6Q', bytes(uc.mem_read(in_ptr, 48)))
                    def vt(a):
                        try:
                            v = struct.unpack('<Q', bytes(uc.mem_read(a, 8)))[0]
                            return [hex(x) for x in struct.unpack('<8Q', bytes(uc.mem_read(v, 64)))]
                        except Exception:
                            return None
                    try:
                        cfg = struct.unpack('<12Q', bytes(uc.mem_read(q[2], 96)))
                        k.log('  [ipmi-k] cfg ' + ' '.join(hex(x) for x in cfg))
                        for x in cfg:
                            v = vt(x) if 0x10000 < x < 0x7fffffffffff else None
                            if v: k.log(f'  [ipmi-k]   cfg ptr {x:#x} vt {v}')
                    except Exception as e:
                        k.log(f'  [ipmi-k] cfg read failed {e}')
                    k.log(f'  [ipmi-k] create-server struct {[hex(x) for x in q]} size {size:#x}; [q0] vt {vt(q[0])}; [q2] vt {vt(q[2])}')
                try:
                    cfgp = struct.unpack('<Q', bytes(uc.mem_read(in_ptr + 0x10, 8)))[0]
                    obj = struct.unpack('<Q', bytes(uc.mem_read(cfgp + 0x30, 8)))[0] or obj
                except Exception:
                    pass
                k.create_server(self.emu, name, h, obj)
            if result_ptr:
                try:
                    uc.mem_write(result_ptr, struct.pack("<i", h))
                except Exception:
                    pass
            self.emu.log(f"  [ipmi] create server '{name}' -> kid {h:#x}")
            return self._ret(uc, 0)
        if cmd == self.IPMI_DISCONNECT:
            # {u64 *status}: the kernel reports the session's close status
            # through the pointer; libSceIpmi asserts it is 0.
            try:
                p_status = struct.unpack("<Q", bytes(uc.mem_read(in_ptr, 8)))[0]
                if p_status:
                    uc.mem_write(p_status, struct.pack("<I", 0))
                if result_ptr:
                    uc.mem_write(result_ptr, struct.pack("<I", 0))
            except Exception:
                pass
            return self._ret(uc, 0)
        if cmd == self.IPMI_CONNECT:
            # Connect always succeeds. Services hosted by another system process
            # (SceSysCore, ...) would already be running on a console, so they
            # get a stand-in session. Services this program hosts itself are
            # often connected to by its libraries at load time, before the
            # server object exists (libSceNpManager's module start connects to
            # SceNpMgrIpc; failing that connect makes it tear down the NP
            # global heap, after which every NP allocation returns NULL). The
            # session is accepted and simply idle until the server is created:
            # receives block and sync invokes get an empty success meanwhile.
            nm = self._ipmi_names.get(kid, "?")
            ok = True
            if nm not in getattr(self, "_ipmi_servers", {}) and self._ipmi_hosted_here(nm):
                self.emu.log(f"  [ipmi] connect '{nm}': server not created yet - "
                             "session accepted, idle until it is")
            code = 0 if ok else IPMI_METHOD_NOT_EXIST
            if result_ptr:
                try:
                    uc.mem_write(result_ptr, struct.pack("<I", code))
                except Exception:
                    pass
            self.emu.log(f"  [ipmi] connect '{nm}' (kid {kid:#x}) -> "
                         + ("ok" if ok else "no such server yet"))
            return self._ret(uc, 0)
        # Other IPMI ops (connect / invoke method / event poll / ...): the target
        # services are separate processes we do not run, so there is nobody to
        # answer. We report success with an empty result. NOTE: this leaves the
        # shell busy-polling SceVideoCoreServer's invoke (cmd 0x490, method 0x22)
        # for a reply that never comes - that service's protocol is the next
        # thing to HLE. Log each op once per (cmd,kid) so the poll does not spam.
        nm = self._ipmi_names.get(kid, "?")
        self._ipmi_seen = getattr(self, "_ipmi_seen", set())
        if (cmd, kid) not in self._ipmi_seen:
            self._ipmi_seen.add((cmd, kid))
            self.emu.log(f"  [ipmi] cmd={cmd:#x} kid={kid:#x} ({nm}) size={size:#x}")
        # Per-op result code (written to result_ptr; the libSceIpmi wrapper
        # returns it to the caller). With no service process behind the client:
        #  * Receive (0x201): SCE_IPMI_ERROR_NO_PACKET (0x80020004) - "no packet
        #    pending". The async receive pump treats that as idle and retries;
        #    returning 0 made it read our zeroed buffer as a type-0 packet and log
        #    "unexpected receivePacketInfo.type".
        #  * InvokeSyncMethod (0x490): the response-delivery framework below -
        #    sync methods return their result (and out-data) directly through the
        #    syscall, so we answer per (service, method).
        #  * everything else (connect, ...): success.
        if cmd in self.IPMI_TRY_RECEIVE:
            # Client "try-receive an event" ops (getEvent / tryReceive):
            # {.., event_buf, size_out_ptr, max_size, ..}. Their callers DRAIN
            # in a tight loop (e.g. SceUserService getEvent @+0x1cb0:
            # `call getEvent; test eax,eax; je loop` - loops while it returns 0
            # = "processed an event"). Reporting empty-SUCCESS makes the caller
            # read a zeroed buffer as a null event, "process" it, and re-poll
            # forever -- the single biggest cycle sink once the UI is up
            # (SceVideoCoreServer 0x252 and SceAppDbIpc 0x251 together spun
            # ~945K ipmimgr_call in an 800M run). The kernel's "no event / no
            # data" code 0x80020023, which these loops test for, makes them stop
            # draining and park/back off instead. Nothing feeds these queues
            # (the real event-source services are not emulated), so an empty
            # queue is the correct steady state. Verified first for
            # SceUserService getEvent (@+0x1d65 branches on exactly this code).
            result = 0x80020023            # SCE_KERNEL_ERROR no-data / no event
            # A console delivers a Login event for the user who is already
            # logged in the first time a client asks (the shell's LoginMgr and
            # the rest wait for it before they bring the UI up). Hand SceUserService
            # clients that event once: argstruct in+0x08 = 8-byte event buffer
            # {u32 type (0 = login, 1 = logout); u32 userId}, in+0x10 = size-out.
            if nm == "SceUserService" and kid not in self.__dict__.setdefault(
                    "_user_login_sent", set()):
                try:
                    p_buf, p_size = struct.unpack("<QQ", bytes(uc.mem_read(in_ptr + 8, 16)))
                    if p_buf and p_size:
                        uc.mem_write(p_buf, struct.pack("<II", 0, self.USER_ID))
                        uc.mem_write(p_size, struct.pack("<Q", 8))
                        self._user_login_sent.add(kid)
                        self.emu.log(f"  [userservice] Login event delivered: user {self.USER_ID}")
                        result = 0
                except Exception:
                    pass
            if result_ptr:
                try:
                    uc.mem_write(result_ptr, struct.pack("<I", result))
                except Exception:
                    pass
            return self._ret(uc, 0)
        if cmd == self.IPMI_RECEIVE:
            # The kernel blocks a receive until a packet arrives for that
            # client/server. Nothing sends packets yet (no request/response
            # loopback), so the receive thread parks - like an idle service -
            # instead of polling "no packet" in a tight loop.
            sched = self.emu.sched
            if sched is not None and getattr(sched, "current", None) is not None:
                waiters = self.__dict__.setdefault("_ipmi_rx_waiters", {})
                waiters.setdefault(kid, []).append(sched.current)
                sched.block({"kind": "ipmi_receive", "kid": kid, "name": nm})
                return
            result = IPMI_NO_PACKET
        elif cmd == self.IPMI_INVOKE_SYNC:
            result = self._ipmi_invoke(uc, nm, in_ptr, size)
        elif cmd == self.IPMI_WAIT_EVF:
            result = self._ipmi_wait_evf(uc, kid, nm, result_ptr, in_ptr)
            if result is None:
                return
        elif cmd == self.IPMI_POLL_EVF:
            result = IPMI_EVF_NOT_SET
        else:
            result = 0
        if result_ptr:
            try:
                uc.mem_write(result_ptr, struct.pack("<I", result & 0xFFFFFFFF))
            except Exception:
                pass
        return self._ret(uc, 0)

    PID = 1000
    APP_ID = 0x3E8          # this process's application id (kernel AppInfo / SysCore)

    def pid_of_process(self):
        """This process's pid: the one its parent got from rfork (spawned processes), else PID."""
        return getattr(self.emu, 'child_pid', 0) or self.PID

    def sys_nmount(self, uc):
        """nmount(struct iovec *iov, u_int iovcnt, int flags): name/value pairs ("fstype", "fspath", "from" ...).
        Nothing is mounted (psemu serves the host firmware tree); the mounts are recorded, machine-wide, so the
        ones that matter (an application's /app0) can be resolved, and logged."""
        iov, cnt, flags = self._args(uc)[:3]
        cnt &= 0xFFFFFFFF
        kv = {}
        try:
            vals = []
            for i in range(min(cnt, 40)):
                ptr, ln = _struct.unpack("<QQ", bytes(uc.mem_read(iov + 16 * i, 16)))
                vals.append(bytes(uc.mem_read(ptr, min(ln, 256))).split(bytes(1))[0].decode("latin1") if ptr and ln else "")
            kv = {vals[i]: vals[i + 1] for i in range(0, len(vals) - 1, 2)}
        except Exception:
            pass
        sysm = getattr(self.emu, "system", None)
        if sysm is not None and kv.get("fspath"):
            sysm.mounts[kv["fspath"]] = kv
        if kv.get("fspath", "").find("app0") >= 0 or "sandbox" in kv.get("fspath", "") or "NPXS" in str(kv):
            self.emu.log(f"  [nmount] {kv}")
        self._ret(uc, 0)

    def sys_getpid(self, uc):
        self._ret(uc, self.pid_of_process())

    def sys_getuid(self, uc):
        self._ret(uc, 0)

    # PS4 priorities run 256 (highest) .. 767 (lowest) for every policy (SCE_KERNEL_PRIO_FIFO_HIGHEST/
    # LOWEST); libScePsm sets its audio mixer thread to 0x208 only when min < max and the value is in
    # range (+0x89300). With both reported as 0 that failed, the sound system was torn down and the Bgm
    # library never registered.
    SCHED_RANGE = {1: (256, 767), 2: (256, 767), 3: (256, 767)}

    def sys_sched_get_priority_max(self, uc):
        pol = self._args(uc)[0] & 0xFFFFFFFF
        r = self.SCHED_RANGE.get(pol)
        self._ret(uc, 22, True) if r is None else self._ret(uc, r[1])

    def sys_sched_get_priority_min(self, uc):
        pol = self._args(uc)[0] & 0xFFFFFFFF
        r = self.SCHED_RANGE.get(pol)
        self._ret(uc, 22, True) if r is None else self._ret(uc, r[0])

    def sys_issetugid(self, uc):
        self._ret(uc, 0)

    REALTIME_EPOCH_NS = 1_767_225_600 * 1_000_000_000   # 2026-01-01 00:00 UTC

    def now_ns(self):
        sched = self.emu.sched
        return sched.now_ns() if sched is not None else self.emu._insn_count

    def sys_clock_gettime(self, uc):
        # clock_gettime(clockid, struct timespec *): psemu's virtual clock
        # (1 ns per executed instruction + time skipped while all threads
        # slept). CLOCK_REALTIME (0) adds a fixed epoch; every other clock
        # (MONOTONIC, UPTIME, PROF...) counts from boot.
        import struct
        clk, ts, *_ = self._args(uc)
        t = self.now_ns() + (self.REALTIME_EPOCH_NS if (clk & 0xFFFFFFFF) == 0 else 0)
        try:
            uc.mem_write(ts, struct.pack("<qq", t // 1_000_000_000, t % 1_000_000_000))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, 0)

    def sys_terminate_process(self, uc):
        # sceKernelTerminateProcess(pid, ...): SceSysCore kills an application (the ShellCore watchdog restarts a
        # ShellUI that stopped heart-beating). Unmodelled it "succeeded" while the process kept running.
        pid = self._args(uc)[0] & 0xFFFFFFFF
        mgr = getattr(self.emu, "manager", None)
        if os.environ.get("PSEMU_NO_TERMINATE"):       # experiment: let the process live to see what it does next
            self.emu.log(f"  [terminate] process {pid:#x}: kill ignored (PSEMU_NO_TERMINATE)")
            return self._ret(uc, 0)
        if mgr is not None and mgr.terminate(pid):
            self.emu.log(f"  [terminate] process {pid:#x} stopped")
            return self._ret(uc, 0)
        self._ret(uc, 3, error=True)          # ESRCH

    def sys_mdbg_call(self, uc):
        # mdbg_call(a, b, c, ...): the kernel's debugger-service call; not modelled (returns 0). A thread that
        # polls it in a loop is reported once (thread, caller) so the spinning code can be found.
        from unicorn.x86_const import UC_X86_REG_RSP
        n = self.counts.get(573, 0)
        if n in (2000, 200000):
            rsp = uc.reg_read(UC_X86_REG_RSP)
            st = _struct.unpack("<6Q", bytes(uc.mem_read(rsp, 48)))
            tid = self.emu.sched.current.tid if self.emu.sched and self.emu.sched.current else 0
            dyn = getattr(self.emu, "dyn", None)
            where = []
            for w in st:
                m = dyn.module_at(w) if dyn is not None and hasattr(dyn, "module_at") else None
                if m:
                    where.append(f"{m.name}+{w - m.base:#x}")
            self.emu.log(f"  [mdbg_call] call #{n} tid {tid:#x} args={[hex(x) for x in self._args(uc)[:6]]} stack code ptrs: {where}")
        self._ret(uc, 0)

    def sys_select(self, uc):
        # select(nfds, readfds, writefds, exceptfds, timeout): no fd is modelled as becoming readable yet
        # except devices/sockets exposing ready(); with nothing ready the thread sleeps on the virtual clock
        # for the timeout (a NULL timeout sleeps one second) and the sets come back empty - unmodelled it
        # returned at once and a select()-as-sleep loop (SceSysCore) burned the whole CPU budget.
        import struct
        nfds, rd, wr, ex, tv = self._args(uc)[:5]
        nfds &= 0xFFFFFFFF
        ns = 1_000_000_000
        if tv:
            try:
                sec, usec = struct.unpack("<qq", bytes(uc.mem_read(tv, 16)))
                ns = max(0, sec) * 1_000_000_000 + max(0, usec) * 1000
            except Exception:
                ns = 0
        nbytes = (min(nfds, 1024) + 7) // 8
        ready = []
        if rd and nbytes:
            try:
                bits = bytes(uc.mem_read(rd, nbytes))
            except Exception:
                return self._ret(uc, EFAULT, error=True)
            for fd in range(min(nfds, 1024)):
                if bits[fd >> 3] >> (fd & 7) & 1:
                    dev = self.devs.get(fd)
                    if dev is not None and hasattr(dev, "ready") and dev.ready():
                        ready.append(fd)
            if self.counts.get(93, 0) <= 3:
                self.emu.log(f"  [select] nfds={nfds} read={[f for f in range(min(nfds,1024)) if bits[f >> 3] >> (f & 7) & 1]} "
                             f"timeout={ns / 1e9:g}s ready={ready}")
        if ready:
            out = bytearray(nbytes)
            for fd in ready:
                out[fd >> 3] |= 1 << (fd & 7)
            uc.mem_write(rd, bytes(out))
            for p_ in (wr, ex):
                if p_ and nbytes:
                    uc.mem_write(p_, bytes(nbytes))
            return self._ret(uc, len(ready))
        for p_ in (rd, wr, ex):
            if p_ and nbytes:
                uc.mem_write(p_, bytes(nbytes))
        self._ret(uc, 0)
        sched = self.emu.sched
        if sched is not None and ns:
            sched.block({"kind": "sleep", "ns": ns}, deadline_ns=sched.now_ns() + ns, timeout_ret=(0, False))

    def sys_nanosleep(self, uc):
        # nanosleep(const timespec *rqtp, timespec *rmtp): sleep on the
        # virtual clock (others run; if nobody can, the clock skips ahead).
        import struct
        rqtp, rmtp = self._args(uc)[:2]
        try:
            sec, nsec = struct.unpack("<qq", bytes(uc.mem_read(rqtp, 16)))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        if rmtp:
            try:
                uc.mem_write(rmtp, b"\x00" * 16)
            except Exception:
                pass
        self._ret(uc, 0)
        ns = max(0, sec) * 1_000_000_000 + max(0, nsec)
        sched = self.emu.sched
        if sched is not None and ns:
            sched.block({"kind": "sleep", "ns": ns}, deadline_ns=sched.now_ns() + ns,
                        timeout_ret=(0, False))

    NOTE_EXIT, NOTE_EXEC = 0x80000000, 0x20000000

    # ---- wait4 / child bookkeeping ---------------------------------------
    ECHILD = 10
    WNOHANG = 1

    def child_done(self, pid, status=0):
        """A child (a spawned process, or a vfork child whose execve failed) is gone: wake a wait4()."""
        import struct
        self.children[pid] = status
        waiters = self.__dict__.setdefault("_wait4_waiters", [])
        sched = self.emu.sched
        if waiters and sched is not None:
            t, status_ptr = waiters.pop(0)
            self.children.pop(pid, None)
            if status_ptr:
                try:
                    self.emu.uc.mem_write(status_ptr, struct.pack("<i", status))
                except Exception:
                    pass
            sched.wake(t, pid, False)

    def sys_wait4(self, uc):
        # wait4(pid, int *status, options, rusage): reap an exited child, block while children run, ECHILD
        # when there are none. (Unmodelled it returned 0 at once: mini-syscore's reaper loop spun on it.)
        import struct
        pid, status_ptr, options = self._args(uc)[:3]
        options &= 0xFFFFFFFF
        zombie = next((p for p, st in self.children.items() if st is not None), None)
        if zombie is not None:
            st = self.children.pop(zombie)
            if status_ptr:
                uc.mem_write(status_ptr, struct.pack("<i", st))
            return self._ret(uc, zombie)
        if not self.children:
            return self._ret(uc, self.ECHILD, error=True)
        if options & self.WNOHANG:
            return self._ret(uc, 0)
        sched = self.emu.sched
        waiters = self.__dict__.setdefault("_wait4_waiters", [])
        waiters.append((sched.current, status_ptr))
        sched.block({"kind": "wait4"})

    def proc_event(self, fflags, data=0, pid=None):
        """Raise an EVFILT_PROC event (a child exec'd / exited) on the proc watches of `pid` (the watch's ident is
        the watched pid); pid None/0 = every watch (a child whose pid is unknown)."""
        pid = pid or None
        for notes in self.knotes.values():
            for (ident, filt), kn in notes.items():
                if filt == -5 and (pid is None or ident == pid):
                    kn["fflags"] = fflags
        self.trigger(-5, pid, data)

    def _app0_root(self, path):
        """The host directory behind '/app0' for a spawned app: the application's own directory, from the
        newest nullfs mount of '.../app0' (its target, e.g. /system/vsh/app/NPXS20001, looked up in the
        firmware tree under system/vsh/app and system_ex/app). None for any other path."""
        if not path.replace(chr(92), "/").lstrip("/").startswith("app0/"):
            return None
        sysm = getattr(self.emu, "system", None)
        for fp, kv in reversed(list((sysm.mounts if sysm is not None else {}).items())):
            if fp.endswith("/app0") and kv.get("target"):
                name = kv["target"].rstrip("/").rsplit("/", 1)[-1]
                for sub in ("system/vsh/app", "system_ex/app", "system/vsh", "system_ex"):
                    d = os.path.join(self.emu.fw_root, *sub.split("/"), name)
                    if os.path.isdir(d):
                        return d
        return None

    def sys_execve(self, uc):
        # mini-syscore's job is early boot, then hand off to the next stage.
        # We can't chain-load that separate firmware module, so report the
        # handoff as a clean terminal state instead of returning into a fallback
        # exit(-1).
        path_ptr, argv_ptr, _env = self._args(uc)[:3]
        path = self._read_cstr(uc, path_ptr, 128)
        argv = []
        try:
            import struct
            for i in range(8):
                p = struct.unpack("<Q", bytes(uc.mem_read(argv_ptr + 8 * i, 8)))[0]
                if not p:
                    break
                argv.append(self._read_cstr(uc, p, 64))
        except Exception:
            pass
        # Process-spawn policy: on PS4, a service like SceSysCore forks (rfork)
        # a child that execve()s a separate process (daemon, or the UI app) and
        # the PARENT keeps running. psemu runs one image at a time, so by
        # default execve chain-loads the child (replacing the image - correct
        # for boot handoffs like mini-syscore -> SceSysAvControl). When the
        # caller is an rfork'd spawn child and spawn_mode says not to follow
        # this one, retire the child thread instead and let the parent run on.
        sched = self.emu.sched
        cur = sched.current if sched else None
        mode = self.emu.spawn_mode
        mgr = getattr(self.emu, "manager", None)
        if cur is not None and getattr(cur, "spawn_child", False) and mode == "spawn" and mgr is not None:
            # a real second process: the child image runs concurrently (own address space) under the
            # ProcessManager while this process carries on
            app_root = self._app0_root(path)
            resolved = os.path.join(app_root, *path.replace(chr(92), "/").lstrip("/")[5:].split("/")) if app_root else self.emu.resolve_path(path)
            if app_root and not os.path.isfile(resolved):
                resolved = None
            if resolved is None:
                # execve fails (ENOENT) in the child, which then exits: the parent sees NOTE_EXIT
                self.emu.log(f"  [execve] spawn '{path}': not found under {self.emu.fw_root} "
                             f"-> the child exits")
                self.proc_event(self.NOTE_EXIT, 1 << 8, getattr(cur, "child_pid", 0))
                self.child_done(getattr(cur, "child_pid", 0), 1 << 8)
            else:
                self.emu.log(f"  [execve] spawn '{path}' -> new process")
                child = mgr.spawn(self.emu, resolved, argv or [path], app_root=app_root)
                ipk = getattr(getattr(self.emu, 'system', None), 'ipmi', None)
                if app_root and ipk is not None and ipk.last_app_id:
                    child.app_id = ipk.last_app_id        # what SceSysCore's AppMgr allocated for it
                self.emu.log(f"  [execve]   -> {resolved}")
                child.child_pid = getattr(cur, "child_pid", 0)
                self.proc_event(self.NOTE_EXEC, 0, getattr(cur, "child_pid", 0))
            sched.exit_current()
            return
        if cur is not None and getattr(cur, "spawn_child", False) and mode not in (None, "follow"):
            follow = (mode != "stay") and (mode in path)
            if not follow:
                self.emu.log(f"  [execve] spawn '{path}' (pid child) -> staying with parent, "
                             f"child retired")
                sched.exit_current()
                return
            self.emu.log(f"  [execve] spawn '{path}' matches follow target -> chain-loading")
        self.emu.log(f"  [execve] '{path}' argv={argv}")
        if not self.emu.exec_module(path, argv):
            # exec_module already set a stop reason (module not found)
            pass

    def sys_kqueue(self, uc):
        fd = self._alloc_fd("kqueue", base=16)
        self.kqueues.add(fd)
        self.emu.log(f"  [kqueue] -> fd {fd}")
        self._ret(uc, fd)

    # ---- kqueue: registrations + events raised by devices -------------
    # struct kevent (FreeBSD 9): u64 ident; i16 filter; u16 flags; u32 fflags;
    #                            i64 data; u64 udata          (32 bytes)
    EV_ADD, EV_DELETE, EV_ENABLE, EV_DISABLE, EV_ONESHOT, EV_CLEAR = 1, 2, 4, 8, 0x10, 0x20
    EVFILT_USER = -11
    NOTE_TRIGGER = 0x01000000

    def trigger(self, filt, ident=None, data=None):
        """Raise an event on every kqueue that registered (ident, filt);
        ident None matches all idents of that filter. Returns how many."""
        n = 0
        for kq, notes in self.knotes.items():
            for (ident_, filt_), kn in notes.items():
                if filt_ != filt or (ident is not None and ident_ != ident):
                    continue
                if data is not None:
                    kn["data"] = data
                pend = self.kq_pending.setdefault(kq, [])
                if (ident_, filt_) not in pend:
                    pend.append((ident_, filt_))
                n += 1
        if n:
            self._wake_kq_waiters()
        return n

    def _wake_kq_waiters(self):
        """Threads blocked in kevent on a queue that now has events: copy the
        events into their buffers and make them runnable."""
        sched = self.emu.sched
        if sched is None:
            return
        for t in list(sched.threads.values()):
            w = t.wait
            if t.state == "blocked" and isinstance(w, dict) and w.get("kind") == "kevent" \
                    and self.kq_pending.get(w["kq"]):
                out = self._copy_events(self.emu.uc, w["kq"], w["evbuf"], w["nev"])
                if out:
                    sched.wake(t, out)

    def sys_kevent_deliver(self, uc, kq, evbuf, nev):
        self._ret(uc, self._copy_events(uc, kq, evbuf, nev))

    def _copy_events(self, uc, kq, evbuf, nev):
        """Copy pending events of `kq` out to an event list; returns the count."""
        import struct
        notes = self.knotes.get(kq, {})
        pend = self.kq_pending.get(kq, [])
        out = 0
        while pend and out < nev:
            key = pend.pop(0)
            kn = notes.get(key)
            if kn is None:
                continue
            ident, filt = key
            uc.mem_write(evbuf + 32 * out, struct.pack(
                "<QhHIqQ", ident, filt, kn["flags"] & 0xFFFF, kn["fflags"],
                kn["data"], kn["udata"]))
            if kn["flags"] & self.EV_ONESHOT:
                notes.pop(key, None)
            out += 1
        self._delivered = getattr(self, "_delivered", 0) + out
        if self._delivered <= 32 or self._delivered % 500 == 0:
            self.emu.log(f"  [kevent] kq {kq}: delivered {out} event(s) "
                         f"(total {self._delivered})")
        return out

    def sys_kevent(self, uc):
        # kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
        # Changes register knotes; events come from trigger() (GPU EOP from
        # /dev/gc, user events). With nothing pending the call returns 0 (as
        # if the timeout expired) and a run of those is how an idle event
        # loop is detected.
        import struct
        kq, chl, nch, evbuf, nev, timeout = self._args(uc)
        kq, nch, nev = kq & 0xFFFFFFFF, nch & 0xFFFFFFFF, nev & 0xFFFFFFFF   # C ints
        if self.trace or self.counts.get(363, 0) <= 64:
            self.emu.log(f"  [kevent] kq={kq} nchanges={nch} nevents={nev} timeout={timeout:#x}")
        notes = self.knotes.setdefault(kq, {})
        for i in range(min(nch, 64)):
            try:
                ident, filt, flags, fflags, data, udata = struct.unpack(
                    "<QhHIqQ", bytes(uc.mem_read(chl + 32 * i, 32)))
            except Exception:
                return self._ret(uc, EFAULT, error=True)
            key = (ident, filt)
            if filt == -5 and self.emu.sched is not None:
                self.emu.log(f"  [kevent] EVFILT_PROC change ident={ident:#x} flags={flags:#x} fflags={fflags:#x}")
            if flags & self.EV_DELETE:
                notes.pop(key, None)
                continue
            if flags & self.EV_ADD or key not in notes:
                notes[key] = {"flags": flags, "fflags": fflags, "data": data, "udata": udata}
            kn = notes[key]
            if flags & self.EV_ADD:
                kn.update(flags=flags, udata=udata)
            if filt == self.EVFILT_USER and fflags & self.NOTE_TRIGGER:
                # sceKernelTriggerUserEvent(eq, id, udata): the kernel copies the change's udata
                # onto the existing knote on every registration (kn_kevent.udata = kev->udata),
                # so the waiter receives the TRIGGER's udata, not the one given at EV_ADD (the
                # vision manager passes a request-message pointer this way)
                kn["udata"] = udata
                self.trigger(self.EVFILT_USER, ident)
        for (ident_, filt_) in list(notes):          # a read filter on a device fd that already has data
            dev_ = self.devs.get(ident_) if filt_ == -1 else None
            if dev_ is not None and hasattr(dev_, "ready") and dev_.ready():
                pend_ = self.kq_pending.setdefault(kq, [])
                if (ident_, filt_) not in pend_:
                    pend_.append((ident_, filt_))
        if nev and self.kq_pending.get(kq):
            return self.sys_kevent_deliver(uc, kq, evbuf, nev)
        if not nev:
            return self._ret(uc, 0)
        dce = self.device_of_kind(DceDevice)
        if notes and kq not in self._kq_wait_logged:
            self._kq_wait_logged.add(kq)
            self.emu.log(f"  [kevent] kq {kq} waits; registered: " + ", ".join(
                f"({i:#x},{f})" for i, f in list(notes)[:8]) + " - nothing pending")
        # Nothing to deliver. A NULL timeout sleeps until an event arrives and
        # a positive one until it expires (virtual clock); {0, 0} polls.
        wait_ns = None
        if timeout:
            try:
                sec, nsec = struct.unpack("<qq", bytes(uc.mem_read(timeout, 16)))
                wait_ns = max(0, sec) * 1_000_000_000 + max(0, nsec)
            except Exception:
                wait_ns = 0
        sched = self.emu.sched
        # A queue waiting for vblank: the display refreshes at 60 Hz of VIRTUAL
        # time, so the wait ends at the next refresh (raising the vblank event
        # for every queue that registered one) instead of returning at once -
        # an instant return makes a vblank thread spin at CPU speed.
        frame_ns = 16_666_667
        if (sched is not None and dce is not None and dce.wants_vblank(kq)
                and (wait_ns is None or wait_ns >= frame_ns)):
            self._ret(uc, 0)

            def on_vblank(th, kq=kq, evbuf=evbuf, nev=nev):
                dce.vblank()                       # wakes every queue that registered one
                th.timeout_ret = (self._copy_events(self.emu.uc, kq, evbuf, nev), False)

            sched.block({"kind": "kevent", "kq": kq, "evbuf": evbuf, "nev": nev,
                         "on_timeout": on_vblank},
                        deadline_ns=sched.now_ns() + frame_ns, timeout_ret=(0, False))
            return
        if sched is not None and wait_ns != 0:
            self._ret(uc, 0)          # value if it times out
            sched.block({"kind": "kevent", "kq": kq, "evbuf": evbuf, "nev": nev},
                        deadline_ns=None if wait_ns is None else sched.now_ns() + wait_ns,
                        timeout_ret=(0, False))
            self._idle_waits += 1
            if self._idle_waits >= self.idle_limit:
                self.emu.log(f"  [kevent] no events after {self._idle_waits} waits "
                             f"-> module is idle in its event loop")
                self.emu.stop("module booted; idle in event loop (no events to deliver)")
            return
        self.yield_cpu()
        self._idle_waits += 1
        if self._idle_waits >= self.idle_limit:
            self.emu.log(f"  [kevent] no events after {self._idle_waits} waits "
                         f"-> module is idle in its event loop")
            self.emu.stop("module booted; idle in event loop (no events to deliver)")
            return
        self._ret(uc, 0)

    def sys_rdup(self, uc):
        # ORBIS sys_603: duplicate a descriptor to the lowest free fd. The
        # module's fd-setup loop requires these to come back as 3, 4, 5, ...
        # A spawned child gets its own descriptor table (0..2 = the console, then 3, 4, 5 ...) and
        # mini-syscore's child checks each rdup returns exactly 3, 4, 5...; psemu shares one table, so the
        # sequence restarts at 3 whenever the child re-points stdio (dup2 onto 0..2) and never
        # overwrites a descriptor the parent still holds.
        fd = getattr(self, "_rdup_next", 3)
        if fd >= 64:
            # a caller that keeps duplicating until the source runs out of descriptors (SceSysCore's spawn
            # helper): the source process has only a few, so the call fails with EBADF
            return self._ret(uc, EBADF, error=True)
        self._rdup_next = fd + 1
        self.fds.setdefault(fd, "rdup")
        self.emu.log(f"  [rdup] args {[hex(x) for x in self._args(uc)[:3]]} -> fd {fd}")
        self._ret(uc, fd)

    # ---- writable file layer (see self.vfs) ----------------------------
    O_APPEND, O_CREAT, O_TRUNC, O_EXCL = 0x8, 0x200, 0x400, 0x800

    @staticmethod
    def _vnorm(path):
        import posixpath
        return posixpath.normpath("/" + path.replace("\\", "/").lstrip("/"))

    def _vfile(self, path):
        """The contents of the regular file at `path` (a shared bytearray),
        loading a firmware file on first use; None if there is none."""
        import os
        p = self._vnorm(path)
        if p in self.vfs:
            return self.vfs[p]
        if p in self.vgone or p.startswith("/dev/"):
            return None
        real = self.emu.resolve_path(p)
        if real and os.path.isfile(real):
            try:
                with open(real, "rb") as fh:
                    self.vfs[p] = bytearray(fh.read())
                return self.vfs[p]
            except OSError:
                return None
        seed = self._db_seed_template(p)
        if seed == "@app_db":
            self.vfs[p] = self._build_app_db()
            self.emu.log(f"  [db-seed] {p} provisioned from the firmware app catalogue (appdb.py)")
            return self.vfs[p]
        if seed is not None:
            real = self.emu.resolve_path(seed)
            if real and os.path.isfile(real):
                try:
                    with open(real, "rb") as fh:
                        self.vfs[p] = bytearray(fh.read())
                    self.emu.log(f"  [db-seed] {p} initialized from template {seed}")
                    return self.vfs[p]
                except OSError:
                    return None
        return None

    # The /priv/mms media-management databases (app content, thumbnails) are user
    # data the firmware does not ship: on first boot the DB-preparation daemon
    # creates each one from a read-only template under mms_ro. psemu has no such
    # daemon (its SceDbPreparationServer is an IPMI stub), so the content engine
    # would open app.db, find nothing, mark it corrupt and ask for a rebuild that
    # never runs. Standing in for the daemon, seed the live DB from its template
    # the first time it is opened, so the engine finds a valid database.
    # live-path suffix -> firmware master/template basename (resolve_path finds it
    # by basename anywhere in the tree). Content DBs come from mms_ro templates;
    # the voice-recognition DBs from recognition/voice/database masters.
    # app.db is the application database: the content engine opens it O_RDWR (no
    # O_CREAT), so a missing one cannot be created in place and is declared
    # corrupt. Its schema (tbl_version / tbl_appinfo / tbl_cmdfunc, "CREATE TABLE
    # IF NOT EXISTS") is compiled into eboot.bin; the engine validates it with
    # "SELECT count(*) FROM sqlite_master WHERE name='tbl_version'". "@app_db"
    # builds exactly that schema with the host sqlite3. The voice-recognition DBs
    # are plain copies of their firmware masters.
    # av_content.db is the media-content (photo/video) database; the firmware's read-only template
    # carries its schema (tbl_PhotoVideo, tbl_Account, ...), copied into place on first use.
    _DB_SEED = {"/mms/app.db": "@app_db",
                "/mms/av_content.db": "template_content.db",
                "/mms/av_content_bg.db": "template_content_bg.db",
                "/nui_data/voice/voice_gnd_gametitle.db": "master_voice_gnd_gametitle.db",
                "/nui_data/voice/voice_gnd_systemcommand.db": "master_voice_gnd_systemcommand.db"}

    def _build_app_db(self):
        """Provision a fresh application database with the schema, versions and system-app
        catalogue the shell's DB engine expects (see appdb.py). PSEMU_APPDB_SQL names an extra
        SQL file applied on top (development aid for schema/value discovery)."""
        import os
        from .appdb import build_app_db
        return build_app_db(self.emu.fw_root, extra_sql=os.environ.get("PSEMU_APPDB_SQL"))

    def _db_seed_template(self, p):
        for suf, tmpl in self._DB_SEED.items():
            if p.endswith(suf):
                return tmpl
        return None

    def _visdir(self, path):
        import os
        p = self._vnorm(path)
        if p == "/" or p in self.vdirs:
            return True
        if p in self.vgone:
            return False
        if os.path.isdir(os.path.join(self.emu.fw_root, p.lstrip("/"))):
            return True
        pre = p + "/"
        return any(k.startswith(pre) for k in self.vfs) or any(d.startswith(pre) for d in self.vdirs)

    @staticmethod
    def _vwrite(data, pos, raw):
        if pos > len(data):
            data.extend(bytes(pos - len(data)))
        data[pos:pos + len(raw)] = raw

    def sys_open(self, uc):
        path_ptr, flags = self._args(uc)[:2]
        flags &= 0xFFFFFFFF
        path = self._read_cstr(uc, path_ptr, 128)
        fd = self._alloc_fd(path, base=16)      # devices open high
        dev = open_device(self, path)
        kind = ""
        if dev is not None:
            self.devs[fd] = dev
            kind = " (device)"
        elif not path.startswith("/dev/"):
            p = self._vnorm(path)
            data = self._vfile(p)
            if data is not None:
                if flags & self.O_CREAT and flags & self.O_EXCL:
                    self.fds.pop(fd, None)
                    self.emu.log(f"  [open] '{path}' O_EXCL -> EEXIST")
                    return self._ret(uc, EEXIST, error=True)
                if flags & self.O_TRUNC:
                    del data[:]
                kind = f" (file {len(data)}B)"
            elif self._visdir(p):
                self.dirfds.add(fd)
                kind = " (dir)"
            elif flags & self.O_CREAT:
                data = self.vfs[p] = bytearray()
                self.vgone.discard(p)
                kind = " (created)"
            elif path.endswith(".la") and self._vfile(p[:-3]) is not None:
                # Mono's AOT-only loader opens a libtool '<name>.dll.sprx.la'
                # descriptor to locate the AOT module; the dump has none.
                # Synthesize a minimal libtool .la pointing at the .sprx that
                # IS present (psemu resolves it by basename), so Mono dlopens it
                # and dlsym's mono_aot_file_info. Keys Mono parses: dlname,
                # libdir, installed.
                import os as _os
                base = _os.path.basename(p[:-3])
                libdir = _os.path.dirname(path) or "/"
                la = (
                    f"# {base}.la - a libtool library file (generated by psemu)\n"
                    f"dlname='{base}'\n"
                    f"library_names='{base}'\n"
                    f"old_library=''\n"
                    f"inherited_linker_flags=''\n"
                    f"dependency_libs=''\n"
                    f"weak_library_names=''\n"
                    f"current=0\n"
                    f"age=0\n"
                    f"revision=0\n"
                    f"installed=yes\n"
                    f"shouldnotlink=no\n"
                    f"dlopen=''\n"
                    f"dlpreopen=''\n"
                    f"libdir='{libdir}'\n"
                ).encode()
                data = bytearray(la)
                kind = f" (generated .la -> {base})"
            elif path.endswith((".dll", ".exe")) and self._vfile(p + ".sprx") is not None:
                # A managed assembly whose CIL .dll isn't in the dump, only its
                # AOT module .dll.sprx. PS4 AOT embeds the original managed PE
                # inside the .sprx, so extract and serve it as the .dll Mono
                # opens (otherwise Mono reads an empty file -> "invalid CIL
                # image"). Cached: the scan is over a multi-MB blob.
                cil = self._cil_cache.get(p)
                if cil is None:
                    cil = _embedded_cil(bytes(self._vfile(p + ".sprx")))
                    self._cil_cache[p] = cil if cil is not None else b""
                if cil:
                    data = bytearray(cil)
                    kind = f" (CIL from .sprx {len(data)}B)"
                else:
                    self.fds.pop(fd, None)
                    self.emu.log(f"  [open] '{path}' -> ENOENT (no embedded CIL in .sprx)")
                    return self._ret(uc, ENOENT, error=True)
            else:
                # Not in the dump and not being created: ENOENT, as on the real system. (This
                # used to hand back a working fd on an empty file whose writes were dropped, so a
                # database opened without O_CREAT - SQLite's open of app.db - lost its own
                # writes, read them back as zeros and was declared corrupt: the shell then
                # asked for a database rebuild.)
                self.fds.pop(fd, None)
                self.emu.log(f"  [open] '{path}' -> ENOENT")
                return self._ret(uc, ENOENT, error=True)
            if data is not None:
                self.files[fd] = {"data": data, "pos": 0, "path": p,
                                  "append": bool(flags & self.O_APPEND)}
        self.emu.log(f"  [open] '{path}' -> fd {fd}{kind}")
        self._ret(uc, fd)

    def _pio_args(self, uc):
        fd, buf, n, off = self._args(uc)[:4]
        return fd & 0xFFFFFFFF, buf, n & 0xFFFFFFFF, off

    def sys_pread(self, uc):
        fd, buf, n, off = self._pio_args(uc)
        dev = self.devs.get(fd)
        if dev is not None and dev.seekable_size is not None:
            try:
                rv = dev.pread(uc, buf, n, off)
            except Exception as e:
                self.emu.log(f"  [pread] {dev.path}: {e} -> EINVAL")
                return self._ret(uc, EINVAL, error=True)
            return self._ret(uc, -rv, error=True) if rv < 0 else self._ret(uc, rv)
        f = self.files.get(fd)
        if f is None:
            return self._ret(uc, 0)
        chunk = bytes(f["data"][off:off + n])
        try:
            if chunk:
                uc.mem_write(buf, chunk)
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, len(chunk))

    def sys_pwrite(self, uc):
        fd, buf, n, off = self._pio_args(uc)
        f = self.files.get(fd)
        try:
            raw = bytes(uc.mem_read(buf, n)) if n else b""
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        if f is not None:
            self._vwrite(f["data"], off, raw)
            self.emu.log(f"  [pwrite] '{f['path']}' +{n:#x} @ {off:#x}")
        self._ret(uc, n)

    def _path_arg(self, uc, i=0):
        return self._vnorm(self._read_cstr(uc, self._args(uc)[i], 256))

    def sys_unlink(self, uc):
        p = self._path_arg(uc)
        if self._vfile(p) is None:
            return self._ret(uc, ENOENT, error=True)
        self.vfs.pop(p, None)
        self.vgone.add(p)
        self.emu.log(f"  [unlink] '{p}'")
        self._ret(uc, 0)

    def sys_rename(self, uc):
        src, dst = self._path_arg(uc, 0), self._path_arg(uc, 1)
        data = self._vfile(src)
        if data is None:
            if self._visdir(src):
                self.vdirs.discard(src)
                self.vdirs.add(dst)
                return self._ret(uc, 0)
            return self._ret(uc, ENOENT, error=True)
        self.vfs.pop(src, None)
        self.vgone.add(src)
        self.vfs[dst] = data
        self.vgone.discard(dst)
        self.emu.log(f"  [rename] '{src}' -> '{dst}'")
        self._ret(uc, 0)

    def sys_mkdir(self, uc):
        p = self._path_arg(uc)
        if self._visdir(p) or self._vfile(p) is not None:
            return self._ret(uc, EEXIST, error=True)
        self.vdirs.add(p)
        self.vgone.discard(p)
        self._ret(uc, 0)

    def sys_rmdir(self, uc):
        p = self._path_arg(uc)
        if not self._visdir(p):
            return self._ret(uc, ENOENT, error=True)
        self.vdirs.discard(p)
        self.vgone.add(p)
        self._ret(uc, 0)

    def sys_access(self, uc):
        p = self._path_arg(uc)
        ok = self._vfile(p) is not None or self._visdir(p)
        self._ret(uc, 0) if ok else self._ret(uc, ENOENT, error=True)

    def sys_close(self, uc):
        fd = self._args(uc)[0] & 0xFFFFFFFF
        self.fds.pop(fd, None)
        if fd in self.kqueues:                   # a closed kqueue takes its registrations with it
            self.kqueues.discard(fd)
            self.knotes.pop(fd, None)
            self.kq_pending.pop(fd, None)
        self.devs.pop(fd, None)
        self.files.pop(fd, None)
        self.shms.pop(fd, None)
        self.dirfds.discard(fd)
        self.emu.log(f"  [close] fd {fd}")
        self._ret(uc, 0)

    # PS4/FreeBSD struct stat: st_mode@0x08 (u16), st_nlink@0x0a, st_size@0x48
    # (i64), st_blksize@0x58 (i32). Enough for callers that size a read buffer.
    # st_dev@0x00 / st_ino@0x04 (u32 each) identify the file: SQLite keys its
    # per-inode lock table on them, so every path needs its own inode number.
    ST_DEV = 0x59

    def _inode(self, path):
        inos = self.__dict__.setdefault("_inodes", {})
        if path is None:
            return 0
        return inos.setdefault(self._vnorm(path), 2 + len(inos))

    def _write_stat(self, uc, buf, size, isdir=False, path=None):
        st = bytearray(0x78)
        _struct.pack_into("<II", st, 0x00, self.ST_DEV, self._inode(path))
        _struct.pack_into("<H", st, 0x08, (0x4000 if isdir else 0x8000) | 0o644)
        _struct.pack_into("<H", st, 0x0A, 1)                 # st_nlink
        _struct.pack_into("<q", st, 0x48, size & 0x7FFFFFFFFFFFFFFF)
        _struct.pack_into("<i", st, 0x58, 0x4000)            # st_blksize
        _struct.pack_into("<q", st, 0x50, (size + 0x1FF) // 0x200)  # st_blocks
        try:
            uc.mem_write(buf, bytes(st))
            return True
        except Exception:
            return False

    # ---- POSIX shared memory (shm_open / ftruncate / fstat / mmap) -----
    # A named object with a size; every mmap of it returns the same guest
    # memory (psemu runs one address space, so "shared" is literal). Objects
    # another system process would have created (opened here without O_CREAT)
    # get a one-page stand-in, like external event flags and semaphores.
    SHM_DEFAULT_SIZE = 0x1000

    @property
    def shm_objs(self):
        """The named shm objects: machine-wide when several processes run (their pages are shared host
        memory mapped into every address space), else this process's own."""
        sysm = getattr(self.emu, "system", None)
        if sysm is not None:
            return sysm.shm_objs
        return self._shm_local

    def sys_shm_open(self, uc):
        path_ptr, flags, mode = self._args(uc)[:3]
        flags &= 0xFFFFFFFF
        O_CREAT = 0x200
        name = "(anon)" if path_ptr == 1 else self._read_cstr(uc, path_ptr, 128)
        obj = self.shm_objs.get(name) if path_ptr != 1 else None
        note = ""
        if obj is None:
            obj = {"name": name, "size": 0, "addr": None}
            if path_ptr != 1:
                self.shm_objs[name] = obj
            if not flags & O_CREAT:
                obj["size"] = self.SHM_DEFAULT_SIZE
                note = " (owned by another system process -> stand-in)"
        fd = self._alloc_fd(f"shm:{name}", base=16)
        self.shms[fd] = obj
        self.emu.log(f"  [shm_open] '{name}' flags={flags:#x} -> fd {fd} "
                     f"size={obj['size']:#x}{note}")
        self._ret(uc, fd)

    def _shm_host(self, obj, span):
        """Host memory (page aligned, zeroed) behind a shm object, at least `span` bytes: the same pages are mapped
        into every process that maps the object. Growing it copies the old contents."""
        import ctypes
        host, hsize = obj.get("host"), obj.get("host_size", 0)
        if host is None or hsize < span:
            try:
                from .whp_uc import _valloc
                new = _valloc(span)
            except Exception:
                buf = (ctypes.c_ubyte * (span + 0x1000))()
                obj.setdefault("_keep", []).append(buf)
                new = (ctypes.addressof(buf) + 0xFFF) & ~0xFFF
            if host is not None:
                ctypes.memmove(new, host, hsize)
            obj["host"], obj["host_size"] = new, span
            host = new
        return host

    def sys_ftruncate(self, uc):
        fd, length = self._args(uc)[:2]
        fd &= 0xFFFFFFFF
        obj = self.shms.get(fd)
        if obj is not None:
            obj["size"] = length
            self.emu.log(f"  [ftruncate] shm '{obj['name']}' -> {length:#x}")
        f = self.files.get(fd)
        if f is not None:
            d = f["data"]
            if length < len(d):
                del d[length:]
            else:
                d.extend(bytes(length - len(d)))
        self._ret(uc, 0)

    def sys_fstat(self, uc):
        fd, buf = self._args(uc)[:2]
        fd &= 0xFFFFFFFF
        if fd in self.shms:
            size = self.shms[fd]["size"]
        else:
            size = len(self.files[fd]["data"]) if fd in self.files else 0
        path = self.files[fd]["path"] if fd in self.files else self.fds.get(fd, f"fd{fd}")
        if not self._write_stat(uc, buf, size, isdir=fd in self.dirfds, path=path):
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, 0)

    def sys_stat(self, uc):
        path = self._read_cstr(uc, self._args(uc)[0], 256)
        buf = self._args(uc)[1]
        if not path.startswith("/dev/"):
            data = self._vfile(path)
            if data is not None:
                self._write_stat(uc, buf, len(data), path=path)
                return self._ret(uc, 0)
            if self._visdir(path):
                self._write_stat(uc, buf, 0, isdir=True, path=path)
                return self._ret(uc, 0)
        elif path.startswith(self.BOOT_DEV_NODES):
            # device nodes of the console's storage / sensor stack that mini-syscore checks (filecheck)
            # before mounting the system partitions; the kernel creates them at boot
            self._write_stat(uc, buf, 0, path=path)
            st = bytearray(bytes(uc.mem_read(buf, 0x78)))
            _struct.pack_into("<H", st, 0x08, 0o20600)                  # S_IFCHR | 0600
            uc.mem_write(buf, bytes(st))
            return self._ret(uc, 0)
        self._ret(uc, ENOENT, error=True)

    BOOT_DEV_NODES = ("/dev/da", "/dev/ada", "/dev/sflash", "/dev/sbram", "/dev/icc", "/dev/es0",
                      "/dev/exfatfs", "/dev/geom", "/dev/idata", "/dev/dipsw", "/dev/dngl", "/dev/deci",
                      "/dev/evlg", "/dev/srtc", "/dev/sbl_srv", "/dev/bt", "/dev/xpt0", "/dev/pass")

    def sys_lseek(self, uc):
        fd, off, whence = self._args(uc)[:3]
        fd &= 0xFFFFFFFF
        dev = self.devs.get(fd)
        if dev is not None and dev.seekable_size is not None:
            off = off - (1 << 64) if off >= (1 << 63) else off
            base = {0: 0, 1: dev.pos, 2: dev.seekable_size}.get(whence & 0xFFFFFFFF, 0)
            if base + off < 0:
                return self._ret(uc, EINVAL, error=True)
            dev.pos = base + off
            return self._ret(uc, dev.pos)
        f = self.files.get(fd)
        if f is None:
            return self._ret(uc, 0)
        off = off - (1 << 64) if off >= (1 << 63) else off
        base = {0: 0, 1: f["pos"], 2: len(f["data"])}.get(whence & 0xFFFFFFFF, 0)
        if base + off < 0:
            return self._ret(uc, EINVAL, error=True)
        f["pos"] = base + off                   # past EOF is allowed (sparse write)
        self._ret(uc, f["pos"])

    # fcntl(fd, cmd, arg). Mono derives a handle's access rights from F_GETFL
    # (O_ACCMODE); with no handler every fd read back as O_RDONLY and Mono then
    # refused to write to the console (UnauthorizedAccessException from every
    # Console.WriteLine / UILog call).
    F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL = 0, 1, 2, 3, 4
    F_DUPFD_CLOEXEC = 67
    O_RDONLY, O_WRONLY, O_RDWR = 0, 1, 2

    def sys_fcntl(self, uc):
        fd, cmd, arg = self._args(uc)[:3]
        fd &= 0xFFFFFFFF
        cmd &= 0xFFFFFFFF
        if fd not in self.fds and fd not in (0, 1, 2) and fd not in self.devs \
                and fd not in self.files:
            return self._ret(uc, 9, error=True)                      # EBADF
        if cmd in (self.F_DUPFD, self.F_DUPFD_CLOEXEC):
            new = self._alloc_fd(self.fds.get(fd, f"dup{fd}"), base=max(3, arg & 0xFFFFFFFF))
            if fd in self.devs:
                self.devs[new] = self.devs[fd]
            if fd in self.files:
                self.files[new] = self.files[fd]
            return self._ret(uc, new)
        if cmd == self.F_GETFL:
            # stdin is read-only, the console/stdout/stderr write-only; anything
            # else (files, devices, sockets) is opened read/write here.
            if fd == 0:
                return self._ret(uc, self.O_RDONLY)
            return self._ret(uc, self.O_RDWR)
        self._ret(uc, 0)               # F_GETFD/SETFD/SETFL/locks: no-ops

    def sys_dup(self, uc):
        oldfd = self._args(uc)[0]
        fd = self._alloc_fd(self.fds.get(oldfd, f"dup{oldfd}"))
        if oldfd in self.devs:
            self.devs[fd] = self.devs[oldfd]
        self._ret(uc, fd)

    def sys_dup2(self, uc):
        # dup2(oldfd, newfd): make newfd refer to oldfd; return newfd.
        oldfd, newfd, *_ = self._args(uc)
        if newfd == 0:
            self._rdup_next = 3
        self.fds[newfd] = self.fds.get(oldfd, f"dup{oldfd}")
        if oldfd in self.devs:
            self.devs[newfd] = self.devs[oldfd]
        self.emu.log(f"  [dup2] {oldfd} -> {newfd}")
        self._ret(uc, newfd)

    def device_of_kind(self, cls):
        return next((d for d in self.devs.values() if isinstance(d, cls)), None)

    def sys_ioctl(self, uc):
        fd, req, argp = self._args(uc)[:3]
        fd &= 0xFFFFFFFF          # int fd: upper register bits are garbage
        req &= 0xFFFFFFFF
        dev = self.devs.get(fd)
        if dev is None:
            if self.trace or (fd, req) not in self._ioctl_seen:
                self._ioctl_seen.add((fd, req))
                self.emu.log(f"  [ioctl] fd {fd} ({self.fds.get(fd, '?')}) "
                             f"req={req:#010x} arg={argp:#x} -> 0")
            return self._ret(uc, 0)
        try:
            rv = dev.ioctl(uc, req, argp)
        except Exception as e:                   # bad guest pointer etc.
            self.emu.log(f"  [ioctl] {dev.path} req={req:#010x}: {e} -> EINVAL")
            return self._ret(uc, EINVAL, error=True)
        if rv is BLOCKED:
            return                      # the device parked the thread; its return value comes on wake
        if rv and rv < 0:
            return self._ret(uc, -rv, error=True)
        self._ret(uc, rv or 0)

    def sys_namedobj_create(self, uc):
        # ORBIS sys_557: create a named kernel object (event flag, mutex, …).
        # args: (name, attr_ptr, type, ...). Return a fresh unique handle.
        name_ptr, attr, otype, _a3, _a4, _a5 = self._args(uc)
        name = self._read_cstr(uc, name_ptr)
        h = self._new_handle(f"namedobj:{otype:#x}", name)
        self.emu.log(f"  [namedobj_create] '{name}' type={otype:#x} -> handle 0x{h:x}")
        self._ret(uc, h)

    # Program authority IDs (SELF "paid") of processes we know. Anything else
    # gets a system ID that none of libkernel's inlined sceKernelIsXxx()
    # identity checks match.
    AUTHORITY_IDS = {
        "sceshellcore": 0x3800000000000010,
    }
    # system applications (all run as eboot.bin) by title id: ShellCore's PsmSharedDmem service only serves a
    # caller whose authority id is the ShellUI's (SceShellCore+0x612a70 compares it with 0x380000000000000f)
    AUTHORITY_IDS_BY_TITLE = {
        "npxs20001": 0x380000000000000F,
    }
    DEFAULT_AUTHORITY_ID = 0x38000000000000FF

    def sys_get_authinfo(self, uc):
        # sys_587 get_authinfo(pid, SceAuthInfo *out): the calling process's
        # SELF authentication info, 0x88 bytes:
        #   u64 paid; u64 caps[4]; u64 attrs[4]; u64 ucred[8]
        # Libraries test capability bits (VideoOut: caps[0] bit 62 enables the
        # display-server port features GnmCompositor needs). The decrypted
        # ELFs no longer carry their SELF headers, so grant the all-ones
        # capability set that PS4 system code is known to run with.
        import os
        import struct
        _pid, buf, *_ = self._args(uc)
        if not buf:
            return self._ret(uc, EINVAL, error=True)
        target = self.emu
        mgr = getattr(self.emu, 'manager', None)
        # IPMI session handles are the client's pid
        if mgr is not None and _pid not in (0, self.pid_of_process()):
            for q in mgr.procs:
                if getattr(q[0], 'child_pid', 0) == _pid:
                    target = q[0]
        name = os.path.splitext(os.path.basename(getattr(target, "path", "") or ""))[0].lower()
        title = os.path.basename(str(getattr(target, "app_root", "") or "").rstrip("/\\")).lower()
        paid = self.AUTHORITY_IDS_BY_TITLE.get(title) or self.AUTHORITY_IDS.get(name, self.DEFAULT_AUTHORITY_ID)
        if __import__('os').environ.get('PSEMU_IPMI_TRACE'):
            self.emu.log(f'  [authinfo] pid {_pid & 0xFFFFFFFF} -> {name} paid {paid:#x}')
        caps = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0, 0]
        info = struct.pack("<Q4Q4Q", paid, *caps, 0, 0, 0, 0) + b"\x00" * 0x40
        try:
            uc.mem_write(buf, info)
        except Exception:
            return self._ret(uc, EINVAL, error=True)
        self._ret(uc, 0)

    def sys_mmap(self, uc):
        # FreeBSD: mmap(addr, len, prot, flags, fd, offset)
        addr, length, prot, flags, fd, offset = self._args(uc)
        prot, flags = prot & 0xFFFFFFFF, flags & 0xFFFFFFFF
        fd = fd & 0xFFFFFFFF
        fd = fd - (1 << 32) if fd >= 0x80000000 else fd          # int fd (-1 = none)
        from unicorn import UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        uprot = UC_PROT_NONE
        if prot & 1: uprot |= UC_PROT_READ
        if prot & 2: uprot |= UC_PROT_WRITE
        if prot & 4: uprot |= UC_PROT_EXEC
        # x86 has no write-only (or exec-only) page: writable/executable memory
        # is always readable. PS4 code maps direct memory CPU_WRITE-only (prot
        # 0x2) and then reads it back (e.g. libc object guards), so a literal
        # write-only mapping faults on read - grant READ whenever W or X is set.
        if uprot & (UC_PROT_WRITE | UC_PROT_EXEC):
            uprot |= UC_PROT_READ
        if uprot == UC_PROT_NONE:
            uprot = UC_PROT_READ | UC_PROT_WRITE
        MAP_ANON = 0x1000
        dev = self.devs.get(fd) if not flags & MAP_ANON else None
        shm = self.shms.get(fd) if not flags & MAP_ANON else None
        if shm is not None:
            span = (max(length, shm["size"], 0x1000) + 0x3FFF) & ~0x3FFF
            mine = self.shm_maps.get(id(shm))
            if mine is None or span > mine[1]:
                # Orbis maps with 16 KiB granularity: a 0xf28-byte shm still covers 0x4000 bytes.
                # libSceAudioOut relies on it: its per-port table (8 x 0x250 bytes at +0x20 of a
                # 0xf28-byte block) reaches past the first 4 KiB page.
                # Always read+write: later mappers of the same object may ask
                # for more access than the first one did (client maps it
                # read-only, the owner read-write) and all share this memory.
                host = self._shm_host(shm, span)
                got = self.emu.map_anon(span, addr_hint=addr, prot=UC_PROT_READ | UC_PROT_WRITE,
                                        host_ptr=host)
                if got == 0xFFFFFFFFFFFFFFFF:
                    return self._ret(uc, ENOMEM, error=True)
                mine = (got, span)
                self.shm_maps[id(shm)] = mine
                shm["addr"], shm["span"] = got, span          # (the last mapper's; kept for the old checks)
                self._add_vma(got, span, prot, flags, 0, False)
            if length <= mine[1]:
                self.emu.log(f"  [mmap] shm '{shm['name']}' -> 0x{mine[0]:x} (len={length:#x})")
                return self._ret(uc, mine[0])
        fil = self.files.get(fd) if not flags & MAP_ANON else None
        if fil is not None:
            # File-backed mmap: anonymous pages with the file's bytes copied in
            # from `offset`. Mono maps assembly (.dll) images this way to read
            # their CIL; without this it would see zeroed pages ("invalid CIL
            # image"). MAP_PRIVATE semantics are fine - these are read as data.
            got = self.emu.map_anon(length, addr_hint=addr,
                                    prot=UC_PROT_READ | UC_PROT_WRITE)
            if got == 0xFFFFFFFFFFFFFFFF:
                return self._ret(uc, ENOMEM, error=True)
            chunk = bytes(fil["data"])[offset:offset + length]
            try:
                uc.mem_write(got, chunk)
            except Exception:
                return self._ret(uc, ENOMEM, error=True)
            self._add_vma(got, length, prot, flags, offset, False)
            self.emu.log(f"  [mmap] file '{fil.get('path', '')}' off={offset:#x} "
                         f"-> 0x{got:x} (len={length:#x})")
            return self._ret(uc, got)
        if dev is not None:
            got = dev.mmap(uc, length, prot, offset)
            if got is not None:
                self.emu.log(f"  [mmap] {dev.path} off={offset:#x} -> 0x{got:x} (len={length:#x})")
                self._add_vma(got, length, prot, flags, 0, False)
                return self._ret(uc, got)
        MAP_FIXED = 0x10
        if flags & MAP_FIXED and addr:
            got = self.emu.map_fixed(addr, length, prot=uprot)
        else:
            # MAP_ALIGNED(n) (flags bits 24..28 = log2 alignment). The kernel gives a direct-memory
            # mapping an address congruent to its physical offset modulo 64 KiB, and libSceVideoOut
            # checks exactly that for every display buffer (sceVideoOutRegisterBuffers fails with
            # 0x80290015 otherwise: the boot splash in SceSysAvControl never got a buffer).
            want = 1 << ((flags >> 24) & 0x1F) if (flags >> 24) & 0x1F else 0
            if isinstance(dev, DmemDevice):
                want = max(want, 0x10000)
            got = self.emu.map_anon(length, addr_hint=addr, prot=uprot, align=want)
        if got == 0xFFFFFFFFFFFFFFFF:
            self.emu.log(f"  [mmap] FAILED len={length:#x}")
            self._ret(uc, ENOMEM, error=True)
            return
        direct = isinstance(dev, DmemDevice)
        self._add_vma(got, length, prot, flags, offset if direct else 0, direct)
        self.emu.log(f"  [mmap] -> 0x{got:x} (len={length:#x}, prot={prot:#x}, "
                     f"flags={flags:#x}, hint={addr:#x}, fd={fd if fd < 0x10000 else -1}"
                     + (f", phys={offset:#x}" if direct else "") + ")")
        self._ret(uc, got)

    # sceKernelBatchMap(entries, count, &processed): map/unmap/protect many ranges
    # in one call. Syscall 548 is called as (fd/flags?, 0x410, entries, count,
    # &processed) -- args[2:5]. Entry (0x20 bytes): {u64 start; u64 offset (a
    # direct-memory offset for MAP_DIRECT); u64 length; u8 protection; u8 type;
    # u16 pad; u32 operation}. libSceComposite maps its shared 2MB chunks this
    # way (operation 0) into the window the GnmCompositor server told it about.
    BATCH_MAP_DIRECT, BATCH_UNMAP, BATCH_PROTECT, BATCH_MAP_FLEXIBLE, BATCH_TYPE_PROTECT = range(5)

    def sys_batch_map(self, uc):
        import struct
        from unicorn import UC_PROT_READ, UC_PROT_WRITE
        entries, count, p_done = self._args(uc)[2:5]
        count &= 0xFFFFFFFF
        done = 0
        for i in range(count):
            try:
                start, off, length, prot, _typ, _pad, op = struct.unpack(
                    "<QQQBBHI", bytes(uc.mem_read(entries + 0x20 * i, 0x20)))
            except Exception:
                return self._ret(uc, EFAULT, error=True)
            if op in (self.BATCH_MAP_DIRECT, self.BATCH_MAP_FLEXIBLE):
                if start:
                    got = self.emu.map_fixed(start, length, prot=UC_PROT_READ | UC_PROT_WRITE)
                else:
                    got = self.emu.map_anon(length, prot=UC_PROT_READ | UC_PROT_WRITE)
                if got == 0xFFFFFFFFFFFFFFFF:
                    self.emu.log(f"  [batch_map] entry {i}: map {length:#x} @ {start:#x} FAILED")
                    break
                self._add_vma(start or got, length, prot, 0,
                              off if op == self.BATCH_MAP_DIRECT else 0,
                              op == self.BATCH_MAP_DIRECT)
            elif op == self.BATCH_UNMAP:
                self._cut_vmas(start, start + length)      # pages are left mapped
            # PROTECT / TYPE_PROTECT: x86 has no per-use protection to change here
            done += 1
        if p_done:
            try:
                uc.mem_write(p_done, struct.pack("<I", done))
            except Exception:
                pass
        self.emu.log(f"  [batch_map] {done}/{count} entries")
        self._ret(uc, 0 if done == count else ENOMEM, error=done != count)

    # ---- stopping another thread and reading its registers --------------
    # thr_suspend_ucontext(tid) / thr_get_ucontext(tid, ucontext_t *) /
    # thr_resume_ucontext(tid) / thr_set_ucontext(tid, ucontext_t *).
    # Mono's stop-the-world (libmonosgen +0x218060) does suspend -> get -> check
    # that the thread's rsp lies in its stack -> keep the context for a
    # conservative stack scan, and resume + retry if it cannot use the thread.
    # They used to be bare "success" stubs: nothing was stopped and the context
    # buffer was never written, so Mono read stale stack, never settled, and the
    # UI thread spun on suspend/get/resume of one event-loop thread forever.
    #
    # FreeBSD amd64 ucontext_t: uc_sigmask at 0, uc_mcontext at 0x10 =
    # {onstack, rdi, rsi, rdx, rcx, r8, r9, rax, rbx, rbp, r10, r11, r12..r15,
    #  trapno/fs/gs, addr, flags/es/ds, err, rip, cs, rflags, rsp, ss, len, ...}
    UCTX_SIZE = 0x370
    UCTX_MC = 0x40       # offset of mcontext_t in the Orbis ucontext_t (64-byte aligned;
                         # recovered from Mono's mono_sigctx_to_monoctx: rip is at +0xE0)
    UCTX_REGS = (            # (mcontext offset, unicorn register)
        (0x08, "RDI"), (0x10, "RSI"), (0x18, "RDX"), (0x20, "RCX"), (0x28, "R8"),
        (0x30, "R9"), (0x38, "RAX"), (0x40, "RBX"), (0x48, "RBP"), (0x50, "R10"),
        (0x58, "R11"), (0x60, "R12"), (0x68, "R13"), (0x70, "R14"), (0x78, "R15"),
        (0xA0, "RIP"), (0xB0, "RFLAGS"), (0xB8, "RSP"),
        # mc_fsbase / mc_gsbase: Mono's stop-the-world reads the target thread's
        # TLS (current domain, JIT thread data) through the fs base; with 0 there
        # it concluded no thread was attached and retried the suspend forever.
        (0x2E0, "FS_BASE"), (0x2E8, "GS_BASE"))

    def _ucontext_target(self, uc, tid):
        """The Thread for lwp id `tid`, or None if it does not exist / has exited."""
        sched = self.emu.sched
        t = sched.threads.get(tid & 0xFFFFFFFF) if sched is not None else None
        return t if t is not None and t.state != "exited" else None

    def sys_thr_suspend_ucontext(self, uc):
        t = self._ucontext_target(uc, self._args(uc)[0])
        if t is None:
            return self._ret(uc, ESRCH, error=True)
        if t is self.emu.sched.current:
            return self._ret(uc, EINVAL, error=True)   # cannot stop the caller
        t.suspended = True
        self._ret(uc, 0)

    def sys_thr_resume_ucontext(self, uc):
        t = self._ucontext_target(uc, self._args(uc)[0])
        if t is None:
            return self._ret(uc, ESRCH, error=True)
        t.suspended = False
        self._ret(uc, 0)

    def sys_thr_get_ucontext(self, uc):
        import unicorn.x86_const as xc
        tid, out = self._args(uc)[:2]
        t = self._ucontext_target(uc, tid)
        if t is None:
            return self._ret(uc, ESRCH, error=True)
        # a thread that is not running has its registers in its saved context
        src = t.ctx if t.ctx is not None else uc
        buf = bytearray(self.UCTX_SIZE)
        base = self.UCTX_MC                             # uc_mcontext
        for off, name in self.UCTX_REGS:
            try:
                _struct.pack_into("<Q", buf, base + off,
                                  src.reg_read(getattr(xc, f"UC_X86_REG_{name}")))
            except Exception:
                pass
        _struct.pack_into("<q", buf, base + 0xC8, 0x320)   # mc_len
        try:
            uc.mem_write(out, bytes(buf))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, 0)

    def sys_thr_set_ucontext(self, uc):
        import unicorn.x86_const as xc
        tid, src_ptr = self._args(uc)[:2]
        t = self._ucontext_target(uc, tid)
        if t is None:
            return self._ret(uc, ESRCH, error=True)
        try:
            raw = bytes(uc.mem_read(src_ptr, self.UCTX_SIZE))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        dst = t.ctx if t.ctx is not None else uc
        for off, name in self.UCTX_REGS:
            try:
                dst.reg_write(getattr(xc, f"UC_X86_REG_{name}"),
                              _struct.unpack_from("<Q", raw, self.UCTX_MC + off)[0])
            except Exception:
                pass
        self._ret(uc, 0)

    # ---- signals: sigaction / sigaltstack / delivery / sigreturn ---------
    # Mono turns hardware faults into managed exceptions: it installs a SIGSEGV
    # handler, and a null dereference in managed code reaches it as a signal
    # whose ucontext it rewrites to jump into its throw routine, then sigreturn
    # resumes there. Without delivery, the first NullReferenceException ended the
    # whole emulation.
    SIGSEGV, SIGBUS = 11, 10
    SA_ONSTACK, SA_SIGINFO = 0x1, 0x40
    SIG_DFL, SIG_IGN = 0, 1
    SS_DISABLE = 4

    def sys_sigaction(self, uc):
        # sigaction(sig, const struct sigaction *act, struct sigaction *oact);
        # FreeBSD struct sigaction = {handler:8, flags:4 (+4 pad), mask:16} (0x20)
        sig, act, oact = self._args(uc)[:3]
        sig &= 0xFFFFFFFF
        old = self.sig_actions.get(sig, (self.SIG_DFL, 0, bytes(16)))
        try:
            if oact:
                uc.mem_write(oact, _struct.pack("<QI4x", old[0], old[1]) + old[2])
            if act:
                raw = bytes(uc.mem_read(act, 0x20))
                handler, flags = _struct.unpack_from("<QI", raw, 0)
                self.sig_actions[sig] = (handler, flags, raw[0x10:0x20])
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, 0)

    # ---- time zone conversion (Sony syscalls 638 / 639) --------------------
    # sceKernelConvertUtcToLocaltime(time_t time, time_t *local, OrbisTimesec *st,
    # u64 *dst_sec): the console's configured zone is UTC with no DST here. The
    # outputs used to stay unwritten, so Mono built TimeZoneInfo.Local from stack
    # garbage ("baseUtcOffset ... whole number of minutes") and the ShellUI's first
    # type initialiser that touched time zones threw.
    # OrbisTimesec = {time_t t; u32 west_sec; u32 dst_sec}
    def sys_convert_utc_to_localtime(self, uc):
        t, p_local, p_st, p_dst = self._args(uc)[:4]
        try:
            if p_local:
                uc.mem_write(p_local, _struct.pack("<q", t))
            if p_st:
                uc.mem_write(p_st, _struct.pack("<qII", t, 0, 0))
            if p_dst:
                uc.mem_write(p_dst, _struct.pack("<Q", 0))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, 0)

    def sys_convert_localtime_to_utc(self, uc):
        # sceKernelConvertLocaltimeToUtc(time_t time, int mode, time_t *utc,
        # OrbisTimesec *st, u64 *dst_sec)
        t, _mode, p_utc, p_st, p_dst = self._args(uc)[:5]
        try:
            if p_utc:
                uc.mem_write(p_utc, _struct.pack("<q", t))
            if p_st:
                uc.mem_write(p_st, _struct.pack("<qII", t, 0, 0))
            if p_dst:
                uc.mem_write(p_dst, _struct.pack("<Q", 0))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, 0)

    def sys_sigaltstack(self, uc):
        # sigaltstack(const stack_t *ss, stack_t *oss); stack_t = {sp:8, size:8, flags:4}
        ss, oss = self._args(uc)[:2]
        tid = self.emu.sched.current.tid if self.emu.sched and self.emu.sched.current else 0
        old = self.sig_altstack.get(tid, (0, 0, self.SS_DISABLE))
        try:
            if oss:
                uc.mem_write(oss, _struct.pack("<QQI4x", *old))
            if ss:
                sp, size, flags = _struct.unpack("<QQI", bytes(uc.mem_read(ss, 20)))
                self.sig_altstack[tid] = (sp, size, flags)
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._ret(uc, 0)

    def _sigtramp_addr(self):
        """A page with the signal return code: after the handler returns, rsp
        points at the ucontext it was given, so `mov rdi, rsp; mov eax, 417;
        syscall` is sigreturn(ucontext)."""
        if self._sigtramp is None:
            from unicorn import UC_PROT_ALL
            page = self.emu.map_anon(0x1000, prot=UC_PROT_ALL)
            self.emu.uc.mem_write(page, bytes([0x48, 0x89, 0xE7,              # mov rdi, rsp
                                               0xB8, 0xA1, 0x01, 0x00, 0x00,  # mov eax, 417
                                               0x0F, 0x05, 0xCC]))            # syscall; int3
            self._sigtramp = page
        return self._sigtramp

    def _pack_ucontext(self, src, fault_addr=0, trapno=0, err=0):
        """A FreeBSD amd64 ucontext_t (mcontext at +0x10) from register source `src`."""
        import unicorn.x86_const as xc
        buf = bytearray(self.UCTX_SIZE)
        base = self.UCTX_MC
        for off, name in self.UCTX_REGS:
            try:
                _struct.pack_into("<Q", buf, base + off,
                                  src.reg_read(getattr(xc, f"UC_X86_REG_{name}")))
            except Exception:
                pass
        _struct.pack_into("<I", buf, base + 0x80, trapno)        # mc_trapno
        _struct.pack_into("<Q", buf, base + 0x88, fault_addr)    # mc_addr
        _struct.pack_into("<Q", buf, base + 0x98, err)           # mc_err
        _struct.pack_into("<q", buf, base + 0xC8, 0x320)         # mc_len
        return bytes(buf)

    def can_deliver(self, sig):
        act = self.sig_actions.get(sig)
        return bool(act and act[0] not in (self.SIG_DFL, self.SIG_IGN))

    def deliver_signal(self, uc, sig, fault_addr, write=False):
        """Run the guest's handler for `sig` as the kernel would: build a signal
        frame on the thread's (alternate) stack and return the handler's address
        to resume at, or None when it cannot be delivered."""
        handler, flags, _mask = self.sig_actions[sig]
        from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RDI,
                                       UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX)
        rip = uc.reg_read(UC_X86_REG_RIP)
        key = (sig, rip, fault_addr)
        self._sig_streak[key] = self._sig_streak.get(key, 0) + 1
        if self._sig_streak[key] > 200:       # the handler does not cure the fault
            return None
        rsp = uc.reg_read(UC_X86_REG_RSP)
        tid = self.emu.sched.current.tid if self.emu.sched and self.emu.sched.current else 0
        top = rsp - 128                                    # skip the red zone
        alt = self.sig_altstack.get(tid)
        if flags & self.SA_ONSTACK and alt and not alt[2] & self.SS_DISABLE and alt[1]:
            if not (alt[0] <= rsp < alt[0] + alt[1]):      # not already on it
                top = alt[0] + alt[1]
        base = (top - 0x600) & ~0xF
        ucp, sip = base + 0x80, base + 0x500
        uctx = self._pack_ucontext(uc, fault_addr, trapno=12, err=(2 if write else 0))
        info = bytearray(0x80)
        _struct.pack_into("<iii", info, 0, sig, 0, 1)      # si_signo, si_errno, si_code=SEGV_MAPERR
        _struct.pack_into("<Q", info, 0x18, fault_addr)    # si_addr
        uc.mem_write(ucp, uctx)
        uc.mem_write(sip, bytes(info))
        uc.mem_write(base + 0x78, _struct.pack("<Q", self._sigtramp_addr()))   # return address
        uc.reg_write(UC_X86_REG_RSP, base + 0x78)
        uc.reg_write(UC_X86_REG_RDI, sig)
        uc.reg_write(UC_X86_REG_RSI, sip)
        uc.reg_write(UC_X86_REG_RDX, ucp)
        uc.reg_write(UC_X86_REG_RCX, fault_addr)
        self._sig_delivered = getattr(self, "_sig_delivered", 0) + 1
        if self._sig_delivered in (2, 3):          # diagnostic: full state at the fault
            import unicorn.x86_const as _x
            rg = {n: uc.reg_read(getattr(_x, "UC_X86_REG_" + n))
                  for n in ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9",
                            "R10", "R11", "R12", "R13", "R14", "R15", "EFLAGS", "CS", "SS", "FS_BASE")}
            self.emu.log("  [signal] fault state: " + " ".join(f"{k.lower()}={v:#x}" for k, v in rg.items()))
            try:
                self.emu.log("  [signal] code at rip: " + bytes(uc.mem_read(rip, 16)).hex(" "))
            except Exception:
                pass
        if self._sig_delivered <= 6 or self._sig_delivered % 1000 == 0:
            self.emu.log(f"  [signal] SIGSEGV #{self._sig_delivered} tid={tid:#x} addr={fault_addr:#x} "
                         f"rip={rip:#x} rsp={rsp:#x} -> handler {handler:#x} (frame {base:#x}, ucontext {ucp:#x})")
        return handler

    def sys_sigreturn(self, uc):
        # sigreturn(const ucontext_t *ucp): restore every register from the (possibly
        # rewritten) context and resume there. The new rip needs the CPU restarted.
        import unicorn.x86_const as xc
        ucp = self._args(uc)[0]
        try:
            raw = bytes(uc.mem_read(ucp, self.UCTX_SIZE))
        except Exception:
            return self._ret(uc, EFAULT, error=True)
        self._sigret_n = getattr(self, "_sigret_n", 0) + 1
        if self._sigret_n <= 6:
            vals = {n: _struct.unpack_from("<Q", raw, self.UCTX_MC + o)[0] for o, n in self.UCTX_REGS}
            self.emu.log("  [signal] sigreturn #%d ucp=%#x: " % (self._sigret_n, ucp) +
                         " ".join(f"{k.lower()}={v:#x}" for k, v in vals.items()
                                  if k in ("RIP", "RSP", "RBP", "RDI", "RSI", "RAX", "FS_BASE")))
        for off, name in self.UCTX_REGS:
            try:
                uc.reg_write(getattr(xc, f"UC_X86_REG_{name}"),
                             _struct.unpack_from("<Q", raw, self.UCTX_MC + off)[0])
            except Exception:
                pass
        # Unicorn advances rip past the 2-byte `syscall` AFTER this hook returns, so
        # a rip written here lands 2 bytes late (mid-instruction: the REX prefix of
        # `push rbp; mov rbp, rsp` was skipped, turning it into a 32-bit mov).
        from unicorn.x86_const import UC_X86_REG_RIP
        uc.reg_write(UC_X86_REG_RIP, (uc.reg_read(UC_X86_REG_RIP) - 2) & 0xFFFFFFFFFFFFFFFF)
        self.emu._hle_pending = True        # resume at the restored rip
        uc.emu_stop()

    # ---- virtual memory areas: what virtual_query reports -------------
    # [start, end, prot (incl. GPU bits 0x10/0x20), flags, phys offset, direct]
    def _add_vma(self, start, length, prot, flags, offset, direct):
        end = start + ((length + 0x3FFF) & ~0x3FFF)
        self._cut_vmas(start, end)
        self.vmas.append([start, end, prot, flags, offset, direct])
        self.vmas.sort()

    def _cut_vmas(self, lo, hi):
        out = []
        for v in self.vmas:
            s, e = v[0], v[1]
            if e <= lo or hi <= s:
                out.append(v)
                continue
            if s < lo:
                out.append([s, lo] + v[2:])
            if hi < e:
                out.append([hi, e, v[2], v[3], v[4] + (hi - s) if v[5] else 0, v[5]])
        self.vmas = sorted(out)

    def sys_virtual_query(self, uc):
        # sys_572 virtual_query(addr, flags, OrbisVirtualQueryInfo *info, size):
        #   u64 start, end, offset; i32 protection, memory_type;
        #   u8 is_flexible:1, is_direct:1, is_stack:1, is_pooled:1, is_committed:1;
        #   char name[32]
        # flags & 1: if addr is unmapped, report the next mapping above it.
        import struct
        addr, qflags, info, size = self._args(uc)[:4]
        hit = next((v for v in self.vmas if v[0] <= addr < v[1]), None)
        if hit is None and qflags & 1:
            hit = next((v for v in self.vmas if v[0] > addr), None)
        if hit is None:
            return self._ret(uc, EACCES, error=True)
        s, e, prot, mflags, off, direct = hit
        mtype = DmemDevice.allocator.type_at(off) if direct else 0
        bits = (0 if direct else 1) | (2 if direct else 0) | (4 if mflags & 0x400 else 0) | 0x10
        rec = struct.pack("<QQQiiB", s, e, off, prot, mtype, bits).ljust(0x48, b"\x00")
        uc.mem_write(info, rec[:max(0, min(size, 0x48))])
        self._ret(uc, 0)

    def sys_munmap(self, uc):
        addr, length, *_ = self._args(uc)
        for obj in list(self.shm_objs.values()) + list(self.shms.values()):
            mine = self.shm_maps.get(id(obj))
            if mine is not None and mine[0] <= addr < mine[0] + mine[1]:
                # A shared-memory object's pages belong to the object, not to
                # one mapper: keep them so its contents survive and the next
                # mmap of the object sees the same memory.
                self.emu.log(f"  [munmap] shm '{obj['name']}' at {addr:#x}: kept (object still exists)")
                return self._ret(uc, 0)
        self.emu.unmap_anon(addr, length)
        self._cut_vmas(addr, addr + length)
        self._ret(uc, 0)

    def sys_mprotect(self, uc):
        # honoured loosely: Unicorn can change perms, but for a scaffold we
        # accept it as success without tightening (keeps the module running).
        self._ret(uc, 0)

    # sysctl MIBs we answer (CTL_KERN=1, CTL_HW=6)
    # sysarch(op, parms): AMD64_GET/SET_FSBASE (128/129), GET/SET_GSBASE (130/131).
    # libkernel installs its own TCB / struct pthread this way.
    def sys_sysarch(self, uc):
        import struct
        from unicorn.x86_const import UC_X86_REG_FS_BASE, UC_X86_REG_GS_BASE
        op, parms = self._args(uc)[:2]
        reg = UC_X86_REG_FS_BASE if op in (128, 129) else UC_X86_REG_GS_BASE
        try:
            if op in (128, 130):
                uc.mem_write(parms, struct.pack("<Q", uc.reg_read(reg)))
            elif op in (129, 131):
                base = struct.unpack("<Q", bytes(uc.mem_read(parms, 8)))[0]
                uc.reg_write(reg, base)
                self.emu.log(f"  [sysarch] {'fs' if op == 129 else 'gs'}_base <- {base:#x}")
            else:
                return self._ret(uc, EINVAL, error=True)
        except Exception:
            return self._ret(uc, EINVAL, error=True)
        self._ret(uc, 0)

    # thr_self(long *id): the calling thread's kernel thread id
    def sys_thr_self(self, uc):
        import struct
        from .emulator import DEFAULT_TID
        ptr = self._args(uc)[0]
        sched = self.emu.sched
        tid = sched.current.tid if sched and sched.current else DEFAULT_TID
        try:
            uc.mem_write(ptr, struct.pack("<q", tid))
        except Exception:
            return self._ret(uc, EINVAL, error=True)
        self._ret(uc, 0)

    # rtprio_thread(function, lwpid, struct rtprio *rtp {u16 type; u16 prio}): libkernel's pthread layer
    # derives a thread's scheduling policy from it (+0x31870 getschedparam / thread init), and
    # pthread_setschedparam rejects anything but SCHED_FIFO/SCHED_RR. A PS4 thread runs a FIFO priority
    # (default SCE_KERNEL_PRIO_FIFO_DEFAULT = 700); until a thread sets its own, report that.
    RTP_LOOKUP, RTP_SET = 0, 1
    RTP_PRIO_FIFO = 10            # PRI_FIFO_BIT (8) | PRI_REALTIME (2)
    RTPRIO_DEFAULT = (RTP_PRIO_FIFO, 700)

    def sys_rtprio_thread(self, uc):
        import struct
        fn, lwpid, rtp = self._args(uc)[:3]
        sched = self.emu.sched
        cur = sched.current.tid if sched and sched.current else 0
        tid = (lwpid & 0xFFFFFFFF) or cur
        table = self.__dict__.setdefault("_rtprio", {})
        try:
            if (fn & 0xFFFFFFFF) == self.RTP_SET:
                typ, prio = struct.unpack("<HH", bytes(uc.mem_read(rtp, 4)))
                table[tid] = (typ, prio)
            elif (fn & 0xFFFFFFFF) == self.RTP_LOOKUP:
                uc.mem_write(rtp, struct.pack("<HH", *table.get(tid, self.RTPRIO_DEFAULT)))
        except Exception:
            return self._ret(uc, EINVAL, error=True)
        self._ret(uc, 0)

    def sys_sysctl(self, uc):
        import struct
        from .emulator import STACK_TOP
        name, namelen, oldp, oldlenp, newp, newlen = self._args(uc)
        mib = []
        try:
            for i in range(min(namelen, 8)):
                mib.append(struct.unpack_from("<i", bytes(uc.mem_read(name + 4 * i, 4)))[0])
        except Exception:
            self._ret(uc, EINVAL, error=True)
            return

        def give(value_bytes):
            # honour oldlenp / oldp if provided
            if oldlenp:
                try:
                    avail = struct.unpack("<Q", bytes(uc.mem_read(oldlenp, 8)))[0]
                except Exception:
                    avail = len(value_bytes)
                n = min(avail, len(value_bytes)) if avail else len(value_bytes)
                if oldp:
                    uc.mem_write(oldp, value_bytes[:n])
                uc.mem_write(oldlenp, struct.pack("<Q", len(value_bytes)))
            elif oldp:
                uc.mem_write(oldp, value_bytes)
            self._ret(uc, 0)

        # kern.arnd (CTL_KERN=1, KERN_ARND=37): return the requested number of
        # random bytes. The runtime uses this to seed the stack canary; failing
        # it sends the module into its abort stub.
        if tuple(mib[:2]) == (1, 37):
            import os
            want = 0
            if oldlenp:
                try:
                    want = struct.unpack("<Q", bytes(uc.mem_read(oldlenp, 8)))[0]
                except Exception:
                    want = 0
            want = want or 8
            self.emu.log(f"  [sysctl] kern.arnd -> {want} random bytes")
            # seeded, so runs are reproducible; PSEMU_RANDOM=1 for real entropy
            if os.environ.get("PSEMU_RANDOM") == "1":
                give(os.urandom(want))
            else:
                if not hasattr(self, "_arnd"):
                    import random
                    self._arnd = random.Random(0x5053454D)
                give(self._arnd.randbytes(want))
            return

        # sysctl.name2oid {0, 3}: `newp` holds a name; answer with a private
        # OID {0x7F00, i} that the query below then serves from NAMED_SYSCTLS.
        if tuple(mib[:2]) == (0, 3):
            try:
                sname = bytes(uc.mem_read(newp, newlen)).split(b"\x00")[0].decode()
            except Exception:
                sname = ""
            names = list(NAMED_SYSCTLS)
            if sname in NAMED_SYSCTLS:
                self.emu.log(f"  [sysctl] name2oid '{sname}' -> served")
                give(struct.pack("<ii", 0x7F00, names.index(sname)))
                return
            self.emu.log(f"  [sysctl] name2oid '{sname}' -> ENOENT (unknown name)")
            self._ret(uc, ENOENT, error=True)
            return
        if len(mib) >= 2 and mib[0] == 0x7F00 and 0 <= mib[1] < len(NAMED_SYSCTLS):
            sname = list(NAMED_SYSCTLS)[mib[1]]
            self.emu.log(f"  [sysctl] {sname} -> served")
            give(NAMED_SYSCTLS[sname])
            return

        if tuple(mib[:3]) == (1, 14, 36):
            # kern.proc.sdk_version.<pid> (libkernel_sys 0x1a370, 8 bytes out): the system software version the
            # process was built for. SceSysCore reads it when it registers a process with SceMbusIpc and picks the
            # registration layout from it; the generic (1, 14) answer (a 4-byte 1000) selected the wrong one.
            self.emu.log(f"  [sysctl] kern.proc.sdk_version.{mib[3] if len(mib) > 3 else '?'} -> 5.05")
            give(_struct.pack("<II", 0x05050001, 0))
            return

        if tuple(mib[:3]) == (1, 14, 35):
            # kern.proc.appinfo.<pid> (sceKernelGetAppInfo): the 0x48-byte AppInfo, app id first. SceSysCore's
            # process spawn SETS it (newp = the new process's AppInfo, the app id its AppMgr allocated); a read
            # returns what was set for that pid, else this process's default id.
            pid = mib[3] if len(mib) > 3 else 0
            sysm = getattr(self.emu, "system", None)
            store = sysm.appinfo if sysm is not None else self.__dict__.setdefault("_appinfo", {})
            if newp and newlen:
                try:
                    store[pid] = bytes(uc.mem_read(newp, min(newlen, 0x48))).ljust(0x48, bytes(1))
                except Exception:
                    pass
                self.emu.log(f"  [sysctl] kern.proc.appinfo.{pid} <- app id {struct.unpack_from('<I', store.get(pid, bytes(4)), 0)[0]:#x}")
                mgr = getattr(self.emu, 'manager', None)
                for q in (mgr.procs if mgr is not None else []):
                    if getattr(q[0], 'child_pid', 0) == pid:
                        q[0].app_id = struct.unpack_from('<I', store[pid], 0)[0]     # that process's own id
                self._ret(uc, 0)
                return
            info = store.get(pid)
            if info is None:
                info = bytearray(0x48)
                struct.pack_into("<I", info, 0, getattr(self.emu, 'app_id', None) or self.APP_ID)
            self.emu.log(f"  [sysctl] kern.proc.appinfo.{pid} -> app id {struct.unpack_from('<I', bytes(info), 0)[0]:#x}")
            give(bytes(info))
            return

        known = {
            (1, 33): struct.pack("<Q", STACK_TOP),      # kern.usrstack
            (6, 7): struct.pack("<Q", 0x4000),          # hw.pagesize-ish (phys?)
            (6, 3): struct.pack("<i", 1),               # hw.ncpu = 1
            (1, 14): struct.pack("<i", 1000),           # kern.securelevel-ish
        }
        key = tuple(mib[:2]) if len(mib) >= 2 else tuple(mib)
        if key in known:
            self.emu.log(f"  [sysctl] mib={mib} -> served")
            give(known[key])
            return
        self.emu.log(f"  [sysctl] mib={mib} -> ENOENT (unserved)")
        self._ret(uc, ENOENT, error=True)

    def summary(self):
        if not self.counts:
            return "no syscalls were made."
        lines = ["syscalls made:"]
        for num in sorted(self.counts):
            name = SYSCALLS.get(num, f"sys_{num}")
            lines.append(f"  {num:>4} {name:<18} x{self.counts[num]}")
        if self.tid_counts:
            for tid in sorted({t for t, _ in self.tid_counts}):
                top = sorted(((n, c) for (t, n), c in self.tid_counts.items() if t == tid), key=lambda x: -x[1])[:4]
                if top and top[0][1] > 2000:
                    lines.append(f"  tid {tid:#x}: " + ", ".join(f"{SYSCALLS.get(n, n)} x{c}" for n, c in top))
        sync = self.sync_summary()
        if sync:
            lines.append(sync)
        ipmi = self.__dict__.get("_ipmi_counts")
        if ipmi:
            top = sorted(ipmi.items(), key=lambda kv: -kv[1])[:8]
            lines.append("IPMI calls (cmd service xN): " + ", ".join(
                f"{c:#x} {n or '-'} x{k}" for (c, n), k in top))
        mc = self.__dict__.get("_ipmi_method_counts")
        if mc:
            top = sorted(mc.items(), key=lambda kv: -kv[1])[:6]
            lines.append("IPMI sync methods: " + ", ".join(
                f"{n}.{m:#x} x{k}" for (n, m), k in top))
        return "\n".join(lines)
