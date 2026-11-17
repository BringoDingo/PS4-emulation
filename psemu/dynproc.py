"""Load a dynamically linked PS4 process the way the ORBIS kernel does.

The kernel maps the executable and every library it needs, relocates them
(sys_dynlib_process_needed_and_relocate does this on request) and transfers
control to libkernel - the program interpreter ("/libexec/ld-elf.so.1" is
libkernel on PS4) - with a FreeBSD initial stack and aux vector. libkernel
then asks the kernel about the loaded modules through the dynlib_* syscalls
and runs their initialisers before calling the executable's entry.

psemu plays the kernel here: this module builds the address space (all images
in host-backed guest memory, see hostvm.py), applies relocations, routes
imports nobody exports to logging stubs, and records per-module facts that
the dynlib syscalls (syscalls.py) report back to libkernel.
"""
import os
import struct

from .dynld import (DynamicLinker, R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
                    R_X86_64_RELATIVE)
from .loader import PT_LOAD, PT_SCE_MODULE_PARAM, PT_SCE_PROCPARAM, PT_SCE_RELRO

PT_GNU_EH_FRAME = 0x6474E550

R_X86_64_DTPMOD64 = 16
R_X86_64_DTPOFF64 = 17
R_X86_64_TPOFF64 = 18
PT_TLS = 7
PT_DYNAMIC = 2
PAGE = 0x4000                     # PS4 pages are 16 KiB

STUB_BASE = 0x0000_000F_0000_0000   # unresolved-import stubs (one ret each)
STUB_SIZE = 0x10000

AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PAGESZ, AT_BASE, AT_FLAGS, AT_ENTRY = 0, 3, 4, 5, 6, 7, 8, 9
AT_EXECPATH = 15


# Correct implementations for imports that live in firmware libraries psemu
# doesn't load (e.g. libkernel_sys variants), so they'd otherwise fall back to
# the generic return-0 stub and misbehave. handler(emu, uc) -> rax; read args
# with emu.hle.args(uc) = (rdi, rsi, rdx, rcx, r8, r9).
def _imp_eqid_from_handle(emu, uc):
    # libkernel_sys QyrxcdBrb0M(handle, int *out): out = (u32)handle; 0 (or
    # EINVAL for a NULL out). SceSysCore's process_monitor extracts an event-
    # queue id this way and asserts it is >= 0.
    rdi, rsi = emu.hle.args(uc)[:2]
    if not rsi:
        return 0x80020016          # SCE_KERNEL_ERROR_EINVAL
    uc.mem_write(rsi, struct.pack("<I", rdi & 0xFFFFFFFF))
    return 0


def _imp_load_start_module(emu, uc):
    # sceKernelLoadStartModule(path, args, argp, flags, opt, int *pRes) -> handle.
    # Mono's AOT dl backend (libmonosgen mono_dl_open -> 0x358ba0) calls this and
    # uses the RETURN VALUE as the module handle: a 0 return reads as a NULL
    # MonoDl* and makes load_aot_module g_error with "assemblies built without
    # AOT enabled". The generic unresolved-import stub returned 0, so every AOT
    # module load failed. Load the PRX like sys_dynlib_load_prx and return its
    # (positive) handle; a negative SceKernelError on failure so the caller's
    # `cmovs` turns it into NULL.
    rdi = emu.hle.args(uc)[0]
    r9 = emu.hle.args(uc)[5]
    path = emu.syscalls._read_cstr(uc, rdi, 256)
    dyn = emu.dyn
    lm = dyn.by_name(path) if dyn else None
    if lm is None and dyn is not None:
        lm = dyn.load_runtime(path)
    if lm is None:
        emu.log(f"  [import] sceKernelLoadStartModule '{path}' -> not found")
        return 0x80020002              # SCE_KERNEL_ERROR_ENOENT (negative -> NULL)
    if r9:
        uc.mem_write(r9, struct.pack("<i", 0))   # module-start result
    emu.log(f"  [import] sceKernelLoadStartModule '{path}' -> handle {lm.handle} ({lm.name})")
    return lm.handle


def _imp_getcwd(emu, uc):
    # __getcwd(buf, size): the syscall form - 0 on success with the path in buf
    # (the generic stub returned 0 without writing, leaving buf uninitialised).
    buf, size = emu.hle.args(uc)[:2]
    cwd = b"/app0\0"
    if not buf or size < len(cwd):
        return 0xFFFFFFFFFFFFFFFF
    uc.mem_write(buf, cwd)
    return 0


def _imp_readlink(emu, uc):
    # readlink(path, buf, size): nothing in the emulated tree is a symlink ->
    # -1 (EINVAL), so callers treat the path as already canonical instead of
    # reading a "0-byte" link target.
    return 0xFFFFFFFFFFFFFFFF


BUILTIN_IMPORTS = {
    "Qsxbb+aty0U": ("__getcwd", _imp_getcwd),
    "pd02UI9TbOA": ("readlink", _imp_readlink),
    "QyrxcdBrb0M": ("sceKernelGetEqueueId", _imp_eqid_from_handle),
    "Y1nEpkCieOY": ("sceKernelLoadStartModule", _imp_load_start_module),
}


def _up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


def _down(x, a=PAGE):
    return x & ~(a - 1)


class LoadedModule:
    """Facts about one mapped module, for the dynlib syscalls."""

    def __init__(self, handle, mod):
        self.handle = handle
        self.mod = mod
        self.name = mod.name
        self.base = mod.base
        e = mod.elf
        self.entry = mod.base + e.entry if e.entry else 0
        segs = [s for s in e.segments if s.type in (PT_LOAD, PT_SCE_RELRO) and s.memsz]
        self.segments = [(mod.base + s.vaddr, s.memsz, s.flags) for s in segs]
        self.lo = min(mod.base + _down(s.vaddr) for s in segs)
        self.hi = max(mod.base + _up(s.vaddr + s.memsz) for s in segs)
        tls = next((s for s in e.segments if s.type == PT_TLS), None)
        self.tls = tls
        self.tls_index = 0           # 1-based module TLS index (0 = none)
        self.tls_offset = 0          # static TLS offset below the TCB
        self.dyn = mod.dyn_vals
        self.init = mod.base + self.dyn["INIT"] if "INIT" in self.dyn else 0
        self.fini = mod.base + self.dyn["FINI"] if "FINI" in self.dyn else 0
        mp = next((s for s in e.segments if s.type in (PT_SCE_MODULE_PARAM, PT_SCE_PROCPARAM)),
                  None)
        self.module_param = mod.base + mp.vaddr if mp else 0
        eh = next((s for s in e.segments if s.type == PT_GNU_EH_FRAME), None)
        self.eh_frame_hdr = (mod.base + eh.vaddr, eh.memsz) if eh else (0, 0)
        # .eh_frame starts where the header's eh_frame_ptr points (pcrel sdata4)
        self.eh_frame = (0, 0)
        if eh and e.data[eh.offset + 1] == 0x1B:
            rel = struct.unpack_from("<i", e.data, eh.offset + 4)[0]
            start = eh.vaddr + 4 + rel
            self.eh_frame = (mod.base + start, max(0, eh.vaddr - start))

    def __repr__(self):
        return "<%s @%#x-%#x>" % (self.name, self.lo, self.hi)


class DynamicProcess:
    def __init__(self, emu, path):
        self.emu = emu
        self.path = path
        self.ld = DynamicLinker(self._find_root(emu.fw_root), log=lambda *a: None)
        self.modules = []            # LoadedModule, load order (exe first)
        self.stubs = {}              # stub address -> NID
        self.unresolved = {}         # NID -> stub address
        self.stub_next = STUB_BASE

    @staticmethod
    def _find_root(start):
        """Walk up from `start` to the firmware root (the folder holding
        system/common/lib), where the shared libraries are searched."""
        d = os.path.abspath(start)
        while True:
            if os.path.isdir(os.path.join(d, "system", "common", "lib")):
                return d
            parent = os.path.dirname(d)
            if parent == d:
                return start
            d = parent

    # ------------------------------------------------------------ build
    def build(self):
        emu = self.emu
        exe = self.ld.load(self.path)
        self.ld.link()
        for i, m in enumerate(self.ld.modules):
            self.modules.append(LoadedModule(i + 1, m))
        emu.log(f"  dynamic process: {len(self.modules)} modules")
        self._assign_tls()
        for lm in self.modules:
            self._map(lm)
        emu.vm.map(STUB_BASE, STUB_SIZE)
        emu.uc.mem_write(STUB_BASE, b"\xC3" * STUB_SIZE)      # each stub: ret
        counts = {"relative": 0, "symbol": 0, "stub": 0, "tls": 0}
        for lm in self.modules:
            self._relocate(lm, counts)
        emu.log(f"  relocations: {counts['relative']} relative, {counts['symbol']} symbol, "
                f"{counts['tls']} TLS, {counts['stub']} -> stubs ({len(self.unresolved)} NIDs)")
        self.exe = self.modules[0]
        pp = next((s for s in self.exe.mod.elf.segments if s.type == PT_SCE_PROCPARAM), None)
        self.proc_param = (self.exe.base + pp.vaddr, pp.memsz) if pp else None
        self.libkernel = next((m for m in self.modules
                               if m.name.startswith("libkernel")), None)
        if self.libkernel is None or not self.libkernel.entry:
            raise RuntimeError("libkernel (the interpreter) was not loaded")
        return self

    def _assign_tls(self):
        """Static TLS, FreeBSD variant II: each module's block sits below the
        TCB; module 1 is the closest. Offsets are positive distances."""
        off = 0
        idx = 0
        for lm in self.modules:
            if lm.tls is None:
                continue
            idx += 1
            lm.tls_index = idx
            align = max(lm.tls.align or 1, 16)
            off = _up(off + lm.tls.memsz, align)
            lm.tls_offset = off
        self.tls_static_size = _up(off, 64)

    def _map(self, lm):
        emu = self.emu
        e = lm.mod.elf
        # union of pages touched by this module's segments
        ranges = []
        for s in e.segments:
            if s.type in (PT_LOAD, PT_SCE_RELRO) and s.memsz:
                ranges.append((lm.base + _down(s.vaddr), lm.base + _up(s.vaddr + s.memsz)))
        ranges.sort()
        merged = []
        for a, b in ranges:
            if merged and a <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], b))
            else:
                merged.append((a, b))
        for a, b in merged:
            emu.vm.map(a, b - a)
            if getattr(emu, "native", None) is not None:
                emu.native.pages_forget(a, b)      # new code: rescan for VEX
        for s in e.segments:
            if s.type in (PT_LOAD, PT_SCE_RELRO) and s.filesz:
                emu.uc.mem_write(lm.base + s.vaddr, e.data[s.offset:s.offset + s.filesz])
        emu.log(f"  map {lm.name:<28} {lm.lo:#012x}-{lm.hi:#012x}"
                f"{'  tls#%d' % lm.tls_index if lm.tls_index else ''}")
        self._module_quirks(lm)

    # ---- per-module behavioural fixups ---------------------------------
    def _module_quirks(self, lm):
        """Model single-process realities that a console splits across
        processes. Keyed by module name so they install when (and only when)
        the module is mapped - including runtime-loaded ones."""
        name = lm.name.lower()
        if name.startswith("libscenpmanager"):
            self._np_shared_heap(lm)
        elif name.startswith("libscenputility"):
            self._np_utility_once(lm)
        elif name.startswith("libmonosgen"):
            self._mono_icall_stub(lm)
        elif name.startswith("libsceaudioout"):
            self._audioout_null_client(lm)

    def _audioout_null_client(self, lm):
        """libSceAudioOut keeps its IPMI client to the audio server in a global
        (+0x1c320) that only sceAudioOutInit fills in; every export loads it and
        calls client->invokeSyncMethod through the vtable (+0x58). The library
        has no module_start, so nothing initialises it until a program calls
        sceAudioOutInit -- and the shell's voice-recognition init
        (shell_ui/recognition/voice Initialize -> export rho9DH-0ehs) calls into
        audio before that ever happens (PSM's sound init, which would call it,
        fails first on the unmodelled /dev/ajm decoder device). With the global
        NULL that is `mov rax,[0]`: a crash, where the library on a console would
        hand back an error.

        Pre-install a stub client whose every vtable slot returns an AudioOut
        error, so audio calls made with no audio server fail cleanly ("no audio
        device") instead of killing the process. sceAudioOutInit, if it is ever
        called, overwrites the global with a real client."""
        emu = self.emu
        page = emu.map_anon(0x1000)
        if page == 0xFFFFFFFFFFFFFFFF:
            return
        ERR = 0x80260001                       # generic 0x8026xxxx AudioOut error
        stub, vtbl, obj = page + 0x200, page + 0x100, page
        emu.uc.mem_write(stub, b"\xb8" + struct.pack("<I", ERR) + b"\xc3")   # mov eax,ERR; ret
        emu.uc.mem_write(vtbl, struct.pack("<32Q", *([stub] * 32)))
        emu.uc.mem_write(obj, struct.pack("<Q", vtbl))
        emu.uc.mem_write(lm.base + 0x1C320, struct.pack("<Q", obj))
        emu.log("  [audio] libSceAudioOut: no audio server -> stub IPMI client "
                f"(calls fail with {ERR:#x} instead of crashing)")

    def _mono_icall_stub(self, lm):
        """libmonosgen g_errors ("Unregistered icall '%s'") and aborts when
        managed code calls an [InternalCall] method whose native implementation
        was never registered via mono_add_internal_call. On a console the Sce
        native libraries register their icalls at startup; psemu runs the
        managed side but not every native registrant, so some icalls (e.g.
        Sce.Cdlg.Framework.Util.NativeFunc:GetCompileSdkVersion, reached deep in
        the system-UI init) are missing and abort the whole process.

        mono_lookup_internal_call (+0x24200) puts the resolved icall pointer in
        r14 and, at +0x24289, a NULL r14 falls through to the g_error. Point a
        NULL r14 at a return-0 guest stub instead, so the call returns 0 rather
        than aborting. The stub's value may be wrong for a given icall and show
        up as odd behaviour later, but it turns a hard abort into forward
        progress -- the right fix is to register the real icalls."""
        emu = self.emu
        from unicorn.x86_const import UC_X86_REG_R14, UC_X86_REG_RBX
        stub = getattr(emu, "_icall_stub_addr", 0)
        if not stub:
            stub = emu.map_anon(0x1000)
            if stub == 0xFFFFFFFFFFFFFFFF:
                return
            # xor eax,eax; xor edx,edx; ret  -> returns 0 (int / ptr / void)
            emu.uc.mem_write(stub, b"\x31\xc0\x31\xd2\xc3")
            emu._icall_stub_addr = stub
        seen = emu.__dict__.setdefault("_icall_stubbed", set())

        def icall_stub(emu, uc):
            if uc.reg_read(UC_X86_REG_R14) == 0:
                uc.reg_write(UC_X86_REG_R14, emu._icall_stub_addr)
                try:
                    meth = struct.unpack("<Q", bytes(uc.mem_read(
                        uc.reg_read(UC_X86_REG_RBX) + 0x20, 8)))[0]
                except Exception:
                    meth = 0
                if meth not in seen:
                    seen.add(meth)
                    emu.log(f"  [mono] unregistered icall (MonoMethod {meth:#x})"
                            f" -> return-0 stub")
            return None

        emu.hle.register(lm.base + 0x24289, icall_stub,
                         name="mono_icall_stub", mode="fixup")

    def _np_utility_once(self, lm):
        """libSceNpUtility's module start (+0x1acc0) calls sceNpUtilityInit
        (+0x1aa80) itself unless its start argument's first byte says not to;
        psemu starts libraries with (0, NULL), so it does. ScePsnCore then
        calls sceNpUtilityInit explicitly, and its sceNpLookupInit (+0xb150)
        finds its "initialised" byte (+0x2cbac) set and returns
        ALREADY_INITIALIZED (0x80550701) - "Failed to init PsnCore", then the
        shell null-derefs at SceShellCore+0x62af44. Same single-process
        collision as the NP heap: the library is up, so a second
        sceNpUtilityInit reports success instead of re-running."""
        emu = self.emu
        base = lm.base
        LOOKUP_INITED = base + 0x2cbac         # sceNpLookupInit's guard byte

        def utility_init_once(emu, uc):
            if bytes(uc.mem_read(LOOKUP_INITED, 1))[0]:
                emu.log("  [np] sceNpUtilityInit again: already up -> 0")
                return 0
            return None

        emu.hle.register(base + 0x1aa80, utility_init_once,
                         name="np_utility_init_once", mode="guard")

    def _np_shared_heap(self, lm):
        """libSceNpManager's NP global-heap init (sub_13e10) is a process-wide
        singleton guarded by a flag at base+0x42b84. On a console the NP
        background service and the VSH each initialise NP in their own address
        space; psemu runs the whole system in one process, so NP's module-start
        auto-init (sceNpManagerPrxStart, a 0x10000 heap) and the VSH's explicit
        sceNpManagerVshInit (a 0x60000 heap) collide on that one flag: VshInit
        gets ALREADY_INITIALIZED (0x80550001), ScePsnCore reports "Failed to
        init PsnCore" and the shell null-derefs at SceShellCore+0x62af44.

        Model the single shared NP heap faithfully instead of forcing the
        guard: size the heap for the largest consumer (the VSH) the first time
        it is created, and let later initialisers succeed against the heap that
        already exists rather than treating "already initialised" as fatal.
        Other NP modules whose boot-time init allocates from this heap
        (libSceNpSns, libSceNpUtility, ...) then find it present and big enough.
        """
        from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RBX, UC_X86_REG_R14
        emu = self.emu
        base = lm.base
        FLAG = base + 0x42b84          # meminit's "initialised" guard (==1 once done)
        VSH_HEAP = 0x60000             # size sceNpManagerVshInit asks for

        def _flag_set(uc):
            return struct.unpack("<I", bytes(uc.mem_read(FLAG, 4)))[0] == 1

        # sub_13e10 entry: on the first (creating) call, grow the heap to the
        # VSH size so later NP allocations don't exhaust a 0x10000 pool.
        def meminit_size(emu, uc):
            if not _flag_set(uc) and uc.reg_read(UC_X86_REG_RDI) < VSH_HEAP:
                uc.reg_write(UC_X86_REG_RDI, VSH_HEAP)

        # sub_13e10 +0x33 (`je already_init`, ebx==0x80550001): when the heap is
        # already there, return success (0) instead of ALREADY_INITIALIZED.
        def meminit_idempotent(emu, uc):
            if _flag_set(uc):
                uc.reg_write(UC_X86_REG_RBX, 0)

        emu.hle.register(base + 0x13e10, meminit_size,
                         name="np_heap_size", mode="fixup")
        emu.hle.register(base + 0x13e43, meminit_idempotent,
                         name="np_heap_idempotent", mode="fixup")

        # sceNpManagerIpcServerInit (sub_eb60) is the same story: module-start's
        # PrxStart brings up the NP IPC server (guard at base+0x42a64) and the
        # VSH's ScePsnCore brings it up again, getting 0x80559d00 and crashing.
        # The server already exists, so make the re-init report success. 0xebba
        # (`jmp exit`) is only reached on the already-initialised branch.
        IPC_FLAG = base + 0x42a64
        def ipcserver_idempotent(emu, uc):
            if struct.unpack("<I", bytes(uc.mem_read(IPC_FLAG, 4)))[0] == 1:
                uc.reg_write(UC_X86_REG_R14, 0)           # return value (r14d -> rax)
        emu.hle.register(base + 0xebba, ipcserver_idempotent,
                         name="np_ipcserver_idempotent", mode="fixup")
        emu.log("  [np] shared NP heap+IPC server: size->VSH, re-init idempotent "
                f"(heap flag @ {FLAG:#x})")

    def _stub(self, nid):
        a = self.unresolved.get(nid)
        if a is None:
            a = self.stub_next
            self.stub_next += 1
            self.unresolved[nid] = a
            self.stubs[a] = nid

            builtin = BUILTIN_IMPORTS.get(nid)
            if builtin is not None:
                name, handler = builtin
                self.emu.hle.register(a, handler, name="import:" + name)
            else:
                def unresolved_import(emu, uc, nid=nid):
                    emu.log(f"  [import] unresolved NID {nid} called -> returning 0")
                    return 0
                self.emu.hle.register(a, unresolved_import, name="import:" + nid)
        return a

    def _relocate(self, lm, counts):
        uc = self.emu.uc
        m = lm.mod
        exports = self.ld.global_exports
        for _tbl, r_off, r_info, r_add in m.relocations():
            rtype = r_info & 0xFFFFFFFF
            sidx = r_info >> 32
            where = lm.base + r_off
            if rtype == R_X86_64_RELATIVE:
                val = lm.base + r_add
                counts["relative"] += 1
            elif rtype in (R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT):
                name, value, _info = m._sym(sidx)
                nid = m._nid(name)
                if value and sidx:                      # defined locally
                    target = lm.base + value
                else:
                    target = exports.get(nid)
                if target is None:
                    target = self._stub(nid)
                    counts["stub"] += 1
                else:
                    counts["symbol"] += 1
                val = target + (r_add if rtype == R_X86_64_64 else 0)
            elif rtype == R_X86_64_DTPMOD64:
                val = lm.tls_index or 1
                counts["tls"] += 1
            elif rtype == R_X86_64_DTPOFF64:
                name, value, _info = m._sym(sidx)
                val = value + r_add
                counts["tls"] += 1
            elif rtype == R_X86_64_TPOFF64:
                name, value, _info = m._sym(sidx)
                val = (value + r_add - lm.tls_offset) & 0xFFFFFFFFFFFFFFFF
                counts["tls"] += 1
            else:
                self.emu.log(f"  [reloc] {lm.name}: unsupported type {rtype} at {where:#x}")
                continue
            try:
                uc.mem_write(where, struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF))
            except Exception:
                self.emu.log(f"  [reloc] {lm.name}: type {rtype} target {where:#x} "
                             f"(offset {r_off:#x}) is outside the mapped image")

    # ------------------------------------------------------------ start
    def initial_stack(self, rsp, argv):
        """FreeBSD process stack for the interpreter: argc, argv, envp, auxv."""
        uc = self.emu.uc
        exe = self.exe
        e = exe.mod.elf
        strings = []
        sp = rsp
        for s in argv + [self.path_guest()]:
            b = s.encode() + b"\x00"
            sp -= len(b)
            uc.mem_write(sp, b)
            strings.append(sp)
        argv_ptrs, execpath = strings[:-1], strings[-1]
        # guest environment: PSEMU_GUEST_ENV="A=1;B=2" (experiments, e.g. Mono tuning)
        env_ptrs = []
        for kv in [x for x in os.environ.get("PSEMU_GUEST_ENV", "").split(";") if "=" in x]:
            b = kv.encode() + b"\x00"
            sp -= len(b)
            uc.mem_write(sp, b)
            env_ptrs.append(sp)
        sp &= ~0xF
        phoff = struct.unpack_from("<Q", e.data, 0x20)[0]      # e_phoff
        phdr = exe.base + phoff
        aux = [(AT_PHDR, phdr), (AT_PHENT, 56), (AT_PHNUM, len(e.segments)),
               (AT_PAGESZ, PAGE), (AT_BASE, self.libkernel.base), (AT_FLAGS, 0),
               (AT_ENTRY, exe.entry), (AT_EXECPATH, execpath), (AT_NULL, 0)]
        words = [len(argv_ptrs)] + argv_ptrs + [0] + env_ptrs + [0]   # argc argv NULL envp.. NULL
        for k, v in aux:
            words += [k, v]
        blob = struct.pack("<%dQ" % len(words), *words)
        sp = (sp - len(blob)) & ~0xF
        uc.mem_write(sp, blob)
        return sp

    def path_guest(self):
        return "/" + os.path.relpath(self.path, self.emu.fw_root).replace("\\", "/")

    def module_at(self, addr):
        for lm in self.modules:
            if lm.lo <= addr < lm.hi:
                return lm
        return None

    def by_name(self, path):
        """Find a loaded module by (guest) path or file name; .prx/.sprx agnostic."""
        base = os.path.basename(path.replace("\\", "/")).lower()
        stem = base.rsplit(".", 1)[0]
        for lm in self.modules:
            n = lm.name.lower()
            if n == base or n.rsplit(".", 1)[0] == stem:
                return lm
        return None

    def by_handle(self, h):
        if 1 <= h <= len(self.modules):
            return self.modules[h - 1]
        return None


def _load_runtime(self, path):
    """sys_dynlib_load_prx for a module that is not loaded yet: load it (and
    any new dependencies) at fresh bases, map, relocate, and return it.
    Runtime-loaded modules get a TLS index but no static TLS slot; libkernel
    allocates their TLS dynamically from the info get_info_ex reports."""
    emu = self.emu
    f = emu.app0_file(path) if hasattr(emu, "app0_file") else None
    if f is None:
        f = self.ld._resolve_lib_file(os.path.basename(path.replace("\\", "/")))
    if f is None:
        cand = os.path.join(self.ld.fw_root, path.lstrip("/").replace("/", os.sep))
        f = cand if os.path.isfile(cand) else None
    if f is None:
        return None
    before = len(self.ld.modules)
    self.ld.load(f, os.path.basename(f))
    new = self.ld.modules[before:]
    if not new:
        return self.by_name(path)
    for m in new:
        for k, v in m.exports.items():
            self.ld.global_exports.setdefault(k, v)
    added = []
    next_tls = max((lm.tls_index for lm in self.modules), default=0)
    for m in new:
        lm = LoadedModule(len(self.modules) + 1, m)
        if lm.tls is not None:
            next_tls += 1
            lm.tls_index = next_tls
        self.modules.append(lm)
        added.append(lm)
        self._map(lm)
    counts = {"relative": 0, "symbol": 0, "stub": 0, "tls": 0}
    for lm in added:
        self._relocate(lm, counts)
    emu.log(f"  [dynlib] runtime-loaded {', '.join(lm.name for lm in added)}: "
            f"{counts['symbol']} symbols, {counts['stub']} -> stubs")
    return self.by_name(path) or added[0]


DynamicProcess.load_runtime = _load_runtime
