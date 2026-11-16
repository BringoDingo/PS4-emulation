"""ORBIS dynlib_* syscalls: the kernel side of PS4 dynamic linking.

libkernel (the program interpreter) relies on the kernel to load and relocate
modules and then queries it for module lists and per-module information to
run initialisers, resolve symbols and set up TLS. psemu has already done the
loading in dynproc.py; these handlers report that state back in the layouts
libkernel expects. Layouts are filled in as libkernel's own code shows which
fields it reads (each handler documents what is known).
"""
import struct

# number -> name, merged into syscalls.SYSCALLS
DYNLIB_SYSCALLS = {
    591: "dynlib_dlsym", 592: "dynlib_get_list", 593: "dynlib_get_info",
    594: "dynlib_load_prx", 595: "dynlib_unload_prx", 596: "dynlib_do_copy_relocations",
    597: "dynlib_prepare_dlclose", 598: "dynlib_get_proc_param",
    599: "dynlib_process_needed_and_relocate", 601: "mdbg_service",
    608: "dynlib_get_info_ex", 649: "dynlib_get_obj_member",
    659: "dynlib_get_list2", 660: "dynlib_get_info2",
}

EINVAL, ESRCH, ENOENT = 22, 3, 2


class DynlibSyscalls:
    """Mixin for SyscallDispatcher (needs self.emu, self._args, self._ret)."""

    def _dyn(self):
        return getattr(self.emu, "dyn", None)

    def _w64(self, uc, addr, *vals):
        uc.mem_write(addr, struct.pack("<%dQ" % len(vals), *vals))

    def _w32(self, uc, addr, *vals):
        uc.mem_write(addr, struct.pack("<%dI" % len(vals), *vals))

    # 599: everything is already loaded and relocated by psemu
    def sys_dynlib_process_needed_and_relocate(self, uc):
        dyn = self._dyn()
        if dyn is None:
            return self._ret(uc, 0)
        self.emu.log(f"  [dynlib] process_needed_and_relocate: {len(dyn.modules)} modules "
                     f"already loaded and relocated")
        self._ret(uc, 0)

    # 598: (void **out_addr, uint64_t *out_size) -> executable's sceProcParam
    def sys_dynlib_get_proc_param(self, uc):
        dyn = self._dyn()
        out_addr, out_size = self._args(uc)[:2]
        if dyn is None or dyn.proc_param is None:
            return self._ret(uc, EINVAL, error=True)
        addr, size = dyn.proc_param
        self._w64(uc, out_addr, addr)
        self._w64(uc, out_size, size)
        self.emu.log(f"  [dynlib] get_proc_param -> {addr:#x} ({size:#x} bytes)")
        self._ret(uc, 0)

    # ---------------------------------------------------------------- helpers
    def _cstr(self, uc, addr, maxlen=1024):
        raw = bytes(uc.mem_read(addr, maxlen))
        end = raw.find(b"\x00")
        return raw[:end if end >= 0 else maxlen].decode("latin1", "replace")

    def _module(self, uc, handle):
        dyn = self._dyn()
        return dyn.by_handle(handle) if dyn else None

    # 594: (const char *path, int flags, int *handle_out, ...) -> handle
    def sys_dynlib_load_prx(self, uc):
        dyn = self._dyn()
        path_p, flags, out = self._args(uc)[:3]
        path = self._cstr(uc, path_p)
        lm = dyn.by_name(path) if dyn else None
        if lm is None and dyn is not None:
            lm = dyn.load_runtime(path)
        if lm is None:
            self.emu.log(f"  [dynlib] load_prx '{path}' -> not found in the firmware")
            return self._ret(uc, ENOENT, error=True)
        if out:
            self._w32(uc, out, lm.handle)
        self.emu.log(f"  [dynlib] load_prx '{path}' -> handle {lm.handle} ({lm.name})")
        self._ret(uc, 0)

    # 595
    def sys_dynlib_unload_prx(self, uc):
        self._ret(uc, 0)

    # 596: copy relocations were applied at load time
    def sys_dynlib_do_copy_relocations(self, uc):
        self._ret(uc, 0)

    # 649: (handle, index, void **out): 1 = init proc, 2 = fini proc,
    #      8 = sceModuleParam / sceProcParam address (first qword = its size)
    def sys_dynlib_get_obj_member(self, uc):
        handle, index, out = self._args(uc)[:3]
        lm = self._module(uc, handle)
        if lm is None:
            return self._ret(uc, ESRCH, error=True)
        val = {1: lm.init, 2: lm.fini, 8: lm.module_param}.get(index, 0)
        self._w64(uc, out, val)
        self._ret(uc, 0)

    # 592: (int *handles, size_t max, size_t *count)
    def sys_dynlib_get_list(self, uc):
        dyn = self._dyn()
        out, maxn, count = self._args(uc)[:3]
        hs = [m.handle for m in dyn.modules][:maxn] if dyn else []
        if hs:
            self._w32(uc, out, *hs)
        self._w64(uc, count, len(hs))
        self._ret(uc, 0)

    sys_dynlib_get_list2 = sys_dynlib_get_list

    def _segments(self, lm):
        segs = []
        for addr, size, flags in lm.segments[:4]:
            prot = (1 if flags & 4 else 0) | (2 if flags & 2 else 0) | (4 if flags & 1 else 0)
            segs.append((addr, size, prot))
        return segs

    # 593: (handle, SceKernelModuleInfo *info): st_size, name[256],
    #      segments[4] {u64 addr, u32 size, s32 prot}, u32 count, fingerprint[20]
    def sys_dynlib_get_info(self, uc):
        handle, info = self._args(uc)[:2]
        lm = self._module(uc, handle)
        if lm is None:
            return self._ret(uc, ESRCH, error=True)
        buf = bytearray(0x160)
        struct.pack_into("<Q", buf, 0, 0x160)
        name = lm.name.encode()[:255]
        buf[8:8 + len(name)] = name
        segs = self._segments(lm)
        for i, (a, sz, p) in enumerate(segs):
            struct.pack_into("<QIi", buf, 0x108 + 16 * i, a, sz, p)
        struct.pack_into("<I", buf, 0x148, len(segs))
        uc.mem_write(info, bytes(buf))
        self._ret(uc, 0)

    sys_dynlib_get_info2 = sys_dynlib_get_info

    # 608: (handle, flags, SceKernelModuleInfoEx *info) - layout as in
    #      shadPS4's OrbisKernelModuleInfoEx (0x1A8 bytes)
    def sys_dynlib_get_info_ex(self, uc):
        handle, _flags, info = self._args(uc)[:3]
        lm = self._module(uc, handle)
        if lm is None:
            return self._ret(uc, ESRCH, error=True)
        buf = bytearray(0x1A8)
        struct.pack_into("<Q", buf, 0, 0x1A8)
        name = lm.name.encode()[:255]
        buf[8:8 + len(name)] = name
        struct.pack_into("<iI", buf, 0x108, lm.handle, lm.tls_index)
        if lm.tls_index:
            t = lm.tls
            struct.pack_into("<QIIII", buf, 0x110, lm.base + t.vaddr, t.filesz, t.memsz,
                             lm.tls_offset, max(t.align, 1))
        struct.pack_into("<QQ", buf, 0x128, lm.init, lm.fini)
        struct.pack_into("<QQII", buf, 0x148, lm.eh_frame_hdr[0], lm.eh_frame[0],
                         lm.eh_frame_hdr[1], lm.eh_frame[1])
        segs = self._segments(lm)
        for i, (a, sz, p) in enumerate(segs):
            struct.pack_into("<QIi", buf, 0x160 + 16 * i, a, sz, p)
        struct.pack_into("<I", buf, 0x1A0, len(segs))
        uc.mem_write(info, bytes(buf))
        self._ret(uc, 0)

    # 591: (handle, const char *symbol, void **out) - by name or NID
    def sys_dynlib_dlsym(self, uc):
        handle, name_p, out = self._args(uc)[:3]
        dyn = self._dyn()
        name = self._cstr(uc, name_p, 256)
        lm = self._module(uc, handle)
        # strictly per module: libkernel probes every module for e.g.
        # module_start and must not get another module's symbol
        exports = lm.mod.exports if lm else {}
        # An 11-char name may be a pre-encoded NID or a plain symbol that is just
        # 11 characters long (e.g. Mono AOT's "call_filter"). Try the raw key
        # first, then fall back to the hashed NID so both resolve.
        addr = None
        key = name
        if len(name) == 11 and " " not in name:
            addr = exports.get(name)
        if addr is None:
            key = nid(name)
            addr = exports.get(key)
        if addr is None:
            self.emu.log(f"  [dynlib] dlsym '{name}' ({key}) -> not found")
            return self._ret(uc, ENOENT, error=True)
        self._w64(uc, out, addr)
        self._ret(uc, 0)


_NID_SALT = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")


def nid(name):
    """PS4 symbol NID: base64 of the first 8 bytes of SHA-1(name + salt)."""
    import base64
    import hashlib
    d = hashlib.sha1(name.encode() + _NID_SALT).digest()
    v = struct.unpack("<Q", d[:8])[0]
    return base64.b64encode(struct.pack(">Q", v)).decode().rstrip("=").replace("/", "-")
