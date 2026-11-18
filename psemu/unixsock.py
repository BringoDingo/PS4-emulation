"""AF_UNIX stream sockets, and the system servers that listen on them.

Several PS4 system libraries talk to a server process over a UNIX-domain
socket instead of IPMI. libSceComposite is one: sceCompositorInit's
sendRequest() opens socket(AF_UNIX, SOCK_STREAM), connects to the
"GnmCompositor" endpoint, writes a 16-byte request header + body, then reads
a 16-byte reply header + body. psemu does not run that server process, so
without this module `socket` fell through to the generic "pretend success"
stub (returning fd 0), the client wrote its request to stdin, and then read
an uninitialised reply buffer off its own stack -- a garbage chunk count made
the compositor walk off the end of the stack.

A `UnixSocket` is a Device (fd -> device in SyscallDispatcher.devs): the
client's writes are buffered; once a whole request (header + body) has been
written, the server named by connect() answers it and the reply is queued for
the client's reads. Servers are small Python objects registered by endpoint
name in SyscallDispatcher.unix_servers.
"""
import os
import struct

from .devices import Device

ECONNREFUSED = 61           # FreeBSD errno


class UnixSocket(Device):
    """One client end of a UNIX stream socket, served by an in-process stand-in
    for the system process that would own the listening end."""

    def __init__(self, sc):
        super().__init__(sc, "unix-socket")
        self.server = None
        self.endpoint = ""
        self.rx = bytearray()       # request bytes the client has written so far
        self.tx = bytearray()       # reply bytes waiting for the client to read
        self.zero_fill = False      # reads past the reply return zeros (see read)

    def connect(self, path):
        """Attach to the server for `path`; returns 0 or a positive errno."""
        name = path.rsplit("/", 1)[-1]
        srv = self.sc.unix_servers.get(name)
        self.path = f"unix:{name}"
        if srv is None:
            self.log(f"connect '{path}': no such server -> ECONNREFUSED")
            return ECONNREFUSED
        self.server, self.endpoint = srv, name
        self.log(f"connect '{path}' -> {type(srv).__name__}")
        return 0

    def write(self, uc, buf, n):
        self.rx += self.rd(uc, buf, n) if n else b""
        # Requests are framed as a 16-byte header whose u32 at +8 is the body size.
        while len(self.rx) >= 16:
            size = struct.unpack_from("<I", self.rx, 8)[0]
            if len(self.rx) < 16 + size:
                break
            hdr, body = bytes(self.rx[:16]), bytes(self.rx[16:16 + size])
            del self.rx[:16 + size]
            if self.server is None:
                continue
            reply, self.zero_fill = self.server.handle(self, uc, hdr, body)
            self.tx += reply
        return n

    def read(self, uc, buf, n):
        chunk = bytes(self.tx[:n])
        del self.tx[:len(chunk)]
        if not chunk and self.zero_fill and n:
            # An unmodelled request: the client reads its own fixed-size reply
            # body and cannot be told its length here, so an "empty success"
            # reply is zeros (matching how unmodelled IPMI methods answer).
            chunk = bytes(n)
        if chunk:
            uc.mem_write(buf, chunk)
        return len(chunk)


# ---------------------------------------------------------------- GnmCompositor

# sceCompositorInit's request header (libSceComposite .rodata @0x6310): cmd=1,
# body 0x1c bytes. Matched whole -- a later request also starts with cmd 1.
INIT_HEADER = bytes.fromhex("01000000000000001c00000000000000")
CHUNK = 0x200000                # the compositor maps its shared memory in 2MB chunks
INIT_REPLY_SIZE = 0x10B8
# Each shared window is a 512MB slice of the client's address space; the client
# batch-maps one CHUNK per direct-memory offset the server hands out into it.
WINDOW_SYSTEM = 0x30_0000_0000
WINDOW_VIDEO = WINDOW_SYSTEM + 0x2000_0000
# sceCompositorMapAnotherProcess maps a second view: distinct windows, so it
# never overwrites the first client's mappings.
WINDOW2_SYSTEM = WINDOW_SYSTEM + 0x4000_0000
WINDOW2_VIDEO = WINDOW2_SYSTEM + 0x2000_0000
# libSceComposite @+0x3e30: header qword {cmd=1, subcmd=0x4000}
MAP_ANOTHER_PROCESS = bytes.fromhex("0100000000400000")
DMEM_BASE = 0x4000_0000         # first direct-memory offset the stand-in "allocates"


class GnmCompositorServer:
    """Stand-in for the GnmCompositor system process (the console's display
    compositor service). It answers libSceComposite's requests.

    sceCompositorInit(systemShared, videoShared, videoPrivate, processOrder)
    sends {u32 order; u32 systemSharedBytes; u32 videoBytes}; the reply body
    (0x10b8 bytes, decoded from libSceComposite's sceCompositorInit @+0x2ef0) is
        +0x00 u64   base of the system-shared window   (client address space)
        +0x08 u64   base of the video window
        +0x10 u32   number of 2MB chunks in the system-shared window
        +0x14 u32   number of 2MB chunks in the video window
        +0x1c u16   flags
        +0x34 char[] name of a shm control block (0x4000 bytes) the client
                     opens, unlinks and maps as "CompositorControl"
        +0xb8  u64[256]  direct-memory offset of each system-shared chunk
        +0x8b8 u64[256]  direct-memory offset of each video chunk
    and the reply header is {cmd, 0, body size, status 0}."""

    CONTROL_SHM = "/SceCompositorControl"

    def __init__(self, sc):
        self.sc = sc
        self.dmem_next = DMEM_BASE
        self.seen = set()
        self.ring = CompositorRing(self)
        # chunk counts the first client asked for, reused for MapAnotherProcess
        self.n_sys, self.n_vid = 7, 64
        self.chunks = None          # (system offsets, video offsets), allocated once

    def _dmem(self, count):
        offs = []
        for _ in range(count):
            offs.append(self.dmem_next)
            self.dmem_next += CHUNK
        return offs

    def _window_reply(self, hdr, n_sys, n_vid, base_sys, base_vid, prot, with_control):
        """The 0x10b8-byte reply body shared by Init and MapAnotherProcess:
        two windows (base + chunk count) and one direct-memory offset per
        chunk. `prot` (+0x30) is what MapAnotherProcess passes to its mapper."""
        reply = bytearray(INIT_REPLY_SIZE)
        struct.pack_into("<QQ", reply, 0x00, base_sys, base_vid)
        struct.pack_into("<II", reply, 0x10, n_sys, n_vid)
        struct.pack_into("<I", reply, 0x30, prot)
        if with_control:
            name = self.CONTROL_SHM.encode() + b"\0"
            reply[0x34:0x34 + len(name)] = name
        # The chunks are one physical allocation made at Init; later clients
        # (MapAnotherProcess) get their own virtual windows onto the SAME
        # direct-memory offsets, so allocate only once per chunk count.
        if self.chunks is None or (len(self.chunks[0]), len(self.chunks[1])) != (n_sys, n_vid):
            self.chunks = (self._dmem(n_sys), self._dmem(n_vid))
        for i, off in enumerate(self.chunks[0]):
            struct.pack_into("<Q", reply, 0xB8 + 8 * i, off)
        for i, off in enumerate(self.chunks[1]):
            struct.pack_into("<Q", reply, 0x8B8 + 8 * i, off)
        cmd = struct.unpack_from("<I", hdr, 0)[0]
        return struct.pack("<IIII", cmd, struct.unpack_from("<I", hdr, 4)[0],
                           INIT_REPLY_SIZE, 0) + bytes(reply)

    def handle(self, sock, uc, hdr, body):
        """Answer one request -> (reply bytes, zero_fill_for_reads_past_it)."""
        cmd = struct.unpack_from("<I", hdr, 0)[0]
        log = self.sc.emu.log
        # Every request is logged once per distinct header/body size, so the
        # protocol can be decoded from a run (the header's first dword alone is
        # not a unique id: a second request also carried 1).
        key = (hdr, len(body))
        if key not in self.seen:
            self.seen.add(key)
            log(f"  [compositor] request hdr={hdr.hex()} body={len(body)}B {body[:48].hex()}")
        if hdr == INIT_HEADER:
            order, sys_bytes, vid_bytes = struct.unpack_from("<III", body.ljust(12, b"\0"))
            self.n_sys = min(256, (sys_bytes + CHUNK - 1) // CHUNK)
            self.n_vid = min(256, (vid_bytes + CHUNK - 1) // CHUNK)
            log(f"  [compositor] Init order={order} systemShared={sys_bytes:#x} "
                f"({self.n_sys} chunks @ {WINDOW_SYSTEM:#x}) video={vid_bytes:#x} "
                f"({self.n_vid} chunks @ {WINDOW_VIDEO:#x})")
            return self._window_reply(hdr, self.n_sys, self.n_vid, WINDOW_SYSTEM,
                                      WINDOW_VIDEO, 3, True), False
        if hdr[:8] == MAP_ANOTHER_PROCESS:
            # sceCompositorMapAnotherProcess (libSceComposite @+0x3df0): header
            # {1, 0x4000, 0, processOrder}, no body, same reply shape as Init.
            # It maps the compositor's shared memory into a second view of the
            # address space, so it needs windows of its own: reusing Init's
            # would map_fixed over the memory the first client is using.
            log(f"  [compositor] MapAnotherProcess order={struct.unpack_from('<I', hdr, 12)[0]} "
                f"({self.n_sys} system + {self.n_vid} video chunks @ "
                f"{WINDOW2_SYSTEM:#x} / {WINDOW2_VIDEO:#x})")
            return self._window_reply(hdr, self.n_sys, self.n_vid, WINDOW2_SYSTEM,
                                      WINDOW2_VIDEO, 3, False), False
        # not modelled: status 0, empty body; the client's fixed-size body read
        # gets zeros
        return struct.pack("<IIII", cmd, 0, 0, 0), True


class CompositorRing:
    """Consumer side of libSceComposite's shared command ring.

    The client (libSceComposite, decoded from its disassembly) queues commands in
    the "CompositorControl" shared block:
        ctrl+0x00      u32  server marker: the producer waits while
                            write_index == marker, so it equals the index of the
                            LAST entry the server consumed (starts at 0)
        ctrl+0x50      u64  ring[256]; entry = (operand << 8) | command, index
                            wraps at 256, the producer starts at slot 1
        ctrl+0x850     pool of 0x18-byte records the entries point at
    Commands seen: 2 = run a Gnm command buffer (operand = record offset in the
    pool; record = {u64 dcb, u64 ptr2, u32 size_bytes, u32 flags}), 0x14 = flip,
    (event << 8) | 0x15 = post event.
    The client's write index is not in shared memory; it lives in the client's own
    globals (libSceComposite +0xc078 +0xec), which a same-address-space stand-in
    server can read directly instead of needing a doorbell."""

    RING, POOL = 0x50, 0x850
    CLIENT_GLOBALS, CLIENT_WIDX = 0xC078, 0xEC     # libSceComposite (5.05)

    def __init__(self, server):
        self.server = server
        self.read = 1                 # next slot to consume
        self.count = {}               # command -> times seen
        self.log_left = 40            # keep the log readable
        self.failed = False
        self.frames = 0

    def _locate(self):
        sc = self.server.sc
        obj = sc.shm_objs.get("/SceCompositorControl")
        dyn = sc.emu.dyn
        lm = dyn.by_name("libSceComposite") if dyn else None
        if not obj or not obj.get("addr") or lm is None:
            return None
        return obj["addr"], lm.base + self.CLIENT_GLOBALS + self.CLIENT_WIDX

    # Fields the real compositor server publishes in the shared control block for
    # its clients. libSceComposite+0x2d20 is `int get(u64 *out)` returning the u64
    # at control+0x10; the ShellUI's frame-timing code reads it once and later
    # divides by it (an unpublished 0 faults with #DE in `div`). It is the GPU
    # timestamp frequency; the exact units are not confirmed, a nonzero tick rate
    # is what the divisions need.
    CTRL_TIMESTAMP_FREQ = 0x10
    GPU_TIMESTAMP_FREQ = 100_000_000

    def _publish_server_fields(self, uc, ctrl, widx_addr):
        if getattr(self, "_published", False):
            return
        self._published = True
        lib = widx_addr - self.CLIENT_WIDX                 # = libSceComposite + 0xC078
        try:
            ptr = struct.unpack("<Q", bytes(uc.mem_read(lib, 8)))[0]
        except Exception:
            ptr = None
        emu = self.server.sc.emu
        emu.log(f"  [compositor] client state ptr={ptr:#x} control block={ctrl:#x}"
                if ptr is not None else "  [compositor] client state ptr unreadable")
        if ptr == ctrl:
            uc.mem_write(ctrl + self.CTRL_TIMESTAMP_FREQ,
                         struct.pack("<Q", self.GPU_TIMESTAMP_FREQ))
            emu.log(f"  [compositor] published timestamp frequency "
                    f"{self.GPU_TIMESTAMP_FREQ} at control+{self.CTRL_TIMESTAMP_FREQ:#x}")

    def service(self, uc):
        """Consume every command the client has queued. Called once per vblank."""
        if self.failed:
            return
        try:
            loc = self._locate()
            if loc is None:
                return
            ctrl, widx_addr = loc
            self._publish_server_fields(uc, ctrl, widx_addr)
            widx = struct.unpack("<I", bytes(uc.mem_read(widx_addr, 4)))[0] & 0xFF
            while self.read != widx:
                slot = self.read
                entry = struct.unpack("<Q", bytes(uc.mem_read(ctrl + self.RING + 8 * slot, 8)))[0]
                self._execute(uc, ctrl, slot, entry)
                self.read = (slot + 1) & 0xFF
                # marker = last consumed index; this is what unblocks the producer
                uc.mem_write(ctrl, struct.pack("<I", slot))
        except Exception as e:                       # never take the emulator down
            self.failed = True
            self.server.sc.emu.log(f"  [compositor] ring service failed: {e!r}")

    def _execute(self, uc, ctrl, slot, entry):
        cmd, operand = entry & 0xFF, entry >> 8
        self.count[cmd] = self.count.get(cmd, 0) + 1
        log = self.server.sc.emu.log
        detail = ""
        if cmd == 2:                                  # run a Gnm command buffer
            rec = bytes(uc.mem_read(ctrl + self.POOL + operand, 0x18))
            dcb, ptr2, size, flags = struct.unpack("<QQII", rec)
            detail = f"GnmContext dcb={dcb:#x} ptr2={ptr2:#x} size={size:#x} flags={flags:#x}"
            detail += self._run_dcb(uc, dcb, size)
        elif cmd == 0x14:
            self.frames += 1
            detail = f"Flip (frame {self.frames})"
            # the pixel stats only feed this log line (capped) and the frame dumps: read the
            # 8 MB target only when one of them will actually use it
            if self.log_left > 0 or self._frame_due():
                detail += self._present()
        elif cmd == 0x15:
            detail = f"PostEvent({operand & 0xF})"
            self._post_event(uc, operand & 0xF)
        else:
            detail = f"cmd {cmd:#x} operand {operand:#x} (not modelled)"
        if self.log_left > 0:
            self.log_left -= 1
            log(f"  [compositor] ring[{slot}] {entry:#018x} -> {detail}")

    # ---- running the client's command buffers on the host GPU -------------
    WIDTH, HEIGHT = 1920, 1080

    def _gpu_setup(self):
        """Lazily bring up the GNM backend and a RGBA8 render target the
        compositor draws into (the DCBs carry no render-target state: the real
        compositor patches its own scanout buffer in, see the "PatchRenderTarget"
        markers). Returns False if the GPU is unavailable."""
        if getattr(self, "gpu_state", None) is not None:
            return self.gpu_state
        self.gpu_state = False
        emu = self.server.sc.emu
        if not getattr(emu, "gpu_enabled", True):
            return False
        try:
            from .gnm import backend, pm4
            import numpy as np
            backend.init()
            self._backend, self._pm4, self._np = backend, pm4, np
            self._heap = backend.HostHeap()
            self._rt = self._heap.alloc(self.WIDTH * self.HEIGHT * 4)
            self._rt[:] = 0
            self._rt_addr = backend.HostHeap.addr(self._rt)
            # psemu's own scanout buffer: the guest program never sees this address, so the
            # backend may keep it on the GPU and write it back only when we read it (_present)
            backend.set_host_only_range(self._rt_addr, self.WIDTH * self.HEIGHT * 4)
            cb = pm4.CommandBuffer()
            cb.set_render_target(0, self._rt_addr, self.WIDTH, self.HEIGHT, fmt=10,
                                 number_type=0, comp_swap=0)
            self._rt_words = cb.words()
            self.gpu_state = True
            self.dcb_ok = self.dcb_bad = 0
        except Exception as e:
            emu.log(f"  [compositor] GPU unavailable: {e!r}")
        return self.gpu_state

    def _patch_dcb(self, words):
        """Insert the render-target registers after every CLEAR_STATE (it resets
        them) and at the start of the stream."""
        np = self._np
        out, i, n = [self._rt_words], 0, len(words)
        noblend = bool(os.environ.get("PSEMU_DCB_NOBLEND"))
        while i < n:
            h = int(words[i])
            if (h >> 30) == 3:
                cnt = ((h >> 16) & 0x3FFF) + 1
                pkt = words[i:i + 1 + cnt]
                if noblend and (h >> 8) & 0xFF == 0x69 and cnt >= 2:
                    reg = int(pkt[1])
                    if reg <= 0x1E0 < reg + cnt - 1:          # CB_BLEND0_CONTROL off
                        pkt = pkt.copy()
                        pkt[2 + 0x1E0 - reg] = 0
                out.append(pkt)
                if (h >> 8) & 0xFF == self._pm4.IT_CLEAR_STATE:
                    out.append(self._rt_words)
                i += 1 + cnt
            else:
                out.append(words[i:i + 1])
                i += 1
        return np.concatenate(out).astype(np.uint32)

    def _dcb_rt0(self, words):
        """Last CB_COLOR0 {base, pitch, slice, view, info, attrib} the stream sets."""
        last = None
        i, n = 0, len(words)
        while i < n:
            h = int(words[i])
            if (h >> 30) != 3:
                i += 1
                continue
            cnt = ((h >> 16) & 0x3FFF) + 1
            if (h >> 8) & 0xFF == 0x69 and cnt >= 2:                # SET_CONTEXT_REG
                reg = int(words[i + 1])
                vals = words[i + 2:i + 1 + cnt]
                if reg <= 0x318 < reg + len(vals):
                    last = [int(x) for x in vals[0x318 - reg:0x318 - reg + 6]]
            i += 1 + cnt
        if last is None:
            return "none"
        base = last[0] << 8
        return f"{base:#x}/info={last[4]:#x}" if len(last) >= 5 else f"{base:#x}"

    def _debug_dump_state(self, uc, words):
        """PSEMU_DCB_DEBUG: log the shader user data and the memory it points at
        (V# buffer descriptors, constant data) for each draw, to see what the
        compositor client actually fed the GPU."""
        sh, i, n, out = {}, 0, len(words), []
        while i < n:
            h = int(words[i])
            if (h >> 30) != 3:
                i += 1
                continue
            cnt = ((h >> 16) & 0x3FFF) + 1
            op = (h >> 8) & 0xFF
            if op == 0x12:
                sh = {}
            if op == 0x76 and cnt >= 2:
                reg = int(words[i + 1])
                for k, v in enumerate(words[i + 2:i + 1 + cnt]):
                    sh[reg + k] = int(v)
            if op in (0x2D, 0x27):
                out.append(dict(sh))
            i += 1 + cnt
        log = self.server.sc.emu.log
        for d, sh in enumerate(out):
            for name, base in (("PS", 0x0C), ("VS", 0x4C)):
                regs = [sh.get(base + k) for k in range(16)]
                if regs[0] is None:
                    continue
                log(f"      draw{d} {name} user data: " + " ".join(
                    "-" if r is None else f"{r:08x}" for r in regs))
                # every consecutive (lo, hi) pair that looks like a 48-bit pointer
                for k in range(0, 14, 2):
                    if regs[k] is None or regs[k + 1] is None:
                        continue
                    addr = regs[k] | ((regs[k + 1] & 0xFFFF) << 32)
                    if 0x3000000000 <= addr < 0x3100000000:
                        try:
                            raw = bytes(uc.mem_read(addr, 96))
                            log(f"        {name}[{k}] -> {addr:#x}: " + raw.hex(" ", 4))
                            # a table of V# buffer descriptors? follow each one
                            for v in range(0, 48, 16):
                                d0, d1, d2, d3 = struct.unpack_from("<4I", raw, v)
                                base = d0 | ((d1 & 0xFFFF) << 32)
                                stride, nrec = (d1 >> 16) & 0x3FFF, d2
                                if (0x3000000000 <= base < 0x3100000000 and 0 < stride <= 64
                                        and 0 < nrec <= 4096):
                                    n = min(stride * nrec, 96)
                                    data = bytes(uc.mem_read(base, n))
                                    fl = struct.unpack_from("<%df" % (n // 4), data)
                                    log(f"          V#{v // 16}: base={base:#x} stride={stride} "
                                        f"num={nrec} dst_sel/fmt={d3:#x} -> " +
                                        " ".join(f"{x:.4g}" for x in fl))
                        except Exception as e:
                            log(f"        {name}[{k}] -> {addr:#x}: unreadable ({e})")

    def _run_dcb(self, uc, dcb, size):
        """Execute one client command buffer; returns a log suffix."""
        emu = self.server.sc.emu
        if not size or not self._gpu_setup():
            return ""
        try:
            if not emu.vm.host_backed(dcb, size):
                self.dcb_bad += 1
                return " [GPU: dcb not host-backed]"
            words = self._np.frombuffer(bytes(uc.mem_read(dcb, size)), dtype=self._np.uint32)
            stats, err = self._backend.submit(self._patch_dcb(words))
        except Exception as e:
            self.dcb_bad += 1
            return f" [GPU: {e}]"
        self.dcb_ok += 1
        # what render target does the buffer itself set (CB_COLOR0_*, ctx reg 0x318..)?
        rt = self._dcb_rt0(words)
        if os.environ.get("PSEMU_DCB_DEBUG") and getattr(self, "_dbg_left", 12) > 0:
            self._dbg_left = getattr(self, "_dbg_left", 12) - 1
            self._debug_dump_state(uc, words)
        fdir = getattr(emu, "frame_dir", None)
        if fdir:
            os.makedirs(fdir, exist_ok=True)
            with open(os.path.join(fdir, f"dcb_{self.dcb_ok:04d}_f{self.frames + 1}.bin"), "wb") as fh:
                fh.write(words.tobytes())
        # running totals + each distinct backend message once, so a long run reports
        # what the GPU path could not do (the per-command log below is capped)
        tot = self.__dict__.setdefault("gpu_totals", {"dcbs": 0, "draws": 0, "failed": 0, "skipped": 0})
        tot["dcbs"] += 1
        tot["draws"] += stats.get("draws", 0)
        tot["failed"] += stats.get("failed", 0)
        tot["skipped"] += stats.get("skipped_packets", 0)
        if err:
            seen = self.__dict__.setdefault("gpu_errs", set())
            key = err.splitlines()[0][:160]
            if key not in seen and len(seen) < 25:
                seen.add(key)
                emu.log(f"  [compositor] GPU message (dcb {size}B, first seen at dcb #{tot['dcbs']}): {err[:400]!r}")
        if stats.get("skipped_packets") and not self.__dict__.get("_skip_logged"):
            self._skip_logged = True
            emu.log(f"  [compositor] GPU skipped packets: opcode {stats.get('first_skipped_opcode', 0):#x} "
                    f"(dcb {size}B) stats={stats}")
        if tot["dcbs"] % 500 == 0:
            emu.log(f"  [compositor] GPU totals after {tot['dcbs']} command buffers: {tot}")
        s = f" rt0={rt} [GPU: {stats.get('draws', 0)} draw(s), {stats.get('failed', 0)} failed"
        return s + (f", {err.splitlines()[0][:100]}" if err else "") + "]"

    def _frame_due(self):
        """True if this flip's frame gets saved (--frames)."""
        fdir = getattr(self.server.sc.emu, "frame_dir", None)
        every = getattr(self.server.sc.emu, "frame_every", 1)
        return bool(fdir) and (self.frames == 1 or self.frames % every == 0)

    def _present(self):
        """Flip: save what the compositor drew (when --frames is given)."""
        if not getattr(self, "gpu_state", False):
            return ""
        fdir = getattr(self.server.sc.emu, "frame_dir", None)
        np = self._np
        # the target may still be on the GPU (lazy write-back): bring memory up to date first
        self._backend.flush_range(self._rt_addr, self.WIDTH * self.HEIGHT * 4)
        raw = bytes(self._rt[:self.WIDTH * self.HEIGHT * 4])
        img = np.frombuffer(raw, dtype=np.uint8).reshape(self.HEIGHT, self.WIDTH, 4)
        # pixels with any non-zero R, G or B byte (RGBA in memory: the low 24 bits of
        # each little-endian dword). Same count as img[..., :3].any(axis=2).sum() but
        # ~8x faster; this runs on every flip.
        lit = int(np.count_nonzero(np.frombuffer(raw, dtype="<u4") & np.uint32(0x00FFFFFF)))
        msg = f" [target: {lit} non-black px]"
        every = getattr(self.server.sc.emu, "frame_every", 1)
        if fdir and (self.frames == 1 or self.frames % every == 0):
            import os
            from PIL import Image
            os.makedirs(fdir, exist_ok=True)
            path = os.path.join(fdir, f"compositor_{self.frames:04d}.png")
            Image.fromarray(img[..., :3].copy()).save(path)
            msg += f" saved {os.path.basename(path)}"
        return msg

    def _post_event(self, uc, event):
        """The server sets the post-event bit when the preceding commands are
        done; sceCompositorWaitPostEvent waits on SceCompositorEventflag."""
        sc = self.server.sc
        if not hasattr(sc, "evfs"):
            return
        ef = next((e for e in sc.evfs.values() if e.name == "SceCompositorEventflag"), None)
        if ef is not None:
            ef.bits |= 1 << event
            sc._evf_release(uc, ef)


def install_default_servers(sc):
    """Register the system servers a single-process emulation stands in for."""
    sc.unix_servers.setdefault("GnmCompositor", GnmCompositorServer(sc))
