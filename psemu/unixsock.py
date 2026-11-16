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
        # chunk counts the first client asked for, reused for MapAnotherProcess
        self.n_sys, self.n_vid = 7, 64

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
        for i, off in enumerate(self._dmem(n_sys)):
            struct.pack_into("<Q", reply, 0xB8 + 8 * i, off)
        for i, off in enumerate(self._dmem(n_vid)):
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


def install_default_servers(sc):
    """Register the system servers a single-process emulation stands in for."""
    sc.unix_servers.setdefault("GnmCompositor", GnmCompositorServer(sc))
