"""Character devices behind open()/ioctl()/mmap(): the PS4 GPU and display drivers.

Sony's user-mode libraries talk to two kernel drivers to draw and present:

* ``/dev/gc``  (libSceGnmDriver) - the graphics/compute command processor.
  Submissions are arrays of PM4 ``INDIRECT_BUFFER`` packets (4 dwords each,
  header ``0xC0023F00`` for the draw engine, ``0xC0023300`` for the constant
  engine) that point at command buffers in shared memory. psemu feeds them
  straight to the native PM4 processor (``psemu.gnm`` / ``gnm_submit``):
  guest memory is host memory at the same address (``hostvm.py``), so no copy.
* ``/dev/dce`` (libSceVideoOut) - the display controller. One multiplexed
  ioctl ``0xc0308203`` carries a 0x30-byte request
  ``{u32 cmd; u32 pad; u64 handle; u64 a2; u64 a3; u64 a4; u64 a5}``.
  Command 0 opens a port (handle -> ``*a4``), command 9 hands out the
  offset/size of a status page the library then ``mmap``s from the same fd.

Requests nobody models yet are logged once per code and answered with success
and zeroed outputs, which is what kept boot moving before devices existed.
"""
import os
import struct

IOCPARM_SHIFT = 16
IOCPARM_MASK = 0x1FFF


def ioc_len(req):
    return (req >> IOCPARM_SHIFT) & IOCPARM_MASK


class Device:
    """One opened device. Subclasses override ``ioctl``/``mmap``."""

    def __init__(self, sc, path):
        self.sc = sc
        self.emu = sc.emu
        self.path = path
        self._unknown_logged = set()

    # -- guest memory helpers ------------------------------------------
    def rd(self, uc, addr, n):
        return bytes(uc.mem_read(addr, n))

    def u32(self, uc, addr):
        return struct.unpack("<I", self.rd(uc, addr, 4))[0]

    def u64(self, uc, addr):
        return struct.unpack("<Q", self.rd(uc, addr, 8))[0]

    def w32(self, uc, addr, v):
        uc.mem_write(addr, struct.pack("<I", v & 0xFFFFFFFF))

    def w64(self, uc, addr, v):
        uc.mem_write(addr, struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))

    def log(self, msg):
        self.emu.log(f"  [{self.path}] {msg}")

    def unknown(self, uc, req, argp, what=""):
        key = (req, what)
        if key not in self._unknown_logged:
            self._unknown_logged.add(key)
            n = ioc_len(req)
            try:
                raw = self.rd(uc, argp, min(n, 0x40)) if argp and n else b""
            except Exception:
                raw = b""
            self.log(f"ioctl {req:#010x}{what} not modelled -> 0  in={raw.hex()}")
        return 0

    # -- driver entry points -------------------------------------------
    def ioctl(self, uc, req, argp):
        return self.unknown(uc, req, argp)

    def read(self, uc, buf, n):
        """Bytes read into ``buf`` (<=n), or a negative errno. Default: EOF."""
        return 0

    def mmap(self, uc, length, prot, offset):
        """Return a guest address, or None for a plain anonymous mapping."""
        return None

    # Seekable devices (block devices): the fd's file position and positioned I/O.
    pos = 0
    seekable_size = None          # None = not seekable (lseek/pread fall through to "no data")

    def pread(self, uc, buf, n, off):
        """Bytes read at `off` into `buf` (<= n), or a negative errno."""
        return 0

    def write(self, uc, buf, n):
        """Bytes accepted (the default discards the data)."""
        return n


# ---------------------------------------------------------------- /dev/gc

EVFILT_GRAPHICS_CORE = -14     # sceGnmAddEqEvent's kevent filter
EQ_GFX_EOP = 0x40               # event id of the graphics ring's end-of-pipe interrupt

GC_SUBMIT = 0xc0108102         # {u32 ring; u32 count; u64 ib_packets}
GC_SUBMIT_FLIP = 0xc020810c     # {u32 ring; u32 count; u64 ib_packets; u64 flip; u32 x}
GC_SET_PID = 0xc0088101         # {u32 pid; u32 0} before a flip submit
GC_STATUS_PTR = 0xc008811b      # out u64: pointer to a kernel-updated status dword
                                #   (submit paths check *ptr != 0 -> extra ioctl first)


class GcDevice(Device):
    """GPU command submission. Runs every submitted command buffer through the
    native PM4 processor (lazily initialising Vulkan on the first one)."""

    gpu_state = None             # process-wide: "ok", "off" or an error string

    shared_page = None           # process-wide driver status page (guest address)

    def __init__(self, sc, path):
        super().__init__(sc, path)
        self.submits = 0

    def _shared(self):
        if GcDevice.shared_page is None:
            from unicorn import UC_PROT_READ, UC_PROT_WRITE
            GcDevice.shared_page = self.emu.map_anon(0x4000, prot=UC_PROT_READ | UC_PROT_WRITE)
            self.log(f"driver status page at {GcDevice.shared_page:#x}")
        return GcDevice.shared_page

    @classmethod
    def _gpu(cls, emu):
        if cls.gpu_state is None:
            if not getattr(emu, "gpu_enabled", True):
                cls.gpu_state = "off"
            else:
                try:
                    from .gnm import backend
                    name = backend.init()
                    cls.gpu_state = "ok"
                    emu.log(f"  [/dev/gc] GPU backend up: {name}")
                except Exception as e:          # no DLL / no Vulkan: keep running
                    cls.gpu_state = f"unavailable ({e})"
                    emu.log(f"  [/dev/gc] GPU backend {cls.gpu_state}; submits are dropped")
        return cls.gpu_state == "ok"

    def _run(self, uc, ring, count, ptr):
        if not count or not ptr:
            return 0
        words = count * 4
        self.submits += 1
        if not self._gpu(self.emu):
            return 0
        from .gnm import backend
        # The IB packet array lives in host-backed guest memory: the processor
        # reads it (and everything it points at) in place.
        if not self.emu.vm.host_backed(ptr, words * 4):
            self.log(f"submit #{self.submits}: packets at {ptr:#x} not host-backed; dropped")
            return 0
        import time
        t0 = time.perf_counter()
        try:
            stats, err = backend.submit_at(ptr, words)
        except Exception as e:
            self.log(f"submit #{self.submits}: {e}")
            return 0
        backend.sync_watches(self.emu.uc)       # a non-lazy submit may have flushed deferred surfaces
        ms = (time.perf_counter() - t0) * 1000
        if self.emu.whp:
            self.emu._excl += ms / 1000.0            # GPU time is not guest time (see Emulator._excl)
        self.gpu_ms = getattr(self, "gpu_ms", 0.0) + ms
        summary = " ".join(f"{k}={v}" for k, v in stats.items() if v)
        self.log(f"submit #{self.submits} ring={ring} ibs={count} {ms:.0f} ms: {summary}"
                 + (f"  first error: {err}" if err else ""))
        if getattr(self.emu, "gpu_profile", False):
            self.log("  profile: " + backend.profile())
        self.emu.gpu_submits = getattr(self.emu, "gpu_submits", 0) + 1
        if stats.get("interrupts"):
            # End-of-pipe interrupt -> EVFILT_GRAPHICS_CORE event, ident 0x40
            # (graphics EOP) on every equeue that sceGnmAddEqEvent'ed it.
            n = self.sc.trigger(EVFILT_GRAPHICS_CORE, EQ_GFX_EOP)
            if not n:
                n = self.sc.trigger(EVFILT_GRAPHICS_CORE)
            self.log(f"EOP interrupt -> {n} equeue event(s)")
        return 0

    def ioctl(self, uc, req, argp):
        if req == GC_SUBMIT:
            ring, count, ptr = struct.unpack("<IIQ", self.rd(uc, argp, 16))
            return self._run(uc, ring, count, ptr)
        if req == GC_SUBMIT_FLIP:
            ring, count, ptr, flip, x = struct.unpack("<IIQQI", self.rd(uc, argp, 28))
            rc = self._run(uc, ring, count, ptr)
            self.log(f"flip request {flip:#x} ({x:#x})")
            dce = self.sc.device_of_kind(DceDevice)
            if dce is not None:
                dce.flip_from_gpu(uc, flip)
            return rc
        if req == GC_SET_PID:
            return 0
        if req == GC_STATUS_PTR:
            self.w64(uc, argp, self._shared())
            return 0
        return self.unknown(uc, req, argp)


# ---------------------------------------------------------------- /dev/dce

DCE_IOCTL = 0xc0308203
DCE_CMD_FLIP_STATUS = 0xA
DCE_CMD_RESOLUTION_STATUS = 0x13   # sub-command: out = raw 0x2c-byte display record
DISPLAY_W, DISPLAY_H = 1920, 1080  # the display the stand-in HDMI sink reports
DISPLAY_REFRESH_HZ = 59.94         # raw record carries the rate as a float32 in Hz
DCE_SET_ATTRIBUTE = 0xc0308207   # {u32 handle,..; buffer attribute: format, w, h, pitch,..}
DCE_REGISTER_BUFFER = 0xc0308206  # {u32 handle,..; u64 index?; u64 address; ...}
DCE_SUBMIT_FLIP = 0xc0488204     # {u64 handle; i64 buffer; u32 mode; u64 arg; u64 0;
                                 #  u32 has_eop; u64 eop; u64 0; u64 *result}
DCE_STATUS_SIZE = 0x4000
DCE_STATUS_OFFSET = 0x10000      # mmap token handed out by command 9

EVFILT_DISPLAY = -13             # VideoOut's kevent filter
DISPLAY_EV_FLIP = 6              # event type at ident bits 48..63
DISPLAY_EV_VBLANK = 7
# The 5.05 VSH libSceVideoOut registers vblank events as ident 0x0063_0101_0000_0000
# (sceVideoOutGetEventId maps type 0x63 -> VBLANK); homebrew-era libs use type 7.
DISPLAY_EV_VBLANK_IDS = (DISPLAY_EV_VBLANK, 0x63)


class DceDevice(Device):
    """Display controller: one port, a status page, flip bookkeeping.

    Display events (kevent filter -13) carry the event type in ident bits
    48..63 (6 = flip, 7 = vblank); data holds count << 12 and, for flips,
    the flip argument << 16 (what sceVideoOutGetEventCount/Data decode)."""

    def __init__(self, sc, path):
        super().__init__(sc, path)
        self.handles = {}            # handle -> port index
        self.status_page = None      # guest address of the mmapped status page
        self.flips = 0
        self.last_arg = 0            # flip argument of the newest submitted flip
        self.last_index = 0          # buffer index of the newest submitted flip
        self.vblanks = 0
        self.cmds = {}               # cmd -> count (for the run summary)
        self.buffers = {}            # buffer index -> guest address
        self.attribute = None        # raw 0x30-byte buffer attribute
        self.frame_hook = None       # callable(dce, buffer_index, address) on each flip

    def _raise(self, ev_type, data):
        types = ev_type if isinstance(ev_type, tuple) else (ev_type,)
        idents = [i for kq in self.sc.knotes.values() for (i, f) in kq
                  if f == EVFILT_DISPLAY and (i >> 48) & 0xFFFF in types]
        for ident in set(idents):
            # An event the waiter has not collected yet is not replaced by the next one: the kernel
            # counts them (data bits 12..15 = how many have fired, sceVideoOutGetEventCount). A boot
            # splash that submits three flips and then waits for them saw one event with count 1 and
            # waited for the other two until its 1 s timeout.
            for kq, notes in self.sc.knotes.items():
                kn = notes.get((ident, EVFILT_DISPLAY))
                if kn is not None and (ident, EVFILT_DISPLAY) in self.sc.kq_pending.get(kq, []):
                    old = (kn.get("data", 0) >> 12) & 0xF
                    data = (data & ~0xF000) | (min(old + 1, 0xF) << 12)
                    break
            self.sc.trigger(EVFILT_DISPLAY, ident, data)
        return len(idents)

    def scanout(self, uc, addr):
        """The registered buffer at `addr` as an RGBA uint8 array (linear
        A8R8G8B8 scanout, the format VideoOut registers), or None."""
        import numpy as np
        if self.attribute is None:
            return None
        fmt, tiling, w, pitch, h = struct.unpack_from("<IIIII", self.attribute, 0xC)
        if not (0 < w <= 8192 and 0 < h <= 8192 and pitch >= w):
            return None
        if tiling:
            # Tiled scanout: the compositor renders it with CB tile mode 10
            # (Display2DThin), which is what VideoOut's tiling 1 means here.
            from .gnm import backend
            tb, pp, ph = backend.tiling_info(10, 4, pitch, h)
            raw = np.frombuffer(bytes(uc.mem_read(addr, tb)), np.uint8)
            bgra = backend.detile(10, raw, 4, pp, ph)[:h, :w]
        else:
            raw = np.frombuffer(bytes(uc.mem_read(addr, pitch * h * 4)), np.uint8)
            bgra = raw.reshape(h, pitch, 4)[:, :w]
        return bgra[..., [2, 1, 0, 3]]          # A8R8G8B8 in memory = B,G,R,A

    def _save_frame(self, uc, fdir, addr):
        import os
        from PIL import Image
        img = self.scanout(uc, addr)
        if img is None:
            return
        os.makedirs(fdir, exist_ok=True)
        path = os.path.join(fdir, f"flip_{self.flips:05d}.png")
        Image.fromarray(img[..., :3].copy()).save(path)
        self.log(f"frame saved: {path} (mean rgb {img[..., :3].mean():.1f})")

    def vblank(self):
        self.vblanks += 1
        return self._raise(DISPLAY_EV_VBLANK_IDS, (self.vblanks << 16) | (1 << 12))

    def wants_vblank(self, kq):
        return any(f == EVFILT_DISPLAY and (i >> 48) & 0xFFFF in DISPLAY_EV_VBLANK_IDS
                   for (i, f) in self.sc.knotes.get(kq, {}))

    def ioctl(self, uc, req, argp):
        if req == DCE_SET_ATTRIBUTE:
            self.attribute = self.rd(uc, argp, 0x30)
            fmt, tiling, w, pitch, h = struct.unpack_from("<IIIII", self.attribute, 0xC)
            self.log(f"buffer attribute: {w}x{h} pitch {pitch} format {fmt:#x} tiling {tiling}")
            return 0
        if req == DCE_REGISTER_BUFFER:
            raw = self.rd(uc, argp, 0x30)
            index, _group, addr = struct.unpack_from("<IIQ", raw, 0x8)
            self.buffers[index] = addr
            self.log(f"register buffer {index} at {addr:#x}")
            return 0
        if req == DCE_SUBMIT_FLIP:
            handle, index, mode, arg, _z, has_eop, eop, _z2, res = struct.unpack(
                "<QqIxxxxQQIxxxxQQQ", self.rd(uc, argp, 0x48))
            if res:
                self.w64(uc, res, 0)
            self.flips += 1
            self.last_arg, self.last_index = arg, index
            addr = self.buffers.get(index)
            if self.flips <= 3 or self.flips % 60 == 0:
                self.log(f"flip #{self.flips}: buffer {index} ({addr or 0:#x}) mode {mode} "
                         f"arg {arg:#x}" + (f" after EOP {eop:#x}" if has_eop else ""))
            if self.frame_hook and addr:
                self.frame_hook(self, index, addr)
            fdir = getattr(self.emu, "frame_dir", None)
            if fdir and addr and (self.flips == 1 or self.flips % self.emu.frame_every == 0):
                self._save_frame(uc, fdir, addr)
            self._raise(DISPLAY_EV_FLIP, ((arg & 0xFFFFFFFFFFFF) << 16) | (1 << 12))
            self.vblank()
            return 0
        if req != DCE_IOCTL:
            return self.unknown(uc, req, argp)
        cmd, _pad, handle, a2, a3, a4, a5 = struct.unpack("<IIQQQQQ", self.rd(uc, argp, 0x30))
        self.cmds[cmd] = self.cmds.get(cmd, 0) + 1
        if cmd == 0:                                 # open port a2 -> *a4 = handle
            h = 0x100 + len(self.handles)
            self.handles[h] = a2
            if a4:
                self.w64(uc, a4, h)
            self.log(f"open port {a2} -> handle {h:#x}")
            return 0
        if cmd == 9:                                 # status page: *a2 = offset, *a3 = size
            if a2:
                self.w64(uc, a2, DCE_STATUS_OFFSET)
            if a3:
                self.w64(uc, a3, DCE_STATUS_SIZE)
            return 0
        if cmd == DCE_CMD_RESOLUTION_STATUS:
            # sceVideoOutGetResolutionStatus (libSceVideoOut export 8XGijEoThE0 ->
            # ioctl cmd 0x13): a2 = out buffer, a3 = 0x2c bytes (the raw display
            # record behind SceVideoOutResolutionStatus). Answered with nothing it was an
            # all-zero "0x0, refresh rate UNKNOWN" display, which libScePsm copies
            # straight into its graphics setup ("VideoOutResolutionStatus UNKNOWN :
            # refresh rate 0") -- it has a 1080p fallback, but only for a FAILED
            # query, not for a successful all-zero one.
            if a2:
                # The raw record is NOT the SDK struct: libSceVideoOut's converter
                # (+0x2ee0) copies the first 16 bytes verbatim and reads the
                # refresh rate at +0x10 as a float32 in Hz (it compares against
                # 59.94f = 0x426fc28f, 60.0f, 120.0f, ...), mapping it to the
                # SDK's SCE_VIDEO_OUT_REFRESH_RATE_* enum itself.
                status = struct.pack("<IIIIf", DISPLAY_W, DISPLAY_H, DISPLAY_W,
                                     DISPLAY_H, DISPLAY_REFRESH_HZ).ljust(0x2C, b"\0")
                self.emu.uc.mem_write(a2, status[:a3] if a3 else status)
            if self.cmds[cmd] == 1:
                self.log(f"resolution status -> {DISPLAY_W}x{DISPLAY_H} @ 59.94Hz")
            return 0
        if cmd == DCE_CMD_FLIP_STATUS:
            # sceVideoOutGetFlipStatus: a2 = out, a3 = size (0x48). SceVideoOutFlipStatus: u64 count,
            # u64 processTime, u64 tsc, i64 flipArg, u64 submitTsc, i32 gcQueueNum, i32 flipPendingNum,
            # i32 currentBuffer. Flips complete at once here (no queue), so the newest flip's
            # argument is already the status. The boot splash (SceSysAvControl waitFlipArg) polls
            # this until flipArg catches up with what it submitted and timed out on a zero status.
            if a2:
                now = int(self.emu._time() * 1e9) if hasattr(self.emu, "_time") else 0
                st = struct.pack("<QQQqQiii", self.flips, now, now, self.last_arg, now, 0, 0,
                                 self.last_index).ljust(max(a3, 0x48), bytes(1))
                self.emu.uc.mem_write(a2, st[:a3 or 0x48])
            return 0
        if self.cmds[cmd] == 1:
            self.log(f"cmd {cmd:#x} handle={handle:#x} a2={a2:#x} a3={a3:#x} "
                     f"a4={a4:#x} a5={a5:#x} (first use; answered 0)")
        return 0

    def mmap(self, uc, length, prot, offset):
        if offset != DCE_STATUS_OFFSET:
            return None
        if self.status_page is None:
            from unicorn import UC_PROT_READ, UC_PROT_WRITE
            addr = self.emu.map_anon(max(length, DCE_STATUS_SIZE),
                                     prot=UC_PROT_READ | UC_PROT_WRITE)
            self.status_page = addr
            self.log(f"status page mapped at {addr:#x} ({length:#x} bytes)")
        return self.status_page

    def flip_from_gpu(self, uc, flip):
        self.flips += 1


# ---------------------------------------------------------------- /dev/dmemN

DMEM_ALLOCATE = 0xc0288001       # {u64 start (out: phys); u64 end; u64 len; u64 align; u32 type}
DMEM_GET_SIZE = 0x4008800a       # out u64: size of direct memory
DMEM_TOTAL = 0x1_3C00_0000       # 5056 MiB, as the PS4 kernel reports to apps


class DmemAllocator:
    """Physical direct-memory ranges handed out by sceKernelAllocateDirectMemory.
    Process-wide: every /dev/dmemN fd shares one physical space."""

    def __init__(self):
        self.allocs = []         # (phys, length, memory_type), sorted by phys

    def allocate(self, start, end, length, align, mtype):
        align = max(align, 0x4000)
        end = min(end or DMEM_TOTAL, DMEM_TOTAL)
        cur = (start + align - 1) & ~(align - 1)
        for p, n, _t in self.allocs:          # first fit
            if cur + length <= p:
                break
            if p + n > cur:
                cur = (p + n + align - 1) & ~(align - 1)
        if cur + length > end:
            return None
        self.allocs.append((cur, length, mtype))
        self.allocs.sort()
        return cur

    def type_at(self, phys):
        for p, n, t in self.allocs:
            if p <= phys < p + n:
                return t
        return 0


class DmemDevice(Device):
    allocator = DmemAllocator()

    def ioctl(self, uc, req, argp):
        if req == DMEM_ALLOCATE:
            start, end, length, align, mtype = struct.unpack("<QQQQI", self.rd(uc, argp, 0x24))
            phys = self.allocator.allocate(start, end, length, align, mtype)
            if phys is None:
                self.log(f"allocate {length:#x} in [{start:#x},{end:#x}) failed: ENOMEM")
                return -12
            self.w64(uc, argp, phys)
            self.log(f"allocate {length:#x} align {align:#x} type {mtype} -> phys {phys:#x}")
            return 0
        if req == DMEM_GET_SIZE:
            self.w64(uc, argp, DMEM_TOTAL)
            return 0
        return self.unknown(uc, req, argp)


# ---------------------------------------------------------------- /dev/hdmi
#
# The AV control plane (SceSysAvControl) polls /dev/hdmi for the sink it is
# driving. Its HdmiCheckAvailability (ioctl 0xc0108d10) passes a 16-byte arg of
# two output pointers - {u64 *txtype; u64 *devout} - and treats the sink as
# connected only when *devout == 2 (it pre-seeds both bytes to 1). With the old
# "return 0, write nothing" default those stayed 1, so the firmware logged
# "hdmi not connected" and av_control_setup_dispclk() timed out. We report a
# connected HDMI transmitter so display setup proceeds.

class HdmiDevice(Device):
    """HDMI transmitter: reports a connected HDMI sink to the AV control plane."""

    HDMI_CHECK_AVAILABILITY = 0xC0108D10   # {u64 *txtype; u64 *devout}
    HDMI_GET_STATE = 0xC0088D0C            # {u64 *state_byte}: wants *state == 2

    def ioctl(self, uc, req, argp):
        if req == self.HDMI_CHECK_AVAILABILITY and argp:
            p_tx = self.u64(uc, argp)          # -> transmitter-type byte
            p_dev = self.u64(uc, argp + 8)     # -> device-out byte
            if p_tx:
                uc.mem_write(p_tx, b"\x01")    # 1 = HDMI transmitter
            if p_dev:
                uc.mem_write(p_dev, b"\x02")   # 2 = HDMI sink connected
            self.log("HdmiCheckAvailability -> connected (TxType=1 DevOut=2)")
            return 0
        if req == self.HDMI_GET_STATE and argp:
            # arg is a pointer to a 1-byte state the firmware polls for == 2.
            p_state = self.u64(uc, argp)
            if p_state:
                uc.mem_write(p_state, b"\x02")   # 2 = connected/active
            self.log("GET_HDMI_STATE -> 2 (connected)")
            return 0
        # Setup/config ioctls (0x8d02/0x8d03/0x8d16/0x8d18/0x8d1e ...): succeed.
        return self.unknown(uc, req, argp)


# ---------------------------------------------------------------- /dev/mbus_av
#
# The AV message bus: SceSysAvControl reads 0x30-byte hotplug/mode events from it
# in a loop (its parser, SceSysAvControl @0x4124c0, keeps events whose first u32
# is 9 and dispatches on the second u32 - code 1 = sink connected). With reads
# returning EOF (0) the firmware logged "unknown sz = 0" every poll and treated
# the sink as "hdmi not connected". We deliver one connected event, then report
# no-more-events with EAGAIN (which the parser handles quietly, not as "unknown
# sz"), so the AV thread sees the sink come up and stops spinning on EOF.

MBUS_EAGAIN = 35                 # FreeBSD EAGAIN: no event pending (non-blocking)
MBUS_EVENT_LEN = 0x30            # one message is 48 bytes
MBUS_TYPE_AV = 9                 # event type the SceSysAvControl parser keeps
MBUS_CODE_CONNECTED = 1          # second u32: 1 = sink connected


class MbusAvDevice(Device):
    """AV message bus: delivers one 'HDMI connected' event, then EAGAIN."""

    def __init__(self, sc, path):
        super().__init__(sc, path)
        self._delivered = False

    def read(self, uc, buf, n):
        if n >= MBUS_EVENT_LEN and not self._delivered:
            self._delivered = True
            ev = struct.pack("<II", MBUS_TYPE_AV, MBUS_CODE_CONNECTED)
            ev += b"\x00" * (MBUS_EVENT_LEN - len(ev))
            uc.mem_write(buf, ev)
            self.log(f"deliver HDMI-connected event (type={MBUS_TYPE_AV} code={MBUS_CODE_CONNECTED})")
            return MBUS_EVENT_LEN
        return -MBUS_EAGAIN       # no (more) events pending


class AvStubDevice(Device):
    """AV plane device with no state model yet (logs, answers success)."""


# ------------------------------------------------------------- /dev/av_control

class AvControlDevice(Device):
    """AV control plane. Models the display-clock status query so
    av_control_setup_dispclk() sees the clock locked instead of timing out.

    Its ready-check (SceSysAvControl @0x476d10) calls ioctl 0xc0109a0e with
    {u32 freq; u32 pad; u64 *out}, validates freq in [20000, 70000], and treats
    the clock as ready only when *out != 0. We report it locked at the requested
    frequency."""

    AV_CLOCK_STATUS = 0xC0109A0E   # {u32 freq; u32 pad; u64 *out}

    def ioctl(self, uc, req, argp):
        if req == self.AV_CLOCK_STATUS and argp:
            freq = self.u32(uc, argp)
            out_ptr = self.u64(uc, argp + 8)
            if out_ptr:
                self.w32(uc, out_ptr, freq or 1)   # nonzero = clock locked
                self.log(f"clock status freq={freq:#x} -> locked")
                return 0
        return self.unknown(uc, req, argp)


class RandomDevice(Device):
    """/dev/urandom, /dev/random: an endless byte source. A read that returns 0
    (EOF) makes Mono's read-all loops (e.g. the ThreadPool/SecureRandom seed
    read) spin forever. Seeded, so runs stay deterministic."""

    def __init__(self, sc, path):
        super().__init__(sc, path)
        import random
        self._rng = random.Random(0x505334)

    def read(self, uc, buf, n):
        n = min(n & 0xFFFFFFFF, 1 << 20)
        if n:
            uc.mem_write(buf, self._rng.randbytes(n))
        return n


# ---------------------------------------------------------------- /dev/ajm
#
# libSceAjm (the audio decoder accelerator: ATRAC9, AAC, MP3 ...) talks to /dev/ajm with twelve ioctls
# 0xc0288900 + n, all `RW size 0x28`. Layout from libSceAjm's wrappers (docs/shellui-boot/README.md):
#   +0x00 u32  status written by the kernel (0 = OK; the wrapper returns it as the SCE result)
#   +0x08..    inputs (MemoryRegister: ptr, size; ModuleRegister: codec; InstanceCreate: flags, codec)
#   InstanceCreate (n = 5) also returns the new instance id as a u32 at +0x14.
# n: 0 finalize, 1 memory register, 2 memory unregister, 3 module register, 4 module unregister,
#    5 instance create, 6 instance destroy, 7 batch start, 8 batch wait, 9 batch cancel,
#    0xa instance extend, 0xb instance switch.
# The generic "return 0, write nothing" left the status dword as stack garbage, so libScePsm's audio
# start-up (sceAjmModuleRegister) failed with 0x80b3f001 and never registered its built-in
# `BgmPlayStatusCheck` native library; the Bgm player's P/Invoke then threw DllNotFoundException.
# Decoding itself is not implemented: batches report "done, nothing decoded".
# On by default (PSEMU_AJM=0 turns it off, back to the generic stub): with the audio server's pacing
# (audioserver.py), 16 KiB shm spans and the sched priority syscalls libScePsm's sound start-up completes.

AJM_REQ_BASE = 0xC0288900
AJM_INSTANCE_CREATE = 5
AJM_BATCH_WAIT = 8

# What Device.ioctl returns after parking the calling thread itself (sched.block): the syscall's
# return value is delivered when the thread wakes, so sys_ioctl must not write one.
BLOCKED = object()


class AjmDevice(Device):
    """/dev/ajm: accepts every request with status OK (no decoding)."""

    _instances = 0

    def ioctl(self, uc, req, argp):
        n = req - AJM_REQ_BASE
        if not 0 <= n <= 0xB:
            return self.unknown(uc, req, argp)
        self.w32(uc, argp, 0)                               # status: SCE_OK
        if n == AJM_INSTANCE_CREATE:
            AjmDevice._instances += 1
            self.w32(uc, argp + 0x14, AjmDevice._instances)
        if n == AJM_BATCH_WAIT:
            # The hardware decoder takes time: a batch is not done until a period of audio has
            # passed. Without this the guest's decode loop (libSceAudiodec -> Batch start/wait, no
            # sleep of its own) spun at ~2500 ioctls/s on results that never advance.
            sched = getattr(self.emu, "sched", None)
            if sched is not None and getattr(sched, "current", None) is not None:
                from . import audioserver
                sched.block({"kind": "ajm_batch_wait"},
                            deadline_ns=audioserver.next_period(sched.now_ns()), timeout_ret=(0, False))
                return BLOCKED
        return 0


# ---------------------------------------------------------------- /dev/hid
#
# libScePad (and the copy linked into the ShellUI) drive the controllers through ioctls on /dev/hid,
# 'H' group. All are "small struct holding an output pointer + arguments in, the kernel writes
# through the pointer". What has been reversed from libScePad (see docs/shellui-boot/README.md):
#   0x80084809  scePadSetProcessPrivilege  {u32 3; u32 privilege}
#   0x800c4802  scePadOpen*                 {i32 id (-1 = any); i32 type; i32 0}: returns the pad
#                                            handle (1..3: libScePad's read takes a port <= 3)
#   0x80084803  scePadClose                 {i32 3; i32 handle}
#   0x80204829  scePadRead/ReadState        {u32 port; u32 _; void *buf; u32 count; u32 _;
#                                            u32 *out_count}: writes up to `count` pad reports to buf
#                                            and returns how many (0 = nothing new, < 0 = error);
#                                            report: +0 u64 timestamp us, +0x0c u32 buttons,
#                                            +0x10 lx ly rx ry l2 r2 (u8)
#   0x8010480e  scePadGetControllerInformation  {u32 handle; u64 *out}: fills a 0x40+ byte block
#                                            (see padsrc.controller_info_block): +0x00 u8 class (2),
#                                            +0x10 u16 vendor, +0x12 u16 product, +0x34 u32 pixel
#                                            density, +0x38/+0x3a u16 touchpad size, +0x3c/+0x3d u8
#                                            stick dead zones
#   0x80104801  scePadGetCapability         {u32 handle; u64 *out}: a block whose dword at +0x24 is the
#                                            capability flags (zeros here)
#   0x8010480f  {u64 *out; u32 arg}: the kernel writes a u64 (a counter/time; semantics unknown)
# Everything else is logged once and answered with 0 (the generic Device.unknown).

HID_SET_PROCESS_PRIVILEGE = 0x80084809
HID_PAD_OPEN = 0x800C4802
HID_PAD_CLOSE = 0x80084803
HID_PAD_READ = 0x80204829
HID_PAD_READ_EX = 0x8030482E
HID_REPORT_SIZE = 0xA8          # stride of libScePad's report records for HID_PAD_READ_EX
HID_QUERY_U64 = 0x8010480F
HID_PAD_INFO = 0x8010480E
HID_PAD_CAPABILITY = 0x80104801
HID_MAX_PORTS = 4


class HidDevice(Device):
    """/dev/hid: one DualShock 4 on port 0 (the host's XInput pad, or an idle one; see padsrc.py)."""

    _handles = 0
    _last = None            # (PadState, timestamp us) of the last report handed out

    def __init__(self, sc, path):
        super().__init__(sc, path)
        from . import padsrc
        self.source = padsrc.get_source()
        self.reads = 0

    def _now_us(self):
        t = getattr(self.emu, "_time", None)
        return int((t() if t else 0.0) * 1_000_000)

    def ioctl(self, uc, req, argp):
        from . import padsrc
        if req == HID_PAD_READ:
            return self._read(uc, argp)
        if req == HID_PAD_READ_EX:
            return self._read_ex(uc, argp)
        if req == HID_PAD_OPEN:
            HidDevice._handles = HidDevice._handles % 3 + 1
            self.log(f"pad open {self.rd(uc, argp, 12).hex()} -> handle {HidDevice._handles}")
            return HidDevice._handles
        if req == HID_PAD_CLOSE:
            return 0
        if req == HID_SET_PROCESS_PRIVILEGE:
            return 0
        if req in (HID_PAD_INFO, HID_PAD_CAPABILITY):
            out = self.u64(uc, argp + 8)
            if out:
                uc.mem_write(out, padsrc.controller_info_block() if req == HID_PAD_INFO else bytes(0x30))
            return 0
        if req == HID_QUERY_U64:
            out = self.u64(uc, argp)
            if out:
                self.w64(uc, out, 0)
            return 0
        return self.unknown(uc, req, argp)

    def _sample(self):
        """(PadState, timestamp us) of the next report. An unchanged controller keeps its last
        timestamp (refreshed every 250 ms): a fresh stamp on every poll made libScePsm treat each
        poll as new input and flood the UI with events."""
        now = self._now_us()
        state = self.source.poll(now / 1e6 - getattr(self.emu, '_t0', 0.0))
        last = HidDevice._last
        if last is None or last[0] != state or now - last[1] >= 250_000:
            if last is None or last[0] != state:
                self.log(f"pad state -> buttons {state.buttons:#x}")       # one line per change
            HidDevice._last = last = (state, now)
        return last

    def _read_ex(self, uc, argp):
        """0x8030482e, the read libScePad's scePadRead/ReadState use in this firmware (+0xe00):
        {u32 handle; u32 _; record *buf; u32 count; _; u32 *out_a; u32 *out_b; _}. The kernel fills
        `buf` with 0xa8-byte records (+0 u64 timestamp us, +0x0c u32 buttons, +0x10 lx ly rx ry l2 r2,
        +0x17 u8 touch count), returns how many, and writes out_a (the pad's generation id the library
        checks against its own; 0 skips the check) and out_b (non-zero = touch data follows)."""
        from . import padsrc
        buf = self.u64(uc, argp + 8)
        count = self.u32(uc, argp + 0x10)
        out_a = self.u64(uc, argp + 0x18)
        out_b = self.u64(uc, argp + 0x20)
        if out_a:
            self.w32(uc, out_a, 0)
        if out_b:
            self.w32(uc, out_b, 0)
        if count < 1 or not buf:
            return 0
        self.reads += 1
        state, ts = self._sample()
        uc.mem_write(buf, padsrc.encode_report(state, ts).ljust(HID_REPORT_SIZE, b"\0"))
        return 1

    def _read(self, uc, argp):
        from . import padsrc
        port = self.u32(uc, argp)
        buf = self.u64(uc, argp + 8)
        count = self.u32(uc, argp + 0x10)
        out_n = self.u64(uc, argp + 0x18)
        if port >= HID_MAX_PORTS:
            return -22                                   # EINVAL
        if count < 1 or not buf:
            return 0
        self.reads += 1
        now = self._now_us()
        state = self.source.poll(now / 1e6 - getattr(self.emu, '_t0', 0.0))
        # An unchanged controller keeps its last timestamp (refreshed every 250 ms): a fresh stamp on
        # every poll made libScePsm treat each poll as new input and flood the UI with events.
        last = HidDevice._last
        if last is None or last[0] != state or now - last[1] >= 250_000:
            HidDevice._last = last = (state, now)
        uc.mem_write(buf, padsrc.encode_report(state, last[1]))
        if out_n:
            self.w32(uc, out_n, 1)
        return 1


class DevActDevice(Device):
    """/dev/devact: the console's developer-activation state. libSceSblDevAct (compiled into ShellCore as
    sceSblDevActIsExpired2) asks with 0x40105303 {u32 activated; ...; u32 status @+12}; when the console is not
    activated it then opens the executable and calls it "expired" if it is a plain ELF. The firmware psemu
    runs is decrypted, i.e. plain ELFs everywhere, so LncService refused to launch the ShellUI
    (LNC_CHECK::0x8094000b). Report an activated unit (status 0), as a dev kit would."""

    def ioctl(self, uc, req, argp):
        if req == 0x40105303:
            uc.mem_write(argp, struct.pack("<IIII", 1, 0, 0, 0))
            return 0
        return super().ioctl(uc, req, argp)


DEVICES = {
    "/dev/hid": HidDevice,
    "/dev/urandom": RandomDevice,
    "/dev/random": RandomDevice,
    "/dev/gc": GcDevice,
    "/dev/dce": DceDevice,
    "/dev/dmem0": DmemDevice,
    "/dev/dmem1": DmemDevice,
    "/dev/dmem2": DmemDevice,
    "/dev/hdmi": HdmiDevice,
    "/dev/mbus_av": MbusAvDevice,
    "/dev/av_control": AvControlDevice,
    "/dev/devact": DevActDevice,
}


# ---------------------------------------------------------------- block devices (/dev/da*)
#
# The console's disk partitions (da0x<N>[.crypt]): mini-syscore checks them (filecheck), asks the
# sector size (DIOCGSECTORSIZE) and, before mounting, reads each UFS superblock to see whether the
# filesystem was left clean (sceFsUfsCheckCleanFlag). The files themselves come from the host firmware
# directory (psemu has no real filesystem), so a partition only has to look like a clean UFS2 volume.

DIOCGSECTORSIZE = 0x40046480    # u32
DIOCGMEDIASIZE = 0x40086481     # u64
DIOCGFWSECTORS = 0x40046482     # u32
DIOCGFWHEADS = 0x40046483       # u32
DIOCGSTRIPESIZE = 0x40086484    # u64
DIOCGSTRIPEOFFSET = 0x40086485  # u64
UFS2_SBLOCK = 0x10000
UFS2_MAGIC = 0x19540119
BLOCK_SECTOR = 512
BLOCK_MEDIA = 1 << 30           # 1 GiB: the size a partition reports


def ufs2_superblock(media=BLOCK_MEDIA):
    """A UFS2 superblock (FreeBSD struct fs) of a clean, empty volume."""
    sb = bytearray(8192)
    bsize, fsize = 32768, 4096
    struct.pack_into("<i", sb, 48, bsize)             # fs_bsize
    struct.pack_into("<i", sb, 52, fsize)             # fs_fsize
    struct.pack_into("<i", sb, 56, bsize // fsize)    # fs_frag
    struct.pack_into("<i", sb, 104, 4096)             # fs_sbsize
    struct.pack_into("<i", sb, 44, 1)                 # fs_ncg
    sb[208] = 0                                       # fs_fmod
    sb[209] = 1                                       # fs_clean
    sb[210] = 0                                       # fs_ronly
    struct.pack_into("<q", sb, 1144, UFS2_SBLOCK)     # fs_sblockloc
    struct.pack_into("<q", sb, 1224, media // fsize)  # fs_size (fragments)
    struct.pack_into("<q", sb, 1232, media // fsize)  # fs_dsize
    struct.pack_into("<i", sb, 1372, UFS2_MAGIC)      # fs_magic
    return bytes(sb)


class BlockDevice(Device):
    seekable_size = BLOCK_MEDIA

    def __init__(self, sc, path):
        super().__init__(sc, path)
        self.pos = 0
        self.sb = ufs2_superblock()

    def _data(self, off, n):
        out = bytearray(n)
        lo = UFS2_SBLOCK
        a, b = max(off, lo), min(off + n, lo + len(self.sb))
        if a < b:
            out[a - off:b - off] = self.sb[a - lo:b - lo]
        return bytes(out)

    def ioctl(self, uc, req, argp):
        if req == DIOCGSECTORSIZE:
            self.w32(uc, argp, BLOCK_SECTOR)
        elif req == DIOCGMEDIASIZE:
            self.w64(uc, argp, BLOCK_MEDIA)
        elif req in (DIOCGFWSECTORS, DIOCGFWHEADS):
            self.w32(uc, argp, 63 if req == DIOCGFWSECTORS else 255)
        elif req in (DIOCGSTRIPESIZE, DIOCGSTRIPEOFFSET):
            self.w64(uc, argp, 0)
        else:
            return self.unknown(uc, req, argp)
        return 0

    def pread(self, uc, buf, n, off):
        n = max(0, min(n, BLOCK_MEDIA - off))
        if n:
            uc.mem_write(buf, self._data(off, n))
        return n

    def read(self, uc, buf, n):
        got = self.pread(uc, buf, n, self.pos)
        self.pos += got
        return got


class EventDevice(Device):
    """A device that delivers event records (/dev/notification*): nothing ever happens here, so a read
    blocks for good, like an idle queue (returning EOF made SceSysCore's button thread spin, logging
    "An illegal event rises" ~500 times a second)."""

    def read(self, uc, buf, n):
        sched = getattr(self.emu, "sched", None)
        if sched is not None and getattr(sched, "current", None) is not None:
            sched.block({"kind": "device_read", "dev": self.path})
            return BLOCKED
        return 0


def open_device(sc, path):
    if path.startswith("/dev/notification"):
        return EventDevice(sc, path)
    if path.startswith("/dev/da") and path[7:8].isdigit():
        return BlockDevice(sc, path)
    if path == "/dev/ajm" and os.environ.get("PSEMU_AJM", "1") not in ("0", "off", ""):
        # The decoder answers "done, nothing decoded"; without it PSM's sound start-up fails and the
        # Bgm native library is never registered (see the README).
        return AjmDevice(sc, path)
    cls = DEVICES.get(path)
    return cls(sc, path) if cls else None
