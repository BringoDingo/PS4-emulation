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
        ms = (time.perf_counter() - t0) * 1000
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


DEVICES = {
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
}


def open_device(sc, path):
    cls = DEVICES.get(path)
    return cls(sc, path) if cls else None
