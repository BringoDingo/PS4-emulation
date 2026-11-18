"""SceMbusIpc: the media-bus service that lists the console's attached devices (controllers etc.).

libScePsm enumerates pads by asking SceMbusIpc for devices of the classes it can drive; each answer
entry is 0x100 bytes. What has been reversed from libScePsm (+0x7fca0 / +0x80184..) and libSceMbus
(+0x4010), see docs/shellui-boot/README.md:

  IPMI method 0xce110028 (GetDeviceList)   in[0] = 0x110 bytes: a 0x100-byte filter + 0x10 more;
                                           out[0] = up to 16 entries (0x100 each), out[1] = u32 count,
                                           out[2] = u32 count again (total)
  filter   +0x00..0x0b  wildcards (-1)          entry  +0x00 u64 device id (unique, non-zero)
           +0x0c        device class (-1 = any)        +0x08 u32 connection kind (4 = remote play,
                                                                5 = share play, else local)
           +0xc8        user id (-1 = any)             +0x0c u32 device class
                                                       +0xc8 u32 user id the device is assigned to
                                                       +0xe2 u8  flags (bit 1)
  device classes libScePsm accepts as pads: 2, 3, 7, 8, 12, 13 (-> pad types 1, 2, 4, 5, 3, 6); it asks
  for classes 2, 3 and 12 (then 13). A DualShock 4 is reported as class 2.
"""
import struct

ENTRY_SIZE = 0x100
MAX_ENTRIES = 16

DEV_CLASS_PAD = 2          # class 2 -> pad type 1 (a standard controller, polled by libScePsm)
CONN_LOCAL = 0             # entry +0x08: libScePsm maps 4 -> REMOTEPLAY, 5 -> SHAREPLAY, anything else = local


def pad_entry(index, user_id):
    """The 0x100-byte device-list entry of the emulated DualShock 4 on port `index`."""
    e = bytearray(ENTRY_SIZE)
    struct.pack_into("<Q", e, 0x00, 0x0100000000000000 | (index + 1))
    struct.pack_into("<I", e, 0x08, CONN_LOCAL)
    struct.pack_into("<I", e, 0x0C, DEV_CLASS_PAD)
    struct.pack_into("<I", e, 0xC8, user_id)
    e[0xE2] = 2
    return bytes(e)


def matches(entry, flt):
    """Does a device entry pass the request filter? (-1 = wildcard in the filter)."""
    cls, = struct.unpack_from("<I", flt, 0x0C)
    user, = struct.unpack_from("<I", flt, 0xC8)
    if cls != 0xFFFFFFFF and struct.unpack_from("<I", entry, 0x0C)[0] != cls:
        return False
    if user != 0xFFFFFFFF and struct.unpack_from("<I", entry, 0xC8)[0] != user:
        return False
    return True


def device_list(devices, flt, max_entries=MAX_ENTRIES):
    """Entries of `devices` that match the filter, at most `max_entries`."""
    flt = bytes(flt).ljust(ENTRY_SIZE, b"\xff")
    return [e for e in devices if matches(e, flt)][:max(0, min(max_entries, MAX_ENTRIES))]
