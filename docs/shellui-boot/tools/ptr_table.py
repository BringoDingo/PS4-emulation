"""Find tables of pointers to a given string in live guest memory and dump the table (WHP).

    python ptr_table.py 9 TITLE_ID [SORT_PRIORITY ...]

For each name: locate its address in the eboot image, scan the eboot's data segments for 8-byte
pointers to it (relocations are applied at load), then print the surrounding entries as
index, pointer, string, and the following qword (an id / flags / length) so a name->id table
shows up as consecutive records.
"""
import struct
import sys

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.emulator import Emulator

EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW = r"D:\Ps4Tools\ps4kernel\firmware"
secs = float(sys.argv[1])
names = [n.encode() for n in sys.argv[2:]]
BASE = 0x100000000
blob = open(EXE, "rb").read()
emu = Emulator(EXE, fw_root=FW, backend="whp")
emu.max_seconds = secs
emu.max_modules = 80
emu.log = lambda *a, **k: None
orig = emu._whp_tick
st = {"done": False}


def cstr(uc, a, n=48):
    try:
        raw = bytes(uc.mem_read(a, n)).split(bytes([0]))[0]
        return raw.decode("latin1") if raw and all(32 <= c < 127 for c in raw) else None
    except Exception:
        return None


def tick():
    orig()
    if st["done"] or emu.sched is None or emu._time() < 5:
        return
    st["done"] = True
    uc = emu.uc
    lo, n = BASE + 0xab0000, 0x100000                 # eboot data/bss region
    mem = bytes(uc.mem_read(lo, n))
    for nm in names:
        # string vaddrs: every NUL-delimited occurrence in the file
        vas = []
        pos = blob.find(nm + b"\x00")
        while pos >= 0:
            if pos == 0 or blob[pos - 1] == 0:
                vas.append(BASE + pos - 0x4000)
            pos = blob.find(nm + b"\x00", pos + 1)
        print(f"\n== {nm.decode()} at {[hex(v) for v in vas]}")
        for va in vas:
            pat = struct.pack("<Q", va)
            i = mem.find(pat)
            while i >= 0 and i % 8 == 0:
                slot = lo + i
                print(f"  pointer slot {slot:#x}; surrounding records (stride 8):")
                for k in range(-6, 9):
                    p = struct.unpack("<Q", bytes(uc.mem_read(slot + 8 * k, 8)))[0]
                    s = cstr(uc, p) if 0x100000000 <= p < 0x101000000 else None
                    print(f"    [{k:+d}] {slot + 8 * k:#x}: {p:#x}" + (f"  '{s}'" if s else ""))
                break
            else:
                pass
    emu.stop("scanned")


emu.uc.tick_cb = tick
emu.run()
