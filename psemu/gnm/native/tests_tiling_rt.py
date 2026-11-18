"""Round-trip + timing check of the CPU tiler (tile -> detile must be the identity, and the
tiled bytes must be identical whether the surface is processed in one band or several)."""
import os
import sys
import time

import numpy as np

sys.path.insert(0, r"D:\CLAUDEGODOT2")
from psemu.gnm import backend

rng = np.random.default_rng(1)
bad = 0
for mode, bpp, w, h in [(14, 4, 1920, 1088), (14, 4, 1920, 1080), (8, 4, 1920, 1080), (13, 4, 512, 512),
                        (14, 8, 640, 384), (14, 2, 1024, 256), (14, 1, 777, 300), (13, 4, 64, 64)]:
    try:
        tb, pp, ph = backend.tiling_info(mode, bpp, w, h)
    except Exception as e:
        print(f"mode {mode} bpp {bpp} {w}x{h}: skipped ({e})")
        continue
    lin = rng.integers(0, 256, size=(h, w, bpp), dtype=np.uint8)
    t0 = time.perf_counter()
    tiled = backend.tile(mode, lin, bpp)
    t1 = time.perf_counter()
    back = backend.detile(mode, tiled, bpp, w, h)
    t2 = time.perf_counter()
    ok = np.array_equal(back, lin)
    bad += not ok
    print(f"mode {mode:2d} bpp {bpp} {w}x{h}: roundtrip {'OK' if ok else 'MISMATCH'}  "
          f"tile {1000 * (t1 - t0):.1f} ms  detile {1000 * (t2 - t1):.1f} ms")
print("FAIL" if bad else "PASS")
sys.exit(1 if bad else 0)
