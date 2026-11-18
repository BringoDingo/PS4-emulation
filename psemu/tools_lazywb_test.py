"""Native lazy write-back of render targets: deferral, eviction, flush, non-lazy submit, failure path.

    python -m psemu.tools_lazywb_test [--fw D:/Ps4Tools/ps4kernel/firmware]

Draws a full-screen quad with the system YUV shaders into one linear 256x256 RGBA target per
submit with gnm_set_lazy_writeback on (the backend keeps 8 surfaces), and checks, through the
guest-visible target memory and the watch events:
  * a lazily held surface leaves its guest memory untouched (sentinel stays) and emits "watch";
  * a surface evicted from the cache is written back first (memory shows the drawing) and unwatched;
  * flush_range on a held surface writes it back and unwatches it;
  * a later non-lazy submit that reuses a held surface writes it back and unwatches it;
  * backend.sync_watches() re-arms a watch and raises when the write-back fails (never silent).
"""
import argparse
import os
import sys

import numpy as np

W = H = 256
SENTINEL = np.array([255, 0, 255, 255], np.uint8)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--fw", default=r"D:\Ps4Tools\ps4kernel\firmware")
    a = ap.parse_args(argv)
    from .gnm import backend, pm4, sb

    app = os.path.join(a.fw, "system_ex", "app", "NPXS20118")
    vs = sb.load_sb(os.path.join(app, "yuv_vv.sb"))
    ps = sb.load_sb(os.path.join(app, "yuv_p.sb"))
    print("GPU:", backend.init())
    heap = backend.HostHeap()
    ybuf = heap.alloc(W * H)
    ybuf[:] = 180
    cbuf = heap.alloc(128 * (H // 2) * 2)
    cbuf[:] = 128
    t_y = backend.tsharp(ybuf, W, H, dfmt=1, nfmt=0, pitch=W)
    t_c = backend.tsharp(cbuf, W // 2, H // 2, dfmt=3, nfmt=0, pitch=128)
    s_lin = backend.ssharp()
    eaddr = heap.addr(heap.put(np.array(t_c + s_lin + [0] * 4, np.uint32)))
    ps_user = t_y + s_lin + [eaddr & 0xFFFFFFFF, eaddr >> 32]
    vr, pr = vs.default_regs(), ps.default_regs()
    vs_code, ps_code = backend.place_code(vs, heap), backend.place_code(ps, heap)

    ok = True

    def check(label, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print("   %-58s %s %s" % (label, "ok  " if cond else "FAIL", detail))

    def draw(rt, lazy):
        rt.reshape(H, W, 4)[:] = SENTINEL
        cb = pm4.CommandBuffer()
        cb.context_control().clear_state()
        cb.set_vs_shader(vs_code, vr["rsrc1"], vr["rsrc2"], vr.get("vs_out_config", 0),
                         vr.get("pos_format", 4), vr.get("pa_cl_vs_out_cntl", 0))
        cb.set_ps_shader(ps_code, pr["rsrc1"], pr["rsrc2"], pr["ps_input_ena"],
                         pr["ps_input_addr"], pr["ps_in_control"] & 0x3F, pr["col_format"],
                         pr.get("z_format", 0), pr.get("db_shader_control", 0x10),
                         pr.get("cb_shader_mask", 0xF))
        cb.set_user_data("ps", ps_user)
        cb.set_render_target(0, heap.addr(rt), W, H)
        cb.set_context_reg(pm4.CB_BLEND0_CONTROL, 0)
        cb.set_context_reg(pm4.VGT_SHADER_STAGES_EN, 0)
        cb.set_viewport(W, H)
        cb.set_primitive_type(pm4.PRIM_TRISTRIP)
        cb.index_type(False).num_instances(1)
        cb.set_context_reg(pm4.CB_TARGET_MASK, 0xF)
        cb.draw_index_auto(4)
        ring = pm4.CommandBuffer().indirect_buffer(heap.addr(heap.put(cb.words())), len(cb))
        backend.set_lazy_writeback(lazy)
        try:
            stats, err = backend.submit(ring.words())
        finally:
            backend.set_lazy_writeback(False)
        if err or stats["failed"]:
            print("      submit error:", err)
        return stats

    def drawn(rt):
        return not np.all(rt.reshape(H, W, 4) == SENTINEL)

    def untouched(rt):
        return bool(np.all(rt.reshape(H, W, 4) == SENTINEL))

    backend.watch_events()                       # drop anything queued before
    targets = [heap.alloc(W * H * 4) for _ in range(10)]
    watched = {}                                  # addr -> currently watched (replay of the events)

    def replay():
        for addr, size, op in backend.watch_events():
            watched[addr] = bool(op)

    print("ten lazy submits, one target each (the cache holds 8):")
    for rt in targets:
        draw(rt, True)
        replay()
    addrs = [heap.addr(t) for t in targets]
    held = [t for t, ad in zip(targets, addrs) if watched.get(ad)]
    evicted = [t for t, ad in zip(targets, addrs) if not watched.get(ad)]
    check("8 surfaces held lazily and watched", len(held) == 8, "(%d)" % len(held))
    check("held surfaces: guest memory untouched (deferred)", all(untouched(t) for t in held))
    check("2 evicted surfaces: written back with the drawing", len(evicted) == 2
          and all(drawn(t) for t in evicted), "(%d evicted)" % len(evicted))
    check("evicted surfaces are unwatched", all(not watched.get(heap.addr(t)) for t in evicted))
    check("the oldest two were the evicted ones",
          [heap.addr(t) for t in evicted] == addrs[:2])

    print("flush_range on a held surface:")
    t = held[3]
    backend.flush_range(heap.addr(t), t.nbytes)
    replay()
    check("memory now holds the drawing", drawn(t))
    check("surface is unwatched", not watched.get(heap.addr(t)))

    print("non-lazy submit reusing a held surface:")
    t = held[5]
    # redraw into the same target without lazy: the held image is reused, then written back
    rt_sentinel_before = untouched(t)
    draw(t, False)       # draw() re-fills the target with the sentinel (the guest 'CPU' wrote it)
    replay()
    check("memory shows the new drawing after a non-lazy submit", drawn(t) and rt_sentinel_before)
    check("surface is unwatched", not watched.get(heap.addr(t)))

    print("sync_watches (fake page-watch host):")

    class FakeUc:
        def __init__(self):
            self.added, self.removed = [], []

        def watch_add(self, addr, size, cb):
            self.added.append((addr, size, cb))

        def watch_remove(self, addr):
            self.removed.append(addr)

    uc = FakeUc()
    t = heap.alloc(W * H * 4)                     # a fresh target: a new watch transition
    draw(t, True)
    backend.sync_watches(uc)
    check("a lazy submit produces a watch for the surface",
          any(ad == heap.addr(t) for ad, _, _ in uc.added))
    cb_ = [c for ad, _, c in uc.added if ad == heap.addr(t)][-1]
    uc.added.clear()
    cb_(heap.addr(t), t.nbytes)                  # the guest 'touched' it
    check("the trap callback writes the surface back", drawn(t))
    check("...and drains an unwatch", heap.addr(t) in uc.removed)

    draw(t, True)
    backend.sync_watches(uc)
    uc.added.clear()
    real = backend.flush_range

    def failing(*args, **kw):
        raise backend.GnmError("injected write-back failure")
    backend.flush_range = failing
    try:
        raised = False
        try:
            cb_(heap.addr(t), t.nbytes)
        except backend.GnmError:
            raised = True
    finally:
        backend.flush_range = real
    check("a failed write-back raises (never silent)", raised)
    check("...and re-arms the watch (guest cannot read stale memory)",
          any(ad == heap.addr(t) for ad, sz, _ in uc.added),
          "(re-armed %d)" % len(uc.added))

    print("transactional event handling (the 2nd of 3 events fails):")
    backend.sync_watches(FakeUc())               # drain whatever is still queued
    fresh = [heap.alloc(W * H * 4) for _ in range(3)]
    for rt in fresh:
        draw(rt, True)                           # three new watch transitions queued natively
    want = [heap.addr(t) for t in fresh]

    class FailSecond(FakeUc):
        def __init__(self):
            super().__init__()
            self.calls = 0
            self.armed_fail = True

        def watch_add(self, addr, size, cb):
            self.calls += 1
            if self.armed_fail and self.calls == 2:
                raise RuntimeError("injected watch_add failure")
            super().watch_add(addr, size, cb)

    uc2 = FailSecond()
    raised = False
    try:
        backend.sync_watches(uc2)
    except RuntimeError:
        raised = True
    check("the failure propagates", raised)
    check("the 1st event was applied", [ad for ad, _, _ in uc2.added] == want[:1],
          "(%s)" % [hex(ad) for ad, _, _ in uc2.added])
    check("the failed and the 3rd event are retained, in order",
          [ev[0] for ev in uc2._gnm_pending if ev[2]] == want[1:],
          "(%d pending incl. unwatches of evicted surfaces)" % len(uc2._gnm_pending))
    uc2.armed_fail = False
    backend.sync_watches(uc2)                    # retry
    check("a retry applies each remaining event exactly once, in order",
          [ad for ad, _, _ in uc2.added] == want and not uc2._gnm_pending)
    check("...and the guard is released", not uc2._gnm_syncing)

    print("a failed re-arm is reported together with the write-back failure:")

    class NoRearm(FakeUc):
        def watch_add(self, addr, size, cb):
            if self.fail:
                raise RuntimeError("injected re-arm failure")
            super().watch_add(addr, size, cb)

    uc3 = NoRearm()
    uc3.fail = False
    t = heap.alloc(W * H * 4)
    draw(t, True)
    backend.sync_watches(uc3)
    cb3 = [c for ad, _, c in uc3.added if ad == heap.addr(t)][-1]
    uc3.fail = True
    backend.flush_range = failing
    try:
        err = None
        try:
            cb3(heap.addr(t), t.nbytes)
        except BaseException as e:
            err = e
    finally:
        backend.flush_range = real
    check("the original write-back failure is raised",
          isinstance(err, backend.GnmError) and "injected write-back failure" in str(err))
    check("...with the re-arm failure attached",
          err is not None and any("re-arm also failed" in n and "injected re-arm failure" in n
                                  for n in getattr(err, "__notes__", [])))

    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
