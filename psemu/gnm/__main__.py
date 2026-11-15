"""psemu GNM tools.

    python -m psemu.gnm disasm  FILE [--index N]      # GCN disassembly of shaders in a file
    python -m psemu.gnm translate FILE [--index N]    # recompile to SPIR-V (shadPS4 recompiler)
    python -m psemu.gnm scan DIR [--report out.txt]   # recompile every shader under DIR
    python -m psemu.gnm cs-test                       # firmware compute shaders via PM4 dispatch
    python -m psemu.gnm yuv [--fw DIR] [--sd] [--image in.png] [--out out.png] [--pm4]
                                                      # run the firmware's YUV->RGB shaders on the GPU
                                                      # (--pm4: through a GNM command buffer)
"""
import argparse
import collections
import os
import re
import sys
import time

import numpy as np

from . import sb

DEFAULT_FW = r"D:\Ps4Tools\ps4kernel\firmware"


def _load_any(path):
    if path.lower().endswith(".sb"):
        return [sb.load_sb(path)]
    with open(path, "rb") as fh:
        return list(sb.find_shaders(fh.read(), path))


def cmd_disasm(a):
    shaders = _load_any(a.file)
    for i, s in enumerate(shaders):
        if a.index is not None and i != a.index:
            continue
        print("#%d %s" % (i, s.describe()))
        print(s.disassemble())
        print()


def cmd_translate(a):
    from . import backend
    backend.set_log_level(a.log)
    for i, s in enumerate(_load_any(a.file)):
        if a.index is not None and i != a.index:
            continue
        try:
            spv, summary = backend.translate(s)
            print("#%d %s ok: %s" % (i, s.stage, summary))
            if a.spv:
                out = "%s.%d.%s.spv" % (a.spv, i, s.stage)
                spv.tofile(out)
                print("   wrote", out)
        except backend.GnmError as e:
            print("#%d %s FAILED: %s" % (i, s.stage, e))


def _norm_error(msg):
    msg = msg.strip().splitlines()[0] if msg.strip() else "?"
    return re.sub(r"0x[0-9a-fA-F]+|\b\d+\b", "N", msg)[:160]


def cmd_scan(a):
    from . import backend
    backend.set_log_level(5)        # keep recompiler chatter out of the report
    t0 = time.time()
    ok = total = 0
    by_stage = collections.Counter()
    ok_stage = collections.Counter()
    errors = collections.Counter()
    examples = {}
    seen = set()
    for path, shaders in sb.scan_tree(a.dir):
        for s in shaders:
            key = (s.hash0, s.hash1, s.length)
            if key in seen:          # identical shader in several files
                continue
            seen.add(key)
            total += 1
            by_stage[s.stage] += 1
            try:
                backend.translate(s)
                ok += 1
                ok_stage[s.stage] += 1
            except backend.GnmError as e:
                k = _norm_error(str(e))
                errors[k] += 1
                examples.setdefault(k, "%s @%#x" % (os.path.relpath(path, a.dir), s.code_off))
            except Exception as e:   # never let one file stop the scan
                k = "python: " + _norm_error(repr(e))
                errors[k] += 1
                examples.setdefault(k, os.path.relpath(path, a.dir))
    lines = ["GNM shader recompile scan of %s" % a.dir,
             "%d unique shaders, %d recompiled to SPIR-V (%.1f%%), %.0fs" % (
                 total, ok, 100.0 * ok / max(total, 1), time.time() - t0), "", "by stage:"]
    for st, n in sorted(by_stage.items()):
        lines.append("  %-4s %5d / %5d ok" % (st, ok_stage[st], n))
    lines += ["", "failures by cause:"]
    for k, n in errors.most_common():
        lines.append("  %5d  %s\n         e.g. %s" % (n, k, examples[k]))
    text = "\n".join(lines)
    print(text)
    if a.report:
        with open(a.report, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print("\nreport written to", a.report)


# ----------------------------------------------------------------- yuv test

def _test_pattern(w, h):
    """Colour bars over a hue/brightness sweep: exercises every channel."""
    img = np.zeros((h, w, 3), np.float32)
    bars = np.array([[.75, .75, .75], [.75, .75, 0], [0, .75, .75], [0, .75, 0],
                     [.75, 0, .75], [.75, 0, 0], [0, 0, .75]], np.float32)
    top = h // 2
    idx = np.minimum((np.arange(w) * 7) // w, 6)
    img[:top] = bars[idx][None]
    x = np.linspace(0, 1, w, dtype=np.float32)[None, :]
    y = np.linspace(0, 1, h - top, dtype=np.float32)[:, None]
    hue = x * 6.0
    c = np.stack([np.clip(np.abs(hue - 3) - 1, 0, 1), np.clip(2 - np.abs(hue - 2), 0, 1),
                  np.clip(2 - np.abs(hue - 4), 0, 1)], -1)
    img[top:] = c * (1 - y[..., None]) + y[..., None] * 0.5
    return img


def _rgb_to_nv12_bt709(rgb):
    """Limited-range BT.709 Y'CbCr, chroma 2x2 subsampled (Y plane + CbCr plane)."""
    r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    yl = 0.2126 * r + 0.7152 * g + 0.0722 * b
    cb = (b - yl) / 1.8556
    cr = (r - yl) / 1.5748
    Y = np.clip(np.rint(16 + 219 * yl), 0, 255).astype(np.uint8)
    h, w = Y.shape
    cb2 = cb[: h // 2 * 2, : w // 2 * 2].reshape(h // 2, 2, w // 2, 2).mean((1, 3))
    cr2 = cr[: h // 2 * 2, : w // 2 * 2].reshape(h // 2, 2, w // 2, 2).mean((1, 3))
    CbCr = np.stack([np.clip(np.rint(128 + 224 * cb2), 0, 255),
                     np.clip(np.rint(128 + 224 * cr2), 0, 255)], -1).astype(np.uint8)
    return Y, CbCr


def _rgb_to_nv12_bt601(rgb):
    r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    yl = 0.299 * r + 0.587 * g + 0.114 * b
    cb = (b - yl) / 1.772
    cr = (r - yl) / 1.402
    Y = np.clip(np.rint(16 + 219 * yl), 0, 255).astype(np.uint8)
    h, w = Y.shape
    cb2 = cb[: h // 2 * 2, : w // 2 * 2].reshape(h // 2, 2, w // 2, 2).mean((1, 3))
    cr2 = cr[: h // 2 * 2, : w // 2 * 2].reshape(h // 2, 2, w // 2, 2).mean((1, 3))
    CbCr = np.stack([np.clip(np.rint(128 + 224 * cb2), 0, 255),
                     np.clip(np.rint(128 + 224 * cr2), 0, 255)], -1).astype(np.uint8)
    return Y, CbCr


def _report(out, src, label, a):
    from PIL import Image
    rgb = out[..., :3].astype(np.float32) / 255.0
    mse = float(np.mean((rgb - src) ** 2))
    psnr = 10 * np.log10(1.0 / max(mse, 1e-12))
    print("%s: match vs source image: PSNR %.1f dB, max abs error %d/255" % (
        label, psnr, int(np.abs(out[..., :3].astype(int) - np.rint(src * 255).astype(int)).max())))
    Image.fromarray(np.ascontiguousarray(out[..., :3])).save(a.out)
    ref = os.path.splitext(a.out)[0] + "_source.png"
    Image.fromarray(np.rint(src * 255).astype(np.uint8)).save(ref)
    print("wrote", a.out, "and", ref)
    return psnr


def cmd_yuv(a):
    from . import backend, pm4
    from PIL import Image

    backend.set_log_level(a.log)
    app = os.path.join(a.fw, "system_ex", "app", "NPXS20118")
    vs = sb.load_sb(os.path.join(app, "yuv_vv.sb"))
    ps = sb.load_sb(os.path.join(app, "yuv_sd_p.sb" if a.sd else "yuv_p.sb"))
    print("GPU:", backend.init())

    if a.image:
        src = np.asarray(Image.open(a.image).convert("RGB"), np.float32) / 255.0
        h, w = src.shape[:2]
        w, h = w // 2 * 2, h // 2 * 2
        src = src[:h, :w]
    else:
        w, h = a.width, a.height
        src = _test_pattern(w, h)
    Y, CbCr = (_rgb_to_nv12_bt601 if a.sd else _rgb_to_nv12_bt709)(src)

    heap = backend.HostHeap()
    pitch_y = (w + 63) // 64 * 64              # linear-aligned pitch, like GNM
    pitch_c = (w // 2 + 63) // 64 * 64
    ybuf = heap.alloc(pitch_y * h)
    ybuf.reshape(h, pitch_y)[:, :w] = Y
    cbuf = heap.alloc(pitch_c * (h // 2) * 2)
    cbuf.reshape(h // 2, pitch_c, 2)[:, : w // 2] = CbCr

    t_y = backend.tsharp(ybuf, w, h, dfmt=1, nfmt=0, pitch=pitch_y)          # R8 unorm
    t_c = backend.tsharp(cbuf, w // 2, h // 2, dfmt=3, nfmt=0, pitch=pitch_c)  # R8G8 unorm
    s_lin = backend.ssharp(clamp=2, bilinear=True)

    # User data exactly as the shader's input-usage slots describe:
    #   s0-7 T# (Y), s8-11 S#, s12-13 -> extended user data table holding
    #   [T# CbCr @dword 0][S# @dword 8]  (slots at s16 and s24 = table + 0/8)
    eud = heap.put(np.array(t_c + s_lin + [0] * 4, np.uint32))
    eaddr = heap.addr(eud)
    ps_user = t_y + s_lin + [eaddr & 0xFFFFFFFF, eaddr >> 32]
    for slot in ps.slots:
        print("   ps input:", slot)

    if not a.pm4:
        t0 = time.perf_counter()
        out = backend.draw(vs, ps, w, h, heap, ps_user=ps_user, prim=backend.PRIM_TRISTRIP,
                           vertex_count=4)
        print("rendered %dx%d with %s + %s in %.1f ms (includes recompiling both shaders)" % (
            w, h, os.path.basename(vs.path), os.path.basename(ps.path),
            (time.perf_counter() - t0) * 1000))
        return _report(out, src, "direct draw", a)

    # ---- the same draw as a GNM command buffer -------------------------------
    pitch = (w + 63) // 64 * 64
    rt = heap.alloc(pitch * h * 4)
    rt.reshape(h, pitch, 4)[:] = (255, 0, 255, 255)   # magenta: must be fully overwritten
    fence = heap.alloc(16)
    vr, pr = vs.default_regs(), ps.default_regs()

    cb = pm4.CommandBuffer()
    cb.context_control().clear_state()
    cb.set_vs_shader(backend.place_code(vs, heap), vr["rsrc1"], vr["rsrc2"],
                     vr.get("vs_out_config", 0), vr.get("pos_format", 4),
                     vr.get("pa_cl_vs_out_cntl", 0))
    cb.set_ps_shader(backend.place_code(ps, heap), pr["rsrc1"], pr["rsrc2"],
                     pr["ps_input_ena"], pr["ps_input_addr"], pr["ps_in_control"] & 0x3F,
                     pr["col_format"], pr.get("z_format", 0),
                     pr.get("db_shader_control", 0x10), pr.get("cb_shader_mask", 0xF))
    cb.set_user_data("ps", ps_user)
    cb.set_render_target(0, heap.addr(rt), pitch, h)
    cb.set_context_reg(pm4.CB_TARGET_MASK, 0xF)
    cb.set_context_reg(pm4.CB_BLEND0_CONTROL, 0)
    cb.set_context_reg(pm4.VGT_SHADER_STAGES_EN, 0)
    cb.set_viewport(w, h)
    if a.rectlist:
        # yuv_vv makes a full-screen quad from the vertex index: its first
        # three vertices are three corners, the RectList's implied 4th closes it
        cb.set_primitive_type(pm4.PRIM_RECTLIST)
        cb.index_type(False).num_instances(1)
        cb.draw_index_auto(3)
    else:
        cb.set_primitive_type(pm4.PRIM_TRISTRIP)
        cb.index_type(False).num_instances(1)
        cb.draw_index_auto(4)
    cb.event_write_eop(heap.addr(fence), 0xC0FFEE)

    # submit it the way the driver does: a small ring entry calling the
    # command buffer through INDIRECT_BUFFER
    dcb = heap.put(cb.words())
    ring = pm4.CommandBuffer().indirect_buffer(heap.addr(dcb), len(cb))
    print("command buffer: %d dwords, %d packets" % (len(cb), len(pm4.decode(cb.words()))))
    backend.reset_gpu()
    t0 = time.perf_counter()
    stats, err = backend.submit(ring.words())
    dt = (time.perf_counter() - t0) * 1000
    print("submitted in %.1f ms: %s" % (dt, stats))
    if err:
        print("first error:", err)
    fv = int(fence.view(np.uint32)[0])
    print("EOP fence = %#x (%s)" % (fv, "signalled" if fv == 0xC0FFEE else "NOT signalled"))
    out = rt.reshape(h, pitch, 4)[:, :w]
    untouched = int(np.all(out == (255, 0, 255, 255), axis=-1).sum())
    print("render target pixels left magenta: %d" % untouched)
    return _report(out, src, "PM4 command buffer", a)


def cmd_depth_test(a):
    """Depth/stencil through PM4: clears, depth tests and writes, stencil
    replace/compare, a resident surface reused within one submit - checked in
    the (tiled) guest depth and stencil planes, for Z32F/Z16 with and without
    stencil in several depth tile modes."""
    from . import backend, pm4

    backend.set_log_level(a.log)
    app = os.path.join(a.fw, "system_ex", "app", "NPXS20118")
    vs = sb.load_sb(os.path.join(app, "yuv_vv.sb"))
    ps = sb.load_sb(os.path.join(app, "yuv_p.sb"))
    print("GPU:", backend.init())
    heap = backend.HostHeap()
    w = h = 256
    ybuf = heap.alloc(w * h)
    ybuf[:] = 180
    cbuf = heap.alloc(128 * (h // 2) * 2)
    cbuf[:] = 128
    t_y = backend.tsharp(ybuf, w, h, dfmt=1, nfmt=0, pitch=w)
    t_c = backend.tsharp(cbuf, w // 2, h // 2, dfmt=3, nfmt=0, pitch=128)
    s_lin = backend.ssharp()
    eaddr = heap.addr(heap.put(np.array(t_c + s_lin + [0] * 4, np.uint32)))
    ps_user = t_y + s_lin + [eaddr & 0xFFFFFFFF, eaddr >> 32]
    vr, pr = vs.default_regs(), ps.default_regs()
    vs_code, ps_code = backend.place_code(vs, heap), backend.place_code(ps, heap)
    rt = heap.alloc(w * h * 4)
    magenta = np.array([255, 0, 255, 255], np.uint8)

    ok = True

    def check(label, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print("   %-46s %s %s" % (label, "ok  " if cond else "FAIL", detail))

    for z_format, stencil, mode in ((pm4.Z_32_FLOAT, True, 0), (pm4.Z_16, True, 2),
                                    (pm4.Z_16, False, 4), (pm4.Z_32_FLOAT, False, 5)):
        zb = 4 if z_format == pm4.Z_32_FLOAT else 2
        ztb, _, _ = backend.tiling_info(mode, zb, w, h)
        zbuf = heap.alloc(ztb)
        sbuf = heap.alloc(backend.tiling_info(mode, 1, w, h)[0]) if stencil else None
        zbuf.view(np.uint8)[:] = 0x3E      # garbage: the clear must replace it
        print("Z%s%s, tile mode %d:" % ("32F" if zb == 4 else "16", "+S8" if stencil else "",
                                        mode))

        def depth():
            d = backend.detile(mode, zbuf, zb, w, h)[:h, :w]
            if zb == 4:
                return d.view(np.float32)[..., 0]
            return d.view(np.uint16)[..., 0].astype(np.float32) / 65535.0

        def stencil_plane():
            return backend.detile(mode, sbuf, 1, w, h)[:h, :w, 0]

        def run(*steps, colour=True):
            """One submit; each step sets state and is followed by a draw."""
            rt.reshape(h, w, 4)[:] = magenta
            cb = pm4.CommandBuffer()
            cb.context_control().clear_state()
            cb.set_vs_shader(vs_code, vr["rsrc1"], vr["rsrc2"], vr.get("vs_out_config", 0),
                             vr.get("pos_format", 4), vr.get("pa_cl_vs_out_cntl", 0))
            cb.set_ps_shader(ps_code, pr["rsrc1"], pr["rsrc2"], pr["ps_input_ena"],
                             pr["ps_input_addr"], pr["ps_in_control"] & 0x3F, pr["col_format"],
                             pr.get("z_format", 0), pr.get("db_shader_control", 0x10),
                             pr.get("cb_shader_mask", 0xF))
            cb.set_user_data("ps", ps_user)
            cb.set_render_target(0, heap.addr(rt), w, h)
            cb.set_context_reg(pm4.CB_BLEND0_CONTROL, 0)
            cb.set_context_reg(pm4.VGT_SHADER_STAGES_EN, 0)
            cb.set_viewport(w, h)
            cb.set_depth_target(heap.addr(zbuf), heap.addr(sbuf) if stencil else 0, w, h,
                                z_format, mode)
            cb.set_primitive_type(pm4.PRIM_TRISTRIP)
            cb.index_type(False).num_instances(1)
            for step in steps:
                cb.set_context_reg(pm4.CB_TARGET_MASK, 0xF)
                cb.set_depth_clear()
                step(cb)
                cb.draw_index_auto(4)
            ring = pm4.CommandBuffer().indirect_buffer(heap.addr(heap.put(cb.words())), len(cb))
            backend.reset_gpu()
            stats, err = backend.submit(ring.words())
            if err or stats["failed"]:
                print("      submit error:", err)
            img = rt.reshape(h, w, 4)
            frac = float(np.mean(np.any(img != magenta, axis=-1)))
            if os.environ.get("PSEMU_DEPTH_DEBUG") and 0 < frac:
                u, n = np.unique(img.reshape(-1, 4), axis=0, return_counts=True)
                print("      rt colours:", [(tuple(int(x) for x in c), int(k))
                                            for c, k in zip(u[:4], n[:4])],
                      "stats:", stats)
            return frac

        def clear(z=1.0, s=0):
            def step(cb):
                cb.set_context_reg(pm4.CB_TARGET_MASK, 0)
                cb.set_depth_control(z_enable=True, z_write=True, stencil_enable=stencil)
                cb.set_depth_clear(depth=z, stencil=s if stencil else None)
            return step

        drawn = run(clear(1.0, 0))
        d = depth()
        check("clear: depth = 1.0 everywhere", np.all(d == 1.0), "(%.4f..%.4f)" % (d.min(), d.max()))
        if stencil:
            check("clear: stencil = 0", np.all(stencil_plane() == 0))
        check("clear: no colour written", drawn == 0.0, "(%.0f%% drawn)" % (drawn * 100))

        def z_test(func, write=True, s_func=pm4.CMP_ALWAYS, s_on=False, ref=0x5A,
                   zpass=pm4.STENCIL_KEEP):
            def step(cb):
                cb.set_depth_control(z_enable=True, z_write=write, z_func=func,
                                     stencil_enable=s_on and stencil, s_func=s_func)
                cb.set_stencil(ref=ref, zpass=zpass)
            return step

        drawn = run(z_test(pm4.CMP_LESS, s_on=True, zpass=pm4.STENCIL_REPLACE_TEST))
        d = depth()
        zq = float(d[h // 2, w // 2])
        check("LESS + write: quad drawn", drawn == 1.0, "(%.0f%%)" % (drawn * 100))
        check("depth written (uniform, < 1.0)", np.all(d == zq) and zq < 1.0, "(z = %.4f)" % zq)
        if stencil:
            check("stencil REPLACE -> 0x5A", np.all(stencil_plane() == 0x5A))
        drawn = run(z_test(pm4.CMP_LESS))
        check("LESS again (same z): nothing drawn", drawn == 0.0, "(%.0f%%)" % (drawn * 100))
        drawn = run(z_test(pm4.CMP_LEQUAL))
        check("LEQUAL: drawn", drawn == 1.0, "(%.0f%%)" % (drawn * 100))
        if stencil:
            drawn = run(z_test(pm4.CMP_ALWAYS, write=False, s_on=True, s_func=pm4.CMP_EQUAL))
            check("stencil EQUAL 0x5A: drawn", drawn == 1.0, "(%.0f%%)" % (drawn * 100))
            drawn = run(z_test(pm4.CMP_ALWAYS, write=False, s_on=True, s_func=pm4.CMP_NOTEQUAL))
            check("stencil NOTEQUAL 0x5A: nothing drawn", drawn == 0.0, "(%.0f%%)" % (drawn * 100))
        # resident within one submit: clear to 0, then LESS must fail everywhere
        drawn = run(clear(0.0, 0), z_test(pm4.CMP_LESS))
        d = depth()
        check("one submit: clear 0.0 then LESS -> nothing", drawn == 0.0 and np.all(d == 0.0),
              "(%.0f%% drawn, z max %.4f)" % (drawn * 100, d.max()))
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def _find_shader(path, code_off):
    with open(path, "rb") as fh:
        blob = fh.read()
    for s in sb.find_shaders(blob, path):
        if s.code_off == code_off:
            return s
    raise SystemExit("no shader at %#x in %s" % (code_off, path))


def _cs_rsrc(user_sgprs, vgprs=32, tgid=(1, 0, 0), tid_comps=2):
    """COMPUTE_PGM_RSRC1/2 for shaders found without their registers."""
    rsrc1 = ((vgprs + 3) // 4 - 1) | (((48 + 7) // 8 - 1) << 6)
    rsrc2 = ((user_sgprs & 0x1F) << 1) | (tgid[0] << 7) | (tgid[1] << 8) | (tgid[2] << 9) |         (tid_comps << 11)
    return rsrc1, rsrc2


def _run_cs(shader, heap, user, threads, groups, fence):
    from . import backend, pm4
    rsrc1, rsrc2 = _cs_rsrc(len(user))
    cb = pm4.CommandBuffer()
    cb.set_cs_shader(backend.place_code(shader, heap), rsrc1, rsrc2, threads)
    cb.set_user_data("cs", user)
    cb.dispatch_direct(*groups)
    cb.event_write_eop(heap.addr(fence), 0x600D)
    t0 = time.perf_counter()
    stats, err = backend.submit(cb.words())
    dt = (time.perf_counter() - t0) * 1000
    fv = int(fence.view(np.uint32)[0])
    print("   %d dispatch(es) in %.1f ms, fence %s%s" % (
        stats["dispatches"], dt, "signalled" if fv == 0x600D else "NOT signalled",
        ("; error: " + err) if err else ""))
    fence[:] = 0
    return stats


def cmd_cs_test(a):
    """Run two firmware compute shaders through PM4 DISPATCH_DIRECT and check
    their results against NumPy."""
    from . import backend, resources
    backend.set_log_level(a.log)
    print("GPU:", backend.init())
    backend.reset_gpu()
    heap = backend.HostHeap()
    fence = heap.alloc(16)
    ok = True

    # 1) bdj.elf: dst[i] = src[i] for float4 records, i = group*64 + thread
    sh = _find_shader(os.path.join(a.fw, "system_ex", "app", "NPXS20113", "bdj.elf"), 0x47e228)
    print("bdj.elf @0x47e228 (buffer copy, %d bytes of GCN):" % sh.length)
    n = 64 * 37
    src = np.random.default_rng(1).random((n, 4), dtype=np.float32)
    sbuf, dbuf = heap.put(src), heap.alloc(n * 16)
    v_src = resources.make_vsharp(heap.addr(sbuf), n, stride=16, dfmt=14, nfmt=7)
    v_dst = resources.make_vsharp(heap.addr(dbuf), n, stride=16, dfmt=14, nfmt=7)
    _run_cs(sh, heap, v_src + v_dst, (64, 1, 1), (n // 64, 1, 1), fence)
    got = dbuf.view(np.float32).reshape(n, 4)
    good = np.array_equal(got, src)
    ok &= good
    print("   %d records copied, exact match: %s" % (n, good))

    # 2) libSceDepth: out[r] = sum_{k<80} min(in[r*80+k], 1024) for r < 50,
    #    a scalar loop with a backward branch; one row per thread (y), 4 per group
    sh = _find_shader(os.path.join(a.fw, "system", "common", "lib", "libSceDepth.sprx"),
                      0xbc29e)
    print("libSceDepth.sprx @0xbc29e (row sums with a loop, %d bytes of GCN):" % sh.length)
    rows, cols = 50, 80
    data = (np.random.default_rng(2).random(rows * cols, dtype=np.float32) * 2048).astype(
        np.float32)
    ibuf, obuf = heap.put(data), heap.alloc(rows * 4)
    v_in = resources.make_vsharp(heap.addr(ibuf), rows * cols, stride=4, dfmt=4, nfmt=7)
    v_out = resources.make_vsharp(heap.addr(obuf), rows, stride=4, dfmt=4, nfmt=7)
    _run_cs(sh, heap, v_in + v_out, (1, 4, 1), ((rows + 3) // 4, 1, 1), fence)
    got = obuf.view(np.float32)
    want = np.minimum(data.reshape(rows, cols), 1024.0).sum(axis=1, dtype=np.float32)
    err = float(np.max(np.abs(got - want) / np.maximum(want, 1)))
    good = err < 1e-5
    ok &= good
    print("   %d row sums, max relative error %.2e: %s" % (rows, err, good))
    print("PASS" if ok else "FAIL")
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m psemu.gnm", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("disasm")
    p.add_argument("file")
    p.add_argument("--index", type=int)
    p.set_defaults(fn=cmd_disasm)
    p = sub.add_parser("translate")
    p.add_argument("file")
    p.add_argument("--index", type=int)
    p.add_argument("--spv", help="write SPIR-V files with this path prefix")
    p.add_argument("--log", type=int, default=3)
    p.set_defaults(fn=cmd_translate)
    p = sub.add_parser("scan")
    p.add_argument("dir", nargs="?", default=DEFAULT_FW)
    p.add_argument("--report")
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("cs-test")
    p.add_argument("--fw", default=DEFAULT_FW)
    p.add_argument("--log", type=int, default=3)
    p.set_defaults(fn=cmd_cs_test)
    p = sub.add_parser("yuv")
    p.add_argument("--fw", default=DEFAULT_FW)
    p.add_argument("--sd", action="store_true", help="use yuv_sd_p.sb (BT.601)")
    p.add_argument("--image", help="RGB image to convert and decode (default: test pattern)")
    p.add_argument("--width", type=int, default=1280)
    p.add_argument("--height", type=int, default=720)
    p.add_argument("--out", default="gnm_yuv.png")
    p.add_argument("--pm4", action="store_true",
                   help="drive the draw through a PM4 command buffer into a guest render target")
    p.add_argument("--rectlist", action="store_true",
                   help="with --pm4: draw the quad as a 3-vertex RectList instead of a strip")
    p.add_argument("--log", type=int, default=3)
    p.set_defaults(fn=cmd_yuv)
    p = sub.add_parser("depth-test", help="depth/stencil through PM4 (clears, tests, planes)")
    p.add_argument("--fw", default=DEFAULT_FW)
    p.add_argument("--log", type=int, default=3)
    p.set_defaults(fn=cmd_depth_test)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(0 if main() is not False else 1)
