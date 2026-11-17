import glob, struct, sys, collections, os

D = sys.argv[1]
files = sorted(glob.glob(os.path.join(D, "dcb_*.bin")))
print(len(files), "dcbs")
ps_use = collections.Counter()          # ps address -> draws
ps_first = {}
sizes = collections.Counter()           # draws per dcb
per_dcb = []
draw_kinds = collections.Counter()
vp = collections.Counter()
for n, f in enumerate(files):
    b = open(f, "rb").read()
    dw = struct.unpack("<%dI" % (len(b) // 4), b)
    i = 0
    ps_lo = None
    draws = 0
    vps = None
    while i < len(dw):
        h = dw[i]
        if h >> 30 != 3:
            i += 1
            continue
        cnt = ((h >> 16) & 0x3FFF) + 1
        op = (h >> 8) & 0xFF
        body = dw[i + 1:i + 1 + cnt]
        if op == 0x76 and cnt >= 2:                      # SET_SH_REG
            reg = body[0]
            for k, v in enumerate(body[1:]):
                if reg + k == 0x2C08 - 0x2C00 and False:
                    pass
            if reg <= 0x08 < reg + cnt - 1:
                ps_lo = body[1 + 0x08 - reg]
        elif op == 0x69 and cnt >= 2:                    # SET_CONTEXT_REG
            reg = body[0]
            if reg <= 0x10F < reg + cnt - 1 and reg + cnt - 1 >= 0x111:
                vps = tuple(struct.unpack("<f", struct.pack("<I", body[1 + 0x10F - reg + k]))[0] for k in range(2))
        elif op in (0x2D, 0x27):
            draws += 1
            draw_kinds[("auto" if op == 0x2D else "idx2", body[0] if op == 0x2D else body[0])] += 0
            ps_use[ps_lo] += 1
            ps_first.setdefault(ps_lo, n)
            if vps:
                vp[(round(vps[0]), round(vps[1]))] += 1
        i += 1 + cnt
    per_dcb.append(draws)
print("draws per dcb histogram:", sorted(collections.Counter(per_dcb).items())[:15])
print("distinct PS programs:", len(ps_use))
for ps, c in ps_use.most_common(12):
    print("  ps_lo=%s draws=%d first_dcb=%d" % (hex(ps) if ps is not None else None, c, ps_first[ps]))
print("viewport xscale,yscale:", vp.most_common(8))
