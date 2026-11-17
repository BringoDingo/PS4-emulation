import struct, sys
P = sys.argv[1] if len(sys.argv)>1 else r"C:\x"
b = open(P, "rb").read()
dw = struct.unpack("<%dI" % (len(b)//4), b)
OPS = {0x10:"NOP",0x11:"SET_BASE",0x12:"CLEAR_STATE",0x13:"INDEX_BUFFER_SIZE",0x15:"DISPATCH_DIRECT",0x16:"DISPATCH_INDIRECT",
 0x25:"DRAW_INDEX_AUTO_?",0x27:"DRAW_INDEX_2?",0x2D:"DRAW_INDEX_AUTO",0x2A:"INDEX_TYPE",0x3C:"WAIT_REG_MEM",0x3D:"MEM_WRITE?",
 0x37:"WRITE_DATA",0x46:"EVENT_WRITE",0x47:"EVENT_WRITE_EOP",0x48:"EVENT_WRITE_EOS",0x49:"RELEASE_MEM",0x68:"SET_CONFIG_REG",
 0x69:"SET_CONTEXT_REG",0x76:"SET_SH_REG",0x79:"SET_UCONFIG_REG",0x1C:"?",0x1D:"?",0x1F:"?",0x35:"DMA_DATA?",0x41:"DMA_DATA",0x50:"DMA_DATA",
 0x43:"?",0x44:"?",0x7F:"?", 0x2C:"DRAW_INDEX_?",0x28:"CONTEXT_CONTROL",0x3F:"INDIRECT_BUFFER",0x32:"INDEX_BASE?",0x33:"?",0x34:"?"}
i = 0
while i < len(dw):
    h = dw[i]
    t = h >> 30
    if t == 3:
        cnt = ((h >> 16) & 0x3FFF) + 1
        op = (h >> 8) & 0xFF
        body = dw[i+1:i+1+cnt]
        print("%04x: T3 op=%#04x %-18s cnt=%d  %s" % (i*4, op, OPS.get(op, "?"), cnt, " ".join("%08x" % x for x in body[:8]) + (" ..." if cnt > 8 else "")))
        i += 1 + cnt
    elif t == 2:
        print("%04x: T2 filler" % (i*4)); i += 1
    else:
        print("%04x: T%d %08x" % (i*4, t, h)); i += 1
