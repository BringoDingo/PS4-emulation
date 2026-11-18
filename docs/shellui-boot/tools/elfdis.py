"""Static disassembly of a firmware .sprx/.elf with its real segment map.

    python elfdis.py libScePad.sprx                 # list segments
    python elfdis.py libScePad.sprx 0x9e04           # file offset -> vaddr
    python elfdis.py libScePad.sprx 0x5dd0 0x80      # disassemble 0x80 bytes at vaddr 0x5dd0
"""
import struct, sys, capstone
p=r"D:/Ps4Tools/ps4kernel/firmware/system/common/lib/"+sys.argv[1]
d=open(p,"rb").read()
phoff=struct.unpack_from("<Q",d,0x20)[0]; phnum=struct.unpack_from("<H",d,0x38)[0]; phes=struct.unpack_from("<H",d,0x36)[0]
segs=[]
for i in range(phnum):
    t,fl,off,va,pa,fs,ms,al=struct.unpack_from("<IIQQQQQQ",d,phoff+i*phes)
    segs.append((t,fl,off,va,fs,ms))
    if len(sys.argv)<3: print(hex(t),hex(fl),hex(off),hex(va),hex(fs),hex(ms))
def f2v(fo):
    for t,fl,off,va,fs,ms in segs:
        if t==1 and off<=fo<off+fs: return va+fo-off
def v2f(v):
    for t,fl,off,va,fs,ms in segs:
        if t==1 and va<=v<va+fs: return off+v-va
if len(sys.argv)>=4:
    start=int(sys.argv[2],16); n=int(sys.argv[3],16)
    fo=v2f(start)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    for ins in md.disasm(d[fo:fo+n],start):
        print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
elif len(sys.argv)==3:
    print(hex(f2v(int(sys.argv[2],16))))
