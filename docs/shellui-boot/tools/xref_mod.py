import struct, sys, re, capstone
p=sys.argv[1]; needle=sys.argv[2].encode()
d=open(p,"rb").read()
phoff=struct.unpack_from("<Q",d,0x20)[0]; phnum=struct.unpack_from("<H",d,0x38)[0]; phes=struct.unpack_from("<H",d,0x36)[0]
segs=[]
for i in range(phnum):
    t,fl,off,va,pa,fs,ms,al=struct.unpack_from("<IIQQQQQQ",d,phoff+i*phes)
    if t==1: segs.append((off,va,fs))
def f2v(fo):
    for off,va,fs in segs:
        if off<=fo<off+fs: return va+fo-off
def v2f(v):
    for off,va,fs in segs:
        if va<=v<va+fs: return off+v-va
so=d.rfind(bytes([0]),0,d.find(needle))+1; sv=f2v(so); print("string at",hex(sv))
code=[(off,va,fs) for off,va,fs in segs][0]
off,va,fs=code
cd=d[off:off+fs]
res=[]
for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',cd):
    i=m.start(); rel=struct.unpack_from("<i",cd,i+3)[0]
    if va+i+7+rel==sv: res.append(va+i)
print("xrefs",[hex(x) for x in res])
if len(sys.argv)>3:
    start=int(sys.argv[3],16); n=int(sys.argv[4],16)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    fo=v2f(start)
    for ins in md.disasm(d[fo:fo+n],start): print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
