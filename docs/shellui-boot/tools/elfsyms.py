import struct, sys, hashlib, base64
SALT=bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
def nid(name):
    h=hashlib.sha1(name.encode()+SALT).digest()
    return base64.b64encode(struct.pack(">Q",struct.unpack("<Q",h[:8])[0])).decode().replace("/","-").rstrip("=")
def load(p):
    d=open(p,"rb").read()
    phoff=struct.unpack_from("<Q",d,0x20)[0]; phnum=struct.unpack_from("<H",d,0x38)[0]; phes=struct.unpack_from("<H",d,0x36)[0]
    segs=[];dyn=None
    for i in range(phnum):
        t,fl,off,va,pa,fs,ms,al=struct.unpack_from("<IIQQQQQQ",d,phoff+i*phes)
        if t==1: segs.append((off,va,fs))
        if t==2: dyn=(off,fs)
        if t==0x61000000: sce=(off,fs)
    def v2f(v):
        for off,va,fs in segs:
            if va<=v<va+fs: return off+v-va
        # sce dynlib data seg may be outside LOAD file ranges
        return None
    return d,segs,dyn,v2f
def exports(p):
    d,segs,dyn,v2f=load(p)
    # SCE dynlib data: DT_SCE_* tags in the dynamic table
    tags={}
    o,sz=dyn
    for i in range(sz//16):
        t,v=struct.unpack_from("<qQ",d,o+i*16)
        tags[t]=v
    return d,tags,v2f
if __name__=="__main__":
    p=sys.argv[1]
    d,tags,v2f=exports(p)
    print({hex(k&0xffffffff):hex(v) for k,v in tags.items()})

def symtab(p):
    d,segs,dyn,v2f=load(p)
    phoff=struct.unpack_from("<Q",d,0x20)[0]; phnum=struct.unpack_from("<H",d,0x38)[0]; phes=struct.unpack_from("<H",d,0x36)[0]
    base=None
    for i in range(phnum):
        t,fl,off,va,pa,fs,ms,al=struct.unpack_from("<IIQQQQQQ",d,phoff+i*phes)
        if t==0x61000000: base=off
    o,sz=dyn
    tags={}
    for i in range(sz//16):
        t,v=struct.unpack_from("<qQ",d,o+i*16); tags[t&0xffffffff]=v
    st=base+tags[0x61000039]; sn=tags[0x6100003f]//24; strt=base+tags[0x61000035]
    out={}
    for i in range(sn):
        nm,info,oth,shn,val,size=struct.unpack_from("<IBBHQQ",d,st+i*24)
        e=d.index(b"\0",strt+nm); name=d[strt+nm:e].decode()
        out[name]=val
    return out
