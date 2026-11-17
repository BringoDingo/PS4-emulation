import sys
sys.path.insert(0, r"D:\CLAUDEGODOT2")
from collections import defaultdict
from psemu import threads
from psemu.emulator import Emulator
EXE = r"D:\Ps4Tools\ps4kernel\firmware\system_ex\app\NPXS20001\eboot.bin"
FW  = r"D:\Ps4Tools\ps4kernel\firmware"
emu=Emulator(EXE,max_insns=2_000_000_000,fw_root=FW); emu.max_modules=80
emu.log=lambda *a,**k: None
orig=threads.Scheduler.switch
state={"last":0,"cur":None}
win=defaultdict(lambda: defaultdict(int))     # window -> tid -> insns
switches=defaultdict(int)
def sw(self):
    now=emu._insn_count
    prev=self.current.tid if self.current else None
    if prev is not None:
        win[now//250_000_000][prev]+= now-state["last"]
    state["last"]=now
    r=orig(self)
    switches[now//250_000_000]+=1
    return r
threads.Scheduler.switch=sw
emu.run()
print("\n=== instructions per thread per 250M window (top 5) ===")
for w in sorted(win):
    tot=sum(win[w].values()) or 1
    top=sorted(win[w].items(), key=lambda kv:-kv[1])[:5]
    print(f" window {w*250}M-{(w+1)*250}M  switches={switches[w]:6d}  "+"  ".join(f"{hex(t)}={100*n//tot}%" for t,n in top))
