"""Unit test of the cross-process IPMI kernel (ipmikernel.py): a server in one fake process, a client in
another, the packets and replies between them.

    python -m psemu.tools_ipmitest
"""
import struct
import sys

from .ipmikernel import IpmiKernel, PKT_CONNECT, PKT_INVOKE


class Mem:
    def __init__(self):
        self.m = {}

    def mem_write(self, a, d):
        for i, b in enumerate(bytes(d)):
            self.m[a + i] = b

    def mem_read(self, a, n):
        return bytearray(self.m.get(a + i, 0) for i in range(n))


class Th:
    def __init__(self, tid):
        self.tid = tid


class Sched:
    def __init__(self):
        self.current = Th(1)
        self.blocked = []
        self.woken = []

    def block(self, what):
        self.blocked.append((self.current.tid, what["kind"]))

    def wake(self, t, value=0, error=False):
        self.woken.append(t.tid)


class Emu:
    def __init__(self, path):
        self.path, self.uc, self.sched = path, Mem(), Sched()


def main():
    ok = True

    def check(name, cond, extra=""):
        nonlocal ok
        ok &= bool(cond)
        print("  %-76s %s %s" % (name, "PASS" if cond else "FAIL", extra))

    k = IpmiKernel(log=lambda m: None)
    srv_emu, cli_emu = Emu("srv"), Emu("cli")
    k.create_server(srv_emu, "SceTest", 0x100, 0x5000)
    srv = k.server_of(srv_emu, 0x100)
    check("the server is registered and found by (process, kid)", srv is not None and k.is_routed("SceTest"))
    check("the audio service stays on the HLE", not (k.servers.update({"SceSysAudioSystemIpc": srv}) or k.is_routed("SceSysAudioSystemIpc")))

    # the server's receive thread parks on an empty queue
    srv_emu.sched.current = Th(7)
    rx = 0x1000
    srv_emu.uc.mem_write(rx, struct.pack("<QQQQ", 0x2000, 0x400, 0x3000, 0x3100))
    check("a receive on an empty queue blocks", k.receive(srv_emu, srv_emu.uc, srv, rx, 0x3200) is False
          and srv_emu.sched.blocked == [(7, "ipmi_receive")])

    # the client connects: the parked receive gets a type-1 packet
    cli_emu.uc.mem_write(0x100, struct.pack("<QQQQ", 0, 0, 0x180, 0))
    k.connect(cli_emu, cli_emu.uc, 0x101, "SceTest", 0x190, 0x100)
    hdr = bytes(srv_emu.uc.mem_read(0x3000, 0x28))
    ln, typ, sid, obj = struct.unpack_from("<QIIQ", hdr)
    check("the connect packet reaches the server with its type, session id and user object",
          typ == PKT_CONNECT and obj == 0x5000 and sid == 0x4000, (typ, hex(sid), hex(obj)))
    check("the server's receive thread was woken, the client blocked", srv_emu.sched.woken == [7]
          and cli_emu.sched.blocked == [(1, "ipmi_connect")])

    # the server registers its session object (cmd 4) and answers (cmd 0x212)
    k.handling[(id(srv_emu), id(srv_emu.sched.current))] = k.sessions[0x4000]
    srv_emu.uc.mem_write(0x1200, struct.pack("<QQ", 0x7777, 0))
    check("cmd 4 hands back a session handle", k.create_session_handle(srv_emu, srv_emu.uc, 0x1200, 0x1300)
          and struct.unpack("<I", bytes(srv_emu.uc.mem_read(0x1300, 4)))[0] == 0x2000)
    srv_emu.uc.mem_write(0x1400, struct.pack("<I", 0))
    k.server_call(srv_emu, srv_emu.uc, srv, 0x212, 0x4000, 0x1400, 4, 0x1500, 0)
    check("the connect answer releases the client, status 0 written to its pointers",
          cli_emu.sched.woken == [1] and struct.unpack("<I", bytes(cli_emu.uc.mem_read(0x190, 4)))[0] == 0
          and struct.unpack("<I", bytes(cli_emu.uc.mem_read(0x180, 4)))[0] == 0)

    # a sync invoke: packet type 0x41 with the session object as the context
    srv_emu.sched.current = Th(8)
    srv_emu.uc.mem_write(rx, struct.pack("<QQQQ", 0x2000, 0x400, 0x3000, 0x3100))
    k.receive(srv_emu, srv_emu.uc, srv, rx, 0x3200)
    cli_emu.uc.mem_write(0x400, b"hello\0")
    cli_emu.uc.mem_write(0x500, struct.pack("<QQ", 0x400, 6))                  # in info
    cli_emu.uc.mem_write(0x600, struct.pack("<IIIIQQQ", 0xaa120012, 1, 0, 0, 0x500, 0x700, 0x800))
    r = k.invoke_sync(cli_emu, cli_emu.uc, 0x101, "SceTest", 0x600, 0x850)
    body = bytes(srv_emu.uc.mem_read(0x2000, 0x40))
    ctx, token, method, n_in, n_out = struct.unpack_from("<QIIII", body)
    hdr = bytes(srv_emu.uc.mem_read(0x3000, 0x28))
    check("the invoke is delivered as type 0x41 with ctx, token, method and the input",
          r is False and hdr[8] == PKT_INVOKE and ctx == 0x7777 and method == 0xaa120012 and n_in == 1
          and body[0x18:0x1e] == b"\x06\0\0\0he", (hex(ctx), hex(method)))

    # the reply (cmd 0x232 on the session handle) completes the client
    cli_emu.sched.woken.clear()
    srv_emu.uc.mem_write(0x1600, struct.pack("<IIQII", 0, 0, 0, 1, 2))
    check("the reply completes the invoke: thread woken, method result and transport status written",
          k.reply(srv_emu, srv_emu.uc, 0x2000, 0x1600, 0x18, 0x1700) and cli_emu.sched.woken == [1]
          and bytes(cli_emu.uc.mem_read(0x800, 4)) == bytes(4) and bytes(cli_emu.uc.mem_read(0x850, 4)) == bytes(4))
    print("ipmi kernel:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
