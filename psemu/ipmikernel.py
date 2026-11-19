"""The kernel side of IPMI between real processes (multi-process mode, see process.py).

libSceIpmi in each process talks to the kernel with `ipmimgr_call(cmd, kid, &result, &args, size)`.
Until now every client was answered by an HLE stub in syscalls.py because the service's process did not
exist. With a real server process (e.g. SceSysCore hosting SceSysCoreApp) the kernel's job is to carry
requests from the client's process to the server's receive pump and the answers back, copying buffers
between the two address spaces.

What is known (all from libSceIpmi.sprx; see docs/shellui-boot/README.md "IPMI between processes"):

  server   cmd 0x0    create server {u64 server_obj; u64 *name; u64 params} -> kid (per process)
           cmd 0x201  receive: args = {u64 data_buf; u64 size; u64 hdr_out; u64 *len_out}; blocks until a
                      packet is queued; fills data_buf and the 0x28-byte header
                         hdr +0x00 u64 data length   +0x08 u32 packet type   +0x0c u32 session id
                         hdr +0x10 u64 server_obj (the pointer the server passed at create)
           packet types: 0x01 a client connected (data = client info), 0x43 a sync method request, ...
           sync request data: u64 context; u32 token; u32 method; u32 n_in; n_in x {u32 len; bytes}
           cmd 0x444  dispatch finished: kid = session id, payload {u32 method}, 6th argument = the request token
           cmd 0x222  {u32 result} with kid = session id: the answer to a connect
           cmd 0x232  {u32 index; u32 flags; ptr data; u32 size}: reply data for a request
  client   cmd 0x2    create client {u64; u64 *name; u64 params} -> kid
           cmd 0x400  connect: the call blocks until the server accepted (cmd 0x222)
           cmd 0x320  invoke a sync method {u32 method; u32 n_in; u32 n_out; in info; out info; *result; flags}
                      and blocks until the server answered

Everything the real server does that is not in this list is logged once per (cmd) so the protocol can be
filled in from the running firmware, which is the only specification there is.
"""
import os
import struct
from collections import deque

PKT_CONNECT = 0x01
PKT_SYNC = 0x43
PKT_INVOKE = 0x41

HDR_SIZE = 0x28


class Server:
    def __init__(self, name, emu, kid, obj):
        self.name, self.emu, self.kid, self.obj = name, emu, kid, obj
        self.queue = deque()            # packets waiting for a receive
        self.waiters = deque()          # blocked receive calls: dict(thread, emu, ptrs, result_ptr)


class Session:
    def __init__(self, sid, client_emu, client_kid, server):
        self.sid, self.client_emu, self.client_kid, self.server = sid, client_emu, client_kid, server
        self.state = "connecting"
        self.waiting = None             # {thread, result_ptr, ...} of the client call blocked on this session
        self.pending = {}               # token -> dict(method, out info, result ptr, thread)
        self.next_token = 1


class IpmiKernel:
    # orbis_audiod's request handler waits for SceSysAudioSystemEvfTick, a tick the audio hardware
    # model does not produce yet; routing it parks AvControl's main thread, so the HLE answers it.
    # SceNpService: ShellCore's own np_ipc2 server rejects the ShellUI's first call (method 0: "invalid syncMethodId";
    # which service table a session gets is decided from state the emulator does not model yet), and the
    # ShellUI then fails initializeSystemAfterPsm. The HLE answers it as before.
    # SceNpService / SceNpTrophyIpc: ShellCore's np_ipc2 servers reject every call the ShellUI makes ("invalid
    # syncMethodId"; the method table a session gets depends on state not modelled yet) and the ShellUI then
    # fails initializeSystemAfterPsm; the HLE answers them as before.
    NOT_ROUTED = frozenset({"SceSysAudioSystemIpc", "SceNpService", "SceNpTrophyIpc", "SceNpMgrIpc"})

    def __init__(self, log=print, routed=None):
        self.log = log
        self.servers = {}               # name -> Server
        self.sessions = {}              # sid -> Session
        self.by_client = {}             # (emu id, client kid) -> Session
        self.next_sid = 0x4000
        self.routed = routed            # None = every hosted service; else a set of names
        self.unknown = set()
        self.handling = {}              # (id(emu), tid) -> Session whose connect packet that server thread is running
        self.next_skid = 0x2000
        self.last_app_id = None
        self.inflight = {}              # (id(emu), id(thread)) -> (Session, token) of the request that thread is serving
        self.skid_sess = {}             # session handle (cmd 0x4) -> Session

    # ------------------------------------------------------------ helpers
    def is_routed(self, name):
        if name in self.NOT_ROUTED and not os.environ.get("PSEMU_IPMI_ROUTE_AUDIO"):
            return False
        return name in self.servers and (self.routed is None or name in self.routed)

    def _once(self, key, msg):
        if key not in self.unknown:
            self.unknown.add(key)
            self.log(msg)

    # ------------------------------------------------------------ server side
    def create_server(self, emu, name, kid, obj):
        self.servers[name] = Server(name, emu, kid, obj)
        self.log(f"  [ipmi-k] server '{name}' registered (process {emu.path.rsplit(chr(92), 1)[-1]}, "
                 f"kid {kid:#x}, obj {obj:#x})")

    def server_of(self, emu, kid):
        for s in self.servers.values():
            if s.emu is emu and s.kid == kid:
                return s
        return None

    def receive(self, emu, uc, srv, in_ptr, result_ptr):
        """cmd 0x201 on a server kid. Returns True when the call completed now, False when it blocked."""
        if os.environ.get("PSEMU_IPMI_TRACE"):
            self.log(f"  [ipmi-k] {srv.name}: receive called by {getattr(emu.sched.current, 'tid', 0):#x}, queued {len(srv.queue)}")
        got = self.inflight.pop((id(emu), id(emu.sched.current)), None)
        if got is not None:
            # the thread is back in receive without having answered its request (the server's dispatcher
            # rejected it, e.g. "invalid syncMethodId"): a client must not wait for ever, so it gets an error
            sess, token = got
            pend = sess.pending.pop(token, None)
            if pend is not None:
                pend["res"] = 0x80020005
                self.log(f"  [ipmi-k] {srv.name}.{pend['method']:#x}: dropped by the server -> error {pend['res']:#x}")
                self._finish(pend)
        if srv.queue:
            self._deliver(emu, uc, srv, in_ptr, result_ptr, srv.queue.popleft())
            return True
        sched = emu.sched
        th = sched.current
        self._once(("rx", srv.name, id(th)), f"  [ipmi-k] {srv.name}: receive parked (thread {getattr(th, 'tid', th)})")
        srv.waiters.append({"thread": th, "emu": emu, "in_ptr": in_ptr, "result_ptr": result_ptr})
        sched.block({"kind": "ipmi_receive", "kid": srv.kid, "name": srv.name})
        return False

    def _deliver(self, emu, uc, srv, in_ptr, result_ptr, pkt, thread=None):
        ptype, sid, data = pkt
        buf, size, hdr, p_len = struct.unpack("<QQQQ", bytes(uc.mem_read(in_ptr, 0x20)))
        data = data[:size] if size else data
        if buf and data:
            uc.mem_write(buf, data)
        if ptype == PKT_INVOKE and sid in self.sessions and os.environ.get("PSEMU_IPMI_TRACE"):
            self.log(f"  [ipmi-k] {srv.name} request served by thread {(thread if thread is not None else emu.sched.current).tid:#x}")
        if ptype in (PKT_INVOKE, PKT_SYNC) and sid in self.sessions:
            self.inflight[(id(emu), id(thread if thread is not None else emu.sched.current))] = (self.sessions[sid], struct.unpack_from('<I', data, 8)[0])
        if ptype == PKT_CONNECT and sid in self.sessions:
            self.sessions[sid].conn_buf = buf
            self.handling[(id(emu), id(thread if thread is not None else emu.sched.current))] = self.sessions[sid]
        if srv.name == "SceNpService" and os.environ.get("PSEMU_IPMI_TRACE") and ptype in (PKT_INVOKE, PKT_SYNC):
            try:
                vt = struct.unpack("<Q", bytes(uc.mem_read(srv.obj, 8)))[0]
                self.log("  [ipmi-k] Np user object %#x vtable %#x: " % (srv.obj, vt) + " ".join(hex(x - 0x100000000) for x in struct.unpack("<10Q", bytes(uc.mem_read(vt, 80)))))
            except Exception as e:
                self.log(f"  [ipmi-k] Np vtable unreadable: {e}")
        if ptype in (PKT_SYNC, PKT_INVOKE) and os.environ.get("PSEMU_IPMI_TRACE"):
            try:
                cx = struct.unpack_from('<Q', data, 0)[0]
                if cx:
                    ob = struct.unpack('<4Q', bytes(uc.mem_read(cx, 32)))
                    vt = struct.unpack('<8Q', bytes(uc.mem_read(ob[0], 64))) if ob[0] else ()
                    self.log(f'  [ipmi-k] ctx {cx:#x}: {[hex(x) for x in ob]} vt {[hex(x) for x in vt]}')
                def q(a, n=8): return [hex(x) for x in struct.unpack(f"<{n}Q", bytes(uc.mem_read(a, 8 * n)))]
                o8 = struct.unpack("<Q", bytes(uc.mem_read(srv.obj + 8, 8)))[0]
                self.log(f"  [ipmi-k] userobj {srv.obj:#x}: {q(srv.obj, 4)}; [obj+8]={o8:#x}; vt(obj)={q(struct.unpack('<Q', bytes(uc.mem_read(srv.obj, 8)))[0], 6)}")
                try:
                    self.log(f"  [ipmi-k] vt([obj+8])={q(struct.unpack('<Q', bytes(uc.mem_read(o8, 8)))[0], 6)}")
                except Exception as e2:
                    self.log(f"  [ipmi-k] [obj+8] not an object: {e2}")
            except Exception as e:
                self.log(f"  [ipmi-k] deliver trace failed {e}")
        h = bytearray(HDR_SIZE)
        struct.pack_into("<QIIQ", h, 0, len(data), ptype, sid, srv.obj)
        if hdr:
            uc.mem_write(hdr, bytes(h))
        if p_len:
            uc.mem_write(p_len, struct.pack("<I", len(data)))
        if result_ptr:
            uc.mem_write(result_ptr, struct.pack("<I", 0))

    def _enqueue(self, srv, ptype, sid, data):
        pkt = (ptype, sid, data)
        if srv.waiters:
            w = srv.waiters.popleft()
            self._deliver(w["emu"], w["emu"].uc, srv, w["in_ptr"], w["result_ptr"], pkt, w["thread"])
            w["emu"].sched.wake(w["thread"], 0, False)
        else:
            srv.queue.append(pkt)

    # ------------------------------------------------------------ client side
    def connect(self, emu, uc, kid, name, result_ptr, in_ptr=0):
        """cmd 0x400: create a session and tell the server; the client blocks until it answers.
        Client struct: {u64 connect data; u64 its length; u64 *status out; u64 ?}."""
        srv = self.servers[name]
        sid = self.next_sid
        self.next_sid += 1
        sess = Session(sid, emu, kid, srv)
        self.sessions[sid] = sess
        self.by_client[(id(emu), kid)] = sess
        p_data = p_len = p_status = 0
        cdata = b""
        try:
            p_data, p_len, p_status, _x = struct.unpack("<QQQQ", bytes(uc.mem_read(in_ptr, 0x20)))
            if p_data and 0 < p_len <= 0x400:
                cdata = bytes(uc.mem_read(p_data, p_len))
        except Exception:
            pass
        sess.status_ptr = p_status
        self.log(f"  [ipmi-k]   client connect struct: {[hex(x) for x in struct.unpack('<4Q', bytes(uc.mem_read(in_ptr, 0x20)))]}")
        # server-side packet data: ..., u64 @0x148 (0 on arrival), u32 @0x150 connect data length, bytes @0x154
        info = bytearray(0x154) + cdata
        struct.pack_into("<I", info, 0x150, len(cdata))
        th = emu.sched.current
        sess.waiting = {"thread": th, "emu": emu, "result_ptr": result_ptr, "what": "connect"}
        self._enqueue(srv, PKT_CONNECT, sid, bytes(info))
        self.log(f"  [ipmi-k] connect '{name}' (client kid {kid:#x}) -> session {sid:#x}, connect data {cdata.hex()}")
        emu.sched.block({"kind": "ipmi_connect", "name": name, "sid": sid})

    def invoke_sync(self, emu, uc, kid, name, in_ptr, result_ptr=0):
        """cmd 0x320. Returns False when the caller was parked (the reply completes it)."""
        sess = self.by_client.get((id(emu), kid))
        if sess is None or sess.state != "connected":
            return None                                 # not routed: let the HLE answer
        a = bytes(uc.mem_read(in_ptr, 0x30))
        method, n_in, n_out = struct.unpack_from("<III", a, 0)
        if struct.unpack_from("<I", a, 0x28)[0] == 0:
            # flags == 0 (the first call of a client, method 0 {u32 in}, no output) is not a method the servers
            # dispatch: np_ipc2 answers it "invalid syncMethodId: 0" and never replies. It stays with the
            # kernel-side HLE (an empty success), as before routing.
            return None
        p_in, p_out, p_res = struct.unpack_from("<QQQ", a, 0x10)
        ins = []
        for i in range(min(n_in, 10)):
            d, sz = struct.unpack("<QQ", bytes(uc.mem_read(p_in + i * 16, 16)))
            ins.append(bytes(uc.mem_read(d, sz)) if sz else b"")
        token = sess.next_token
        sess.next_token += 1
        outs = []
        for i in range(min(n_out, 16)):
            info = p_out + i * 24
            d, sz = struct.unpack("<QQ", bytes(uc.mem_read(info, 16)))
            outs.append((d, sz, info))
        # packet type 0x41 (what a client sync invoke becomes on the server): u64 context, u32 token,
        # u32 method, u32 n_in, u32 n_out, then the inputs as {u32 len; bytes}, then each output's capacity
        wire_outs = [o for o in outs if o[1] > 0]      # an output with no room is not sent
        body = struct.pack("<QIIII", getattr(sess, "ctx", 0), token, method, len(ins), len(wire_outs)) + b"".join(
            struct.pack("<I", len(x)) + x for x in ins) + b"".join(struct.pack("<I", o[1]) for o in wire_outs)
        th = emu.sched.current
        sess.pending[token] = {"thread": th, "emu": emu, "method": method, "outs": outs, "p_res": p_res, "rp": result_ptr}
        ptype = PKT_INVOKE
        self._enqueue(sess.server, ptype, sess.sid, body)
        if os.environ.get("PSEMU_IPMI_TRACE") == "3":
            try:
                from unicorn.x86_const import UC_X86_REG_RSP
                rsp = uc.reg_read(UC_X86_REG_RSP)
                words = struct.unpack("<256Q", bytes(uc.mem_read(rsp, 2048)))
                ch = []
                for w in words:
                    m = emu.dyn.module_at(w) if getattr(emu, "dyn", None) else None
                    if m: ch.append(f"{m.name}+{w - m.base:#x}")
                self.log("  [ipmi-k]   client stack: " + " ".join(ch[:40]))
            except Exception as e:
                self.log(f"  [ipmi-k]   no stack: {e}")
        self.log(f"  [ipmi-k] sync {name}.{method:#x} in={[x[:12].hex() if len(x) <= 12 else len(x) for x in ins]} out={[o[1] for o in outs]} flags {a[0x28:0x30].hex()} token {token}")
        emu.sched.block({"kind": "ipmi_invoke", "name": name, "method": method})
        return False

    def create_session_handle(self, emu, uc, in_ptr, result_ptr):
        """cmd 0x4 (kid -1) {u64 object; u64 slot}: a server's connect callback registers the per-session
        object it just built and its slot record. The kernel returns a handle, written to *result (libSceIpmi
        keeps it in object+8; the app also feeds it to get_authinfo as the client's pid, so the low 16 bits are
        the pid and the rest tells one client's sessions apart). cmd 0x302 later gives the slot back, and the
        object is the context of every request on the session."""
        sess = self.handling.get((id(emu), id(emu.sched.current)))
        if sess is None:
            return False
        obj, aux = struct.unpack("<QQ", bytes(uc.mem_read(in_ptr, 16)))
        self.next_skid += 1
        kid = (sess.client_emu.syscalls.pid_of_process() & 0xFFFF) | ((self.next_skid & 0x7FFF) << 16)
        try:                                    # the second operand points at {u64 0x10; ...; u64 slot record @+8}
            slot = struct.unpack('<Q', bytes(uc.mem_read(aux + 8, 8)))[0]
        except Exception:
            slot = 0
        if os.environ.get('PSEMU_IPMI_TRACE'):
            try:
                self.log(f'  [ipmi-k]   cmd4 operands: obj {bytes(uc.mem_read(obj, 0x30)).hex()} aux {bytes(uc.mem_read(aux, 0x30)).hex()}')
            except Exception as e:
                self.log(f'  [ipmi-k]   cmd4 operands unreadable {e}')
        sess.ctx, sess.skid, sess.slot = obj, kid, slot
        self.skid_sess[kid] = sess
        self.log(f"  [ipmi-k] session {sess.sid:#x}: object {obj:#x}, slot {slot:#x} registered as handle {kid:#x}")
        if result_ptr:
            uc.mem_write(result_ptr, struct.pack("<I", kid))
        return True

    def client_pid(self, emu, uc, kid, in_ptr):
        """cmd 0x302 {u32 *out} on a session handle: the client's pid."""
        sess = self.skid_sess.get(kid)
        if sess is None:
            return False
        p = struct.unpack("<Q", bytes(uc.mem_read(in_ptr, 8)))[0]
        if p:
            uc.mem_write(p, struct.pack("<I", sess.client_emu.syscalls.pid_of_process()))
        return True

    def client_info(self, emu, uc, kid, in_ptr):
        """cmd 0x468 {u64 *out} on a session handle: the slot record registered with cmd 4."""
        sess = self.skid_sess.get(kid)
        if sess is None:
            return False
        p = struct.unpack("<Q", bytes(uc.mem_read(in_ptr, 8)))[0]
        if p:
            uc.mem_write(p, struct.pack("<Q", sess.slot))
        return True

    @staticmethod
    def _finish(pend):
        """Complete a client's sync invoke: the method result and the transport status (the syscall's
        result pointer) are written, then the thread resumes."""
        mem = pend["emu"].uc
        if pend["p_res"]:
            mem.mem_write(pend["p_res"], struct.pack("<I", pend.get("res", 0) & 0xFFFFFFFF))
        if pend.get("rp"):
            mem.mem_write(pend["rp"], struct.pack("<I", 0))
        pend["emu"].sched.wake(pend["thread"], 0, False)

    def reply(self, emu, uc, kid, in_ptr, size, result_ptr):
        """cmd 0x232 on a session handle {u32 method result; u32 ?; u64 out descriptor; u32 count; ..}: the
        answer to the request this thread is serving. The descriptor lists {u64 ptr; u64 len} per output;
        each is copied into the client's output buffer (in the client's address space)."""
        key = (id(emu), id(emu.sched.current))
        got = self.inflight.pop(key, None)
        sess = got[0] if got else self.skid_sess.get(kid)
        if sess is None:
            return False
        token = got[1] if got and got[0] is sess else (next(iter(sess.pending), None))
        pend = sess.pending.pop(token, None)
        if pend is None:
            return False
        res = 0
        try:
            raw = bytes(uc.mem_read(in_ptr, 0x18))
            res, _a, p, cnt = struct.unpack_from("<IIQI", raw, 0)
            for i in range(min(cnt, len(pend["outs"]))):
                sp, ln = struct.unpack("<QQ", bytes(uc.mem_read(p + 16 * i, 16)))
                d, cap, info = pend["outs"][i]
                if sp and d and 0 < ln <= cap:
                    pend["emu"].uc.mem_write(d, bytes(uc.mem_read(sp, ln)))
                    pend["emu"].uc.mem_write(info + 16, struct.pack("<Q", ln))
                    self.log(f"  [ipmi-k]   output {i}: {ln} bytes {bytes(uc.mem_read(sp, ln)).hex()}")
            self.log(f"  [ipmi-k] reply to {sess.server.name}.{pend['method']:#x}: result {res:#x}, {cnt} output(s)")
        except Exception as e:
            self.log(f"  [ipmi-k] reply (unreadable: {e})")
        pend["res"] = res
        if pend["method"] == 0xaa120000 and res < 0x80000000:
            self.last_app_id = res          # SceSysCoreApp2 createApp: the new application's id (it is then spawned)
        self._finish(pend)
        if result_ptr:
            uc.mem_write(result_ptr, struct.pack("<I", 0))
        return True

    # ------------------------------------------------------------ server replies
    def server_call(self, emu, uc, srv, cmd, kid, in_ptr, size, result_ptr, arg6):
        """A server-side command other than create/receive. Returns True if handled."""
        self._once(("sc", srv.name, cmd), f"  [ipmi-k] {srv.name} server cmd {cmd:#x} kid {kid:#x} size {size:#x}: "
                   + (bytes(uc.mem_read(in_ptr, min(size, 0x40))).hex() if in_ptr and size else ""))
        if cmd in (0x222, 0x212):                                # connect answer; kid = session id
            sess = self.sessions.get(kid)
            res = struct.unpack("<I", bytes(uc.mem_read(in_ptr, 4)))[0] if in_ptr else 0
            if sess is None:
                return False
            self.log(f"  [ipmi-k] connect answer for session {kid:#x}: {res:#x}")
            cb = getattr(sess, 'conn_buf', 0)
            if cb:
                self.log(f"  [ipmi-k]   connect buffer after the callback: {bytes(uc.mem_read(cb + 0x140, 0x30)).hex()}")
            sess.state = "connected" if res < 0x80000000 else "refused"      # a non-negative answer (e.g. a slot index) accepts; it is also the client's status
            self.handling.pop((id(emu), id(emu.sched.current)), None)
            w, sess.waiting = sess.waiting, None
            if w is not None:
                if w["result_ptr"]:
                    w["emu"].uc.mem_write(w["result_ptr"], struct.pack("<I", 0 if res < 0x80000000 else 1))
                if getattr(sess, 'status_ptr', 0):
                    w["emu"].uc.mem_write(sess.status_ptr, struct.pack("<I", res))
                w["emu"].sched.wake(w["thread"], 0, False)
            if result_ptr:
                uc.mem_write(result_ptr, struct.pack("<I", 0))
            return True
        if cmd in (0x469, 0x46a, 0x46b):                  # {char *buf}: the service name, used in log lines
            p = struct.unpack("<Q", bytes(uc.mem_read(in_ptr, 8)))[0]
            if p:
                uc.mem_write(p, srv.name.encode()[:0x3f] + bytes(1))
            if result_ptr:
                uc.mem_write(result_ptr, struct.pack("<I", 0))
            return True
        if cmd == 0x444:                                  # async dispatch finished: {u32 token}, kid = session id
            sess = self.sessions.get(kid)
            token = arg6 & 0xFFFFFFFF            # type 0x41: the request serial rides in the 6th argument, the payload is the method
            if sess and token not in sess.pending and in_ptr and size >= 4:
                token = struct.unpack("<I", bytes(uc.mem_read(in_ptr, 4)))[0]        # type 0x43: the payload is the serial
            pend = sess.pending.pop(token, None) if sess else None
            if pend is not None:
                self._finish(pend)
                self.log(f"  [ipmi-k] sync {srv.name}.{pend['method']:#x} done (token {token})")
            if result_ptr:
                uc.mem_write(result_ptr, struct.pack("<I", 0))
            return True
        return False
