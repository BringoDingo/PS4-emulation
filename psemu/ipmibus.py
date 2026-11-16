"""Shared IPMI bus for multi-process psemu (see MULTIPROCESS.md).

On a console, IPMI is how system processes talk: a process hosts a *service*
(server) under a name, other processes open a *client* for that name, connect,
and `invokeSyncMethod` to call it. psemu today runs one process at a time, so
`syscalls.py sys_ipmimgr_call` fakes service replies (HLE) because no real
server process exists. This module is the data model + routing that lets a real
server process (e.g. SceSysCore hosting SceSysCoreApp) receive invokes from a
client process (e.g. SceShellCore) once psemu runs them concurrently.

It is deliberately standalone (no Emulator/unicorn imports) so it can be unit
tested and wired in incrementally. Blocking is expressed by returning a
`Pending` token the caller's scheduler parks on; the bus never touches threads
itself. Guest memory transfer (reading the invoke's in-buffers, writing the
out-buffers) stays in the syscall layer, which owns the per-process Uc; the bus
only moves the *request/response records* between processes.

ipmimgr_call command numbers (from RE, see memory psemu-gnm-status):
  0x0   create server      0x2   create client
  0x400 connect            0x310 disconnect
  0x320 invokeSyncMethod   0x201 receive packet
  0x490 wait event flag    0x491 poll event flag
"""
from collections import deque


# IPMI packet types the libSceIpmi receive pump dispatches on (RE'd earlier):
PKT_SYNC_RESPONSE = 3        # reply to an invokeSyncMethod, delivered via vtable


class Request:
    """One in-flight invokeSyncMethod from a client to a server.

    The syscall layer fills `in_args` by reading the caller's in-buffers before
    handing the Request to the bus, and copies `out_args`/`result` back to the
    caller's out-buffers when the Request completes. `context` is the client
    object pointer libSceIpmi echoes into the type-3 response packet.
    """
    __slots__ = ("client_kid", "method", "in_args", "out_args", "result",
                 "context", "done")

    def __init__(self, client_kid, method, in_args, context=0):
        self.client_kid = client_kid
        self.method = method
        self.in_args = in_args        # list[bytes] copied from the caller
        self.out_args = []            # list[bytes] the server produced
        self.result = None            # method result (int); None = not replied
        self.context = context
        self.done = False


class Server:
    __slots__ = ("name", "owner", "pending", "evf")

    def __init__(self, name, owner):
        self.name = name
        self.owner = owner            # the Process hosting this service
        self.pending = deque()        # Requests waiting for the server to receive
        self.evf = {}                 # idx -> event-flag bit pattern


class Client:
    __slots__ = ("kid", "name", "owner", "server", "waiting")

    def __init__(self, kid, name, owner):
        self.kid = kid
        self.name = name
        self.owner = owner            # the Process that opened this client
        self.server = None            # resolved Server once connected
        self.waiting = None           # Request this client blocks on, if any


class IpmiBus:
    """System-wide registry + router. One instance lives on the shared System
    object every Process points at."""

    def __init__(self):
        self.servers = {}             # name -> Server
        self.clients = {}             # kid -> Client
        self._next_kid = 0x100

    # ---- lifecycle ------------------------------------------------------
    def create_server(self, name, owner):
        srv = self.servers.get(name)
        if srv is None:
            srv = self.servers[name] = Server(name, owner)
        return srv

    def create_client(self, name, owner):
        kid = self._next_kid
        self._next_kid += 1
        self.clients[kid] = Client(kid, name, owner)
        return kid

    def connect(self, kid):
        """Resolve a client to its server. Returns True if a real server is
        hosted (route to it), False if none exists yet (the caller should keep
        the console's 'session accepted, idle' behaviour)."""
        cl = self.clients.get(kid)
        if cl is None:
            return False
        cl.server = self.servers.get(cl.name)
        return cl.server is not None

    def disconnect(self, kid):
        cl = self.clients.pop(kid, None)
        if cl and cl.waiting is not None:
            cl.waiting.done = True

    # ---- invoke / receive routing --------------------------------------
    def invoke(self, kid, method, in_args, context=0):
        """Client invokes a method. If a real server hosts the service, queue a
        Request on it and return it (the caller blocks until req.done). Returns
        None when no server is hosted -> the syscall layer falls back to its HLE
        reply (the current single-process behaviour)."""
        cl = self.clients.get(kid)
        srv = cl.server if cl else None
        if srv is None:
            srv = self.servers.get(cl.name) if cl else None
        if srv is None:
            return None
        req = Request(kid, method, in_args, context)
        srv.pending.append(req)
        if cl:
            cl.waiting = req
        return req

    def receive(self, name):
        """A server process pops its next pending Request, or None if idle
        (the caller returns NO_PACKET 0x80020004 and retries)."""
        srv = self.servers.get(name)
        if srv is None or not srv.pending:
            return None
        return srv.pending.popleft()

    def reply(self, req, result, out_args):
        """The server finished a Request; wake the waiting client."""
        req.result = result
        req.out_args = out_args
        req.done = True
        cl = self.clients.get(req.client_kid)
        if cl and cl.waiting is req:
            cl.waiting = None

    # ---- housekeeping on process exit ----------------------------------
    def drop_process(self, owner):
        for name in [n for n, s in self.servers.items() if s.owner is owner]:
            del self.servers[name]
        for kid in [k for k, c in self.clients.items() if c.owner is owner]:
            del self.clients[kid]
