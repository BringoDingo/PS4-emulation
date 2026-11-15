"""Blocking synchronisation syscalls: FreeBSD 9 `_umtx_op` and Sony event flags.

These are the calls that put a thread to sleep until another thread (or a
timeout on psemu's virtual clock) wakes it. They run on threads.Scheduler:
`block()` parks the calling thread, `wake()` makes it runnable with a return
value. Errors are plain errno values; libkernel turns them into 0x8002xxxx.

_umtx_op(obj, op, val, uaddr1, uaddr2) - the primitive libthr builds mutexes,
condition variables, rwlocks, semaphores and pthread_join on. Waiters queue
per guest address. Kernel-managed locks (MUTEX_LOCK, rwlocks) hand ownership
straight to the woken thread, so a woken thread never has to retry.

Event flags (538-546): a 64-bit pattern; waiters wait for AND/OR of bits and
may clear them on wake. Semantics follow shadPS4's
core/libraries/kernel/threads/event_flag.cpp (GPL-2.0-or-later); the syscall
argument layout is libkernel's (the API passes its arguments through).

Semaphores (549-556, sceKernel*Sema): a counter with a maximum; waiters ask
for `need` tokens. Semantics follow shadPS4's threads/semaphore.cpp; the
layout is libkernel's: create(name, attr, init, max) returns the handle
(libkernel stores it in *sem), wait(h, need, u32 *timeout_us),
poll(h, need), signal(h, n), cancel(h, set_count, int *num_waiters).
Waiters queue in arrival order (thread priorities are not modelled).
"""
import struct

EPERM, EDEADLK, EACCES, EFAULT, EBUSY, EINVAL = 1, 11, 13, 14, 16, 22
ESRCH, ETIMEDOUT, ECANCELED = 3, 60, 85

SYNC_SYSCALLS = {
    538: "evf_create", 539: "evf_delete", 540: "evf_open", 541: "evf_close",
    542: "evf_wait", 543: "evf_trywait", 544: "evf_set", 545: "evf_clear",
    546: "evf_cancel",
    549: "osem_create", 550: "osem_delete", 551: "osem_open", 552: "osem_close",
    553: "osem_wait", 554: "osem_trywait", 555: "osem_post", 556: "osem_cancel",
}

# _umtx_op operations (FreeBSD 9)
UMTX_OP_WAIT, UMTX_OP_WAKE = 2, 3
UMTX_OP_MUTEX_TRYLOCK, UMTX_OP_MUTEX_LOCK, UMTX_OP_MUTEX_UNLOCK = 4, 5, 6
UMTX_OP_SET_CEILING = 7
UMTX_OP_CV_WAIT, UMTX_OP_CV_SIGNAL, UMTX_OP_CV_BROADCAST = 8, 9, 10
UMTX_OP_WAIT_UINT = 11
UMTX_OP_RW_RDLOCK, UMTX_OP_RW_WRLOCK, UMTX_OP_RW_UNLOCK = 12, 13, 14
UMTX_OP_WAIT_UINT_PRIVATE, UMTX_OP_WAKE_PRIVATE = 15, 16
UMTX_OP_MUTEX_WAIT, UMTX_OP_MUTEX_WAKE = 17, 18
UMTX_OP_SEM_WAIT, UMTX_OP_SEM_WAKE = 19, 20
UMTX_OP_NWAKE_PRIVATE = 21
UMTX_OP_MUTEX_WAKE2 = 22

UMUTEX_CONTESTED = 0x80000000
CVWAIT_ABSTIME = 0x02
URWLOCK_WRITE_OWNER, URWLOCK_WRITE_WAITERS, URWLOCK_READ_WAITERS = 0x80000000, 0x40000000, \
    0x20000000
URWLOCK_READER_MASK = 0x1FFFFFFF

EVF_ATTR_SINGLE, EVF_ATTR_MULTI = 0x10, 0x20
EVF_WAITMODE_AND, EVF_WAITMODE_OR = 0x01, 0x02
EVF_WAITMODE_CLEAR_ALL, EVF_WAITMODE_CLEAR_PAT = 0x10, 0x20


class EventFlag:
    def __init__(self, handle, name, attr, bits, external=False):
        self.handle = handle
        self.name = name
        self.attr = attr
        self.bits = bits & 0xFFFFFFFFFFFFFFFF
        self.waiters = []        # threads, FIFO
        # Opened, not created, here: on a real console another process
        # (SceSysCore, SceShellCore...) owns and sets it.
        self.external = external
        self.assumed = set()     # (bits, mode) we stood in for that owner

    @property
    def single(self):
        return not (self.attr & EVF_ATTR_MULTI)

    def satisfied(self, bits, mode):
        if mode & EVF_WAITMODE_AND:
            return self.bits & bits == bits
        return self.bits & bits != 0

    def consume(self, bits, mode):
        if mode & EVF_WAITMODE_CLEAR_ALL:
            self.bits = 0
        elif mode & EVF_WAITMODE_CLEAR_PAT:
            self.bits &= ~bits & 0xFFFFFFFFFFFFFFFF


class Semaphore:
    def __init__(self, handle, name, attr, init, maximum, external=False):
        self.handle = handle
        self.name = name
        self.attr = attr
        self.count = init
        self.init = init
        self.max = maximum
        self.waiters = []          # [Thread] in arrival order
        self.external = external   # opened only: owned by a process psemu doesn't run
        self.assumed = False


def _s32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


class SyncSyscalls:
    """Mixin for SyscallDispatcher (needs self.emu, self._args, self._ret,
    self._new_handle, self._read_cstr)."""

    # ---- helpers ---------------------------------------------------------
    def _sync_init(self):
        if not hasattr(self, "umtx_q"):
            self.umtx_q = {}           # guest address -> [Thread] (FIFO)
            self.evfs = {}             # handle -> EventFlag
            self.sems = {}             # handle -> Semaphore
            self.umtx_ops = {}         # op -> count (summary)

    def _rd32(self, uc, a):
        return struct.unpack("<I", bytes(uc.mem_read(a, 4)))[0]

    def _wr32(self, uc, a, v):
        uc.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))

    def _rel_timeout_ns(self, uc, ts_ptr):
        """Relative struct timespec* -> ns (None = no timeout)."""
        if not ts_ptr:
            return None
        sec, nsec = struct.unpack("<qq", bytes(uc.mem_read(ts_ptr, 16)))
        return max(0, sec) * 1_000_000_000 + max(0, nsec)

    def _queue(self, addr):
        return self.umtx_q.setdefault(addr, [])

    def _sleep_on(self, addr, what, timeout_ns=None, **extra):
        """Block the current thread on umtx address `addr`."""
        sched = self.emu.sched
        t = sched.current
        self._queue(addr).append(t)

        def on_timeout(th, addr=addr):
            q = self.umtx_q.get(addr, [])
            if th in q:
                q.remove(th)
        wait = {"kind": what, "addr": addr, "on_timeout": on_timeout}
        wait.update(extra)
        sched.block(wait,
                    deadline_ns=None if timeout_ns is None else sched.now_ns() + timeout_ns,
                    timeout_ret=(ETIMEDOUT, True))

    def _wake_addr(self, addr, n, value=0):
        """Wake up to n threads sleeping on `addr`; returns how many."""
        q = self.umtx_q.get(addr, [])
        woken = 0
        while q and woken < n:
            t = q.pop(0)
            if self.emu.sched.wake(t, value):
                woken += 1
        return woken

    def umtx_wake(self, addr, n):
        self._sync_init()
        return self._wake_addr(addr, n)

    def _tid(self):
        return self.emu.sched.current.tid

    # ---- _umtx_op --------------------------------------------------------
    def sys__umtx_op(self, uc):
        self._sync_init()
        obj, op, val, uaddr1, uaddr2 = self._args(uc)[:5]
        op &= 0xFFFFFFFF
        self.umtx_ops[op] = self.umtx_ops.get(op, 0) + 1
        try:
            rv = self._umtx(uc, obj, op, val, uaddr1, uaddr2)
        except Exception as e:                # bad guest pointer
            self.emu.log(f"  [_umtx_op] op {op} on {obj:#x}: {e}")
            rv = EFAULT
        if rv is None:                         # blocked: result comes on wake
            return
        self._ret(uc, rv, error=rv != 0)

    def _umtx(self, uc, obj, op, val, uaddr1, uaddr2):
        if op in (UMTX_OP_WAIT, UMTX_OP_WAIT_UINT, UMTX_OP_WAIT_UINT_PRIVATE):
            cur = struct.unpack("<Q", bytes(uc.mem_read(obj, 8)))[0] if op == UMTX_OP_WAIT \
                else self._rd32(uc, obj)
            want = val if op == UMTX_OP_WAIT else val & 0xFFFFFFFF
            if cur != want:
                return 0
            self._sleep_on(obj, "umtx_wait", self._rel_timeout_ns(uc, uaddr2))
            return None
        if op in (UMTX_OP_WAKE, UMTX_OP_WAKE_PRIVATE):
            self._wake_addr(obj, val & 0x7FFFFFFF)
            return 0
        if op == UMTX_OP_NWAKE_PRIVATE:
            for i in range(val & 0xFFFF):
                a = struct.unpack("<Q", bytes(uc.mem_read(obj + 8 * i, 8)))[0]
                self._wake_addr(a, 1 << 30)
            return 0
        if op == UMTX_OP_MUTEX_WAIT:
            owner = self._rd32(uc, obj)
            if owner & ~UMUTEX_CONTESTED == 0:
                return 0                      # unlocked: go retry the CAS
            self._wr32(uc, obj, owner | UMUTEX_CONTESTED)
            self._sleep_on(obj, "mutex_wait", None)
            return None
        if op in (UMTX_OP_MUTEX_WAKE, UMTX_OP_MUTEX_WAKE2):
            owner = self._rd32(uc, obj)
            if owner & ~UMUTEX_CONTESTED:
                return 0                      # owned again meanwhile
            q = self.umtx_q.get(obj, [])
            if len(q) <= 1 and owner == UMUTEX_CONTESTED:
                self._wr32(uc, obj, 0)
            self._wake_addr(obj, 1)
            return 0
        if op in (UMTX_OP_MUTEX_LOCK, UMTX_OP_MUTEX_TRYLOCK):
            tid = self._tid()
            owner = self._rd32(uc, obj)
            if owner & ~UMUTEX_CONTESTED == 0:
                waiters = bool(self.umtx_q.get(obj))
                self._wr32(uc, obj, tid | (UMUTEX_CONTESTED if waiters else 0))
                return 0
            if owner & ~UMUTEX_CONTESTED == tid:
                return EDEADLK
            if op == UMTX_OP_MUTEX_TRYLOCK:
                return EBUSY
            self._wr32(uc, obj, owner | UMUTEX_CONTESTED)
            self._sleep_on(obj, "mutex_lock", self._rel_timeout_ns(uc, uaddr2), lock=True)
            return None
        if op == UMTX_OP_MUTEX_UNLOCK:
            return self._mutex_unlock(uc, obj)
        if op == UMTX_OP_SET_CEILING:
            if uaddr1:
                self._wr32(uc, uaddr1, 0)
            return 0
        if op == UMTX_OP_CV_WAIT:
            # obj = struct ucond {u32 c_has_waiters; u32 c_flags; ...}
            # uaddr1 = the umutex to release, uaddr2 = timeout (val & ABSTIME)
            self._wr32(uc, obj, 1)
            if uaddr1:
                rv = self._mutex_unlock(uc, uaddr1)
                if rv:
                    return rv
            timeout = None
            if uaddr2:
                sec, nsec = struct.unpack("<qq", bytes(uc.mem_read(uaddr2, 16)))
                ns = max(0, sec) * 1_000_000_000 + max(0, nsec)
                if val & CVWAIT_ABSTIME:
                    clockid = self._rd32(uc, obj + 4)     # c_clockid (CLOCK_REALTIME = 0)
                    base = self.REALTIME_EPOCH_NS if clockid == 0 else 0
                    ns = max(0, ns - base - self.emu.sched.now_ns())
                timeout = ns
            self._sleep_on(obj, "cv_wait", timeout)
            return None
        if op in (UMTX_OP_CV_SIGNAL, UMTX_OP_CV_BROADCAST):
            self._wake_addr(obj, 1 if op == UMTX_OP_CV_SIGNAL else 1 << 30)
            if not self.umtx_q.get(obj):
                self._wr32(uc, obj, 0)
            return 0
        if op == UMTX_OP_SEM_WAIT:
            # struct _usem {u32 has_waiters; u32 count; u32 flags}
            if self._rd32(uc, obj + 4):
                return 0
            self._wr32(uc, obj, 1)
            self._sleep_on(obj, "sem_wait", self._rel_timeout_ns(uc, uaddr2))
            return None
        if op == UMTX_OP_SEM_WAKE:
            self._wake_addr(obj, 1)
            if not self.umtx_q.get(obj):
                self._wr32(uc, obj, 0)
            return 0
        if op in (UMTX_OP_RW_RDLOCK, UMTX_OP_RW_WRLOCK):
            return self._rw_lock(uc, obj, op == UMTX_OP_RW_WRLOCK, self._rel_timeout_ns(uc, uaddr2))
        if op == UMTX_OP_RW_UNLOCK:
            return self._rw_unlock(uc, obj)
        self.emu.log(f"  [_umtx_op] unsupported op {op} on {obj:#x} -> EINVAL")
        return EINVAL

    def _mutex_unlock(self, uc, m):
        """Release a umutex the current thread owns; hand it to a waiter."""
        tid = self._tid()
        owner = self._rd32(uc, m)
        if owner & ~UMUTEX_CONTESTED != tid:
            return EPERM
        q = self.umtx_q.get(m, [])
        sched = self.emu.sched
        # a kernel-managed locker (MUTEX_LOCK) takes ownership directly;
        # MUTEX_WAIT sleepers only get woken to retry their CAS
        while q:
            t = q.pop(0)
            if t.state != "blocked":
                continue
            if isinstance(t.wait, dict) and t.wait.get("lock"):
                self._wr32(uc, m, t.tid | (UMUTEX_CONTESTED if q else 0))
            else:
                self._wr32(uc, m, UMUTEX_CONTESTED if q else 0)
            sched.wake(t, 0)
            return 0
        self._wr32(uc, m, 0)
        return 0

    # struct urwlock {i32 rw_state; u32 rw_flags; u32 rw_blocked_readers;
    #                 u32 rw_blocked_writers; ...}
    def _rw_lock(self, uc, rw, write, timeout_ns):
        state = self._rd32(uc, rw)
        if write:
            if state & (URWLOCK_WRITE_OWNER | URWLOCK_READER_MASK) == 0:
                self._wr32(uc, rw, state | URWLOCK_WRITE_OWNER)
                return 0
            self._wr32(uc, rw, state | URWLOCK_WRITE_WAITERS)
        else:
            if not state & (URWLOCK_WRITE_OWNER | URWLOCK_WRITE_WAITERS):
                self._wr32(uc, rw, state + 1)
                return 0
            self._wr32(uc, rw, state | URWLOCK_READ_WAITERS)
        self._sleep_on(rw, "rw_wrlock" if write else "rw_rdlock", timeout_ns, writer=write)
        return None

    def _rw_unlock(self, uc, rw):
        state = self._rd32(uc, rw)
        if state & URWLOCK_WRITE_OWNER:
            state &= ~URWLOCK_WRITE_OWNER
        elif state & URWLOCK_READER_MASK:
            state -= 1
        else:
            return EPERM
        q = self.umtx_q.get(rw, [])
        sched = self.emu.sched
        writers = [t for t in q if t.wait and t.wait.get("writer")]
        readers = [t for t in q if t.wait and not t.wait.get("writer")]
        if state & URWLOCK_READER_MASK == 0 and writers:
            t = writers[0]
            q.remove(t)
            state |= URWLOCK_WRITE_OWNER
            if len(writers) == 1:
                state &= ~URWLOCK_WRITE_WAITERS
            sched.wake(t, 0)
        elif not writers and readers:
            for t in readers:
                q.remove(t)
                state += 1
                sched.wake(t, 0)
            state &= ~URWLOCK_READ_WAITERS
        self._wr32(uc, rw, state)
        return 0

    # ---- event flags -----------------------------------------------------
    def _evf(self, handle):
        self._sync_init()
        return self.evfs.get(handle & 0xFFFFFFFF)

    def sys_evf_create(self, uc):
        # evf_create(const char *name, u32 attr, u64 init_pattern) -> handle
        self._sync_init()
        name_ptr, attr, init = self._args(uc)[:3]
        name = self._read_cstr(uc, name_ptr, 32)
        h = self._new_handle("evf", name)
        self.evfs[h] = EventFlag(h, name, attr & 0xFFFFFFFF, init)
        self.emu.log(f"  [evf] create '{name}' attr={attr & 0xFFFFFFFF:#x} "
                     f"bits={init:#x} -> {h:#x}")
        self._ret(uc, h)

    def sys_evf_open(self, uc):
        # evf_open(const char *name): flags created by other processes are
        # created here on first open (psemu runs one process)
        self._sync_init()
        name = self._read_cstr(uc, self._args(uc)[0], 32)
        ef = next((e for e in self.evfs.values() if e.name == name), None)
        if ef is None:
            h = self._new_handle("evf", name)
            ef = self.evfs[h] = EventFlag(h, name, EVF_ATTR_MULTI, 0, external=True)
            self.emu.log(f"  [evf] open '{name}': owned by another system process "
                         f"-> stand-in {h:#x}")
        self._ret(uc, ef.handle)

    def sys_evf_close(self, uc):
        self._ret(uc, 0 if self._evf(self._args(uc)[0]) else ESRCH,
                  error=not self._evf(self._args(uc)[0]))

    def sys_evf_delete(self, uc):
        ef = self._evf(self._args(uc)[0])
        if ef is None:
            return self._ret(uc, ESRCH, error=True)
        for t in list(ef.waiters):
            self.emu.sched.wake(t, EACCES, True)
        ef.waiters.clear()
        del self.evfs[ef.handle]
        self._ret(uc, 0)

    def _evf_result(self, uc, ptr, bits):
        if ptr:
            uc.mem_write(ptr, struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))

    def sys_evf_wait(self, uc):
        # evf_wait(handle, u64 pattern, u32 mode, u64 *result, u32 *timeout_us)
        h, bits, mode, result, timeout_p = self._args(uc)[:5]
        mode &= 0xFFFFFFFF
        ef = self._evf(h)
        if ef is None:
            return self._ret(uc, ESRCH, error=True)
        if not bits or not mode & (EVF_WAITMODE_AND | EVF_WAITMODE_OR):
            return self._ret(uc, EINVAL, error=True)
        if ef.satisfied(bits, mode):
            self._evf_result(uc, result, ef.bits)
            ef.consume(bits, mode)
            return self._ret(uc, 0)
        if ef.single and ef.waiters:
            return self._ret(uc, EPERM, error=True)
        timeout_us = self._rd32(uc, timeout_p) if timeout_p else None
        if ef.external:
            # The owner process isn't emulated; on a booted console it has
            # set these bits (boot status, service ready...). Stand in for it.
            # This holds whether or not the caller passed a timeout: the bits
            # would be set on real hardware, so satisfy the wait immediately
            # instead of blocking/polling until the timeout fires.
            if (bits, mode) not in ef.assumed:
                ef.assumed.add((bits, mode))
                self.emu.log(f"  [evf] '{ef.name}': no owner process here - assuming "
                             f"bits {bits:#x} are set (as on a booted system)")
            ef.bits |= bits
            self._evf_result(uc, result, ef.bits)
            ef.consume(bits, mode)
            return self._ret(uc, 0)
        if timeout_us == 0:
            self._evf_result(uc, result, ef.bits)
            return self._ret(uc, ETIMEDOUT, error=True)
        sched = self.emu.sched
        t = sched.current
        ef.waiters.append(t)

        def on_timeout(th, ef=ef, result=result, timeout_p=timeout_p):
            if th in ef.waiters:
                ef.waiters.remove(th)
            self._evf_result(self.emu.uc, result, ef.bits)
            if timeout_p:
                self._wr32(self.emu.uc, timeout_p, 0)
        sched.block({"kind": "evf_wait", "evf": ef.handle, "name": ef.name, "bits": bits,
                     "mode": mode, "result": result, "timeout_p": timeout_p,
                     "on_timeout": on_timeout},
                    deadline_ns=None if timeout_us is None else sched.now_ns() + timeout_us * 1000,
                    timeout_ret=(ETIMEDOUT, True))

    def sys_evf_trywait(self, uc):
        # evf_trywait(handle, u64 pattern, u32 mode, u64 *result): poll
        h, bits, mode, result = self._args(uc)[:4]
        mode &= 0xFFFFFFFF
        ef = self._evf(h)
        if ef is None:
            return self._ret(uc, ESRCH, error=True)
        self._evf_result(uc, result, ef.bits)
        if not ef.satisfied(bits, mode):
            return self._ret(uc, EBUSY, error=True)
        ef.consume(bits, mode)
        self._ret(uc, 0)

    def _evf_release(self, uc, ef):
        """Wake every waiter whose condition the pattern now meets (FIFO),
        applying each one's clear mode before checking the next."""
        sched = self.emu.sched
        for t in list(ef.waiters):
            w = t.wait
            if t.state != "blocked" or not isinstance(w, dict):
                ef.waiters.remove(t)
                continue
            if ef.satisfied(w["bits"], w["mode"]):
                self._evf_result(uc, w["result"], ef.bits)
                if w["timeout_p"] and t.deadline is not None:
                    left = max(0, t.deadline - sched.now_ns()) // 1000
                    self._wr32(uc, w["timeout_p"], left)
                ef.consume(w["bits"], w["mode"])
                ef.waiters.remove(t)
                sched.wake(t, 0)

    def sys_evf_set(self, uc):
        h, bits = self._args(uc)[:2]
        ef = self._evf(h)
        if ef is None:
            return self._ret(uc, ESRCH, error=True)
        ef.bits |= bits & 0xFFFFFFFFFFFFFFFF
        self._evf_release(uc, ef)
        self._ret(uc, 0)

    def sys_evf_clear(self, uc):
        h, bits = self._args(uc)[:2]
        ef = self._evf(h)
        if ef is None:
            return self._ret(uc, ESRCH, error=True)
        ef.bits &= bits & 0xFFFFFFFFFFFFFFFF          # keeps the bits in `pattern`
        self._ret(uc, 0)

    def sys_evf_cancel(self, uc):
        # evf_cancel(handle, u64 set_pattern, int *num_waiters)
        h, pattern, num_p = self._args(uc)[:3]
        ef = self._evf(h)
        if ef is None:
            return self._ret(uc, ESRCH, error=True)
        if num_p:
            self._wr32(uc, num_p, len(ef.waiters))
        ef.bits = pattern & 0xFFFFFFFFFFFFFFFF
        for t in list(ef.waiters):
            if isinstance(t.wait, dict):
                self._evf_result(uc, t.wait["result"], ef.bits)
            self.emu.sched.wake(t, ECANCELED, True)
        ef.waiters.clear()
        self._ret(uc, 0)

    # ---- semaphores --------------------------------------------------------
    def _sem(self, handle):
        self._sync_init()
        return self.sems.get(handle & 0xFFFFFFFF)

    def sys_osem_create(self, uc):
        # osem_create(const char *name, u32 attr, s32 init, s32 max) -> handle
        self._sync_init()
        name_ptr, attr, init, maximum = self._args(uc)[:4]
        init, maximum = _s32(init), _s32(maximum)
        if not name_ptr or init < 0 or maximum <= 0 or init > maximum:
            return self._ret(uc, EINVAL, error=True)
        name = self._read_cstr(uc, name_ptr, 32)
        h = self._new_handle("sema", name)
        self.sems[h] = Semaphore(h, name, attr & 0xFFFFFFFF, init, maximum)
        self.emu.log(f"  [sema] create '{name}' attr={attr & 0xFFFFFFFF:#x} "
                     f"count={init} max={maximum} -> {h:#x}")
        self._ret(uc, h)

    def sys_osem_open(self, uc):
        # osem_open(const char *name): a semaphore another process created
        self._sync_init()
        name = self._read_cstr(uc, self._args(uc)[0], 32)
        sem = next((x for x in self.sems.values() if x.name == name), None)
        if sem is None:
            h = self._new_handle("sema", name)
            sem = self.sems[h] = Semaphore(h, name, 1, 0, 0x7FFFFFFF, external=True)
            self.emu.log(f"  [sema] open '{name}': owned by another system process "
                         f"-> stand-in {h:#x}")
        self._ret(uc, sem.handle)

    def sys_osem_close(self, uc):
        ok = self._sem(self._args(uc)[0]) is not None
        self._ret(uc, 0 if ok else ESRCH, error=not ok)

    def sys_osem_delete(self, uc):
        sem = self._sem(self._args(uc)[0])
        if sem is None:
            return self._ret(uc, ESRCH, error=True)
        for t in sem.waiters:
            self.emu.sched.wake(t, EACCES, True)
        sem.waiters.clear()
        del self.sems[sem.handle]
        self._ret(uc, 0)

    def sys_osem_wait(self, uc):
        # osem_wait(handle, s32 need, u32 *timeout_us)
        h, need, timeout_p = self._args(uc)[:3]
        need = _s32(need)
        sem = self._sem(h)
        if sem is None:
            return self._ret(uc, ESRCH, error=True)
        if need < 1 or need > sem.max:
            return self._ret(uc, EINVAL, error=True)
        if sem.count >= need:
            sem.count -= need
            return self._ret(uc, 0)
        timeout_us = self._rd32(uc, timeout_p) if timeout_p else None
        if sem.external and timeout_us is None and not sem.assumed:
            # The owner process isn't emulated; stand in for its signal ONCE,
            # so a start-up handshake completes. After that nobody posts it: a
            # semaphore used as an event queue ("wait, then fetch the event")
            # must block like an idle queue rather than be granted forever.
            sem.assumed = True
            self.emu.log(f"  [sema] '{sem.name}': no owner process here - "
                         f"assuming it is signalled once")
            return self._ret(uc, 0)
        if timeout_us == 0:
            return self._ret(uc, ETIMEDOUT, error=True)
        sched = self.emu.sched
        t = sched.current
        sem.waiters.append(t)

        def on_timeout(th, sem=sem, timeout_p=timeout_p):
            if th in sem.waiters:
                sem.waiters.remove(th)
            if timeout_p:
                self._wr32(self.emu.uc, timeout_p, 0)
        sched.block({"kind": "sema_wait", "sema": sem.handle, "name": sem.name, "need": need,
                     "timeout_p": timeout_p, "on_timeout": on_timeout},
                    deadline_ns=None if timeout_us is None else sched.now_ns() + timeout_us * 1000,
                    timeout_ret=(ETIMEDOUT, True))

    def sys_osem_trywait(self, uc):
        # osem_trywait(handle, s32 need): sceKernelPollSema
        h, need = self._args(uc)[:2]
        need = _s32(need)
        sem = self._sem(h)
        if sem is None:
            return self._ret(uc, ESRCH, error=True)
        if need < 1 or need > sem.max:
            return self._ret(uc, EINVAL, error=True)
        if sem.count < need:
            return self._ret(uc, EBUSY, error=True)
        sem.count -= need
        self._ret(uc, 0)

    def sys_osem_post(self, uc):
        # osem_post(handle, s32 count): sceKernelSignalSema
        h, n = self._args(uc)[:2]
        n = _s32(n)
        sem = self._sem(h)
        if sem is None:
            return self._ret(uc, ESRCH, error=True)
        if n < 1 or sem.count + n > sem.max:
            return self._ret(uc, EINVAL, error=True)
        sem.count += n
        # hand tokens to waiters in order; one that needs more than is left
        # keeps waiting without holding up the ones behind it
        sched = self.emu.sched
        for t in list(sem.waiters):
            w = t.wait
            if t.state != "blocked" or not isinstance(w, dict):
                sem.waiters.remove(t)
                continue
            if w["need"] > sem.count:
                continue
            sem.count -= w["need"]
            sem.waiters.remove(t)
            if w["timeout_p"] and t.deadline is not None:
                self._wr32(uc, w["timeout_p"], max(0, t.deadline - sched.now_ns()) // 1000)
            sched.wake(t, 0)
        self._ret(uc, 0)

    def sys_osem_cancel(self, uc):
        # osem_cancel(handle, s32 set_count, s32 *num_waiters); set_count < 0
        # restores the initial count
        h, set_count, num_p = self._args(uc)[:3]
        set_count = _s32(set_count)
        sem = self._sem(h)
        if sem is None:
            return self._ret(uc, ESRCH, error=True)
        if set_count > sem.max:
            return self._ret(uc, EINVAL, error=True)
        if num_p:
            self._wr32(uc, num_p, len(sem.waiters))
        for t in sem.waiters:
            self.emu.sched.wake(t, ECANCELED, True)
        sem.waiters.clear()
        sem.count = sem.init if set_count < 0 else set_count
        self._ret(uc, 0)

    def sync_summary(self):
        if not (getattr(self, "umtx_ops", None) or getattr(self, "evfs", None)
                or getattr(self, "sems", None)):
            return ""
        ops = ", ".join(f"{k}:{v}" for k, v in sorted(self.umtx_ops.items()))
        return (f"_umtx_op by op: {ops or '-'}; event flags: {len(self.evfs)}; "
                f"semaphores: {len(self.sems)}")
