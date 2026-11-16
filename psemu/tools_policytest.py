"""Scenario test for opened-only (externally owned) event flags/semaphores.

    python -m psemu.tools_policytest

Reuses tools_synctest's Harness. Checks the legacy defaults are unchanged and
that PSEMU_EXT_POLICY-style rules (bits / block / timeout / signals / timed)
behave as documented in ext_policy.py.
"""
import json
import os
import struct
import sys
import tempfile

from .ext_policy import ExtPolicy, PolicyError
from .sys_sync import (EVF_WAITMODE_AND, EVF_WAITMODE_OR, EVF_WAITMODE_CLEAR_PAT,
                       ETIMEDOUT)
from .tools_synctest import Harness, MEM

AND, OR = EVF_WAITMODE_AND, EVF_WAITMODE_OR
NAME_A, NAME_B, NAME_S = MEM + 0x200, MEM + 0x240, MEM + 0x280
RES = MEM + 0x300
TO = MEM + 0x310


def setup(h, rules):
    sc = h.emu.syscalls
    sc._sync_init()
    sc.evfs.clear()                                   # fresh stand-ins per scenario
    sc.sems.clear()
    sc.ext_policy = ExtPolicy(rules, h.emu.log)      # private policy for this scenario
    return sc.ext_policy


def result(h):
    return struct.unpack("<Q", bytes(h.uc.mem_read(RES, 8)))[0]


def evf_tests(h):
    A, B = h.A, h.B
    h.uc.mem_write(NAME_A, b"SceBootStatusFlags\x00")
    h.uc.mem_write(NAME_B, b"SceOtherFlags\x00")

    # --- no policy: legacy behaviour (assume exactly the asked-for bits) -------
    pol = setup(h, [])
    hd, err = h.run_as(A, "evf_open", NAME_A)
    h.check("open ok", err, False)
    h.check("legacy AND wait satisfied", h.run_as(A, "evf_wait", hd, 0x3, AND, RES, 0), (0, False))
    h.check("legacy result has asked bits", result(h), 0x3)
    h.check("legacy OR multi-bit satisfied", h.run_as(A, "evf_wait", hd, 0xC, OR, RES, 0), (0, False))
    h.check("legacy OR sets ALL asked bits", result(h) & 0xC, 0xC)
    amb = [r for r in pol.audit.values() if r["ambiguous"]]
    h.check("OR multi-bit flagged ambiguous", len(amb), 1)
    h.check("report lists ambiguous first", pol.report()[1].endswith("AMBIGUOUS"), True)

    # --- bits rule: only the owner's bits are set; the wait is then judged -----
    setup(h, [{"name": "SceBootStatus*", "kind": "evf", "bits": "0x1"}])
    hd, _ = h.run_as(A, "evf_open", NAME_A)
    h.check("bits rule: OR 0x3 satisfied", h.run_as(A, "evf_wait", hd, 0x3, OR, RES, 0), (0, False))
    h.check("bits rule: result is 0x1, not 0x3", result(h), 0x1)
    h.check("bits rule: AND 0x3 not met -> blocks", h.run_as(B, "evf_wait", hd, 0x3, AND, RES, 0),
            "blocked")
    h.uc.mem_write(TO, struct.pack("<I", 100))
    h.check("bits rule: AND 0x3 with timeout blocks", h.run_as(A, "evf_wait", hd, 0x3, AND, RES, TO),
            "blocked")
    h.check("bits rule: AND 0x1 satisfied", h.run_as(h.C, "evf_wait", hd, 0x1, AND, RES, 0), (0, False))

    # --- block / timeout actions ------------------------------------------------
    setup(h, [{"name": "SceOtherFlags", "action": "block"},
              {"name": "SceBootStatusFlags", "action": "timeout"}])
    hb, _ = h.run_as(A, "evf_open", NAME_B)
    h.check("block rule: wait blocks", h.run_as(A, "evf_wait", hb, 0x1, AND, RES, 0), "blocked")
    ha, _ = h.run_as(B, "evf_open", NAME_A)
    h.check("timeout rule: ETIMEDOUT now", h.run_as(B, "evf_wait", ha, 0x1, AND, RES, 0),
            (ETIMEDOUT, True))
    # a real owner (same process) can still set the flag and release the blocker
    h.check("owner set releases blocked waiter", h.run_as(h.C, "evf_set", hb, 0x1), (0, False))
    h.check("blocked waiter woken ok", h.woken(A), (0, False))

    # --- flags this process creates itself keep exact semantics ---------------
    setup(h, [{"name": "*", "action": "satisfy"}])
    h.uc.mem_write(NAME_S, b"MyOwnFlag\x00")
    hd, _ = h.run_as(A, "evf_create", NAME_S, 0x20, 0)
    h.check("own flag: wait blocks (no assumption)", h.run_as(A, "evf_wait", hd, 0x1, AND, RES, 0),
            "blocked")


def sema_tests(h):
    A, B, C = h.A, h.B, h.C
    h.uc.mem_write(NAME_S, b"SceRemoteSema\x00")
    h.uc.mem_write(TO, struct.pack("<I", 50))

    setup(h, [])
    hd, _ = h.run_as(A, "osem_open", NAME_S)
    h.check("legacy: timed wait blocks", h.run_as(A, "osem_wait", hd, 1, TO), "blocked")
    h.check("legacy: first untimed wait granted", h.run_as(B, "osem_wait", hd, 1, 0), (0, False))
    h.check("legacy: second untimed wait blocks", h.run_as(C, "osem_wait", hd, 1, 0), "blocked")

    setup(h, [{"name": "SceRemote*", "kind": "sema", "signals": 2}])
    hd, _ = h.run_as(A, "osem_open", NAME_S)
    h.check("signals=2: 1st", h.run_as(A, "osem_wait", hd, 1, 0), (0, False))
    h.check("signals=2: 2nd", h.run_as(B, "osem_wait", hd, 1, 0), (0, False))
    h.check("signals=2: 3rd blocks", h.run_as(C, "osem_wait", hd, 1, 0), "blocked")

    setup(h, [{"name": "SceRemote*", "kind": "sema", "signals": -1, "timed": True}])
    hd, _ = h.run_as(A, "osem_open", NAME_S)
    ok = all(h.run_as(A, "osem_wait", hd, 1, TO if i % 2 else 0) == (0, False) for i in range(6))
    h.check("unlimited + timed: always granted", ok, True)

    setup(h, [{"name": "SceRemote*", "action": "timeout"}])
    hd, _ = h.run_as(A, "osem_open", NAME_S)
    h.check("timeout rule: ETIMEDOUT now", h.run_as(A, "osem_wait", hd, 1, 0), (ETIMEDOUT, True))

    setup(h, [{"name": "SceRemote*", "action": "block"}])
    hd, _ = h.run_as(A, "osem_open", NAME_S)
    h.check("block rule: blocks", h.run_as(A, "osem_wait", hd, 1, 0), "blocked")
    h.check("block rule: a real post still wakes it", h.run_as(B, "osem_post", hd, 1), (0, False))
    h.check("woken ok", h.woken(A), (0, False))


def file_tests(h):
    def bad(rules):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(rules, fh)
        try:
            ExtPolicy.from_file(fh.name)
            return False
        except PolicyError:
            return True
        finally:
            os.unlink(fh.name)

    h.check("rejects unknown field", bad([{"name": "x", "bitz": 1}]), True)
    h.check("rejects missing name", bad([{"action": "block"}]), True)
    h.check("rejects bad action", bad([{"name": "x", "action": "maybe"}]), True)
    h.check("rejects bits on sema", bad([{"name": "x", "kind": "sema", "bits": 1}]), True)
    h.check("rejects bad bits", bad([{"name": "x", "bits": "zz"}]), True)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"rules": [{"name": "A*", "bits": "0x5", "_comment": "ok"}]}, fh)
    try:
        p = ExtPolicy.from_file(fh.name)
        h.check("accepts {rules:[...]} + _comment", (len(p.rules), p.rules[0].bits), (1, 5))
    finally:
        os.unlink(fh.name)


def main():
    h = Harness()
    evf_tests(h)
    sema_tests(h)
    file_tests(h)
    print(f"external-object policy: {h.checks} checks, {h.failures} failed")
    return 1 if h.failures else 0


if __name__ == "__main__":
    sys.exit(main())
