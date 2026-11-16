"""What psemu does when guest code waits on a kernel object that another
(unemulated) system process owns.

psemu runs one process. On a real console SceSysCore, SceShellCore and friends
own named event flags / semaphores and signal them; a process that only
*opens* such an object gets a stand-in here. This module decides, per object
name, how the stand-in behaves, and keeps an audit trail so every assumption
psemu makes is visible (and can be pinned down) instead of silent.

Actions for a wait on an opened-only object
  satisfy   the owner "has signalled": the wait succeeds now
  block     the owner never signals: the wait blocks (timeouts still fire)
  timeout   the wait fails with ETIMEDOUT at once (service absent / offline)

Rules come from a JSON file named by PSEMU_EXT_POLICY (a list of objects, or
{"rules": [...]}). First matching rule wins. Fields:
  name     fnmatch glob on the object name (required)
  kind     "evf" | "sema" | "any" (default "any")
  action   "satisfy" | "block" | "timeout" (default "satisfy")
  bits     evf + satisfy: the bits the owner has set (int or "0x.."). Only
           these are ORed into the flag; the wait is then judged normally, so
           a wait the bits do not meet blocks. Omit for the legacy behaviour
           (assume exactly the bits the waiter asked for).
  signals  sema + satisfy: how many waits get an assumed signal (default 1,
           -1 = unlimited)
  timed    sema + satisfy: also grant waits that pass a timeout (default
           false: legacy behaviour grants only untimed waits)
  note     free text, shown in the report

With no file, every object behaves exactly as before this module existed.
"""
import atexit
import fnmatch
import json
import os
import sys

SATISFY, BLOCK, TIMEOUT = "satisfy", "block", "timeout"
_ACTIONS = (SATISFY, BLOCK, TIMEOUT)
_KINDS = ("evf", "sema", "any")


class PolicyError(ValueError):
    pass


def _bits(v, where):
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        raise PolicyError(f"{where}: bad bits value {v!r}")


class Rule:
    def __init__(self, d, idx):
        where = f"rule {idx}"
        if not isinstance(d, dict) or "name" not in d:
            raise PolicyError(f"{where}: needs a 'name'")
        unknown = set(d) - {"name", "kind", "action", "bits", "signals", "timed", "note",
                            "_comment"}
        if unknown:
            raise PolicyError(f"{where}: unknown field(s) {sorted(unknown)}")
        self.name = str(d["name"])
        self.kind = d.get("kind", "any")
        self.action = d.get("action", SATISFY)
        if self.kind not in _KINDS:
            raise PolicyError(f"{where}: kind must be one of {_KINDS}")
        if self.action not in _ACTIONS:
            raise PolicyError(f"{where}: action must be one of {_ACTIONS}")
        self.bits = _bits(d["bits"], where) & 0xFFFFFFFFFFFFFFFF if "bits" in d else None
        self.signals = int(d.get("signals", 1))
        self.timed = bool(d.get("timed", False))
        self.note = str(d.get("note", ""))
        if self.bits is not None and self.kind == "sema":
            raise PolicyError(f"{where}: 'bits' only applies to event flags")

    def matches(self, name, kind):
        return self.kind in ("any", kind) and fnmatch.fnmatchcase(name, self.name)


class Verdict:
    __slots__ = ("action", "set_bits")

    def __init__(self, action, set_bits=0):
        self.action = action
        self.set_bits = set_bits


class ExtPolicy:
    def __init__(self, rules=None, log=None):
        self.rules = [Rule(r, i) for i, r in enumerate(rules or [])]
        self.log = log or (lambda m: None)
        self.audit = {}          # (kind, name, bits, mode) -> record
        self.granted = {}        # (kind, name) -> assumed signals handed out

    # ------------------------------------------------------------ loading
    @classmethod
    def from_file(cls, path, log=None):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            raise PolicyError(f"cannot read policy {path}: {e}")
        if isinstance(data, dict):
            data = data.get("rules", [])
        if not isinstance(data, list):
            raise PolicyError(f"{path}: expected a list of rules")
        return cls(data, log)

    def rule_for(self, name, kind):
        for r in self.rules:
            if r.matches(name, kind):
                return r
        return None

    # ----------------------------------------------------------- decisions
    def evf_wait(self, name, bits, and_mode, caller=""):
        """A wait on opened-only event flag `name` for `bits` is not met.
        Returns a Verdict: for SATISFY, set_bits are the bits to OR into the
        flag before the wait is judged."""
        rule = self.rule_for(name, "evf")
        ambiguous = (not and_mode) and bin(bits).count("1") > 1
        if rule is None:
            v = Verdict(SATISFY, bits)          # legacy: owner set what you asked
            src = "default"
        elif rule.action == SATISFY:
            v = Verdict(SATISFY, bits if rule.bits is None else rule.bits)
            src = "rule"
            ambiguous = ambiguous and rule.bits is None
        else:
            v = Verdict(rule.action)
            src = "rule"
            ambiguous = False
        self._note("evf", name, bits, "AND" if and_mode else "OR", v.action, src,
                   ambiguous, caller)
        return v

    def sema_wait(self, name, timed, caller=""):
        """A wait on opened-only semaphore `name` with count 0. Returns the
        action to take."""
        rule = self.rule_for(name, "sema")
        key = ("sema", name)
        if rule is None:                         # legacy: one assumed signal, untimed
            act = SATISFY if (not timed and self.granted.get(key, 0) < 1) else BLOCK
            src = "default"
        elif rule.action != SATISFY:
            act, src = rule.action, "rule"
        else:
            src = "rule"
            used = self.granted.get(key, 0)
            ok_time = rule.timed or not timed
            ok_count = rule.signals < 0 or used < rule.signals
            act = SATISFY if (ok_time and ok_count) else BLOCK
        if act == SATISFY:
            self.granted[key] = self.granted.get(key, 0) + 1
        self._note("sema", name, 0, "timed" if timed else "untimed", act, src, False, caller)
        return act

    # --------------------------------------------------------------- audit
    def _note(self, kind, name, bits, mode, action, src, ambiguous, caller):
        k = (kind, name, bits, mode, action)
        rec = self.audit.get(k)
        if rec is None:
            self.audit[k] = {"n": 1, "src": src, "ambiguous": ambiguous, "caller": caller}
            what = f"bits {bits:#x} ({mode})" if kind == "evf" else f"wait ({mode})"
            tag = "  AMBIGUOUS: OR-wait on several bits, all assumed set" if ambiguous else ""
            self.log(f"  [ext] {kind} '{name}' {what}: {action} [{src}]"
                     + (f" from {caller}" if caller else "") + tag)
        else:
            rec["n"] += 1

    def report(self):
        """Lines summarising every assumption made, ambiguous ones first."""
        rows = sorted(self.audit.items(),
                      key=lambda kv: (not kv[1]["ambiguous"], kv[1]["src"] != "default", kv[0][:2]))
        out = []
        if not rows:
            return out
        out.append(f"psemu: {len(rows)} assumption(s) about objects owned by processes "
                   "that are not emulated:")
        for (kind, name, bits, mode, action), r in rows:
            what = f"bits {bits:#x} {mode}" if kind == "evf" else mode
            flag = " AMBIGUOUS" if r["ambiguous"] else ""
            out.append(f"  {kind:<4} {name:<40} {what:<22} -> {action:<8} x{r['n']} "
                       f"[{r['src']}]{flag}")
        n_amb = sum(1 for _, r in rows if r["ambiguous"])
        if n_amb:
            out.append(f"  {n_amb} ambiguous: pin each with a rule (bits) in PSEMU_EXT_POLICY")
        return out


_singleton = None


def get_policy(log=None):
    """Process-wide policy (execve chain-loading keeps the same one)."""
    global _singleton
    if _singleton is None:
        path = os.environ.get("PSEMU_EXT_POLICY")
        _singleton = ExtPolicy.from_file(path, log) if path else ExtPolicy([], log)
        atexit.register(_print_report)
    elif log is not None:
        _singleton.log = log
    return _singleton


def _print_report():
    if _singleton is not None:
        for line in _singleton.report():
            print(line, file=sys.stderr)
