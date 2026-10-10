"""
Kernel release parsing, distro detection and version-range logic.

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import os
import re

_VER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(.*)$")


class KernelVersion:
    """Comparable (major, minor, patch) tuple with a raw suffix."""

    __slots__ = ("extra", "major", "minor", "patch")

    def __init__(self, major: int, minor: int, patch: int, extra: str = ""):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.extra = extra or ""

    @classmethod
    def parse(cls, text: str) -> KernelVersion:
        m = _VER_RE.match(text.strip())
        if not m:
            raise ValueError("unparseable kernel version: %r" % text)
        return cls(int(m.group(1)), int(m.group(2)), int(m.group(3) or 0),
                   (m.group(4) or "").strip())

    @property
    def key(self):
        return (self.major, self.minor, self.patch)

    @property
    def base(self) -> str:
        return "%d.%d.%d" % self.key

    def __str__(self) -> str:
        return "%s%s" % (self.base, self.extra)

    def __repr__(self) -> str:
        return "KernelVersion(%s)" % str(self)

    def __eq__(self, other) -> bool:
        return isinstance(other, KernelVersion) and self.key == other.key

    def __lt__(self, other) -> bool:
        return self.key < other.key

    def __le__(self, other) -> bool:
        return self.key <= other.key

    def __gt__(self, other) -> bool:
        return self.key > other.key

    def __ge__(self, other) -> bool:
        return self.key >= other.key

    def __hash__(self) -> int:
        return hash(self.key)


class DistroRelease:
    """Kernel release interpreted in its distribution's versioning scheme."""

    def __init__(self, distro_id="unknown", version="", pretty="",
                 kernel_release="", kernel=None, abi=None, rpm_release=None,
                 family="other"):
        self.id = distro_id
        self.version = version
        self.pretty = pretty
        self.kernel_release = kernel_release
        self.kernel = kernel or KernelVersion(0, 0, 0)
        self.abi = abi               # ubuntu/debian: "-<abi>" number
        self.rpm_release = rpm_release  # rhel family: "427.13.1.el9_4"
        self.family = family         # debian | rpm | arch | other

    def to_dict(self):
        return {
            "id": self.id, "version": self.version, "pretty": self.pretty,
            "kernel_release": self.kernel_release, "kernel": str(self.kernel),
            "abi": self.abi, "rpm_release": self.rpm_release, "family": self.family,
        }

    def __str__(self):
        s = "%s %s, kernel %s" % (self.id, self.version, self.kernel_release)
        if self.abi is not None:
            s += " (abi %d)" % self.abi
        if self.rpm_release:
            s += " (rpm %s)" % self.rpm_release
        return s


def _rpm_version_cmp(a: str, b: str) -> int:
    """rpm-vercmp style comparison of two release strings."""
    def chunks(v):
        return re.findall(r"\d+|[A-Za-z]+", v)
    ca, cb = chunks(a), chunks(b)
    for x, y in zip(ca, cb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif x.isdigit():
            return 1
        elif y.isdigit():
            return -1
        else:
            return -1 if x < y else 1
    if len(ca) == len(cb):
        return 0
    return -1 if len(ca) < len(cb) else 1


def detect_distro(kernel_release: str | None = None) -> DistroRelease:
    """Build a DistroRelease for the running box (or a given release string)."""
    if kernel_release is None:
        kernel_release = os.uname().release
    distro_id, version, pretty = "unknown", "", ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    distro_id = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    version = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("PRETTY_NAME="):
                    pretty = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass

    family = "other"
    debian_like = {"ubuntu", "debian", "linuxmint", "pop", "kali", "devuan", "raspbian"}
    rpm_like = {"rhel", "centos", "fedora", "rocky", "almalinux", "alma",
                "ol", "oracle", "amzn", "amazon", "sles", "suse", "opensuse",
                "opensuse-leap", "opensuse-tumbleweed", "mageia"}
    if distro_id in debian_like:
        family = "debian"
    elif distro_id in rpm_like:
        family = "rpm"
    elif distro_id in {"arch", "manjaro", "endeavouros", "garuda"}:
        family = "arch"

    kernel = KernelVersion.parse(kernel_release)
    abi = None
    rpm_release = None
    if family == "debian":
        m = re.match(r"^(\d+\.\d+\.\d+)-(\d+)", kernel_release)
        if m:
            abi = int(m.group(2))
    elif family == "rpm":
        m = re.match(r"^(\d+\.\d+\.\d+)-(.+)$", kernel_release)
        if m:
            rpm_release = re.sub(r"\.(x86_64|i386|aarch64|ppc64le|s390x)$", "", m.group(2))
    elif family == "arch":
        m = re.match(r"^(\d+\.\d+\.\d+)(?:-(\d+))?", kernel_release)
        if m and m.group(2):
            abi = int(m.group(2))
    return DistroRelease(distro_id, version, pretty, kernel_release, kernel,
                         abi, rpm_release, family)


def in_range(kv: KernelVersion, lo: KernelVersion | None = None,
             hi: KernelVersion | None = None) -> bool:
    """True when kv is inside [lo, hi); hi is the first fixed version."""
    if lo is not None and kv < lo:
        return False
    return not (hi is not None and kv >= hi)


def is_fixed_by_distro(fixes: dict, dr: DistroRelease):
    """
    Apply per-distro 'fixed in' data. Returns True (patched), False (vulnerable)
    or None (no data for this distro -> fall back to upstream ranges).

    fixes layout:
      {"debian": [("5.15.0", 25), ("5.10.0", 102)],   # (base, min abi)
       "rpm":    ["427.13.1.el9_4", ...]}             # min rpm release strings
    """
    entry = fixes.get(dr.family)
    if not entry:
        return None
    if dr.family == "debian":
        for base, min_abi in entry:
            if dr.kernel.base == base:
                return (dr.abi or 0) >= min_abi
        # kernel base not listed anywhere: no data -> caller falls back to
        # the upstream version ranges
        return None
    if dr.family == "rpm":
        return any(_rpm_version_cmp(dr.rpm_release or "", fix) >= 0 for fix in entry)
    return None
