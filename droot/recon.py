"""
System profiling: everything the viability engine needs about the target.

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import grp
import os
import pwd
import re
import socket
import subprocess

from . import kernelver

_CAP_NAMES = [
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
    "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap",
    "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
    "cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
    "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
    "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
    "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
    "cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
    "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
    "cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
    "cap_checkpoint_restore",
]


class SystemProfile:
    """Everything droot knows about the host it is running on."""

    def __init__(self):
        self.distro = None            # DistroRelease
        self.uid = 0
        self.gid = 0
        self.username = ""
        self.groups = []
        self.in_sudo_group = False
        self.sudo_nopasswd = []
        self.container = {"is_container": False, "kind": "none", "evidence": []}
        self.lsm = {"selinux": "unknown", "apparmor_profiles": 0}
        self.capabilities = {"effective": [], "bounding": []}
        self.kernel_config = {}
        self.modules = set()
        self.sysctls = {}
        self.af_alg = False
        self.authencesn = False
        self.crypto_names = []
        self.pkexec = None
        self.pkexec_version = None
        self.sudo_version = None
        self.polkit_version = None       # e.g. "0.117" (RHEL 7/8 ship 0.112/0.115)
        self.accounts_daemon = False     # accountsservice + dbus (CVE-2021-3560)
        self.dbus_system = False         # system bus socket reachable
        self.glibc_version = None        # e.g. "2.28" (CVE-2018-1000001)
        self.fusermount3 = None
        self.dbus_send = None
        self.packagekit = None
        self.cifs_upcall = None
        self.tuntap = None
        self.docker_sock_writable = False
        self.docker_images = []
        self.suid_binaries = []
        self.writable = {}
        self.mounts = []
        self.notes = []

    def to_dict(self):
        d = dict(self.__dict__)
        d["distro"] = self.distro.to_dict() if self.distro else None
        d["modules"] = sorted(self.modules)
        return d


def _run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                           text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception:
        return ""


def _parse_capabilities():
    eff, bnd = [], []
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    v = int(line.split()[1], 16)
                    eff = [n for i, n in enumerate(_CAP_NAMES) if v >> i & 1]
                elif line.startswith("CapBnd:"):
                    v = int(line.split()[1], 16)
                    bnd = [n for i, n in enumerate(_CAP_NAMES) if v >> i & 1]
    except OSError:
        pass
    return eff, bnd


def _detect_container():
    out = {"is_container": False, "kind": "none", "evidence": []}
    if os.path.exists("/.dockerenv"):
        out.update(is_container=True, kind="docker")
        out["evidence"].append("/.dockerenv")
    if os.path.exists("/run/.containerenv"):
        out.update(is_container=True, kind="podman")
        out["evidence"].append("/run/.containerenv")
    try:
        with open("/proc/1/cgroup") as f:
            c = f.read()
        if "kubepods" in c:
            out.update(is_container=True, kind="kubernetes")
            out["evidence"].append("kubepods cgroup")
        elif "docker" in c and not out["is_container"]:
            out.update(is_container=True, kind="docker")
            out["evidence"].append("docker cgroup")
    except OSError:
        pass
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        out.update(is_container=True, kind="kubernetes")
        out["evidence"].append("KUBERNETES_SERVICE_HOST env")
    try:
        with open("/proc/1/sched") as f:
            first = f.readline()
        if "systemd" not in first and "init" not in first:
            out["evidence"].append("pid1=%s" % first.strip()[:40])
    except OSError:
        pass
    return out


def _read_sysctls():
    keys = ["kernel.unprivileged_userns_clone", "kernel.kptr_restrict",
            "kernel.dmesg_restrict", "kernel.core_pattern", "kernel.modprobe",
            "kernel.unprivileged_bpf_disabled", "user.max_user_namespaces",
            "kernel.tainted", "fs.protected_symlinks", "kernel.yama.ptrace_scope"]
    out = {}
    for k in keys:
        path = "/proc/sys/" + k.replace(".", "/")
        try:
            with open(path) as f:
                out[k] = f.read().strip()
        except OSError:
            out[k] = None
    return out


def _kernel_config():
    cfg = {}
    src = None
    for path in ("/proc/config.gz",):
        try:
            import gzip
            with gzip.open(path, "rt") as f:
                src = f.read()
            break
        except Exception:
            continue
    if src is None:
        try:
            with open("/boot/config-%s" % os.uname().release) as f:
                src = f.read()
        except OSError:
            src = None
    if src:
        want = ("CONFIG_USER_NS", "CONFIG_NETFILTER", "CONFIG_NETFILTER_XTABLES",
                "CONFIG_CRYPTO_USER_API", "CONFIG_CRYPTO_USER_API_AEAD",
                "CONFIG_FUSE_FS", "CONFIG_TUN", "CONFIG_BONDING", "CONFIG_SCTP",
                "CONFIG_RDS", "CONFIG_TLS", "CONFIG_BRIDGE_NF_EBTABLES",
                "CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "CONFIG_BPF_SYSCALL",
                "CONFIG_SECURITY_SELINUX", "CONFIG_SECURITY_APPARMOR",
                "CONFIG_OVERLAY_FS", "CONFIG_KEYS", "CONFIG_NET_SCHED",
                "CONFIG_PPPOE", "CONFIG_XFRM_USER", "CONFIG_IPV6")
        for line in src.splitlines():
            m = re.match(r"^(CONFIG_\w+)=(.*)$", line.strip())
            if m and m.group(1) in want:
                cfg[m.group(1)] = m.group(2)
    return cfg


def _probe_af_alg(profile):
    profile.af_alg = False
    profile.authencesn = False
    try:
        s = socket.socket(38, 5, 0)  # AF_ALG, SOCK_SEQPACKET
        s.close()
        profile.af_alg = True
        s = socket.socket(38, 5, 0)
        s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        s.close()
        profile.authencesn = True
    except Exception:
        pass


def _probe_userspace(profile):
    pk = _run("command -v pkexec")
    if pk:
        profile.pkexec = pk
        v = _run("pkexec --version")
        m = re.search(r"(\d+)", v)
        if m:
            try:
                profile.pkexec_version = float(m.group(1)) / 100.0
            except ValueError:
                pass
    sv = _run("sudo --version | head -1")
    m = re.search(r"(\d+\.\d+(?:\.\d+)?p\d*)", sv)
    if m:
        profile.sudo_version = m.group(1)
    # polkit version: `pkexec --version` prints "polkit version 0.117" on
    # RHEL-family builds; `pkaction --version` is the portable probe
    pv = _run("pkaction --version 2>/dev/null || pkexec --version 2>/dev/null")
    m = re.search(r"(\d+\.\d+)", pv or "")
    if m:
        profile.polkit_version = m.group(1)
    # accounts-daemon reachable over the system bus (CVE-2021-3560 needs
    # accountsservice + a live dbus; probe without dbus-send dependency)
    profile.dbus_system = any(
        os.path.exists(p) for p in ("/run/dbus/system_bus_socket",
                                    "/var/run/dbus/system_bus_socket"))
    ad = _run("test -x /usr/libexec/accounts-daemon && echo yes "
              "|| test -x /usr/lib/accountsservice/accounts-daemon && echo yes")
    profile.accounts_daemon = bool(ad) and profile.dbus_system
    gl = _run("ldd --version | head -1")
    m = re.search(r"(\d+\.\d+)", gl or "")
    if m:
        profile.glibc_version = m.group(1)
    f3 = _run("command -v fusermount3 || command -v fusermount")
    if f3:
        profile.fusermount3 = f3
    profile.dbus_send = _run("command -v dbus-send") or None
    pkcon = _run("command -v pkcon")
    pkd = _run("test -x /usr/sbin/packagekitd && echo /usr/sbin/packagekitd")
    if pkcon or pkd:
        profile.packagekit = pkcon or pkd
    for p in ("/usr/sbin/cifs.upcall", "/sbin/cifs.upcall"):
        if os.path.exists(p):
            profile.cifs_upcall = p
            break
    profile.tuntap = "/dev/net/tun" if os.access("/dev/net/tun", os.R_OK | os.W_OK) else None
    if os.path.exists("/var/run/docker.sock"):
        profile.docker_sock_writable = os.access("/var/run/docker.sock", os.W_OK)
        if profile.docker_sock_writable:
            out = _run("curl -s --max-time 5 --unix-socket /var/run/docker.sock "
                       "http://localhost/v1.45/images/json 2>/dev/null", timeout=10)
            try:
                import json
                imgs = json.loads(out)
                profile.docker_images = sorted({t.split(":")[0] for i in imgs
                                                for t in i.get("RepoTags") or [] if "<" not in t})
            except Exception:
                pass


def _probe_suid(profile):
    # -xdev keeps us on the root mount; container overlay trees can be slow,
    # so allow a generous timeout rather than reporting a bogus empty list
    out = _run("find / -xdev -perm -4000 -type f 2>/dev/null", timeout=180)
    profile.suid_binaries = sorted(set(out.splitlines())) if out else []


def _probe_writable(profile):
    w = {}
    cp = profile.sysctls.get("kernel.core_pattern")
    if cp is not None:
        try:
            w["core_pattern"] = os.access("/proc/sys/kernel/core_pattern", os.W_OK)
        except OSError:
            w["core_pattern"] = False
    for name, path in (("etc_passwd", "/etc/passwd"),
                       ("ld_so_preload", "/etc/ld.so.preload"),
                       ("cron_d", "/etc/cron.d"),
                       ("systemd_system", "/etc/systemd/system"),
                       ("profile_d", "/etc/profile.d")):
        try:
            if name == "ld_so_preload" and not os.path.exists(path):
                w[name] = os.access("/etc", os.W_OK)
            else:
                w[name] = os.access(path, os.W_OK)
        except OSError:
            w[name] = False
    profile.writable = w


def _probe_mounts(profile):
    try:
        with open("/proc/mounts") as f:
            profile.mounts = [ln.split()[2] for ln in f if len(ln.split()) > 2]
    except OSError:
        pass


def gather_profile() -> SystemProfile:
    p = SystemProfile()
    p.distro = kernelver.detect_distro()
    p.uid, p.gid = os.getuid(), os.getgid()
    try:
        p.username = pwd.getpwuid(p.uid).pw_name
    except KeyError:
        p.username = str(p.uid)
    p.groups = [g.gr_name for g in grp.getgrall() if p.username in g.gr_mem]
    p.in_sudo_group = bool({"sudo", "wheel", "admin"} & set(p.groups))
    out = _run("sudo -n -l 2>/dev/null | tail -n +2", timeout=10)
    p.sudo_nopasswd = [ln.split("NOPASSWD:")[1].strip()
                       for ln in out.splitlines() if "NOPASSWD" in ln]
    p.container = _detect_container()
    try:
        with open("/sys/fs/selinux/enforce") as f:
            p.lsm["selinux"] = "enforcing" if f.read().strip() == "1" else "permissive"
    except OSError:
        p.lsm["selinux"] = "absent"
    try:
        with open("/sys/kernel/security/apparmor/profiles") as f:
            p.lsm["apparmor_profiles"] = len(f.read().splitlines())
    except OSError:
        p.lsm["apparmor_profiles"] = 0
    p.capabilities["effective"], p.capabilities["bounding"] = _parse_capabilities()
    p.kernel_config = _kernel_config()
    p.modules = set(_run("lsmod | tail -n +2 | awk '{print $1}'").split())
    p.sysctls = _read_sysctls()
    _probe_af_alg(p)
    try:
        with open("/proc/crypto") as f:
            p.crypto_names = sorted(set(re.findall(r"name\s+:\s+(.+)", f.read())))
    except OSError:
        pass
    _probe_userspace(p)
    _probe_writable(p)
    _probe_mounts(p)
    _probe_suid(p)
    return p
