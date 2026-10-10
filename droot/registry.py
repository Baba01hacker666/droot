"""
The CVE database: every exploit droot knows about, with metadata the
viability engine needs (kernel ranges, distro fixes, requirements, risk).

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import importlib
import shutil
from dataclasses import dataclass, field

from .kernelver import KernelVersion, in_range, is_fixed_by_distro

V = KernelVersion.parse


@dataclass
class ExploitSpec:
    id: str
    name: str
    kind: str                     # native | csource | pysource | binary
    cve: str = None
    module: str = None            # droot.exploits.<module> (native)
    payload: str = None           # path under droot/payloads/
    kernel_ranges: list = field(default_factory=list)   # [(lo|None, hi|None)]
    distro_fixes: dict = field(default_factory=dict)
    requires: list = field(default_factory=list)
    risk: str = "medium"          # safe | low | medium | crashy
    reliability: int = 3          # 1-5
    technique: str = ""
    refs: list = field(default_factory=list)
    timeout: int = 120
    args: list = field(default_factory=list)
    stdin_payload: bool = False   # feed canary commands to a spawned root shell
    post_verify: str = None       # shell command that proves root (prints 0)
    build_flags: list = field(default_factory=list)
    build_mode: str = "single"    # single | make
    notes: str = ""


@dataclass
class Verdict:
    status: str                   # VULNERABLE | PATCHED | UNAVAILABLE | NEEDS_REVIEW
    reasons: list = field(default_factory=list)
    score: int = 0

    def to_dict(self):
        return {"status": self.status, "reasons": self.reasons, "score": self.score}


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

REGISTRY: list = []


def _add(**kw):
    REGISTRY.append(ExploitSpec(**kw))


# ---- userspace (no kernel version involved) ---------------------------------

_add(id="pwnkit", name="PwnKit", cve="CVE-2021-4034", kind="native",
     module="pwnkit", requires=["pkexec"], risk="safe", reliability=5,
     technique="pkexec argc==0 out-of-bounds argv read -> GCONV_PATH module "
               "executed with setuid-root creds",
     refs=["https://www.qualys.com/2021/01/26/cve-2021-4034/pwnkit.txt"],
     timeout=90)

_add(id="samedit", name="Sudo Baron Samedit", cve="CVE-2021-3156", kind="pysource",
     payload="py/worawit/exploit_nss.py", requires=["sudo_samedit"],
     risk="safe", reliability=4, stdin_payload=False,
     post_verify="su yoga -c 'id -u'",
     technique="heap overflow in sudoedit set_cmnd() -> overwrite service_user "
               "struct -> NSS callback as root",
     refs=["https://www.sudo.ws/security/advisories/"],
     notes="adds uid-0 user 'yoga' to /etc/passwd; version range is enforced "
           "by the module's own checks")

_add(id="dockersock", name="Docker Socket Escape", kind="native",
     module="dockersock", requires=["docker_sock"], risk="safe", reliability=5,
     technique="writable /var/run/docker.sock -> privileged container with "
               "host / bind-mounted -> suid shell on the host",
     timeout=180)

_add(id="userspace", name="Userspace LPE Sweep", kind="native",
     module="userspace", risk="safe", reliability=4,
     technique="writable core_pattern / /etc/passwd / ld.so.preload, SUID "
               "GTFOBins, NOPASSWD sudo entries, file capabilities",
     timeout=120)

# ---- classic kernel CVEs ----------------------------------------------------

_add(id="dirtycow", name="Dirty COW", cve="CVE-2016-5195", kind="csource",
     payload="c/dirtycow.c", build_flags=["-lcrypt", "-lpthread"],
     kernel_ranges=[(V("2.6.22"), V("4.8.3"))],
     requires=["gcc"], risk="low", reliability=5, stdin_payload=True,
     technique="race on private COW mapping of /proc/self/mem -> write to "
               "read-only file (e.g. /etc/passwd)",
     refs=["http://www.securityfocus.com/bid/92686"])

_add(id="dirtypipe", name="DirtyPipe", cve="CVE-2022-0847", kind="native",
     module="dirtypipe",
     kernel_ranges=[(V("5.8"), V("5.16.11"))],
     distro_fixes={"debian": [("5.15.0", 25), ("5.10.0", 102), ("5.13.0", 52)]},
     risk="low", reliability=5,
     technique="PIPE_BUF_FLAG_CAN_MERGE splice -> overwrite page cache of an "
               "O_RDONLY file (e.g. /etc/passwd root entry)",
     refs=["https://dirtypipe.cm4all.com/"], timeout=90)

_add(id="netfilter-oob", name="Netfilter OOB Write", cve="CVE-2021-22555",
     kind="csource", payload="c/netfilter-oob.c",
     kernel_ranges=[(V("2.6.19"), V("5.12"))],
     requires=["gcc", "config:CONFIG_NETFILTER_XTABLES"], risk="medium",
     reliability=4, stdin_payload=True,
     technique="setsockopt IPT_SO_SET_REPLACE OOB write -> zero msg_msg "
               "security pointer -> modprobe_path overwrite",
     refs=["https://github.com/theori-io/CVE-2021-22555"])

_add(id="overlayfs", name="OverlayFS", cve="CVE-2021-3493", kind="csource",
     payload="c/overlayfs.c",
     kernel_ranges=[(V("5.11"), V("5.13.19"))],
     requires=["gcc"], risk="medium", reliability=4, stdin_payload=True,
     technique="Ubuntu overlayfs shiftfs mount -> task creds overwrite "
               "(Ubuntu-specific unprivileged mount path)",
     refs=["https://ubuntu.com/security/CVE-2021-3493"])

_add(id="ovfs-fuse", name="OverlayFS + FUSE", cve="CVE-2023-0386", kind="csource",
     payload="c/ovfs-fuse.c",
     kernel_ranges=[(V("5.11"), V("6.2"))],
     requires=["gcc", "fusermount3"], risk="medium", reliability=5,
     stdin_payload=True,
     technique="OverlayFS copy-up of a FUSE-backed file -> capability set "
               "leak -> full root creds via idmapped mounts",
     refs=["https://github.com/sxlmnwb/CVE-2023-0386"])

_add(id="nft-uaf2", name="nftables UAF", cve="CVE-2022-2586", kind="binary",
     payload="bin/nft-uaf2-static",
     kernel_ranges=[(V("5.7"), V("5.18.5"))],
     risk="medium", reliability=3, stdin_payload=True,
     technique="nft_set_lookup use-after-free -> cred overwrite",
     refs=["https://github.com/theori-io/nftables-uaf"],
     notes="prebuilt static binary; source variant needs libnftnl headers")

_add(id="nft-uaf", name="nftables UAF (2024)", cve="CVE-2024-1086", kind="make",
     payload="c/nft-uaf-1086",
     kernel_ranges=[(V("5.14"), V("6.6.7"))],
     requires=["gcc"], risk="medium", reliability=4, stdin_payload=True,
     technique="nft_verdict_init use-after-free via netlink -> cred overwrite",
     refs=["https://github.com/Notselwyn/CVE-2024-1086"])

_add(id="copyfail", name="CopyFail", cve="CVE-2026-31431", kind="native",
     module="copyfail", kernel_ranges=[(V("4.14"), V("6.19.14"))],
     requires=["af_alg", "authencesn"], risk="safe", reliability=5,
     technique="algif_aead in-place optimization + splice() -> deterministic "
               "4-byte write into page cache of a suid binary -> root shell",
     refs=["https://copy.fail/"], timeout=300)

_add(id="copyfail-py", name="CopyFail (python PoC)", cve="CVE-2026-31431",
     kind="pysource", payload="py/euriconicacio/copy-fail-poc.py",
     kernel_ranges=[(V("4.14"), V("6.19.14"))],
     requires=["af_alg", "authencesn"], risk="safe", reliability=5,
     post_verify="su -c 'id -u'",
     technique="public python PoC of the AF_ALG splice page-cache write",
     refs=["https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc"],
     timeout=300)

# ---- 2026 CVEs from the reference toolkit -----------------------------------

_add(id="zcopyreaper", name="ZcopyReaper", cve="CVE-2026-43502", kind="csource",
     payload="c/zcopyreaper.c",
     kernel_ranges=[(V("4.17"), V("7.1"))],
     requires=["gcc", "module:rds"], risk="medium", reliability=4,
     stdin_payload=True,
     technique="RDS zerocopy send invalid page free -> modprobe_path "
               "overwrite -> root shell",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="dirty-pedit", name="Dirty Pedit", cve="CVE-2026-46331", kind="csource",
     payload="c/dirty_pedit.c",
     kernel_ranges=[(V("5.18"), V("7.1"))],
     requires=["gcc", "cap:cap_net_admin"], risk="medium", reliability=4,
     stdin_payload=True,
     technique="tc pedit page-cache write primitive -> su binary patched "
               "in memory -> root",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="skb-shift", name="skb_shift", cve="CVE-2026-43503", kind="csource",
     payload="c/skb_shift.c",
     kernel_ranges=[(V("3.9"), V("7.1"))],
     requires=["gcc"], risk="crashy", reliability=3, stdin_payload=True,
     technique="ESP-in-TCP byte-at-a-time page-cache write -> su patched "
               "in memory -> root (13 years of kernels)",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="gro-flag-loss", name="GRO Flag Loss", cve="CVE-2026-43503",
     kind="csource", payload="c/gro_flag_loss.c",
     kernel_ranges=[(V("3.9"), V("7.1"))],
     requires=["gcc"], risk="crashy", reliability=3, stdin_payload=True,
     technique="ESP-in-UDP over veth byte-at-a-time page-cache write; "
               "container-escape capable",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="dirtyclone", name="DirtyClone", cve="CVE-2026-43503", kind="csource",
     payload="c/dirtyclone_jfrog.c",
     kernel_ranges=[(V("7.1"), V("7.1.5"))],
     requires=["gcc"], risk="crashy", reliability=3, stdin_payload=True,
     technique="page-cache corruption chain on 7.1-rc kernels",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="bad-epoll", name="Bad Epoll", cve="CVE-2026-46242", kind="csource",
     payload="c/bad_epoll.c",
     kernel_ranges=[(V("6.12"), V("6.12.68"))],
     requires=["gcc"], risk="medium", reliability=4, stdin_payload=True,
     technique="epoll waiter UAF -> refs zeroing primitive -> root",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="cifswitch", name="CIFSwitch", cve="CVE-2026-46243", kind="csource",
     payload="c/cifswitch.c",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     requires=["gcc", "cifs"], risk="medium", reliability=3, stdin_payload=True,
     technique="cifs.upcall keyring confusion -> root",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="pack2theroot", name="Pack2TheRoot", cve="CVE-2026-41651", kind="csource",
     payload="c/pack2theroot.c",
     requires=["gcc", "packagekit", "dbus"], risk="safe", reliability=4,
     stdin_payload=True,
     technique="PackageKit pkcon D-Bus race -> root package install",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="fuse-oob", name="FUSE OOB", cve="CVE-2026-31694", kind="csource",
     payload="c/fuse_oob.c",
     kernel_ranges=[(V("6.15"), V("6.15.13"))],
     requires=["gcc", "fusermount3"], risk="medium", reliability=3,
     stdin_payload=True,
     technique="FUSE_NAME_MAX overflow -> adjacent page overwrite -> root",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="pidfd-race", name="pidfd race", cve="CVE-2026-46333", kind="csource",
     payload="c/cve_2026_46333.c", build_flags=["-lcrypt"],
     kernel_ranges=[(V("5.0"), V("7.1"))],
     requires=["gcc"], risk="crashy", reliability=2, stdin_payload=True,
     technique="pidfd_getfd race -> /etc/passwd overwrite (needs -lcrypt)",
     refs=["https://github.com/khadafigans/LPE-Toolkit"],
     notes="unstable; marked crashy on purpose")

_add(id="bonding-uaf", name="Bonding header_ops UAF", cve="CVE-2026-43456",
     kind="csource", payload="c/bonding_uaf_cve_2026_43456.c",
     kernel_ranges=[(V("2.6.24"), V("6.12.77"))],
     requires=["gcc", "userns"], risk="crashy", reliability=4,
     stdin_payload=True,
     technique="net/bonding header_ops type confusion via GRE chain -> "
               "LL_RESERVED_SPACE underflow -> root (99% < 1s)",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="ipv6-frag-escape", name="IPv6 Frag Escape", kind="csource",
     payload="c/ipv6_frag_escape_universal.c",
     kernel_ranges=[(V("6.12.0"), V("6.12.100"))],
     requires=["gcc", "userns"], risk="crashy", reliability=3,
     stdin_payload=True,
     technique="IPv6 fragment reassembly container escape (RHEL/CentOS 10 "
               "6.12 kernels)",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="proc-readdir-de", name="proc_readdir_de", cve="CVE-2025-40271",
     kind="csource", payload="c/proc_readdir_de_52550.c",
     kernel_ranges=[(V("3.14"), V("6.18"))],
     requires=["gcc"], risk="crashy", reliability=3, stdin_payload=True,
     technique="procfs rb_erase UAF on pde removal -> cred overwrite",
     refs=["https://www.exploit-db.com/exploits/52550"])

_add(id="afalg-race", name="AF_ALG concurrent-write race", cve="CVE-2025-39964",
     kind="csource", payload="c/n1k0oowang/exploit.c",
     kernel_ranges=[(V("2.6.38"), V("6.16.10"))],
     requires=["gcc", "af_alg"], risk="crashy", reliability=2,
     stdin_payload=True,
     technique="af_alg_sendmsg scatterlist underflow -> OOB write -> "
               "core_pattern overwrite (offset-tuned)",
     refs=["https://github.com/n1k0oowang/CVE-2025-39964_EXP"],
     notes="hardcoded offsets; needs per-kernel grooming")

_add(id="sched-uaf", name="net/sched act_api UAF", cve="CVE-2026-53264",
     kind="make", payload="c/HORKimhab/CVE-2026-53264",
     kernel_ranges=[(V("4.14"), V("5.10.259")), (V("5.11"), V("5.15.210")),
                    (V("5.16"), V("6.1.176")), (V("6.2"), V("6.6.143")),
                    (V("6.7"), V("6.12.94")), (V("6.13"), V("6.18.36")),
                    (V("6.19"), V("7.0.13"))],
     requires=["gcc", "userns"], risk="crashy", reliability=3,
     stdin_payload=True,
     technique="tc action IDR lookup vs free race -> UAF -> root "
               "(KASLR bypass included)",
     refs=["https://github.com/HORKimhab/CVE-2026-53264"])

# ---- Manizada quartet (Sept 2026) -------------------------------------------

_add(id="dirtyah6", name="DirtyAH6", cve="CVE-2026-80844", kind="pysource",
     payload="py/manizada/dirtyah6_root_repro.py",
     kernel_ranges=[(V("2.6.12"), V("7.1"))],
     requires=["userns", "config:CONFIG_XFRM_USER", "config:CONFIG_IPV6"],
     risk="crashy", reliability=4,
     post_verify="su -c 'id -u'",
     technique="ipv6_rearrange_rthdr segments_left OOB memmove -> skb "
               "metadata corruption -> /etc/pam.d/su patch -> root",
     refs=["https://github.com/manizada/DirtyAH6"], timeout=300)

_add(id="tunderflow", name="TUNderflow", cve="CVE-2026-81000", kind="pysource",
     payload="py/manizada/tunderflow_root_repro.py",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     requires=["userns", "tuntap"], risk="crashy", reliability=3,
     post_verify="su -c 'id -u'",
     technique="tun_set_headroom unbounded -> SKB_MAX_HEAD underflow via "
               "OVS datapath -> /etc/pam.d/su patch -> root",
     refs=["https://github.com/manizada/TUNderflow"], timeout=300)

_add(id="pppoeject", name="PPPoEject", cve="CVE-2026-68121", kind="pysource",
     payload="py/manizada/pppoeject_root_repro.py",
     kernel_ranges=[(V("2.6.12"), V("7.1"))],
     requires=["userns", "config:CONFIG_PPPOE"], risk="crashy", reliability=3,
     post_verify="su -c 'id -u'",
     technique="pppoe_sendmsg skb head UAF across dev_hard_header() -> "
               "heap corruption -> root",
     refs=["https://github.com/manizada/PPPoEject"], timeout=300)

_add(id="diagspill", name="DiagSpill", cve="CVE-2026-74469", kind="pysource",
     payload="py/manizada/diagspill_root_repro.py",
     kernel_ranges=[(V("4.0"), V("7.1"))],
     requires=["config:CONFIG_SCTP"], risk="crashy", reliability=3,
     post_verify="su -c 'id -u'",
     technique="SCTP transport_count 16-bit overflow -> ~8MiB Netlink "
               "OOB write -> page-table corruption -> root (NO userns needed)",
     refs=["https://github.com/manizada/DiagSpill"], timeout=300,
     notes="destructive: writes ~8MiB past a netlink reply; VM may hang")

# ---- binary-only payloads (no clean public source) ---------------------------

_add(id="fragnesia", name="Fragnesia", cve="CVE-2026-46300", kind="binary",
     payload="bin/fragnesia-static",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     risk="crashy", reliability=3, stdin_payload=True,
     technique="IPv6 fragment page-cache write -> su patched in memory",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="fragnesia2", name="Fragnesia v2", kind="binary",
     payload="bin/fragnesia2-static",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     risk="crashy", reliability=3, stdin_payload=True,
     technique="enhanced Fragnesia variant",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="dirtyfrag", name="DirtyFrag", cve="CVE-2026-43284", kind="binary",
     payload="bin/dirtyfrag-static",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     risk="crashy", reliability=3, stdin_payload=True,
     technique="fragment-based page-cache corruption",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="dirtydecrypt", name="DirtyDecrypt", cve="CVE-2026-31635", kind="binary",
     payload="bin/dirtydecrypt-static",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     risk="crashy", reliability=3, stdin_payload=True,
     technique="crypto-path page-cache corruption",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="pintheft", name="PinTheft", kind="binary", payload="bin/pintheft-static",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     risk="crashy", reliability=2, stdin_payload=True,
     technique="page-pin theft primitive",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="packet-edit-meme", name="PACKET_EDIT_MEME", cve="CVE-2026-46331",
     kind="binary", payload="bin/packet-edit-meme-static",
     kernel_ranges=[(V("5.18"), V("7.1"))],
     requires=["cap:cap_net_admin"], risk="crashy", reliability=2,
     stdin_payload=True,
     technique="packet-socket pedit page-cache write",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="copyfail-go", name="CopyFail (Go build)", cve="CVE-2026-31431",
     kind="binary", payload="bin/copyfail-go-static",
     kernel_ranges=[(V("4.14"), V("6.19.14"))],
     requires=["af_alg"], risk="safe", reliability=5, stdin_payload=True,
     technique="AF_ALG splice page-cache write (static Go build)",
     refs=["https://github.com/khadafigans/LPE-Toolkit"], timeout=300)

_add(id="nft-uaf-bin", name="nftables UAF (2024, prebuilt)", cve="CVE-2024-1086",
     kind="binary", payload="bin/nft-uaf-static",
     kernel_ranges=[(V("5.14"), V("6.6.7"))],
     risk="medium", reliability=4, stdin_payload=True,
     technique="nft_verdict_init UAF -> cred overwrite (prebuilt)",
     refs=["https://github.com/Notselwyn/CVE-2024-1086"])

_add(id="ipv6-frag-escape-bin", name="IPv6 Frag Escape (prebuilt)", kind="binary",
     payload="bin/ipv6-frag-escape-static",
     kernel_ranges=[(V("6.12.0"), V("6.12.100"))],
     requires=["userns"], risk="crashy", reliability=3, stdin_payload=True,
     technique="IPv6 fragment reassembly container escape (prebuilt)",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])

_add(id="pidfd-race-bin", name="pidfd race (prebuilt)", cve="CVE-2026-46333",
     kind="binary", payload="bin/pidfd-race-static",
     kernel_ranges=[(V("5.0"), V("7.1"))],
     risk="crashy", reliability=2, stdin_payload=True,
     technique="pidfd_getfd race -> /etc/passwd overwrite (prebuilt)",
     refs=["https://github.com/khadafigans/LPE-Toolkit"])


# ---------------------------------------------------------------------------
# Requirement checking
# ---------------------------------------------------------------------------

def check_requirement(req: str, profile):
    """Returns (ok, reason)."""
    cfg = getattr(profile, "kernel_config", {}) or {}
    if req == "pkexec":
        return (bool(profile.pkexec),
                "pkexec present" if profile.pkexec else "pkexec not installed")
    if req == "sudo":
        return (bool(profile.sudo_version),
                "sudo present" if profile.sudo_version else "sudo not found")
    if req == "dbus":
        return (bool(profile.dbus_send),
                "dbus-send present" if profile.dbus_send else "dbus-send not found")
    if req == "packagekit":
        return (bool(profile.packagekit),
                "PackageKit present" if profile.packagekit else "PackageKit not found")
    if req == "cifs":
        return (bool(profile.cifs_upcall),
                "cifs.upcall present" if profile.cifs_upcall else "cifs.upcall not found")
    if req == "fusermount3":
        return (bool(profile.fusermount3),
                "fusermount present" if profile.fusermount3 else "fusermount not found")
    if req == "tuntap":
        return (bool(profile.tuntap),
                "/dev/net/tun accessible" if profile.tuntap
                else "/dev/net/tun missing or not accessible")
    if req == "docker_sock":
        return (profile.docker_sock_writable,
                "docker.sock writable" if profile.docker_sock_writable
                else "docker.sock not writable (need docker group)")
    if req == "af_alg":
        return (profile.af_alg,
                "AF_ALG available" if profile.af_alg
                else "AF_ALG unavailable (no CONFIG_CRYPTO_USER_API or blocked)")
    if req == "authencesn":
        return (profile.authencesn,
                "authencesn template available" if profile.authencesn
                else "authencesn(hmac(sha256),cbc(aes)) template not registered")
    if req == "userns":
        ok = (profile.sysctls.get("user.max_user_namespaces") not in (None, "0")
              and profile.sysctls.get("kernel.unprivileged_userns_clone") not in (None, "0"))
        return (ok, "unprivileged user namespaces enabled" if ok
                else "user namespaces disabled (user.max_user_namespaces=0)")
    if req == "sudo_samedit":
        v = profile.sudo_version
        if not v:
            return (False, "sudo not found")
        # vulnerable: 1.8.2..1.8.31p2 and 1.9.0..1.9.5p1
        def ver_tuple(s):
            import re
            m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?p(\d+)$", s)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0),
                        int(m.group(4)))
            m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?$", s)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0), 0)
            return (0, 0, 0, 0)
        t = ver_tuple(v)
        vuln = ((1, 8, 2, 0) <= t <= (1, 8, 31, 2)
                or (1, 9, 0, 0) <= t <= (1, 9, 5, 1))
        return (vuln, "sudo %s %s" % (v, "in vulnerable range" if vuln
                                      else "is patched (>= 1.9.5p2)"))
    if req == "gcc":
        have = bool(shutil.which("gcc") or shutil.which("cc"))
        return (have, "gcc present" if have else "no compiler on target")
    if req.startswith("cap:"):
        cap = req.split(":", 1)[1]
        have = cap in profile.capabilities["effective"]
        return (have, "%s held" % cap if have else "%s not held" % cap)
    if req.startswith("config:"):
        key = req.split(":", 1)[1]
        val = cfg.get(key)
        ok = val in ("y", "m")
        return (ok, "%s=%s" % (key, val) if ok else "%s missing or =n" % key)
    if req.startswith("module:"):
        mod = req.split(":", 1)[1]
        have = mod in profile.modules
        return (have, "module %s loaded" % mod if have
                else "module %s not loaded (try modprobe %s)" % (mod, mod))
    return (False, "unknown requirement %r" % req)


# ---------------------------------------------------------------------------
# Viability evaluation
# ---------------------------------------------------------------------------

def evaluate(spec: ExploitSpec, profile) -> Verdict:
    reasons = []
    status = "VULNERABLE"

    # 1) kernel version / distro patch state
    if spec.kernel_ranges:
        kv = profile.distro.kernel if profile.distro else None
        if kv is None or kv.key == (0, 0, 0):
            reasons.append("kernel version unknown")
            status = "NEEDS_REVIEW"
        else:
            fixed = is_fixed_by_distro(spec.distro_fixes, profile.distro) \
                if spec.distro_fixes else None
            if fixed is True:
                status = "PATCHED"
                reasons.append("distro kernel %s carries the fix (fixed-in data)"
                               % profile.distro.kernel_release)
            elif fixed is False:
                reasons.append("distro kernel %s is pre-fix per fixed-in data"
                               % profile.distro.kernel_release)
            else:
                if any(in_range(kv, lo, hi) for lo, hi in spec.kernel_ranges):
                    reasons.append("kernel %s in affected range" % kv)
                else:
                    status = "PATCHED"
                    reasons.append("kernel %s outside affected range %s"
                                   % (kv, " / ".join(
                                       "%s-%s" % (lo or "*", hi or "*")
                                       for lo, hi in spec.kernel_ranges)))

    # 2) requirements
    if status == "VULNERABLE" or status == "NEEDS_REVIEW":
        for req in spec.requires:
            ok, why = check_requirement(req, profile)
            if not ok:
                status = "UNAVAILABLE"
                reasons.append(why)
            else:
                reasons.append(why)

    # 3) score for auto mode ranking
    risk_bonus = {"safe": 6, "low": 3, "medium": 0, "crashy": -9}.get(spec.risk, 0)
    score = spec.reliability * 10 + risk_bonus
    if status == "VULNERABLE":
        score += 5
    if spec.kind == "native":
        score += 2
    return Verdict(status, reasons, score)


def by_id(cid: str):
    for s in REGISTRY:
        if s.id == cid:
            return s
    return None


def by_cve(cve: str):
    cve = cve.upper()
    out = []
    for s in REGISTRY:
        if s.cve and s.cve.upper() == cve:
            out.append(s)
    return out


def find(token: str):
    """Resolve an id, cve, or unique name substring to specs."""
    s = by_id(token)
    if s:
        return [s]
    found = by_cve(token)
    if found:
        return found
    low = token.lower()
    return [s for s in REGISTRY if low in s.id.lower() or low in s.name.lower()]


def refine(spec: ExploitSpec, profile, verdict: Verdict) -> Verdict:
    """Merge a native exploit module's own check() into the registry verdict."""
    if spec.kind != "native" or not spec.module:
        return verdict
    try:
        mod = importlib.import_module("droot.exploits.%s" % spec.module)
    except Exception:
        return verdict
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and issubclass(obj, base_cls()) \
                and obj is not base_cls() and getattr(obj, "id", None) == spec.id:
            extra = obj().check(profile)
            if extra is None:
                return verdict
            if extra.status in ("PATCHED", "UNAVAILABLE"):
                return Verdict(extra.status, verdict.reasons + extra.reasons,
                               max(0, verdict.score - 5))
            if extra.status == "VULNERABLE":
                verdict.reasons.extend(extra.reasons)
            return verdict
    return verdict


def base_cls():
    from .exploits.base import NativeExploit
    return NativeExploit
