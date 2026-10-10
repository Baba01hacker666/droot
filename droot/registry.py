"""
The CVE database: every exploit droot knows about, with metadata the
viability engine needs (kernel ranges, distro fixes, requirements, risk).

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import importlib
import os
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
    pkg_config: str = None       # e.g. "dbus-1": use pkg-config --cflags/--libs
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
     distro_fixes={"rpm": ["327.36.3"]},
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
# Classic 2.6.x / 3.x canon + RHEL-era userspace (SecWiki/lucyoa/bcoles
# collections; ranges from NVD CPE data and the PoCs' own tested-kernel lists)
# ---------------------------------------------------------------------------

_add(id="memodipper", name="memodipper (/proc/self/mem)", cve="CVE-2012-0056",
     kind="csource", payload="old/memodipper.c", kernel_ranges=[(V("2.6.30"), V("3.2"))],
     requires=["bin:/bin/su"], risk="safe", reliability=3, timeout=60,
     technique="mem_open inode->i_mode check missing in mem_write -> write "
               "/proc/<suid-su-child>/mem; classic RHEL 6.0-6.2 / vanilla "
               "2.6.30-3.1.x LPE (lucyoa tested 2.6.39, 3.0.x, 3.1.0)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/memodipper",
           "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0056"])

_add(id="msr", name="MSR driver writable ioctl", cve="CVE-2013-0268",
     kind="csource", payload="old/msr.c", kernel_ranges=[(V("2.6.18"), V("3.7.6"))],
     build_flags=["-m32"],
     requires=["module:msr", "bin:/dev/cpu/0/msr"], risk="safe", reliability=3,
     timeout=60,
     technique="/dev/cpu/*/msr ioctl MSR write from unprivileged user -> "
               "modify MSR_LSTAR -> root (lucyoa tested 2.6.18-3.7.6; 32-bit "
               "inline-asm PoC, needs gcc -m32 and a 32-bit kernel; needs "
               "the msr module loaded and the device accessible)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/msr"])

_add(id="rds", name="RDS sendmsg", cve="CVE-2010-3904",
     kind="csource", payload="old/rds.c", kernel_ranges=[(V("2.6.30"), V("2.6.36"))],
     requires=["module:rds"], risk="medium", reliability=3, timeout=60,
     technique="rds_page_copy_user OOB write via RDS sendmsg -> root shell "
               "(lucyoa tested Debian 6 / Ubuntu 10.04/10.10; needs the rds "
               "module loaded)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/rds"])

_add(id="perf_swevent", name="perf_swevent (semtex)", cve="CVE-2013-2094",
     kind="csource", payload="old/perf_swevent.c",
     kernel_ranges=[(V("2.6.37"), V("3.8.9"))],
     risk="medium", reliability=4, timeout=60,
     technique="perf_swevent_enabled int truncation -> OOB write in "
               "sw_perf_event_destroy -> root shell. NVD: before 3.8.9; "
               "RHEL 6.1+ affected via backport (RHEL 6.0/5 not affected)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/perf_swevent",
           "http://packetstormsecurity.com/files/121616/semtex.c"])

_add(id="sock_diag", name="NETLINK_SOCK_DIAG OOB", cve="CVE-2013-1763",
     kind="csource", payload="old/sock_diag.c", build_flags=["-m32"],
     kernel_ranges=[(V("3.3"), V("3.7.10"))],
     risk="medium", reliability=3, timeout=60,
     technique="__sock_diag_rcv_msg family index OOB -> root shell "
               "(NVD: before 3.7.10; edb 33336 variant)",
     refs=["https://github.com/SecWiki/linux-kernel-exploits/tree/master/2013/CVE-2013-1763"])

_add(id="clown_newuser", name="clone CLONE_NEWUSER+CLONE_FS chroot",
     cve="CVE-2013-1858", kind="csource", payload="old/clown_newuser.c",
     kernel_ranges=[(V("3.8"), V("3.8.3"))], requires=["userns"],
     risk="safe", reliability=4, timeout=60,
     technique="chroot in a CLONE_NEWUSER|CLONE_FS child with the parent's "
               "fs shared -> write anywhere as root (NVD: before 3.8.3)",
     refs=["https://github.com/SecWiki/linux-kernel-exploits/tree/master/2013/CVE-2013-1858"])

_add(id="rawmodepty", name="pty race (rawmodePTY)", cve="CVE-2014-0196",
     kind="csource", payload="old/rawmodepty.c",
     kernel_ranges=[(V("2.6.31"), V("3.16"))],
     risk="medium", reliability=3, timeout=90,
     technique="n_tty write_buf race on a setraw ioctl'd pty -> kernel stack "
               "smash -> root (lucyoa tested 2.6.31-3.15; ROP shellcode)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/rawmodepty"])

_add(id="timeoutpwn", name="recvmmsg (timeoutpwn)", cve="CVE-2014-0038",
     kind="csource", payload="old/timeoutpwn.c",
     kernel_ranges=[(V("3.4"), V("3.13.1"))],
     risk="medium", reliability=3, timeout=90,
     technique="recvmmsg timeout stack infoleak -> arbitrary read/write via "
               "syscall -> root (lucyoa tested 3.4-3.13.1)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/timeoutpwn"])

_add(id="futex", name="futex_requeue (towelroot)", cve="CVE-2014-3153",
     kind="csource", payload="old/futex.c",
     kernel_ranges=[(V("2.6.18"), V("3.14.5"))],
     risk="crashy", reliability=3, timeout=90,
     technique="FUTEX_REQUEUE with uaddr1==uaddr2 leaves rt_waiter linked -> "
               "kernel stack write via rt_mutex waiter -> root. NVD: through "
               "3.14.5; timwr/c3c PoC targets 3.13-3.14; RHEL 7 early 3.10.0 "
               "kernels carried the backported code",
     refs=["https://github.com/c3c/CVE-2014-3153"])

_add(id="ptrace_kmod2", name="ptrace + modprobe (kmod2)", cve="CVE-2014-4699",
     kind="csource", payload="old/ptrace_kmod2.c",
     kernel_ranges=[(V("2.6.26"), V("2.6.34"))],
     risk="medium", reliability=3, timeout=60,
     technique="ptrace write to a module-loading window -> modprobe path "
               "hijack -> root (lucyoa tested Debian 6 / Ubuntu 10.04/10.10)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/ptrace_kmod2"])

_add(id="overlayfs1328", name="OverlayFS userns mount", cve="CVE-2015-1328",
     kind="csource", payload="old/overlayfs1328.c",
     kernel_ranges=[(V("3.13"), V("3.19"))],
     requires=["userns", "module:overlay"], risk="safe", reliability=4,
     timeout=60,
     technique="unprivileged overlayfs mount in a user namespace -> "
               "copy_up to suid target -> root (Ubuntu 3.13/3.16/3.19 only; "
               "lucyoa ofs_64/ofs_32)",
     refs=["https://github.com/lucyoa/kernel-exploits/tree/master/overlayfs"])

_add(id="pp_key", name="keyring refcount (pp_key)", cve="CVE-2016-0728",
     kind="csource", payload="old/pp_key.c", build_flags=["-lkeyutils"],
     kernel_ranges=[(V("3.8"), V("3.13.1"))],
     risk="safe", reliability=3, timeout=90,
     technique="join_session_keyring refcount leak race -> UAF of keyring -> "
               "cred overwrite -> root (lucyoa tested 3.8.0-3.13.1)",
     refs=["https://github.com/SecWiki/linux-kernel-exploits/tree/master/2016/CVE-2016-0728"])

_add(id="usb_midi", name="USB MIDI double free", cve="CVE-2016-2384",
     kind="csource", payload="old/usb_midi.c",
     kernel_ranges=[(V("3.0"), V("4.5"))],
     requires=["config:CONFIG_SND_USB_AUDIO"], risk="medium", reliability=2,
     timeout=90,
     technique="snd_usbmidi double free on endpoint disable -> root; needs a "
               "USB MIDI device attached and snd-usb-audio built in/loaded",
     refs=["https://github.com/SecWiki/linux-kernel-exploits/tree/master/2016/CVE-2016-2384"])

_add(id="so_bufforce", name="SO_*BUFFORCE signedness", cve="CVE-2016-9793",
     kind="csource", payload="old/so_bufforce.c",
     kernel_ranges=[(V("3.11"), V("4.8"))],
     requires=["cap:cap_net_admin"], risk="crashy", reliability=2, timeout=60,
     technique="signedness in sock_setsockopt SO_RCVBUFFORCE -> negative "
               "sk_rcvbuf -> OOB write -> root. CAP_NET_ADMIN needed; "
               "xairy PoC tested in QEMU only",
     refs=["https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793"])

_add(id="af_packet", name="AF_PACKET packet_set_ring", cve="CVE-2017-7308",
     kind="csource", payload="old/af_packet.c",
     kernel_ranges=[(V("2.6.27"), V("4.10.14"))],
     requires=["cap:cap_net_raw"], risk="crashy", reliability=3, timeout=90,
     technique="packet_set_ring block-size signedness -> OOB write -> root. "
               "Pwn2Own issue; NVD CPE 2.6.27-4.10.14; needs CAP_NET_RAW",
     refs=["https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html"])

_add(id="dccp", name="DCCP double free", cve="CVE-2017-6074",
     kind="csource", payload="old/dccp.c",
     kernel_ranges=[(V("2.6.18"), V("4.9.11"))],
     requires=["config:CONFIG_IP_DCCP"], risk="crashy", reliability=2,
     timeout=90,
     technique="dccp_disconnect double free -> kernel heap grooming -> root; "
               "xairy PoC, semireliable SMEP/SMAP bypass (kernel may crash "
               "shortly after success); needs DCCP enabled",
     refs=["https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074"])

_add(id="ufo", name="UDP fragmentation offload", cve="CVE-2017-1000112",
     kind="csource", payload="old/ufo.c",
     kernel_ranges=[(V("2.6.15"), V("4.12.7"))],
     distro_fixes={"rpm": ["693.5.2"]}, risk="medium", reliability=3,
     timeout=90,
     technique="UFO->non-UFO append path switch -> negative copy -> "
               "skb_copy_and_csum_bits OOB write -> root (KASLR+SMEP bypass, "
               "no SMAP bypass). NVD CPE 2.6.15-4.12.7; Red Hat: affects "
               "RHEL 5/6/7, RHEL7 fixed at 3.10.0-693.5.2",
     refs=["https://access.redhat.com/security/cve/cve-2017-1000112"])

_add(id="c0wl", name="eBPF verifier (c0wl)", cve="CVE-2017-16995",
     kind="csource", payload="old/c0wl.c",
     kernel_ranges=[(V("4.4"), V("4.14"))],
     requires=["cap:cap_sys_admin", "config:CONFIG_BPF_SYSCALL"],
     risk="crashy", reliability=3, timeout=90,
     technique="check_alu_op branch-boundary bug -> OOB map read/write -> "
               "cred overwrite -> root. BPF_PROG_LOAD needs CAP_SYS_ADMIN "
               "on this era; secwiki upstream44 variant targets 4.4-4.14",
     refs=["https://github.com/SecWiki/linux-kernel-exploits/tree/master/2017/CVE-2017-16995"])

_add(id="waitid", name="waitid access_ok", cve="CVE-2017-5123",
     kind="csource", payload="old/waitid.c",
     kernel_ranges=[(V("4.14"), V("4.15"))],
     risk="crashy", reliability=2, timeout=60,
     technique="waitid() missing access_ok on infop -> kernel write at "
               "user-controlled address -> shellcode at NULL via pingv6_ops "
               "-> root. EDB 43029: 'Linux Kernel 4.14.0-rc4+'",
     refs=["https://www.exploit-db.com/exploits/43029"])

# ---- userspace, RHEL-flavored -------------------------------------------------

_add(id="polkit_race", name="polkit dbus race (Kevin Backhouse)",
     cve="CVE-2021-3560", kind="csource", payload="old/polkit_race.c",
     pkg_config="dbus-1", requires=["polkit_lt_120", "accounts_daemon",
                                   "dbus_system"],
     risk="safe", reliability=3, timeout=120,
     post_verify="id -u",
     technique="polkit auth-bypass race on accountsservice D-Bus "
               "CreateUser/SetPassword -> new admin user -> su -> root. "
               "hakivvi PoC (dbus C API, fork+timeout+kill). THE RHEL "
               "escalation: Red Hat shipped polkit 0.112/0.115 in RHEL 7/8 "
               "(upstream fix landed only in 0.120)",
     refs=["https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/",
           "https://github.com/hakivvi/CVE-2021-3560"])

_add(id="sudo_selinux", name="sudo SELinux get_default_context",
     cve="CVE-2017-1000367", kind="csource", payload="old/sudo_selinux.c",
     requires=["sudo_selinux"], risk="safe", reliability=3, timeout=120,
     post_verify="id -u",
     technique="sudo 1.8.6p7-1.8.20 with SELinux: get_default_context "
               "stack overflow via user-controlled SELinux context on a "
               "NOPASSWD rule -> root (c0d3z3r0 PoC; classic RHEL 6 path)",
     refs=["https://github.com/c0d3z3r0/sudo-CVE-2017-1000367"])

_add(id="realpath", name="glibc realpath underflow", cve="CVE-2018-1000001",
     kind="csource", payload="old/realpath.c",
     requires=["glibc_le_226"], risk="safe", reliability=3, timeout=120,
     post_verify="id -u",
     technique="glibc <= 2.26 realpath/getcwd buffer underflow (RationalLove "
               "PoC) -> code exec via a suid binary calling realpath",
     refs=["https://www.exploit-db.com/exploits/43775/"])

_add(id="subuid", name="userns map_write OOB (Jann Horn)",
     cve="CVE-2018-18955", kind="binary",
     payload="old/subuid/exploit.polkit.sh",
     kernel_ranges=[(V("4.15"), V("4.19.2"))],
     requires=["userns", "bin:/usr/bin/newuidmap", "pkexec"],
     risk="safe", reliability=3, timeout=180, post_verify="id -u",
     technique="map_write() nested-userns id-map OOB (bcoles wrappers of "
               "Jann Horn's PoC): polkit/dbus/cron/ldpreload delivery writes "
               "a suid /tmp/sh. NVD: 4.15.x through 4.19.2; RHEL 8.0/8.1 "
               "(4.18) and Ubuntu 18.04 (4.15) territory",
     refs=["https://github.com/bcoles/kernel-exploits/tree/master/CVE-2018-18955"])


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
    if req == "polkit_lt_120":
        # CVE-2021-3560: polkit <= 0.119 (fixed upstream in 0.120; RHEL
        # backported a fix to 0.112-26.el7_9.1 / 0.115-13.el8_6.1, so a
        # version match is necessary-but-not-sufficient -- the race itself
        # fails safely on a patched polkit)
        v = profile.polkit_version
        if not v:
            return (False, "polkit not found")
        try:
            t = tuple(int(x) for x in v.split("."))
        except ValueError:
            return (False, "unparseable polkit version %r" % v)
        ok = t < (0, 120)
        return (ok, "polkit %s %s" % (v, "< 0.120 (CVE-2021-3560 range)" if ok
                                      else ">= 0.120 (upstream-fixed)"))
    if req == "accounts_daemon":
        ok = profile.accounts_daemon
        return (ok, "accounts-daemon on the system bus" if ok
                else "accountsservice/dbus not running")
    if req == "dbus_system":
        ok = profile.dbus_system
        return (ok, "system bus socket present" if ok
                else "no system dbus socket")
    if req == "glibc_le_226":
        # CVE-2018-1000001 realpath/getcwd underflow, glibc <= 2.26
        v = profile.glibc_version
        if not v:
            return (False, "glibc version unknown")
        try:
            t = tuple(int(x) for x in v.split("."))
        except ValueError:
            return (False, "unparseable glibc version %r" % v)
        ok = t <= (2, 26)
        return (ok, "glibc %s %s" % (v, "<= 2.26 (CVE-2018-1000001 range)" if ok
                                     else "> 2.26 (patched)"))
    if req == "sudo_selinux":
        # CVE-2017-1000367: sudo 1.8.6p7..1.8.20, SELinux enforcing, sudo
        # built with SELinux support, and the user has any sudo rule
        v = profile.sudo_version
        if not v:
            return (False, "sudo not found")
        selinux = str(profile.lsm.get("selinux", "unknown")).lower() == "enforcing"
        if not selinux:
            return (False, "SELinux not enforcing (CVE-2017-1000367 needs it)")
        rules = bool(profile.in_sudo_group or profile.sudo_nopasswd)
        if not rules:
            return (False, "user has no sudo rules")
        # sudo 1.8.6p7 .. 1.8.20
        def ver_tuple(s):
            import re
            m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?p(\d*)$", s)
            if not m:
                m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?$", s + "p0")
            return (int(m.group(1)), int(m.group(2)),
                    int(m.group(3) or 0), int(m.group(4) or 0))
        try:
            t = ver_tuple(v)
        except Exception:
            return (False, "unparseable sudo version %r" % v)
        ok = (1, 8, 6, 7) <= t <= (1, 8, 20, 0)
        return (ok, "sudo %s %s" % (v, "in 1.8.6p7-1.8.20 + SELinux" if ok
                                    else "outside 1.8.6p7-1.8.20"))
    if req.startswith("bin:"):
        path = req.split(":", 1)[1]
        ok = os.path.exists(path)
        return (ok, "%s present" % path if ok else "%s missing" % path)
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
