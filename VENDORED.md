# Vendored payload provenance

The droot toolkit itself is authored by baba01hacker. The exploit payloads
under `droot/payloads/` are public proof-of-concept code kept for authorized
testing; their origins:

## C sources (`payloads/c/`)

| payload | origin |
|---|---|
| dirtycow.c | firefart/dirtycow (CVE-2016-5195) |
| netfilter-oob.c | theori-io/CVE-2021-22555, via khadafigans/LPE-Toolkit Source-Code |
| overlayfs.c | CVE-2021-3493 PoC, via khadafigans/LPE-Toolkit |
| ovfs-fuse.c | CVE-2023-0386 PoC, via khadafigans/LPE-Toolkit |
| zcopyreaper.c | khadafigans/LPE-Toolkit (CVE-2026-43502) |
| dirty_pedit.c | khadafigans/LPE-Toolkit (CVE-2026-46331) |
| skb_shift.c, gro_flag_loss.c, dirtyclone_jfrog.c | khadafigans/LPE-Toolkit (CVE-2026-43503) |
| bad_epoll.c | khadafigans/LPE-Toolkit (CVE-2026-46242) |
| cifswitch.c | khadafigans/LPE-Toolkit (CVE-2026-46243) |
| pack2theroot.c | khadafigans/LPE-Toolkit (CVE-2026-41651) |
| fuse_oob.c | khadafigans/LPE-Toolkit (CVE-2026-31694) |
| cve_2026_46333.c | khadafigans/LPE-Toolkit (pidfd race) |
| bonding_uaf_cve_2026_43456.c | khadafigans/LPE-Toolkit (CVE-2026-43456) |
| ipv6_frag_escape_universal.c | khadafigans/LPE-Toolkit (6.12.x container escape) |
| proc_readdir_de_52550.c | Exploit-DB 52550, Aviral Srivastava (CVE-2025-40271) |
| n1k0oowang/exploit.c | n1k0oowang/CVE-2025-39964_EXP |
| nft-uaf-1086/ | Notselwyn/CVE-2024-1086 (musl-gcc build) |
| HORKimhab/CVE-2026-53264/ | HORKimhab/CVE-2026-53264 |

## Python PoCs (`payloads/py/`)

| payload | origin |
|---|---|
| worawit/exploit_nss.py | worawit/CVE-2021-3156 (Sudo Baron Samedit) |
| manizada/dirtyah6_root_repro.py | manizada/DirtyAH6 (CVE-2026-80844) |
| manizada/tunderflow_root_repro.py | manizada/TUNderflow (CVE-2026-81000) |
| manizada/pppoeject_root_repro.py | manizada/PPPoEject (CVE-2026-68121) |
| manizada/diagspill_root_repro.py | manizada/DiagSpill (CVE-2026-74469) |
| euriconicacio/copy-fail-poc.py | euriconicacio/copy-fail-CVE-2026-31431-poc |

## Prebuilt binaries (`payloads/bin/`)

Prebuilt static x86_64 binaries from khadafigans/LPE-Toolkit (fragnesia,
fragnesia2, dirtyfrag, dirtydecrypt, pintheft, packet-edit-meme,
copyfail-go, nft-uaf, nft-uaf2, ipv6-frag-escape, pidfd-race).

## Native modules

pwnkit, dirtypipe, copyfail, dockersock and userspace are original droot
implementations (the copyfail primitive follows the public mechanism from
copy.fail / tgies/copy-fail-c; the hand-built ELF payload is original).

## Classic canon (`payloads/old/`)

Ranges were taken from NVD CPE data and each PoC's own tested-kernel list
(lucyoa/SecWiki READMEs) — never guessed.

| payload | origin | range basis |
|---|---|---|
| memodipper.c | lucyoa/kernel-exploits | lucyoa tested list + RHEL 6.0-6.2 knowledge |
| msr.c | lucyoa/kernel-exploits | lucyoa tested 2.6.18-3.7.6 (patched sysexit->sysexitq for modern GAS) |
| rds.c | lucyoa/kernel-exploits | lucyoa tested 2.6.30-2.6.36 |
| perf_swevent.c | lucyoa (sorbo/sd semtex lineage) | NVD before 3.8.9 + Red Hat statement |
| sock_diag.c | SecWiki (edb 33336) | NVD before 3.7.10 |
| clown_newuser.c | SecWiki (Sebastian Krahmer) | NVD before 3.8.3 (fixed broken printf) |
| rawmodepty.c | lucyoa/kernel-exploits | lucyoa tested 2.6.31-3.15 |
| timeoutpwn.c | lucyoa/kernel-exploits | lucyoa tested 3.4-3.13.1 (fixed open('r') typo) |
| futex.c | c3c/CVE-2014-3153 (timwr) | NVD through 3.14.5 |
| ptrace_kmod2.c | lucyoa/kernel-exploits | lucyoa tested 2.6.26-2.6.34 |
| overlayfs1328.c | lucyoa/kernel-exploits | lucyoa tested 3.13/3.16/3.19 (Ubuntu) |
| pp_key.c | SecWiki (Perception) | lucyoa tested 3.8.0-3.13.1 |
| usb_midi.c | SecWiki (CVE-2016-2384 PoC) | upstream fix 2016-02, NVD 3.0-4.5 |
| so_bufforce.c | SecWiki (xairy) | xairy header: 3.11-4.8, CAP_NET_ADMIN |
| af_packet.c | SecWiki (Pwn2Own PoC) | NVD CPE 2.6.27-4.10.14 |
| dccp.c | SecWiki (xairy) | xairy header: through 4.9.11 |
| ufo.c | SecWiki (CVE-2017-1000112 PoC) | NVD CPE 2.6.15-4.12.7 + Red Hat statement (RHEL7 fix 693.5.2) |
| c0wl.c | SecWiki (upstream44) | secwiki README: 4.14-4.4 |
| waitid.c | SecWiki (edb 43029) | EDB title: 4.14.0-rc4+ |
| polkit_race.c | hakivvi/CVE-2021-3560 | Kevin Backhouse analysis, polkit <= 0.119 |
| sudo_selinux.c | SecWiki (c0d3z3r0) | sudo 1.8.6p7-1.8.20 + SELinux |
| realpath.c | SecWiki (RationalLove, edb 43775) | glibc <= 2.26 |
| subuid/ | SecWiki/bcoles wrappers of Jann Horn's PoC | NVD: 4.15.x-4.19.2 |
