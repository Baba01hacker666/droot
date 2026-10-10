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
