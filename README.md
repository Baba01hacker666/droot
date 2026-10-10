# droot

Linux local privilege escalation toolkit — kernel-aware viability engine, safe
exploit runner, canary root verification.

Author: baba01hacker

## What it is

droot profiles the host, decides which of its **42 exploits (36 CVEs)** are
actually viable for THIS kernel/distro/container, runs them safely, and proves
root with an independent canary instead of trusting the exploit's exit code.

## Why not just a folder of binaries

The obvious approach (ship precompiled exploits + a menu) fails in the field:
it marks exploits "viable" because a file exists, burns your time on
impossible ones, and reports success when nothing happened. droot fixes that:

| problem | droot |
|---|---|
| no kernel version logic | per-CVE upstream ranges **plus** distro "fixed-in" data (Ubuntu ABI, RHEL rpm releases) |
| "viable = file exists" | requirement engine: modules, kernel config, capabilities, userns, AF_ALG templates, userspace versions |
| exploit lies about success | canary verification: marker file + suid shell must be uid-0 owned, checked by the parent |
| hangs / panics | hard timeout per exploit, crash-risk classification, crashy exploits deprioritized and skipped unless `--allow-risky` |
| no record | every attempt journaled (`~/.droot/state.json`), logs per run, JSON reports |
| one-shot | ranked auto mode stops on first confirmed root; `droot shell` drops you into the suid shell afterwards |

## Install / run

```bash
git clone <repo> && cd droot
python3 -m droot scan            # profile host, rank viable exploits
python3 -m droot run copyfail    # run one exploit
python3 -m droot run --all       # ranked auto mode (safe exploits first)
python3 -m droot info CVE-2026-31431
python3 -m droot report          # JSON report
python3 -m droot shell           # enter the root shell an exploit left behind
python3 -m droot selftest        # 11-check self-verification on this box
```

Or `pip install -e .` for the `droot` entry point. Python 3.10+ (uses
`os.splice`), stdlib only.

### Prebuilt payloads (no compiler on target)

Every release ships CI-compiled static x86_64 binaries for all C payloads.
Install them anywhere with a one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/droot/main/scripts/droot-download.sh | sh
# -> ~/.droot/prebuilt/ (override: --out DIR, or DROOT_PREBUILT_DIR)
```

The script verifies every binary against the sha256 manifest bundled in the
release tarball before installing anything. Specific release: append
`--tag vX.Y.Z`.

### How it is built / verified in CI

`.github/workflows/ci.yml` runs on every push and PR:

- **lint** — ruff (first-party code only; vendored PoCs keep upstream style)
- **selftest** — the full 11-check `droot selftest` on the runner kernel,
  including the live CopyFail AF_ALG 4-byte page-cache write probe and a
  compile of every C payload
- **compile payloads** — `scripts/build-payloads.py` compiles all 42 C
  payloads with the exact flags the on-target runner uses (same
  `csource.build()` code path) and posts a build table to the job summary

On a published release, the workflow static-compiles everything, packages
`droot-payloads-<tag>-linux-<arch>.tar.gz` (+ sha256 + the download script),
builds the wheel/sdist, and uploads them all to the release.

## Exploit inventory (65 entries, 59 CVEs)

**Userspace / no kernel bug**
- PwnKit CVE-2021-4034 (native, gconv module)
- Sudo Baron Samedit CVE-2021-3156 (worawit PoC)
- Docker socket escape (privileged container, host / bind mount)
- Userspace sweep: SUID GTFOBins, NOPASSWD sudo, writable /etc/passwd,
  writable core_pattern

**RHEL-flavored userspace**
- polkit dbus race CVE-2021-3560 (hakivvi PoC) — the RHEL 7/8 path: Red Hat
  shipped polkit 0.112/0.115, the upstream fix only landed in 0.120
- sudo+SELinux CVE-2017-1000367 (sudo 1.8.6p7–1.8.20 + SELinux + any sudo
  rule — the classic RHEL 6 escalation)
- glibc realpath underflow CVE-2018-1000001 (glibc ≤ 2.26)

**Classic 2.6.x/3.x canon** (RHEL 5/6/7, Debian 6/7, Ubuntu 12.04/14.04 era —
ranges from NVD CPE data + each PoC's own tested-kernel list)
- memodipper CVE-2012-0056 (RHEL 6.0–6.2), MSR CVE-2013-0268, RDS
  CVE-2010-3904, perf_swevent/semtex CVE-2013-2094 (RHEL 6.1+ backport),
  NETLINK_SOCK_DIAG CVE-2013-1763, clone CLONE_NEWUSER CVE-2013-1858,
  rawmodePTY CVE-2014-0196, timeoutpwn CVE-2014-0038, futex/towelroot
  CVE-2014-3153, ptrace kmod2 CVE-2014-4699, OverlayFS userns CVE-2015-1328
  (Ubuntu 3.13/3.16/3.19), pp_key CVE-2016-0728, USB MIDI CVE-2016-2384,
  SO_*BUFFORCE CVE-2016-9793, AF_PACKET CVE-2017-7308 (Pwn2Own), DCCP
  CVE-2017-6074, UFO CVE-2017-1000112, eBPF c0wl CVE-2017-16995, waitid
  CVE-2017-5123, userns map_write CVE-2018-18955 (RHEL 8.0/8.1 era)

**Mid-era classics** — DirtyCOW CVE-2016-5195, DirtyPipe CVE-2022-0847
(native), netfilter OOB CVE-2021-22555, OverlayFS CVE-2021-3493,
OverlayFS+FUSE CVE-2023-0386, nftables UAF CVE-2022-2586 / CVE-2024-1086

**2025–2026** — CopyFail CVE-2026-31431 (native, AF_ALG+splice, verified
live), AF_ALG race CVE-2025-39964, proc_readdir_de CVE-2025-40271, net/sched
act_api UAF CVE-2026-53264, Manizada quartet (DirtyAH6 CVE-2026-80844,
TUNderflow CVE-2026-81000, PPPoEject CVE-2026-68121, DiagSpill CVE-2026-74469),
plus the 2026 set from the reference toolkit (ZcopyReaper, DirtyPedit,
skb_shift/GRO/DirtyClone, Bad Epoll, CIFSwitch, Pack2TheRoot, FUSE OOB,
pidfd race, bonding UAF, IPv6 frag escape, Fragnesia family, CopyFail Go).

**RHEL fixed-in data**: rpm-release comparison (e.g. `3.10.0-327.36.3.el7`)
with the well-documented fixes only (DirtyCOW RHEL7 327.36.3, UFO RHEL7
693.5.2) — unverifiable fixed-in data is deliberately absent rather than
guessed; upstream ranges still apply.

## Payload kinds

- **native** — Python in-process (pwnkit, dirtypipe, copyfail, dockersock,
  userspace)
- **csource** — vendored C, compiled on target with gcc and cached under
  `~/.droot/cache` (some need extra flags: `-lcrypt`, `-lpthread`;
  the nftables-1086 PoC needs musl-gcc, reported honestly when absent)
- **pysource** — public python PoCs run with droot's marker env
- **binary** — prebuilt static binaries for payloads with no clean source

## Safety model

- Every exploit runs in a subprocess with a hard timeout (default 120s,
  300s for the slow page-cache walkers)
- C/python/binary exploits get canary commands on stdin: a spawned root shell
  writes `~/.droot/marker` (must be uid 0) and drops a suid shell at
  `~/.droot/.rootshell` — that is what "root confirmed" means
- risk classes: `safe`/`low` (userspace, well-understood) run in auto mode;
  `medium`/`crashy` (kernel races that can panic) need `--allow-risky`
- the resume journal survives reboots: `droot run --all` picks up where a
  kernel panic stopped it

## Legal

For authorized penetration testing and security research only. Unauthorized
use is illegal (CFAA, Computer Misuse Act, etc.).
