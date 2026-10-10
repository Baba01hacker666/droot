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

## Exploit inventory (42 entries, 36 CVEs)

**Userspace / no kernel bug**
- PwnKit CVE-2021-4034 (native, gconv module)
- Sudo Baron Samedit CVE-2021-3156 (worawit PoC)
- Docker socket escape (privileged container, host / bind mount)
- Userspace sweep: SUID GTFOBins, NOPASSWD sudo, writable /etc/passwd,
  writable core_pattern

**Classics** — DirtyCOW CVE-2016-5195, DirtyPipe CVE-2022-0847 (native),
netfilter OOB CVE-2021-22555, OverlayFS CVE-2021-3493, OverlayFS+FUSE
CVE-2023-0386, nftables UAF CVE-2022-2586 / CVE-2024-1086

**2025–2026** — CopyFail CVE-2026-31431 (native, AF_ALG+splice, verified
live), AF_ALG race CVE-2025-39964, proc_readdir_de CVE-2025-40271, net/sched
act_api UAF CVE-2026-53264, Manizada quartet (DirtyAH6 CVE-2026-80844,
TUNderflow CVE-2026-81000, PPPoEject CVE-2026-68121, DiagSpill CVE-2026-74469),
plus the 2026 set from the reference toolkit (ZcopyReaper, DirtyPedit,
skb_shift/GRO/DirtyClone, Bad Epoll, CIFSwitch, Pack2TheRoot, FUSE OOB,
pidfd race, bonding UAF, IPv6 frag escape, Fragnesia family, CopyFail Go).

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
