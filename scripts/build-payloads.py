#!/usr/bin/env python3
"""
Compile every csource/make payload in the droot registry into a directory.

Reuses droot.exploits.csource.build() so the CI build compiles with exactly
the same flags (pkg-config resolution, per-exploit build_flags, make-mode
handling) as the on-target build -- release binaries never drift from what
`droot run` compiles locally.

Usage:
    python3 scripts/build-payloads.py --out dist/payloads
    python3 scripts/build-payloads.py --out dist/payloads --static \
        --report dist/build-report.json

Single-file payloads are first attempted with -static; when the static link
fails (missing .a on the builder) it falls back to a dynamic build and the
report records the fallback. make-mode payloads build through their own
Makefiles (nft-uaf-1086 requires musl-gcc, i.e. the musl-tools package).

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from droot.registry import REGISTRY          # noqa: E402
from droot.exploits import csource           # noqa: E402


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_all(out_dir: str, static: bool):
    """Compile every csource/make spec. Returns a list of result dicts."""
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for spec in REGISTRY:
        if spec.kind not in ("csource", "make"):
            continue
        flags = list(spec.build_flags)
        if static and spec.build_mode == "single":
            flags.append("-static")
        s = dataclasses.replace(spec, build_flags=flags)
        binary, err = csource.build(s, out_dir)
        note = ""
        if not binary and static and spec.build_mode == "single":
            # static link failed (no .a for -lcrypt/-lkeyutils/etc. on this
            # builder) -> retry dynamic so the release still ships a binary
            s = dataclasses.replace(spec,
                                    build_flags=list(spec.build_flags))
            binary, err = csource.build(s, out_dir)
            if binary:
                note = "static link failed; shipped dynamic build"
        entry = {"id": spec.id, "cve": spec.cve, "kind": spec.kind,
                 "build_mode": spec.build_mode, "ok": bool(binary),
                 "error": err, "note": note}
        if binary:
            # csource.build names the artifact <id>-<sha1[:12]> or make-<id>;
            # rename to the plain id so release tarballs have stable names
            final = os.path.join(out_dir, spec.id)
            if os.path.abspath(binary) != os.path.abspath(final):
                os.replace(binary, final)
            entry["file"] = spec.id
            entry["bytes"] = os.path.getsize(final)
            entry["sha256"] = sha256_file(final)
        results.append(entry)
    return results


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compile every csource/make payload in the registry")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--static", action="store_true",
                    help="link single-file payloads statically")
    ap.add_argument("--report", default=None, help="write JSON report here")
    ap.add_argument("--manifest", default=None,
                    help="manifest path (default: <out>/manifest.json)")
    args = ap.parse_args()

    results = build_all(args.out, args.static)
    ok = [r for r in results if r["ok"]]
    bad = [r for r in results if not r["ok"]]

    print("built %d/%d payloads into %s" % (len(ok), len(results), args.out))
    for r in ok:
        print("  [ok]   %-22s %8d bytes  %s%s" %
              (r["id"], r["bytes"], r["sha256"][:12],
               "  (%s)" % r["note"] if r["note"] else ""))
    for r in bad:
        print("  [FAIL] %-22s %s" % (r["id"], r["error"]))

    manifest = {"repo": "Baba01hacker666/droot",
                "payloads": {r["id"]: {"file": r.get("file"),
                                       "sha256": r.get("sha256")}
                             for r in results if r["ok"]}}
    manifest_path = args.manifest or os.path.join(args.out, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)),
                    exist_ok=True)
        with open(args.report, "w") as f:
            json.dump({"static": args.static,
                       "built": len(ok), "failed": len(bad),
                       "results": results}, f, indent=2)

    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
