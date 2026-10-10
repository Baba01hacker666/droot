"""
JSON / text reporting.

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import json
import time


def write_report(path, profile, rows, root=False, notes=None):
    report = {
        "tool": "droot",
        "author": "baba01hacker",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "system": profile.to_dict() if profile else None,
        "root_obtained": bool(root),
        "exploits": [
            {
                "id": spec.id, "name": spec.name, "cve": spec.cve,
                "kind": spec.kind, "risk": spec.risk,
                "reliability": spec.reliability,
                "verdict": verdict.to_dict(),
                "technique": spec.technique,
                "refs": spec.refs,
            } for spec, verdict in rows
        ],
        "notes": notes or [],
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


def summary(rows, root=False):
    counts = {}
    for _, v in rows:
        counts[v.status] = counts.get(v.status, 0) + 1
    parts = ["%d %s" % (n, s.lower()) for s, n in sorted(counts.items())]
    line = ", ".join(parts)
    if root:
        line += "  |  ROOT OBTAINED"
    return line
