"""
Terminal UI: calm, readable output. No neon, no gradients.

droot -- Linux LPE toolkit. Author: baba01hacker.
"""
from __future__ import annotations

import os
import shutil
import sys

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

C = {
    "dim": "\033[2m", "bold": "\033[1m", "red": "\033[31m", "green": "\033[32m",
    "yellow": "\033[33m", "blue": "\033[34m", "cyan": "\033[36m",
    "reset": "\033[0m",
}


def c(text, *styles):
    if not _USE_COLOR or not styles:
        return text
    return "".join(C[s] for s in styles) + text + C["reset"]


def width():
    return min(shutil.get_terminal_size((100, 24)).columns, 110)


def header(title, subtitle=""):
    line = "=" * width()
    print(c(line, "cyan"))
    print(c(" " + title, "bold", "cyan"))
    if subtitle:
        print(c(" " + subtitle, "dim"))
    print(c(line, "cyan"))


def kv(key, value, indent=2):
    print(" " * indent + c("%-16s" % key, "dim") + str(value))


STATUS_STYLE = {
    "VULNERABLE": ("green", "VULN "),
    "PATCHED": ("dim", "FIXED"),
    "UNAVAILABLE": ("yellow", "N/A  "),
    "NEEDS_REVIEW": ("yellow", "?    "),
}

RISK_STYLE = {"safe": "green", "low": "green", "medium": "yellow",
              "crashy": "red"}


def verdict_table(rows):
    """rows: list of (spec, verdict)."""
    name_w = max([len(s.name) for s, _ in rows] + [4])
    cve_w = max([len(s.cve or "-") for s, _ in rows] + [3])
    print(c("%-6s %-*s  %-*s  %-7s %-4s %s" %
            ("state", name_w, "exploit", cve_w, "cve", "risk", "rel", "notes"),
            "dim"))
    for spec, verdict in rows:
        color, tag = STATUS_STYLE.get(verdict.status, ("dim", verdict.status))
        note = verdict.reasons[0] if verdict.reasons else ""
        print(c("%-6s " % tag, color) +
              "%-*s  %-*s  %-7s %-4d %s" %
              (name_w, spec.name, cve_w, spec.cve or "-",
               c(spec.risk, RISK_STYLE.get(spec.risk, "dim")),
               spec.reliability, note[:width() - name_w - cve_w - 30]))


def info_block(spec, verdict):
    header(spec.name, spec.cve or "no CVE")
    kv("id", spec.id)
    kv("kind", spec.kind)
    kv("risk", c(spec.risk, RISK_STYLE.get(spec.risk, "dim")))
    kv("reliability", "%d/5" % spec.reliability)
    kv("kernel range", " / ".join("%s - %s" % (lo or "any", hi or "any")
                                  for lo, hi in spec.kernel_ranges) or "n/a (userspace)")
    kv("timeout", "%ds" % spec.timeout)
    if spec.payload:
        kv("payload", spec.payload)
    if spec.requires:
        kv("requires", ", ".join(spec.requires))
    if spec.notes:
        kv("notes", spec.notes)
    print()
    print(c("  technique", "dim"))
    print("    " + spec.technique)
    if spec.refs:
        print(c("  references", "dim"))
        for r in spec.refs:
            print("    " + r)
    print()
    print(c("  viability: %s" % verdict.status,
            STATUS_STYLE.get(verdict.status, ("dim",))[0]))
    for r in verdict.reasons:
        print("    - " + r)
    print()


def result_line(spec, result):
    if result.root:
        print(c("[+] ROOT ", "bold", "green") +
              "%s (%s) -- %s" % (spec.name, spec.cve or "-", result.detail))
    else:
        print(c("[-] fail ", "yellow") +
              "%s (%s) -- %s" % (spec.name, spec.cve or "-", result.detail))


def prompt(text):
    try:
        return input(c(text, "cyan"))
    except (EOFError, KeyboardInterrupt):
        return ""
