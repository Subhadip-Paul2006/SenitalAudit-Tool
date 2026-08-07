"""SentinelAudit — Windows security auditing tool (Orchestrator).

Phase 18 — argparse CLI, per-module execution with graceful degradation,
scoring, CLI dashboard, report generation, and history persistence.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import sys
from typing import Any

if sys.platform != "win32":
    sys.stderr.write(
        "SentinelAudit only runs on Windows 10/11 (it relies on winreg, WMI, "
        "and PowerShell). Detected platform: %s\n" % sys.platform
    )
    sys.exit(2)

from utils import cli_display, elevation, history, system_info
from utils.config import get
from utils.logsetup import setup_logging
from utils.scoring import compute

logger = logging.getLogger("sentinelaudit.main")

ALL_MODULES = [
    "firewall", "defender", "services", "ports", "users", "password_policy",
    "startup", "software", "usb", "registry", "updates", "eventlogs", "tasks",
]
# Heavier/slower modules skipped in --quick mode
QUICK_SKIP = {"eventlogs", "software", "tasks", "updates"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sentinelaudit",
        description="SentinelAudit — read-only Windows security configuration auditor.",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="Run all audit modules (default).")
    mode.add_argument("--quick", action="store_true",
                      help="Skip slow modules (event logs, installed software, tasks, updates).")
    p.add_argument("--export", metavar="FMTS",
                   help="Comma-separated report formats: pdf,html,json (default: none).")
    p.add_argument("--compare-last", action="store_true",
                   help="Diff this run against the most recent prior run in history.")
    p.add_argument("--no-admin-check", action="store_true",
                   help="Skip the interactive admin-rights prompt.")
    p.add_argument("--no-save", action="store_true",
                   help="Do not persist this run to the history database.")
    p.add_argument("--list-history", action="store_true",
                   help="List recent historical runs and exit.")
    return p.parse_args(argv)


def run_modules(module_names: list[str]) -> dict[str, dict[str, Any]]:
    """Import and run each audit module, isolating failures."""
    results: dict[str, dict[str, Any]] = {}
    with cli_display.progress_run(module_names) as tasks:
        for name in module_names:
            task_id = tasks[name]
            try:
                mod = importlib.import_module(f"audit.{name}")
                results[name] = mod.run()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Failed to load/run module %s", name)
                from utils.module_base import error_result
                results[name] = error_result(name, exc)
    return results


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging()
    logger.info("SentinelAudit starting (args: %s)", vars(args))

    if args.list_history:
        for r in history.list_runs():
            print(f"#{r['id']:>4}  {r['timestamp']}  {r['hostname']:<16}  "
                  f"score={r['score']:>3}  {r['band']}")
        return 0

    if not args.no_admin_check:
        elevation.ensure_admin(interactive=True)
    elif not elevation.is_admin():
        logger.warning("Running without admin rights; some checks will be degraded.")

    sysinfo = system_info.collect()

    module_names = list(ALL_MODULES)
    if args.quick:
        module_names = [m for m in module_names if m not in QUICK_SKIP]

    results = run_modules(module_names)
    scoring = compute(results)

    cli_display.render_dashboard(sysinfo, results, scoring)

    # Reports
    exports = {fmt.strip().lower() for fmt in (args.export or "").split(",") if fmt.strip()}
    if exports:
        from report import html as html_report
        from report import pdf as pdf_report
        if "json" in exports:
            path = html_report.write_json_report(sysinfo, results, scoring)
            print(f"JSON report: {path}")
            logger.info("Wrote JSON report %s", path)
        if "html" in exports:
            path = html_report.generate(sysinfo, results, scoring)
            print(f"HTML report: {path}")
            logger.info("Wrote HTML report %s", path)
        if "pdf" in exports:
            path = pdf_report.generate(sysinfo, results, scoring)
            print(f"PDF report: {path}")
            logger.info("Wrote PDF report %s", path)

    # History
    if not args.no_save:
        run_id = history.save_run(
            hostname=str(sysinfo.get("hostname", "unknown")),
            score=int(scoring["score"]),
            band=str(scoring["band"]),
            results=results,
        )
        logger.info("Saved run #%s to history", run_id)
        if args.compare_last:
            prev = history.get_last_run(exclude_id=run_id)
            diff = history.compare(results, int(scoring["score"]), prev)
            if diff.get("first_run"):
                print("\nNo previous run found for comparison (this is the first recorded run).")
            else:
                cli_display.render_compare(diff)
    elif args.compare_last:
        print("\n--compare-last requires history saving (omit --no-save).")

    logger.info("SentinelAudit complete. Score=%s band=%s", scoring["score"], scoring["band"])
    # Exit code reflects posture: 0 good, 1 fair, 2 poor
    score = int(scoring["score"])
    return 0 if score >= 75 else (1 if score >= 50 else 2)


if __name__ == "__main__":
    sys.exit(main())
