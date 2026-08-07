"""Phase 15 — Rich-based CLI dashboard rendering."""

from __future__ import annotations

from typing import Any, Iterable

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console(legacy_windows=False, _environ={"PYTHONIOENCODING": "utf-8"})

_STATUS_ICON = {
    "ok": "[green][OK][/green]",
    "warning": "[yellow][WARN][/yellow]",
    "critical": "[red][CRIT][/red]",
    "error": "[magenta][ERR][/magenta]",
}

_SEV_STYLE = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def progress_run(items: Iterable[str]):
    """Create a rich Progress context with spinners for module execution."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    )
    tasks = {name: progress.add_task(f"[cyan]{name}[/cyan]", total=None) for name in items}

    class _Runner:
        def __enter__(self):
            progress.start()
            return tasks

        def __exit__(self, *exc):
            progress.stop()
            return False

    return _Runner()


def render_dashboard(system_info: dict[str, Any],
                     results: dict[str, dict[str, Any]],
                     scoring: dict[str, Any]) -> None:
    """Render the full dashboard: system info header, module table, score panel."""
    console.print()
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold cyan")
    header.add_column(style="bold")
    si = system_info or {}
    console.print(Panel.fit(
        f"[bold white]SentinelAudit Security Report[/bold white]\n"
        f"Host: {si.get('hostname', '?')}   OS: Windows {si.get('os_release', '?')} "
        f"(build {si.get('os_version', '?')})   User: {si.get('current_user', '?')}\n"
        f"IP: {si.get('local_ip', '?')}   RAM: {si.get('ram_total_gb', '?')} GB   "
        f"Time: {si.get('timestamp', '?')}",
        title="System", border_style="cyan",
    ))

    table = Table(title="Audit Modules", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Impact", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Top finding", overflow="fold", max_width=70)

    for name, res in results.items():
        if not isinstance(res, dict):
            continue
        status = str(res.get("status", "ok"))
        icon = _STATUS_ICON.get(status, status)
        impact = res.get("score_impact", 0)
        findings = res.get("findings", [])
        top = ""
        for sev in ("high", "medium", "low", "info"):
            match = next((f for f in findings if f.get("severity") == sev), None)
            if match:
                top = f"[{_SEV_STYLE.get(sev, 'white')}]{match.get('title', '')}[/]"
                break
        impact_str = f"[red]{impact:+d}[/red]" if impact < 0 else (
            f"[green]+{impact}[/green]" if impact > 0 else "0")
        table.add_row(name, icon, impact_str, str(len(findings)), top)

    console.print(table)

    score = scoring.get("score", 0)
    band = scoring.get("band", "?")
    band_color = {"Excellent": "green", "Good": "blue", "Fair": "yellow", "Poor": "red"}.get(band, "white")
    recs = scoring.get("recommendations", [])
    rec_lines = []
    for r in recs[:8]:
        rec_lines.append(
            f"[{_SEV_STYLE.get(r['severity'], 'white')}]- ({r['severity']}) {r['recommendation']}[/]"
        )
    rec_text = "\n".join(rec_lines) if rec_lines else "[green]No outstanding recommendations.[/green]"
    console.print(Panel(
        f"[bold {band_color}]Overall Score: {score}/100 - {band}[/bold {band_color}]\n\n"
        f"[bold]Top recommendations:[/bold]\n{rec_text}",
        title="Security Posture", border_style=band_color,
    ))
    console.print()


def render_compare(diff: dict[str, Any]) -> None:
    """Render a comparison against the previous run."""
    console.print(Panel(
        f"Previous run: {diff.get('previous_timestamp', '?')} "
        f"(score {diff.get('previous_score', '?')})\n"
        f"Score delta: {diff.get('score_delta', 0):+d}\n"
        f"New findings: {len(diff.get('new_findings', []))}, "
        f"resolved: {len(diff.get('resolved_findings', []))}",
        title="Comparison vs Last Run", border_style="blue",
    ))
    if diff.get("new_findings"):
        t = Table(title="New findings", box=box.SIMPLE)
        t.add_column("Module", style="cyan")
        t.add_column("Severity")
        t.add_column("Title", overflow="fold")
        for f in diff["new_findings"][:20]:
            t.add_row(f.get("module", ""), f.get("severity", ""), f.get("title", ""))
        console.print(t)
    if diff.get("resolved_findings"):
        t = Table(title="Resolved findings", box=box.SIMPLE)
        t.add_column("Module", style="cyan")
        t.add_column("Severity")
        t.add_column("Title", overflow="fold")
        for f in diff["resolved_findings"][:20]:
            t.add_row(f.get("module", ""), f.get("severity", ""), f.get("title", ""))
        console.print(t)
