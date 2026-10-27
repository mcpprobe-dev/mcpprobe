"""Terminal summary rendered with rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpprobe.models import CheckStatus, ScanReport, Severity

_COLOURS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _standards_line(f: object) -> str:
    std = getattr(f, "standards")
    parts = [f"{m} (beta)" for m in std.mcp] + list(std.asi) + list(std.llm_2026)
    return ", ".join(parts) if parts else "-"


def render(report: ScanReport, console: Console | None = None, *, show_evidence: bool = False, verbose: bool = False) -> None:
    console = console or Console()
    fp = report.fingerprint
    header = Text()
    header.append(f"mcpprobe {report.version}  ", style="bold")
    header.append(report.target)
    sub = []
    if fp:
        sub.append(f"transport={fp.transport}")
        sub.append(f"revision={fp.protocol_version or 'unknown'} ({fp.flavour})")
        sub.append("auth=required" if fp.auth_required else "auth=none")
        if fp.server_info.get("name"):
            sub.append(f"server={fp.server_info.get('name')} {fp.server_info.get('version', '')}".strip())
    inv = report.inventory_summary
    if inv:
        sub.append(f"tools={inv.get('tools', 0)} prompts={inv.get('prompts', 0)} resources={inv.get('resources', 0)}")
    sub.append(f"mode={report.mode.value}")
    console.print(Panel(header, subtitle=" | ".join(sub), subtitle_align="left"))

    counts = report.counts()
    summary = Text("Findings: ")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        summary.append(f" {sev.value} {counts[sev.value]} ", style=_COLOURS[sev])
    console.print(summary)

    if report.findings:
        table = Table(show_lines=False, expand=True)
        table.add_column("Severity", width=9)
        table.add_column("Check", width=9)
        table.add_column("Conf.", width=6)
        table.add_column("Finding", ratio=3)
        table.add_column("Location", ratio=2)
        for f in report.findings:
            table.add_row(
                Text(f.severity.value.upper(), style=_COLOURS[f.severity]),
                f.id,
                f.confidence.value,
                f.title if not verbose else f"{f.title}\n[dim]{f.description}[/dim]\n[green]Fix:[/green] {f.fix}\n[dim]{_standards_line(f)}[/dim]",
                f.location or "",
            )
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    cov = Table(title="Check coverage", expand=False, show_header=True)
    cov.add_column("Check")
    cov.add_column("Mode")
    cov.add_column("Status")
    cov.add_column("Findings", justify="right")
    cov.add_column("Reason")
    for c in report.checks:
        style = {
            CheckStatus.RAN: "green",
            CheckStatus.SKIPPED: "dim",
            CheckStatus.NOT_IMPLEMENTED: "yellow",
            CheckStatus.ERROR: "red",
        }[c.status]
        cov.add_row(c.check_id, c.mode.value, Text(c.status.value, style=style), str(len(c.findings)), c.reason or "")
    console.print(cov)

    if report.notes:
        console.print("[bold]Notes[/bold]")
        for note in report.notes:
            console.print(f"  - {note}")
    if show_evidence:
        console.print(f"[dim]{report.evidence_count} request/response pairs recorded as evidence.[/dim]")
