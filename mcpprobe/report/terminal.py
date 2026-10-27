"""Terminal summary rendered with rich.

Every string that originates from the target (tool names, descriptions,
evidence bodies, server info) is rendered as plain :class:`rich.text.Text`
after control characters are made visible, so a hostile server cannot inject
rich markup or ANSI escape sequences into the operator's terminal.
"""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpprobe.checks._util import visible
from mcpprobe.models import CheckStatus, Finding, ScanReport, Severity, Standards

#: Brand severity palette (hex), also used for badges and the website.
SEVERITY_HEX: dict[Severity, str] = {
    Severity.CRITICAL: "#B3261E",
    Severity.HIGH: "#C2410C",
    Severity.MEDIUM: "#9A6200",
    Severity.LOW: "#4A5560",
    Severity.INFO: "#4A5560",
}
PASS_HEX = "#2E7D4F"

_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def severity_style(sev: Severity, *, badge: bool = False) -> str:
    colour = SEVERITY_HEX[sev]
    if badge:
        return f"bold #FFFFFF on {colour}"
    return f"bold {colour}" if sev in (Severity.CRITICAL, Severity.HIGH) else colour


def standards_text(std: Standards) -> str:
    """``MCP07:2025 (beta), ASI03, LLM03:2026, LLM06:2025`` (2026 IDs first, per OWASP guidance)."""
    parts = [f"{m} (beta)" for m in std.mcp] + list(std.asi) + list(std.llm_2026) + list(std.llm_2025)
    return ", ".join(parts) if parts else "spec conformance / hygiene"


def _plain(value: object, limit: int | None = None) -> str:
    text = visible(str(value))
    if limit is not None and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _finding_block(f: Finding, verbose: bool) -> Group:
    head = Text()
    head.append(f" {f.severity.value.upper():<8} ", style=severity_style(f.severity, badge=True))
    head.append(f" {f.id}  ", style="bold")
    head.append(_plain(f.title), style="bold")
    meta = Text("    ")
    meta.append("confidence ", style="dim")
    meta.append(f.confidence.value)
    if f.location:
        meta.append("  where ", style="dim")
        meta.append(_plain(f.location, 120))
    lines: list[Text] = [head, meta]
    std = Text("    standards ", style="dim")
    std.append(standards_text(f.standards))
    lines.append(std)
    if verbose:
        desc = Text("    ")
        desc.append(_plain(f.description, 600))
        lines.append(desc)
    if f.evidence_excerpt:
        ev = Text("    evidence ", style="dim")
        ev.append(_plain(f.evidence_excerpt, 300 if not verbose else 1200), style="dim")
        lines.append(ev)
    fix = Text("    fix ", style=f"bold {PASS_HEX}")
    fix.append(_plain(f.fix, 400 if not verbose else 2000))
    lines.append(fix)
    lines.append(Text(""))
    return Group(*lines)


def render(
    report: ScanReport,
    console: Console | None = None,
    *,
    show_evidence: bool = False,
    verbose: bool = False,
    fail_on: Severity | None = None,
) -> None:
    console = console or Console()
    fp = report.fingerprint
    header = Text()
    header.append(f"mcpprobe {report.version}  ", style="bold")
    header.append(_plain(report.target, 200))
    sub: list[str] = []
    if fp:
        sub.append(f"transport={fp.transport}")
        sub.append(f"revision={fp.protocol_version or 'unknown'} ({fp.flavour})")
        sub.append("auth=required" if fp.auth_required else "auth=none")
        name = fp.server_info.get("name") if isinstance(fp.server_info, dict) else None
        if name:
            sub.append(_plain(f"server={name} {fp.server_info.get('version', '')}".strip(), 60))
    inv = report.inventory_summary
    if inv:
        sub.append(f"tools={inv.get('tools', 0)} prompts={inv.get('prompts', 0)} resources={inv.get('resources', 0)}")
    sub.append(f"mode={report.mode.value}")
    console.print(Panel(header, subtitle=Text(" | ".join(sub)), subtitle_align="left"))

    counts = report.counts()
    summary = Text("Findings ")
    for sev in _ORDER:
        style = severity_style(sev, badge=True) if counts[sev.value] else "dim"
        summary.append(f" {sev.value} {counts[sev.value]} ", style=style)
        summary.append(" ")
    console.print(summary)
    console.print()

    if report.findings:
        for f in report.findings:
            console.print(_finding_block(f, verbose))
    else:
        console.print(Text("No findings.", style=f"bold {PASS_HEX}"))

    cov = Table(title="Check coverage", expand=False, show_header=True, header_style="bold")
    cov.add_column("Check")
    cov.add_column("Mode")
    cov.add_column("Status")
    cov.add_column("Findings", justify="right")
    cov.add_column("Reason")
    for c in report.checks:
        if c.status == CheckStatus.RAN:
            status = Text("pass" if not c.findings else "ran", style=PASS_HEX if not c.findings else "")
            if c.findings:
                worst = max((x.severity for x in c.findings), key=lambda s: s.rank)
                status = Text(worst.value, style=severity_style(worst))
        else:
            status = Text(
                c.status.value,
                style={
                    CheckStatus.SKIPPED: "dim",
                    CheckStatus.NOT_IMPLEMENTED: "dim italic",
                    CheckStatus.ERROR: f"bold {SEVERITY_HEX[Severity.CRITICAL]}",
                }.get(c.status, ""),
            )
        cov.add_row(c.check_id, c.mode.value, status, str(len(c.findings)), Text(_plain(c.reason or "", 70)))
    console.print(cov)

    if report.attestations:
        gov = Text("Attestation only (not assessable by scan): ", style="bold")
        gov.append(", ".join(f"{a.id} {a.title}" for a in report.attestations), style="dim")
        console.print(gov)

    if report.notes and verbose:
        console.print(Text("Notes", style="bold"))
        for note in report.notes:
            console.print(Text(f"  - {_plain(note, 300)}"))
    if show_evidence:
        console.print(
            Text(f"{report.evidence_count} request/response pairs recorded as evidence.", style="dim")
        )
    if fail_on is not None:
        worst = report.max_severity()
        if worst is not None and worst >= fail_on:
            console.print(
                Text(f"Result: FAIL (findings at or above {fail_on.value})", style=severity_style(worst))
            )
        else:
            console.print(Text(f"Result: PASS (nothing at or above {fail_on.value})", style=f"bold {PASS_HEX}"))
