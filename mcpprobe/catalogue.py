"""Generate the public checks catalogue (CHECKS.md) from check metadata.

``mcpprobe checks --format markdown`` prints the same text, and a test asserts
that the committed CHECKS.md matches, so the documentation cannot drift from
the code.
"""

from __future__ import annotations

from mcpprobe import __version__
from mcpprobe.checks import ALL_CHECKS, Check
from mcpprobe.governance import GOVERNANCE_ITEMS
from mcpprobe.models import CheckMode, Standards


def _std(std: Standards) -> str:
    parts = [f"{m} (beta)" for m in std.mcp] + list(std.asi) + list(std.llm_2026) + list(std.llm_2025)
    return ", ".join(parts) if parts else "MCP spec conformance / hygiene (no OWASP item)"


def _transports(cls: type[Check]) -> str:
    return ", ".join(sorted(cls.applies_to))


def _section(cls: type[Check]) -> list[str]:
    status = "implemented" if cls.mode == CheckMode.PASSIVE else "stub (gated, not implemented)"
    return [
        f"### {cls.id} - {cls.title}",
        "",
        "| | |",
        "|---|---|",
        f"| Mode | {cls.mode.value} ({status}) |",
        f"| Default severity | {cls.severity.value} |",
        f"| Transports | {_transports(cls)} |",
        f"| Standards | {_std(cls.standards)} |",
        f"| Evidence | {cls.evidence_type or '-'} |",
        "",
        cls.description,
        "",
        f"**False positives.** {cls.false_positive_notes or 'None known.'}",
        "",
        f"**Fix.** {cls.fix or '-'}",
        "",
    ]


def checks_markdown() -> str:
    lines: list[str] = [
        "# mcpprobe checks catalogue",
        "",
        f"Generated from the check metadata of mcpprobe {__version__} "
        "(`mcpprobe checks --format markdown`). Do not edit by hand.",
        "",
        "Standards: OWASP MCP Top 10 (IDs `MCP0x:2025`, still a beta list, so shown with `(beta)`), "
        "OWASP Top 10 for Agentic Applications (`ASI0x`), OWASP Top 10 for LLM Applications 2026 "
        "(`LLM0x:2026`, primary) and 2025 (`LLM0x:2025`, kept for one release cycle). Severities are "
        "defaults; a check can raise or lower the severity of an individual finding (for example "
        "loopback-only servers are reported one level lower), and heuristic checks never rate a "
        "finding Critical on their own.",
        "",
        "Passive checks send only what a normal MCP client would send plus a few benign malformed "
        "requests. They never call a tool. Active checks are listed so coverage is reported honestly; "
        "in this release they are stubs that run only behind the authorisation gate and report "
        "`not_implemented`.",
        "",
        "## Summary",
        "",
        "| ID | Mode | Default severity | Title | Standards |",
        "|---|---|---|---|---|",
    ]
    for cls in ALL_CHECKS:
        lines.append(
            f"| [{cls.id}](#{cls.id.lower()}---{_anchor(cls.title)}) | {cls.mode.value} | "
            f"{cls.severity.value} | {cls.title} | {_std(cls.standards)} |"
        )
    for item in GOVERNANCE_ITEMS:
        lines.append(f"| {item.id} | attestation | - | {item.title} | {_std(item.standards)} |")
    lines += ["", "## Passive checks", ""]
    for cls in ALL_CHECKS:
        if cls.mode == CheckMode.PASSIVE:
            lines += _section(cls)
    lines += [
        "## Active checks (stubs)",
        "",
        "Rules of engagement for when these are implemented: non-destructive, non-persistent "
        "canaries only; tools excluded with `--exclude-tool` or annotated `destructiveHint: true` are "
        "never called; at most one concurrent tool call; every payload is recorded as evidence; the "
        "scan stops on the first sign of an unintended side effect.",
        "",
    ]
    for cls in ALL_CHECKS:
        if cls.mode == CheckMode.ACTIVE:
            lines += _section(cls)
    lines += [
        "## Governance items (attestation only)",
        "",
        "These cannot be assessed by an automated black-box scan. Every report lists them as "
        "`attestation-only` with the checklist below; mcpprobe never marks them passed or failed.",
        "",
    ]
    for item in GOVERNANCE_ITEMS:
        lines += [
            f"### {item.id} - {item.title}",
            "",
            f"Standards: {_std(item.standards)}",
            "",
            item.reason,
            "",
        ]
        lines += [f"- [ ] {c}" for c in item.checklist]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _anchor(title: str) -> str:
    out = []
    for ch in title.lower():
        if ch.isalnum() or ch in "-_":
            out.append(ch)
        elif ch == " ":
            out.append("-")
    return "".join(out)


__all__ = ["checks_markdown"]
