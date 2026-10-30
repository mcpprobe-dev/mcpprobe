"""Attack chains: findings that together form one attack path.

A chain is emitted only when every constituent finding is present in the
report; it never adds evidence of its own and never upgrades a finding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcpprobe.models import Chain, Finding, ScanReport, Severity

if TYPE_CHECKING:
    from mcpprobe.checks.base import ScanContext

EXEC = "arbitrary_command_execution"
FILE_READ = "arbitrary_file_read"
FILE_WRITE = "arbitrary_file_write"


def _first(findings: list[Finding], check_id: str) -> Finding | None:
    return next((f for f in findings if f.id == check_id), None)


def _dangerous_tools(findings: list[Finding]) -> dict[str, list[str]]:
    """``{tool: [capability, ...]}`` from META-03's arbitrary-capability finding."""
    out: dict[str, list[str]] = {}
    for f in findings:
        if f.id != "META-03":
            continue
        caps = f.details.get("arbitrary")
        if isinstance(caps, dict):
            for tool, kinds in caps.items():
                if isinstance(kinds, list):
                    out.setdefault(str(tool), []).extend(str(k) for k in kinds)
    return out


def _poisoned_tools(findings: list[Finding], candidates: set[str]) -> list[str]:
    hits: list[str] = []
    for f in findings:
        if f.id == "META-01" and f.severity >= Severity.MEDIUM:
            hits.extend(t for t in f.affected if t in candidates and t not in hits)
    return hits


def build_chains(report: ScanReport, ctx: ScanContext) -> list[Chain]:
    findings = report.findings
    chains: list[Chain] = []
    auth01 = _first(findings, "AUTH-01")
    dangerous = _dangerous_tools(findings)
    if auth01 is None or not dangerous:
        return chains
    exec_tools = sorted(t for t, k in dangerous.items() if EXEC in k)
    file_tools = sorted(t for t, k in dangerous.items() if FILE_READ in k or FILE_WRITE in k)
    poisoned = _poisoned_tools(findings, set(dangerous))
    ids = ["AUTH-01", "META-03"] + (["META-01"] if poisoned else [])
    if exec_tools:
        what = "remote code execution"
        tools_text = ", ".join(exec_tools + [t for t in file_tools if t not in exec_tools])
    else:
        what = "arbitrary file access"
        tools_text = ", ".join(file_tools)
    title = f"Unauthenticated {what}" + (" steered by a poisoned description" if poisoned else "")
    narrative = (
        f"Anyone who can reach {ctx.target} can call {tools_text} without credentials (AUTH-01). "
        f"The advertised capability of {'these tools' if len(dangerous) > 1 else 'this tool'} is "
        + "; ".join(
            f"{t}: {', '.join(k.replace('_', ' ') for k in sorted(set(v)))}"
            for t, v in sorted(dangerous.items())
        )
        + " (META-03)."
    )
    if poisoned:
        narrative += (
            f" The description of {', '.join(poisoned)} also tells the model to call it and hand over "
            "context (META-01), so a connected AI client can be steered into the same path without "
            "the attacker ever touching the endpoint."
        )
    narrative += (
        " Fix the chain by removing or sandboxing the tool first; adding authentication alone "
        "leaves it open to every authenticated or prompt-injected client."
    )
    chains.append(
        Chain(id="CHAIN-01", title=title, severity=Severity.CRITICAL, finding_ids=ids, narrative=narrative)
    )

    trans01 = _first(findings, "TRANS-01")
    if trans01 is not None and not ctx.environment.public and ctx.is_http:
        chains.append(
            Chain(
                id="CHAIN-02",
                title="Browser-driven access to a local server's dangerous tools (DNS rebinding)",
                severity=Severity.HIGH,
                finding_ids=["TRANS-01", "AUTH-01", "META-03"],
                narrative=(
                    f"The server at {ctx.target} runs on a local or private address, accepts foreign "
                    "Origin headers (TRANS-01) and needs no credentials (AUTH-01). A web page the user "
                    f"visits can use DNS rebinding to reach it and call {tools_text} (META-03)."
                ),
            )
        )
    return chains
