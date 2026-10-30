"""Directory listing readiness: public MCP directory requirements mapped onto check outcomes.

Every item is derived from checks that actually ran in this scan. A requirement a
scan cannot decide (ownership proof, anything behind authentication that was not
supplied, a check that was skipped or rate limited) is ``not_assessable`` with the
reason in ``note``. Nothing here is ever reported ``met`` on the strength of a
check that did not run, and no new requests are made.

Sources (requirement wording checked on 2026-10-30):

* Anthropic Software Directory Policy, sections 2G, 3F, 5D and 5E.
* OpenAI app review, MCP server requirements (tool annotations).
* HubSpot MCP server listing requirements (security).
"""

from __future__ import annotations

from typing import Any

from mcpprobe.models import (
    CheckResult,
    CheckStatus,
    ReadinessItem,
    ReadinessStatus,
    ScanReport,
    Severity,
)

ANTHROPIC_URL = "https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy"
OPENAI_URL = "https://developers.openai.com/plugins/deploy/app-review.md"
HUBSPOT_URL = (
    "https://developers.hubspot.com/docs/apps/developer-platform/list-apps/mcp-server-listing-requirements"
)

MET = ReadinessStatus.MET
NOT_MET = ReadinessStatus.NOT_MET
NA = ReadinessStatus.NOT_ASSESSABLE

REQ_OAUTH = (
    "5D: remote MCP servers that require authentication use OAuth 2.0 "
    "(discoverable protected resource and authorization server metadata)"
)
REQ_ANNOTATIONS = "5E: all applicable tool annotations, in particular readOnlyHint, destructiveHint and title"
REQ_HIDDEN = "2G: no hidden, obfuscated or encoded instructions"
REQ_OWNERSHIP = "3F: the developer owns or controls every endpoint and domain the software connects to"
REQ_OPENAI_ANNOTATIONS = "Accurate readOnlyHint, destructiveHint and openWorldHint on every tool"
REQ_NO_HIGH = "No unresolved critical or high vulnerabilities at the time of review"
REQ_EXFIL = "Low security risk for data exfiltration and tool poisoning"
REQ_HTTPS = "mcpUrl uses HTTPS"


def _by_id(report: ScanReport) -> dict[str, CheckResult]:
    return {c.check_id: c for c in report.checks}


def _why_not_run(check: CheckResult | None, check_id: str) -> str:
    if check is None:
        return f"{check_id} was not run in this scan (--only/--skip)."
    if check.status == CheckStatus.NOT_APPLICABLE:
        return f"{check_id} was not applicable: {check.reason}"
    return f"{check_id} did not run ({check.status.value}{': ' + check.reason if check.reason else ''})."


def _single_check(
    report: ScanReport,
    check_id: str,
    *,
    directory: str,
    requirement: str,
    source_url: str,
    met_note: str,
    not_met_note: str,
) -> ReadinessItem:
    check = _by_id(report).get(check_id)
    if check is None or check.status != CheckStatus.RAN:
        status, note = NA, _why_not_run(check, check_id)
    elif check.findings:
        affected = sorted({a for f in check.findings for a in f.affected})
        status = NOT_MET
        note = not_met_note + (f" Affected: {', '.join(affected)}." if affected else "")
    else:
        status, note = MET, met_note
    return ReadinessItem(
        directory=directory,
        requirement=requirement,
        source_url=source_url,
        status=status,
        check_ids=[check_id],
        note=note,
    )


def _poisoning(report: ScanReport, *, directory: str, requirement: str, source_url: str) -> ReadinessItem:
    """META-01: medium or higher is not met; only low indicators cannot be decided either way."""
    check = _by_id(report).get("META-01")
    if check is None or check.status != CheckStatus.RAN:
        status, note = NA, _why_not_run(check, "META-01")
    else:
        loud = [f for f in check.findings if f.severity >= Severity.MEDIUM]
        quiet = [f for f in check.findings if f.severity < Severity.MEDIUM]
        if loud:
            status = NOT_MET
            note = "META-01 found instructions aimed at the model in: " + ", ".join(
                sorted({f.location or "?" for f in loud})
            )
        elif quiet:
            status = NA
            note = (
                "META-01 raised only low-severity indicators (for example a URL or a mention of another "
                "tool), which can be legitimate; review them: "
                + ", ".join(sorted({f.location or "?" for f in quiet}))
            )
        else:
            status, note = MET, "META-01 found no hidden, obfuscated or model-directed text in any metadata."
    return ReadinessItem(
        directory=directory,
        requirement=requirement,
        source_url=source_url,
        status=status,
        check_ids=["META-01"],
        note=note,
    )


def _oauth(report: ScanReport) -> ReadinessItem:
    by = _by_id(report)
    ids = ["AUTH-01", "AUTH-02", "AUTH-03"]
    base: dict[str, Any] = {
        "directory": "anthropic",
        "requirement": REQ_OAUTH,
        "source_url": ANTHROPIC_URL,
        "check_ids": ids,
    }
    if report.fingerprint is not None and report.fingerprint.transport != "http":
        return ReadinessItem(
            **base, status=NA, note="Local stdio server: 5D concerns remote servers; not assessed."
        )
    a1, a2, a3 = (by.get(i) for i in ids)
    if a1 is not None and a1.status == CheckStatus.RAN and a1.findings:
        return ReadinessItem(
            **base,
            status=NOT_MET,
            note=(
                "AUTH-01: the endpoint answers without any authentication. 5D applies to servers that "
                "require authentication; if this server acts for a user or reaches a remote service on "
                "their behalf, it needs OAuth 2.0."
            ),
        )
    failing = [c.check_id for c in (a2, a3) if c is not None and c.status == CheckStatus.RAN and c.findings]
    if failing:
        return ReadinessItem(
            **base,
            status=NOT_MET,
            note="Authentication is required but OAuth discovery is incomplete: see "
            + ", ".join(failing)
            + ".",
        )
    if all(c is not None and c.status == CheckStatus.RAN and not c.findings for c in (a1, a2, a3)):
        return ReadinessItem(
            **base,
            status=MET,
            note=(
                "AUTH-01, AUTH-02 and AUTH-03 passed: 401 without a token, RFC 9728 metadata and RFC 8414 "
                "authorization server metadata with PKCE S256 over HTTPS. Certificate trust is only as "
                "strong as the TLS verification of this scan's connection."
            ),
        )
    missing = [i for i, c in zip(ids, (a1, a2, a3), strict=True) if c is None or c.status != CheckStatus.RAN]
    return ReadinessItem(
        **base,
        status=NA,
        note=" ".join(_why_not_run(by.get(i), i) for i in missing),
    )


def _no_critical_high(report: ScanReport) -> ReadinessItem:
    base: dict[str, Any] = {
        "directory": "hubspot",
        "requirement": REQ_NO_HIGH,
        "source_url": HUBSPOT_URL,
    }
    loud = [f for f in report.findings if f.severity >= Severity.HIGH]
    if loud:
        ids = sorted({f.id for f in loud})
        return ReadinessItem(
            **base,
            status=NOT_MET,
            check_ids=ids,
            note=f"{len(loud)} critical/high finding(s): " + ", ".join(ids) + ".",
        )
    passive = [c for c in report.checks if c.mode.value == "passive"]
    unseen = [
        c
        for c in passive
        if c.status == CheckStatus.ERROR or (c.status == CheckStatus.NOT_APPLICABLE and c.blocked)
    ]
    ran = [c.check_id for c in passive if c.status == CheckStatus.RAN]
    if unseen or not ran:
        return ReadinessItem(
            **base,
            status=NA,
            check_ids=[c.check_id for c in unseen],
            note=(
                "No critical or high finding, but these checks could not observe the server, so a "
                "critical or high issue may be hidden: "
                + ", ".join(f"{c.check_id} ({c.reason})" for c in unseen)
                if unseen
                else "No passive check ran."
            ),
        )
    return ReadinessItem(
        **base,
        status=MET,
        check_ids=ran,
        note=(
            "No critical or high finding from the passive checks that ran. A passive scan does not "
            "call tools, so implementation flaws behind them are outside its view."
        ),
    )


def _exfiltration(report: ScanReport) -> ReadinessItem:
    """HubSpot: low risk of data exfiltration and tool poisoning (META-01 + META-07)."""
    poison = _poisoning(report, directory="hubspot", requirement="", source_url="")
    flow = _by_id(report).get("META-07")
    ids = ["META-01", "META-07"]
    base: dict[str, Any] = {
        "directory": "hubspot",
        "requirement": REQ_EXFIL,
        "source_url": HUBSPOT_URL,
        "check_ids": ids,
    }
    flow_bad = flow is not None and flow.status == CheckStatus.RAN and bool(flow.findings)
    if poison.status == NOT_MET or flow_bad:
        parts = []
        if poison.status == NOT_MET:
            parts.append(poison.note)
        if flow_bad:
            parts.append(
                "META-07: the server combines private-data access, untrusted-content intake and an "
                "external send channel (lethal trifecta)."
            )
        return ReadinessItem(**base, status=NOT_MET, note=" ".join(parts))
    if poison.status == MET and flow is not None and flow.status == CheckStatus.RAN:
        return ReadinessItem(
            **base,
            status=MET,
            note="META-01 found no poisoning and META-07 found no toxic combination of tool capabilities.",
        )
    parts = []
    if poison.status != MET:
        parts.append(poison.note)
    if flow is None or flow.status != CheckStatus.RAN:
        parts.append(_why_not_run(flow, "META-07"))
    return ReadinessItem(**base, status=NA, note=" ".join(parts))


def _https(report: ScanReport) -> ReadinessItem:
    base: dict[str, Any] = {
        "directory": "hubspot",
        "requirement": REQ_HTTPS,
        "source_url": HUBSPOT_URL,
        "check_ids": ["TRANS-05"],
    }
    check = _by_id(report).get("TRANS-05")
    if check is None or check.status != CheckStatus.RAN:
        return ReadinessItem(**base, status=NA, note=_why_not_run(check, "TRANS-05"))
    plain = [f for f in check.findings if f.details.get("scheme") == "http"]
    if plain:
        return ReadinessItem(
            **base, status=NOT_MET, note=f"The endpoint is served over plain HTTP: {report.target}"
        )
    return ReadinessItem(**base, status=MET, note=f"The endpoint is served over HTTPS: {report.target}")


def build_readiness(report: ScanReport) -> list[ReadinessItem]:
    """Map this report's check outcomes onto Anthropic, OpenAI and HubSpot listing requirements."""
    if report.target_kind != "mcp":
        reason = f"Not assessable: the target is '{report.target_kind}', so no check ran."
        return [
            ReadinessItem(directory=d, requirement=r, source_url=u, status=NA, check_ids=[], note=reason)
            for d, r, u in _REQUIREMENTS
        ]
    annotations_note_met = "META-06 found every tool annotated, with no annotation contradicting the tool."
    items = [
        _oauth(report),
        _single_check(
            report,
            "META-06",
            directory="anthropic",
            requirement=REQ_ANNOTATIONS,
            source_url=ANTHROPIC_URL,
            met_note=annotations_note_met,
            not_met_note="META-06 found missing or contradictory annotations.",
        ),
        _poisoning(
            report,
            directory="anthropic",
            requirement=REQ_HIDDEN,
            source_url=ANTHROPIC_URL,
        ),
        ReadinessItem(
            directory="anthropic",
            requirement=REQ_OWNERSHIP,
            source_url=ANTHROPIC_URL,
            status=NA,
            check_ids=[],
            note=(
                "Ownership cannot be proven by a CLI scan. The hosted mcpprobe service records the "
                "DNS TXT or .well-known verification for verified owners; an --active scan with "
                "--verify dns-txt writes the proof into its authorisation record."
            ),
        ),
        _single_check(
            report,
            "META-06",
            directory="openai",
            requirement=REQ_OPENAI_ANNOTATIONS,
            source_url=OPENAI_URL,
            met_note=annotations_note_met,
            not_met_note="META-06 found missing or contradictory annotations.",
        ),
        _no_critical_high(report),
        _exfiltration(report),
        _https(report),
    ]
    return items


_REQUIREMENTS: list[tuple[str, str, str]] = [
    ("anthropic", REQ_OAUTH, ANTHROPIC_URL),
    ("anthropic", REQ_ANNOTATIONS, ANTHROPIC_URL),
    ("anthropic", REQ_HIDDEN, ANTHROPIC_URL),
    ("anthropic", REQ_OWNERSHIP, ANTHROPIC_URL),
    ("openai", REQ_OPENAI_ANNOTATIONS, OPENAI_URL),
    ("hubspot", REQ_NO_HIGH, HUBSPOT_URL),
    ("hubspot", REQ_EXFIL, HUBSPOT_URL),
    ("hubspot", REQ_HTTPS, HUBSPOT_URL),
]

__all__ = ["ANTHROPIC_URL", "HUBSPOT_URL", "OPENAI_URL", "build_readiness"]
