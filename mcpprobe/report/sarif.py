"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

Severity mapping: critical/high -> ``error``, medium -> ``warning``,
low/info -> ``note``. The numeric ``security-severity`` property follows the
GitHub convention (critical 9.0+, high 7.0-8.9, medium 4.0-6.9, low <4.0).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcpprobe import POLICY_URL, __version__
from mcpprobe.checks import ALL_CHECKS
from mcpprobe.models import Finding, ScanReport, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.5",
}


def _rules() -> list[dict[str, Any]]:
    rules = []
    for cls in ALL_CHECKS:
        rules.append(
            {
                "id": cls.id,
                "name": cls.__name__,
                "shortDescription": {"text": cls.title},
                "fullDescription": {"text": cls.description or cls.title},
                "help": {
                    "text": (cls.fix or "") + ("\n\nFalse positives: " + cls.false_positive_notes if cls.false_positive_notes else ""),
                    "markdown": f"**Fix:** {cls.fix}\n\n**False positives:** {cls.false_positive_notes}",
                },
                "defaultConfiguration": {"level": _LEVEL[cls.severity]},
                "properties": {
                    "tags": ["security", "mcp", cls.mode.value, *cls.standards.as_tags()],
                    "security-severity": _SCORE[cls.severity],
                    "precision": "medium",
                    "mode": cls.mode.value,
                },
            }
        )
    return rules


def _result(f: Finding, rule_index: dict[str, int], target: str) -> dict[str, Any]:
    text = f.description
    if f.fix:
        text += f"\n\nFix: {f.fix}"
    evidence_ids = [e.id for e in f.evidence]
    return {
        "ruleId": f.id,
        "ruleIndex": rule_index.get(f.id, -1),
        "level": _LEVEL[f.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                },
                "logicalLocations": [{"name": f.location or target, "kind": "resource"}],
            }
        ],
        "partialFingerprints": {"mcpprobe/v1": f.fingerprint},
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "security-severity": _SCORE[f.severity],
            "standards": f.standards.model_dump(),
            "evidence": evidence_ids,
            "details": f.details,
        },
    }


def to_sarif(report: ScanReport) -> dict[str, Any]:
    rules = _rules()
    rule_index = {r["id"]: i for i, r in enumerate(rules)}
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "mcpprobe",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": POLICY_URL,
                "rules": rules,
            }
        },
        "automationDetails": {"id": f"mcpprobe/{report.mode.value}/{report.started_at.isoformat()}"},
        "invocations": [
            {
                "executionSuccessful": True,
                "startTimeUtc": report.started_at.isoformat(),
                "endTimeUtc": report.finished_at.isoformat() if report.finished_at else None,
                "toolExecutionNotifications": [
                    {
                        "level": "note",
                        "message": {"text": f"{c.check_id}: {c.status.value}" + (f" ({c.reason})" if c.reason else "")},
                        "associatedRule": {"id": c.check_id},
                    }
                    for c in report.checks
                    if c.status.value != "ran"
                ],
            }
        ],
        "results": [_result(f, rule_index, report.target) for f in report.findings],
        "properties": {
            "fingerprint": report.fingerprint.model_dump(mode="json") if report.fingerprint else None,
            "counts": report.counts(),
            "notes": report.notes,
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def write_sarif(report: ScanReport, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(to_sarif(report), indent=2), "utf-8")
    return out
