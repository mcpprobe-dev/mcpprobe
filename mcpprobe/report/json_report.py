"""JSON report writer: a faithful dump of the ScanReport plus the evidence log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcpprobe.models import ScanReport
from mcpprobe.transport import EvidenceLog


def report_to_dict(report: ScanReport, evidence: EvidenceLog | None = None) -> dict[str, Any]:
    data: dict[str, Any] = report.model_dump(mode="json")
    worst = report.max_severity()
    coverage = report.coverage()
    data["summary"] = {
        "counts": report.counts(),
        "max_severity": worst.value if worst is not None else None,
        "target_kind": report.target_kind,
        # "passed" = ran and found nothing; not_applicable never counts as passed.
        "checks_passed": coverage["passed"],
        "checks_with_findings": coverage["with_findings"],
        "checks_not_applicable": coverage["not_applicable"],
        "checks_applicable": coverage["passed"] + coverage["with_findings"],
        "checks_ran": sum(1 for c in report.checks if c.status.value == "ran"),
        "checks_skipped": sum(1 for c in report.checks if c.status.value == "skipped"),
        "checks_not_implemented": sum(1 for c in report.checks if c.status.value == "not_implemented"),
        "checks_error": sum(1 for c in report.checks if c.status.value == "error"),
    }
    if evidence is not None:
        data["evidence"] = [rec.model_dump(mode="json") for rec in evidence.records]
    return data


def write_json(report: ScanReport, path: str | Path, evidence: EvidenceLog | None = None) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report_to_dict(report, evidence), indent=2, ensure_ascii=False), "utf-8")
    return out
