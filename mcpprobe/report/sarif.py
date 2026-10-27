"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

Severity mapping: critical/high -> ``error``, medium -> ``warning``,
low/info -> ``note``. The numeric ``security-severity`` rule property follows
the GitHub convention (critical 9.0+, high 7.0-8.9, medium 4.0-6.9, low <4.0).

Results need a ``physicalLocation``. A scanned endpoint is not a file in the
repository, so by default the location URI is the target URL (or a
``stdio:`` URI for a local command). Pass ``location_uri`` (CLI
``--sarif-location``) to anchor results to a repository file instead, e.g. the
server's entry point or the client config that references it.

:func:`validate_sarif` checks the structural requirements of the SARIF 2.1.0
specification that matter for consumers (required properties, enumerations,
index consistency, no ``null`` values). The test-suite additionally validates
against the official JSON schema.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from mcpprobe import POLICY_URL, __version__
from mcpprobe.checks import ALL_CHECKS
from mcpprobe.models import Finding, ScanReport, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://mcpprobe.tech"

LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.5",
}
_LEVELS = {"none", "note", "warning", "error"}
_KINDS = {"notApplicable", "pass", "fail", "review", "open", "informational"}


def _rules() -> list[dict[str, Any]]:
    rules = []
    for cls in ALL_CHECKS:
        fp_note = f"\n\nFalse positives: {cls.false_positive_notes}" if cls.false_positive_notes else ""
        rules.append(
            {
                "id": cls.id,
                "name": cls.__name__,
                "shortDescription": {"text": cls.title},
                "fullDescription": {"text": cls.description or cls.title},
                "helpUri": f"{INFORMATION_URI}/checks/{cls.id.lower()}",
                "help": {
                    "text": (cls.fix or cls.title) + fp_note,
                    "markdown": f"**Fix:** {cls.fix or cls.title}"
                    + (
                        f"\n\n**False positives:** {cls.false_positive_notes}"
                        if cls.false_positive_notes
                        else ""
                    ),
                },
                "defaultConfiguration": {"level": LEVEL[cls.severity]},
                "properties": {
                    "tags": _unique(["security", "mcp", cls.mode.value, *cls.standards.as_tags()]),
                    "security-severity": SECURITY_SEVERITY[cls.severity],
                    "precision": "medium",
                    "problem.severity": "error" if LEVEL[cls.severity] == "error" else "warning",
                    "mode": cls.mode.value,
                },
            }
        )
    return rules


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def default_location_uri(report: ScanReport) -> str:
    if report.fingerprint is not None and report.fingerprint.transport == "stdio":
        return "stdio:" + quote(report.target, safe="")
    return report.target


def _result(f: Finding, rule_index: dict[str, int], uri: str) -> dict[str, Any]:
    text = f.description
    if f.evidence_excerpt:
        text += f"\n\nEvidence: {f.evidence_excerpt}"
    if f.fix:
        text += f"\n\nFix: {f.fix}"
    result: dict[str, Any] = {
        "ruleId": f.id,
        "level": LEVEL[f.severity],
        "kind": "fail",
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f.location or uri, "kind": "resource"}],
            }
        ],
        "partialFingerprints": {"mcpprobe/v1": f.fingerprint},
        "properties": {
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "standards": f.standards.model_dump(),
            "evidenceIds": [e.id for e in f.evidence],
            "details": _strip_nulls(f.details),
        },
    }
    if f.id in rule_index:
        result["ruleIndex"] = rule_index[f.id]
    return result


def _strip_nulls(value: Any) -> Any:
    """SARIF property bags accept any JSON, but consumers choke on nulls; drop them."""
    if isinstance(value, dict):
        return {str(k): _strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nulls(v) for v in value if v is not None]
    return value


def to_sarif(report: ScanReport, *, location_uri: str | None = None) -> dict[str, Any]:
    rules = _rules()
    rule_index = {r["id"]: i for i, r in enumerate(rules)}
    uri = location_uri or default_location_uri(report)
    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "startTimeUtc": report.started_at.isoformat(),
        "toolExecutionNotifications": [
            {
                "level": "note",
                "message": {
                    "text": f"{c.check_id}: {c.status.value}" + (f" ({c.reason})" if c.reason else "")
                },
                "associatedRule": {"id": c.check_id},
            }
            for c in report.checks
            if c.status.value != "ran"
        ],
    }
    if report.finished_at is not None:
        invocation["endTimeUtc"] = report.finished_at.isoformat()
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "mcpprobe",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
                "properties": {"scanningPolicy": POLICY_URL},
            }
        },
        "automationDetails": {
            "id": f"mcpprobe/{report.mode.value}/{report.started_at.strftime('%Y%m%dT%H%M%SZ')}"
        },
        "invocations": [invocation],
        "results": [_result(f, rule_index, uri) for f in report.findings],
        "properties": _strip_nulls(
            {
                "target": report.target,
                "mode": report.mode.value,
                "fingerprint": report.fingerprint.model_dump(mode="json") if report.fingerprint else None,
                "counts": report.counts(),
                "attestationOnly": [
                    {"id": a.id, "title": a.title, "status": a.status} for a in report.attestations
                ],
                "notes": report.notes,
            }
        ),
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def write_sarif(report: ScanReport, path: str | Path, *, location_uri: str | None = None) -> Path:
    doc = to_sarif(report, location_uri=location_uri)
    problems = validate_sarif(doc)
    if problems:  # pragma: no cover - guarded by tests
        raise ValueError("generated SARIF is invalid: " + "; ".join(problems))
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2), "utf-8")
    return out


# --------------------------------------------------------------------------- validation
def _nulls(value: Any, path: str, out: list[str]) -> None:
    if value is None:
        out.append(f"{path}: null is not allowed")
    elif isinstance(value, dict):
        for k, v in value.items():
            _nulls(v, f"{path}.{k}", out)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _nulls(v, f"{path}[{i}]", out)


def _message_ok(msg: Any) -> bool:
    return isinstance(msg, dict) and (isinstance(msg.get("text"), str) or isinstance(msg.get("id"), str))


def validate_sarif(doc: Any) -> list[str]:
    """Return a list of problems (empty when the log satisfies the checked SARIF 2.1.0 rules)."""
    p: list[str] = []
    if not isinstance(doc, dict):
        return ["sarifLog must be an object"]
    _nulls(doc, "$", p)
    if doc.get("version") != SARIF_VERSION:
        p.append("sarifLog.version must be '2.1.0'")
    runs = doc.get("runs")
    if not isinstance(runs, list):
        return [*p, "sarifLog.runs must be an array"]
    for ri, run in enumerate(runs):
        where = f"runs[{ri}]"
        if not isinstance(run, dict):
            p.append(f"{where} must be an object")
            continue
        driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str) or not driver["name"]:
            p.append(f"{where}.tool.driver.name is required")
            driver = {}
        rules = driver.get("rules", [])
        if not isinstance(rules, list):
            p.append(f"{where}.tool.driver.rules must be an array")
            rules = []
        ids = [r.get("id") for r in rules if isinstance(r, dict)]
        if any(not isinstance(i, str) or not i for i in ids) or len(ids) != len(rules):
            p.append(f"{where}: every rule needs a string id")
        if len(set(ids)) != len(ids):
            p.append(f"{where}: rule ids must be unique")
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                continue
            lvl = (r.get("defaultConfiguration") or {}).get("level")
            if lvl is not None and lvl not in _LEVELS:
                p.append(f"{where}.rules[{i}].defaultConfiguration.level invalid: {lvl!r}")
            tags = (r.get("properties") or {}).get("tags")
            if tags is not None and (not isinstance(tags, list) or len(set(tags)) != len(tags)):
                p.append(f"{where}.rules[{i}].properties.tags must be unique strings")
        for ii, inv in enumerate(run.get("invocations") or []):
            if not isinstance(inv, dict) or not isinstance(inv.get("executionSuccessful"), bool):
                p.append(f"{where}.invocations[{ii}].executionSuccessful (boolean) is required")
                continue
            for n, note in enumerate(inv.get("toolExecutionNotifications") or []):
                if not _message_ok(note.get("message")):
                    p.append(f"{where}.invocations[{ii}].toolExecutionNotifications[{n}].message required")
        results = run.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            p.append(f"{where}.results must be an array")
            continue
        for xi, res in enumerate(results):
            rw = f"{where}.results[{xi}]"
            if not isinstance(res, dict):
                p.append(f"{rw} must be an object")
                continue
            if not _message_ok(res.get("message")):
                p.append(f"{rw}.message with text or id is required")
            rid = res.get("ruleId")
            if rid is not None and not isinstance(rid, str):
                p.append(f"{rw}.ruleId must be a string")
            idx = res.get("ruleIndex")
            if idx is not None:
                if not isinstance(idx, int) or idx < -1 or idx >= len(rules):
                    p.append(f"{rw}.ruleIndex out of range")
                elif idx >= 0 and rid is not None and ids[idx] != rid:
                    p.append(f"{rw}.ruleIndex does not match ruleId")
            if rid is None and idx is None:
                p.append(f"{rw} needs ruleId or ruleIndex")
            if res.get("level", "warning") not in _LEVELS:
                p.append(f"{rw}.level invalid")
            if res.get("kind", "fail") not in _KINDS:
                p.append(f"{rw}.kind invalid")
            for li, loc in enumerate(res.get("locations") or []):
                phys = loc.get("physicalLocation") if isinstance(loc, dict) else None
                if phys is None:
                    continue
                art = phys.get("artifactLocation")
                if (
                    not (isinstance(art, dict) and isinstance(art.get("uri"), str) and art["uri"])
                    and "address" not in phys
                ):
                    p.append(f"{rw}.locations[{li}].physicalLocation needs artifactLocation.uri")
                region = phys.get("region")
                if region is not None and (
                    not isinstance(region.get("startLine", 1), int) or region.get("startLine", 1) < 1
                ):
                    p.append(f"{rw}.locations[{li}].region.startLine must be >= 1")
            pf = res.get("partialFingerprints")
            if pf is not None and not all(isinstance(v, str) for v in pf.values()):
                p.append(f"{rw}.partialFingerprints values must be strings")
    return p


__all__ = [
    "LEVEL",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SECURITY_SEVERITY",
    "to_sarif",
    "validate_sarif",
    "write_sarif",
]
