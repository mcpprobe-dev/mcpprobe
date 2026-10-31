"""Anonymised aggregates over the checkpoint, with 95% Wilson score intervals.

The output (``aggregates.json``) contains counts, rates and category tallies only:
no host, URL or registry server name. Categories seen on fewer than
:data:`MIN_CELL` hosts are merged into "other" so a rare protocol revision or edge
cannot single out a server. The one per-host artefact, the disclosure queue, is
written to a separate file whose name starts with ``PRIVATE-`` and is never read by
the renderer.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from mcpprobe import __version__
from mcpprobe.models import utcnow
from mcpprobe.registry.common import (
    SEVERITY_OUTCOMES,
    STATIC_CHECKS,
    SURVEY_CHECKS,
    HostStatus,
    Outcome,
    is_assessed,
    is_finding,
)

Z_95 = 1.959963984540054
#: Categories with fewer hosts than this are merged into "other".
MIN_CELL = 3
MEDIUM_PLUS = ("critical", "high", "medium")
HIGH_PLUS = ("critical", "high")


def wilson(k: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials ((0, 0) when n = 0)."""
    if n <= 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def proportion(metric_id: str, label: str, k: int, n: int, population: str) -> dict[str, Any]:
    lo, hi = wilson(k, n)
    return {
        "id": metric_id,
        "label": label,
        "numerator": k,
        "denominator": n,
        "rate": (k / n) if n else None,
        "ci95": [lo, hi] if n else None,
        "population": population,
    }


def _rate_of(
    records: list[dict[str, Any]],
    check: str,
    hit: Iterable[str],
    metric_id: str,
    label: str,
    population: str,
    where: Any = None,
) -> dict[str, Any]:
    hits = set(hit)
    rows = [r for r in records if where is None or where(r)]
    assessed = [r for r in rows if is_assessed(r.get("outcomes", {}).get(check))]
    k = sum(1 for r in assessed if r["outcomes"][check] in hits)
    return proportion(metric_id, label, k, len(assessed), population)


def suppress_small(counts: Counter[str], min_cell: int = MIN_CELL) -> dict[str, int]:
    out: dict[str, int] = {}
    other = 0
    for key, n in counts.most_common():
        if n >= min_cell:
            out[key] = n
        else:
            other += n
    if other:
        out[f"other (categories under {min_cell} hosts)"] = other
    return out


_BENCH_ROW = re.compile(
    r"^\|\s*(?P<dataset>[^|]+?)\s*\|\s*(?P<detector>[^|]+?)\s*\|\s*(?P<n>\d+)\s*\|\s*(?P<tp>\d+)\s*\|"
    r"\s*(?P<fp>\d+)\s*\|\s*(?P<tn>\d+)\s*\|\s*(?P<fn>\d+)\s*\|",
    re.M,
)


def parse_benchmark(text: str) -> list[dict[str, Any]]:
    """Rows of the generated table in docs/benchmark.md, with FP rate and recall intervals."""
    rows = []
    for m in _BENCH_ROW.finditer(text):
        tp, fp, tn, fn = (int(m[g]) for g in ("tp", "fp", "tn", "fn"))
        fpr_lo, fpr_hi = wilson(fp, fp + tn)
        rec_lo, rec_hi = wilson(tp, tp + fn)
        rows.append(
            {
                "dataset": m["dataset"],
                "detector": m["detector"],
                "n": int(m["n"]),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "fp_rate": fp / (fp + tn) if fp + tn else None,
                "fp_rate_ci95": [fpr_lo, fpr_hi],
                "recall": tp / (tp + fn) if tp + fn else None,
                "recall_ci95": [rec_lo, rec_hi],
            }
        )
    return rows


def default_benchmark_path() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "benchmark.md"


def aggregate(
    scan_records: Iterable[dict[str, Any]],
    static_records: Iterable[dict[str, Any]] = (),
    selection_summary: dict[str, Any] | None = None,
    *,
    benchmark_text: str | None = None,
    calibration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    records = list(scan_records)
    static = list(static_records)
    statuses = Counter(str(r.get("status")) for r in records)
    scanned = [r for r in records if r.get("status") == HostStatus.SCANNED.value]

    def auth_required(r: dict[str, Any]) -> bool:
        return bool(r.get("auth_required"))

    live = "hosts that negotiated MCP; check reached a result"
    metrics = [
        _rate_of(
            scanned, "AUTH-01", SEVERITY_OUTCOMES, "no_auth", "Answers MCP requests without credentials", live
        ),
        _rate_of(
            scanned,
            "AUTH-02",
            SEVERITY_OUTCOMES,
            "missing_prm_auth",
            "Requires auth but has no usable RFC 9728 protected-resource metadata",
            "remote hosts that require authentication",
            where=auth_required,
        ),
        _rate_of(
            scanned,
            "AUTH-02",
            SEVERITY_OUTCOMES,
            "missing_prm_any",
            "No usable RFC 9728 metadata (any host)",
            live,
        ),
        _rate_of(
            scanned,
            "META-01",
            SEVERITY_OUTCOMES,
            "poisoning_any",
            "Any tool-poisoning indicator (META-01)",
            live,
        ),
        _rate_of(
            scanned,
            "META-01",
            MEDIUM_PLUS,
            "poisoning_medium",
            "Tool-poisoning indicator at medium or above (META-01)",
            live,
        ),
        _rate_of(
            scanned,
            "META-06",
            (Outcome.PASSED.value,),
            "annotations_complete",
            "Complete, consistent tool annotations (META-06 passed)",
            live,
        ),
        _rate_of(
            scanned,
            "META-07",
            SEVERITY_OUTCOMES,
            "toxic_flow",
            "Lethal trifecta / toxic flow (META-07)",
            live,
        ),
        _rate_of(
            scanned,
            "META-03",
            HIGH_PLUS,
            "dangerous_capability",
            "Advertises command execution or file access at high/critical (META-03)",
            live,
        ),
        _rate_of(
            scanned,
            "TRANS-05",
            SEVERITY_OUTCOMES,
            "transport_hygiene",
            "Plain HTTP or missing response security headers (TRANS-05)",
            live,
        ),
    ]
    reachable = [
        r
        for r in records
        if r.get("status")
        in (HostStatus.SCANNED.value, HostStatus.NOT_MCP.value, HostStatus.UNREACHABLE.value)
    ]
    metrics.append(
        proportion(
            "negotiated",
            "Listed remote endpoints that negotiated MCP",
            len(scanned),
            len(reachable),
            "hosts we were allowed to contact (not opted out, blocked or private)",
        )
    )
    metrics.append(
        proportion(
            "auth_required",
            "Require authentication for MCP requests",
            sum(1 for r in scanned if auth_required(r)),
            len(scanned),
            "remote hosts that negotiated MCP",
        )
    )
    na_rates: dict[str, dict[str, int]] = {}
    for check in SURVEY_CHECKS:
        c = Counter(str(r.get("outcomes", {}).get(check)) for r in scanned)
        na_rates[check] = {
            "assessed": sum(n for k, n in c.items() if is_assessed(k)),
            "findings": sum(n for k, n in c.items() if is_finding(k)),
            "n_a": c.get(Outcome.NOT_APPLICABLE.value, 0),
            "blocked": c.get(Outcome.BLOCKED.value, 0),
            "error": c.get(Outcome.ERROR.value, 0),
            "total": len(scanned),
        }
    static_summary: dict[str, Any] = {
        "entries": len(static),
        "assessable": sum(1 for s in static if s.get("assessable")),
        "by_kind": dict(Counter(str(s.get("kind")) for s in static)),
        "metrics": [],
    }
    assessable = [s for s in static if s.get("assessable")]
    static_summary["metrics"] = [
        proportion(
            "static_assessable",
            "Registry entries that carry full tool definitions",
            len(assessable),
            len(static),
            "all registry entries",
        ),
        *[
            _rate_of(
                assessable,
                check,
                SEVERITY_OUTCOMES if check != "META-06" else (Outcome.PASSED.value,),
                f"static_{check.lower().replace('-', '')}",
                f"{check} on registry tool definitions"
                + (" (passed)" if check == "META-06" else " (any finding)"),
                "registry entries with tool definitions",
            )
            for check in STATIC_CHECKS
        ],
    ]
    accuracy: dict[str, Any] = {"benchmark": None, "calibration": calibration}
    if benchmark_text:
        accuracy["benchmark"] = parse_benchmark(benchmark_text)
    return {
        "schema": "mcpprobe-registry-aggregates/1",
        "generated_at": utcnow().isoformat(),
        "scanner_version": __version__,
        "survey_checks": list(SURVEY_CHECKS),
        "funnel": {**(selection_summary or {}), "host_statuses": dict(sorted(statuses.items()))},
        "metrics": metrics,
        "na_rates": na_rates,
        "protocol_versions": suppress_small(
            Counter(str(r.get("protocol_version") or "none") for r in scanned)
        ),
        "flavours": suppress_small(Counter(str(r.get("flavour") or "unknown") for r in scanned)),
        "edge_providers": suppress_small(Counter(str(r.get("edge") or "none detected") for r in scanned)),
        "static": static_summary,
        "accuracy": accuracy,
        "min_cell": MIN_CELL,
    }


def disclosure_queue(scan_records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """PRIVATE: hosts with a high or critical outcome, for responsible disclosure. Never published."""
    out = []
    for r in scan_records:
        if r.get("status") != HostStatus.SCANNED.value:
            continue
        serious = {c: o for c, o in (r.get("outcomes") or {}).items() if o in HIGH_PLUS}
        if serious:
            out.append(
                {
                    "host": r["host"],
                    "url": r.get("url"),
                    "entries": r.get("entries", []),
                    "checks": dict(sorted(serious.items())),
                    "scanned_at": r.get("finished_at"),
                    "notified_at": None,
                    "fixed_at": None,
                }
            )
    return sorted(out, key=lambda d: (-sum(1 for o in d["checks"].values() if o == "critical"), d["host"]))
