"""Anonymised aggregates over the checkpoint, with 95% Wilson score intervals.

Survey records are the ``scan.jsonl`` checkpoint overlaid with any later ``recheck.jsonl``
results (:func:`merge_rechecks`). META-01 rates only count hosts whose META-01 outcome was
produced by the current rules (:data:`META01_RULES`); older outcomes are reported as stale.

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
from mcpprobe.checks.poisoning import RULES_VERSION as META01_RULES
from mcpprobe.models import utcnow
from mcpprobe.registry.common import (
    SEVERITY_OUTCOMES,
    STATIC_CHECKS,
    SURVEY_CHECKS,
    WRITE_EXEC_CAPABILITIES,
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


def small_cell_proportion(
    metric_id: str, label: str, k: int, n: int, population: str, min_cell: int = MIN_CELL
) -> dict[str, Any]:
    """A proportion whose numerator is withheld when 0 < k < min_cell (or n < min_cell)."""
    out = proportion(metric_id, label, k, n, population)
    if 0 < k < min_cell or 0 < n < min_cell:
        out.update(numerator=None, rate=None, ci95=None, suppressed=f"fewer than {min_cell} hosts")
    return out


# ----------------------------------------------------------------------------- record helpers
def merge_rechecks(
    scan_records: Iterable[dict[str, Any]], recheck_records: Iterable[dict[str, Any]] = ()
) -> list[dict[str, Any]]:
    """Overlay each host's latest ``recheck`` result on its original scan record.

    Only the checks the recheck ran replace the stored outcomes; a recheck that did not
    complete (429/403, unreachable, opted out) leaves the original outcomes in place and is
    noted in ``recheck_status``. Hosts that were never scanned are not added.
    """
    last: dict[str, dict[str, Any]] = {}
    last_ok: dict[str, dict[str, Any]] = {}
    for rec in recheck_records:  # in time order: later results win
        last[str(rec.get("host"))] = rec
        if rec.get("status") == HostStatus.SCANNED.value:
            last_ok[str(rec.get("host"))] = rec
    merged = []
    for r in scan_records:
        host = str(r.get("host"))
        if host not in last:
            merged.append(r)
            continue
        m = dict(r)
        m["recheck_status"] = last[host].get("status")
        m["rechecked_at"] = last[host].get("finished_at")
        rc = last_ok.get(host)
        if rc is not None:
            ran = list(rc.get("checks_run") or (rc.get("outcomes") or {}).keys())
            new = rc.get("outcomes") or {}
            m["outcomes"] = {**(r.get("outcomes") or {}), **{c: new[c] for c in ran if c in new}}
            for key in ("auth_required", "inventory", "protocol_version", "flavour", "edge"):
                if rc.get(key) is not None:
                    m[key] = rc[key]
            for key in ("capabilities", "meta01_indicators", "meta01_rules"):
                if key in rc:
                    m[key] = rc[key]
            if "AUTH-01" not in ran and rc.get("auth_required") is not None:
                # The stored AUTH-01 outcome predates the recheck; trust the newer observation.
                m["open_observed"] = not rc["auth_required"]
        merged.append(m)
    return merged


def is_open(r: dict[str, Any]) -> bool:
    """The host answered MCP requests without credentials (AUTH-01), as last observed."""
    if "open_observed" in r:
        return bool(r["open_observed"])
    auth01 = (r.get("outcomes") or {}).get("AUTH-01")
    if is_finding(auth01):
        return True
    if auth01 == Outcome.PASSED.value:
        return False
    return r.get("auth_required") is False


def meta01_current(r: dict[str, Any]) -> bool:
    """The stored META-01 outcome came from the current rules."""
    return r.get("meta01_rules") == META01_RULES


def _outcome(r: dict[str, Any], check: str) -> str | None:
    return (r.get("outcomes") or {}).get(check)


def tool_bucket(n: int) -> str:
    for hi, label in (
        (0, "0"),
        (1, "1"),
        (5, "2-5"),
        (10, "6-10"),
        (20, "11-20"),
        (50, "21-50"),
        (100, "51-100"),
    ):
        if n <= hi:
            return label
    return "over 100"


TOOL_BUCKETS = ("0", "1", "2-5", "6-10", "11-20", "21-50", "51-100", "over 100")


def crosstabs(scanned: list[dict[str, Any]], min_cell: int = MIN_CELL) -> dict[str, Any]:
    """Cross-tabulations for the report; numerators under ``min_cell`` are withheld."""
    tools_seen = [r for r in scanned if is_assessed(_outcome(r, "META-03"))]
    open_tools = [r for r in tools_seen if is_open(r)]
    auth_tools = [r for r in tools_seen if not is_open(r)]

    def rate(
        rows: list[dict[str, Any]], check: str, hit: Iterable[str], mid: str, label: str, pop: str
    ) -> dict[str, Any]:
        hits = set(hit)
        assessed = [r for r in rows if is_assessed(_outcome(r, check))]
        k = sum(1 for r in assessed if _outcome(r, check) in hits)
        return small_cell_proportion(mid, label, k, len(assessed), pop, min_cell)

    with_caps = [r for r in open_tools if isinstance(r.get("capabilities"), list)]
    k_write = sum(1 for r in with_caps if WRITE_EXEC_CAPABILITIES & set(r["capabilities"]))
    counts: Counter[str] = Counter(
        tool_bucket(int((r.get("inventory") or {}).get("tools") or 0)) for r in open_tools
    )
    distribution = {}
    for b in TOOL_BUCKETS:
        n = counts.get(b, 0)
        distribution[b] = None if 0 < n < min_cell else n
    return {
        "dangerous_capability_by_auth": [
            rate(
                open_tools,
                "META-03",
                HIGH_PLUS,
                "dangerous_capability_open",
                "Command execution or file access (META-03 high/critical): open servers",
                "servers whose tool list was visible and that answer without credentials",
            ),
            rate(
                auth_tools,
                "META-03",
                HIGH_PLUS,
                "dangerous_capability_auth",
                "Command execution or file access (META-03 high/critical): servers requiring auth",
                "servers whose tool list was visible although they require authentication for some requests",
            ),
        ],
        "toxic_flow_by_auth": [
            rate(
                open_tools,
                "META-07",
                SEVERITY_OUTCOMES,
                "toxic_flow_open",
                "Lethal trifecta (META-07): open servers",
                "servers whose tool list was visible and that answer without credentials",
            ),
            rate(
                auth_tools,
                "META-07",
                SEVERITY_OUTCOMES,
                "toxic_flow_auth",
                "Lethal trifecta (META-07): servers requiring auth",
                "servers whose tool list was visible although they require authentication for some requests",
            ),
        ],
        "open_capability": [
            small_cell_proportion(
                "open_write_exec",
                "Open and exposes write/exec-capable tools (exec, file or database write, e-mail, payments)",
                k_write,
                len(with_caps),
                "open servers rechecked with capability labels (scanner 0.3.1 or later)",
                min_cell,
            ),
            rate(
                open_tools,
                "META-03",
                SEVERITY_OUTCOMES,
                "open_high_impact",
                "Open and exposes any high-impact tool (META-03 any finding)",
                "servers whose tool list was visible and that answer without credentials",
            ),
        ],
        "tool_count_distribution": {
            "population": "servers whose tool list was visible and that answer without credentials",
            "hosts": len(open_tools),
            "buckets": distribution,
        },
    }


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
    disclosure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    records = list(scan_records)
    static = list(static_records)
    statuses = Counter(str(r.get("status")) for r in records)
    scanned = [r for r in records if r.get("status") == HostStatus.SCANNED.value]

    def auth_required(r: dict[str, Any]) -> bool:
        return bool(r.get("auth_required"))

    live = "hosts that negotiated MCP; check reached a result"
    meta01_pop = f"{live}; META-01 rules {META01_RULES} only (older outcomes excluded)"
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
            meta01_pop,
            where=meta01_current,
        ),
        _rate_of(
            scanned,
            "META-01",
            MEDIUM_PLUS,
            "poisoning_medium",
            "Tool-poisoning indicator at medium or above (META-01)",
            meta01_pop,
            where=meta01_current,
        ),
        _rate_of(
            scanned,
            "META-01",
            HIGH_PLUS,
            "poisoning_high",
            "Tool-poisoning indicator at high (META-01)",
            meta01_pop,
            where=meta01_current,
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
        "crosstabs": crosstabs(scanned),
        "meta01_rules": {
            "current": META01_RULES,
            "hosts_by_rules": dict(
                Counter(
                    "current" if meta01_current(r) else "older (excluded from META-01 rates)"
                    for r in scanned
                    if is_assessed(_outcome(r, "META-01"))
                )
            ),
        },
        "disclosure": public_disclosure_counts(disclosure) if disclosure else None,
        "accuracy": accuracy,
        "min_cell": MIN_CELL,
    }


# ----------------------------------------------------------------------------- disclosure
PRIORITIES = {
    "P1": "secrets in tool metadata (META-05 high/critical)",
    "P2": "command execution or file access without authentication (META-03 high/critical on an open "
    "server), or a token-validation bypass (AUTH-04 high/critical)",
    "P3": f"tool poisoning at high severity (META-01 high, rules {META01_RULES})",
    "P4": "lethal trifecta without authentication (META-07 on an open server)",
}
#: What never qualifies on its own in the survey: an open server is a description, not a vulnerability.
DESCRIPTIVE_ONLY = ("AUTH-01", "AUTH-02", "TRANS-05", "TRANS-06", "TRANS-09", "META-04", "META-06")


def disclosure_reasons(r: dict[str, Any]) -> list[tuple[str, str]]:
    """(priority, reason) pairs for one merged survey record; empty when it does not qualify."""
    out: list[tuple[str, str]] = []
    open_ = is_open(r)
    meta05 = _outcome(r, "META-05")
    if meta05 in HIGH_PLUS:
        out.append(("P1", f"META-05 {meta05}: secret in tool metadata"))
    meta03 = _outcome(r, "META-03")
    if meta03 in HIGH_PLUS and open_:
        out.append(("P2", f"META-03 {meta03}: command execution or file access, no authentication"))
    auth04 = _outcome(r, "AUTH-04")
    if auth04 in HIGH_PLUS:
        out.append(("P2", f"AUTH-04 {auth04}: token validation bypass"))
    meta01 = _outcome(r, "META-01")
    if meta01 in HIGH_PLUS and meta01_current(r):
        out.append(("P3", f"META-01 {meta01}: tool poisoning (rules {META01_RULES})"))
    if is_finding(_outcome(r, "META-07")) and open_:
        out.append(("P4", f"META-07 {_outcome(r, 'META-07')}: lethal trifecta, no authentication"))
    return out


def disclosure_queue(scan_records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """PRIVATE: hosts that qualify for responsible disclosure, by priority. Never published.

    Pass merged records (:func:`merge_rechecks`). AUTH-01, AUTH-02 and TRANS-05 never qualify
    on their own; see :data:`PRIORITIES` for what does.
    """
    out = []
    for r in scan_records:
        if r.get("status") != HostStatus.SCANNED.value:
            continue
        reasons = disclosure_reasons(r)
        if not reasons:
            continue
        priority = min(p for p, _ in reasons)
        qualifying = {c.split(" ", 1)[0] for _, c in reasons}
        outcomes = r.get("outcomes") or {}
        out.append(
            {
                "host": r["host"],
                "url": r.get("url"),
                "entries": r.get("entries", []),
                "priority": priority,
                "priorities": sorted({p for p, _ in reasons}),
                "reasons": [reason for _, reason in sorted(reasons)],
                "checks": {c: outcomes[c] for c in sorted(qualifying) if c in outcomes},
                "context": {
                    c: o for c, o in sorted(outcomes.items()) if c not in qualifying and is_finding(o)
                },
                "open": is_open(r),
                "meta01_rules": r.get("meta01_rules"),
                "scanned_at": r.get("finished_at"),
                "recheck_status": r.get("recheck_status"),
                "notified_at": None,
                "fixed_at": None,
            }
        )
    return sorted(out, key=lambda d: (d["priority"], d["host"]))


def disclosure_summary(queue: list[dict[str, Any]], records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Counts only, no host: what the queue holds and what the rules left out."""
    rows = [r for r in records if r.get("status") == HostStatus.SCANNED.value]
    current = [d for d in queue if d.get("priority")]
    by_reason: Counter[str] = Counter()
    for d in current:
        for reason in d.get("reasons") or []:
            by_reason[reason.split(":", 1)[0]] += 1
    qualifying_hosts = {d["host"] for d in current}
    high_anywhere = [r for r in rows if any(o in HIGH_PLUS for o in (r.get("outcomes") or {}).values())]
    stale = [
        r
        for r in rows
        if _outcome(r, "META-01") in HIGH_PLUS and not meta01_current(r) and r["host"] not in qualifying_hosts
    ]
    return {
        "schema": "mcpprobe-disclosure-summary/1",
        "generated_at": utcnow().isoformat(),
        "scanner_version": __version__,
        "meta01_rules": META01_RULES,
        "criteria": PRIORITIES,
        "never_qualify_alone": list(DESCRIPTIVE_ONLY),
        "hosts": len(current),
        "by_priority": {p: sum(1 for d in current if d["priority"] == p) for p in PRIORITIES},
        "meeting_criterion": {
            p: sum(1 for d in current if p in (d.get("priorities") or [d["priority"]])) for p in PRIORITIES
        },
        "by_reason": dict(sorted(by_reason.items())),
        "high_or_critical_but_not_qualifying": len(
            [r for r in high_anywhere if r["host"] not in qualifying_hosts]
        ),
        "meta01_high_on_older_rules_pending_recheck": len(stale),
        "carried_over_notified": sum(1 for d in queue if not d.get("priority")),
    }


def public_disclosure_counts(summary: dict[str, Any], min_cell: int = MIN_CELL) -> dict[str, Any]:
    """The summary as it may appear in aggregates.json: small counts withheld."""

    def cell(n: int) -> int | None:
        return None if 0 < n < min_cell else n

    return {
        "criteria": summary.get("criteria"),
        "hosts": cell(int(summary.get("hosts") or 0)),
        "by_priority": {p: cell(int(n)) for p, n in (summary.get("by_priority") or {}).items()},
        "meeting_criterion": {p: cell(int(n)) for p, n in (summary.get("meeting_criterion") or {}).items()},
        "meta01_rules": summary.get("meta01_rules"),
    }
