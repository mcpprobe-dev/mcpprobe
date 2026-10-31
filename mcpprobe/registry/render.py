"""Render ``aggregates.json`` into a Markdown report with SVG charts (standard library only).

The renderer only ever reads aggregates, so it has no host to leak; as a second line of
defence :func:`assert_no_identifiers` refuses to write any file that contains a host,
URL or registry server name from the working directory, except hosts the operator
explicitly allows (our own, or a disclosed finding the operator has confirmed fixed and
agreed to name).
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from mcpprobe.registry.common import MAX_CONCURRENCY, PER_HOST_INTERVAL

#: Hosts that are ours and may always be named.
OUR_HOSTS = ("mcpprobe.tech",)

PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")

# Chart palette: neutral ink plus one accent; readable on white and in dark-mode viewers
# because every chart draws its own white background.
INK = "#1f2933"
MUTED = "#616e7c"
GRID = "#d9dee3"
BAR = "#3e6fb0"
WHISKER = "#102a43"
BG = "#ffffff"


class IdentifierLeakError(Exception):
    """A rendered file would name a third-party host, URL or registry entry."""


def default_template() -> str:
    from mcpprobe.registry.template import DEFAULT_TEMPLATE

    return DEFAULT_TEMPLATE


def pct(x: float | None, digits: int = 1) -> str:
    return "n/a" if x is None else f"{100 * x:.{digits}f}%"


def _ci(m: dict[str, Any]) -> str:
    ci = m.get("ci95")
    return "n/a" if not ci else f"{pct(ci[0])} to {pct(ci[1])}"


def metrics_table(metrics: list[dict[str, Any]]) -> str:
    lines = ["| Measure | Hosts | Rate | 95% CI | Population |", "|---|---|---|---|---|"]
    for m in metrics:
        lines.append(
            f"| {m['label']} | {m['numerator']}/{m['denominator']} | {pct(m['rate'])} | {_ci(m)} | {m['population']} |"
        )
    return "\n".join(lines)


def counts_table(counts: dict[str, int], header: str) -> str:
    total = sum(counts.values())
    lines = [f"| {header} | Hosts | Share |", "|---|---|---|"]
    for k, n in counts.items():
        lines.append(f"| {k} | {n} | {pct(n / total if total else None)} |")
    if not counts:
        lines.append("| (none) | 0 | n/a |")
    return "\n".join(lines)


def funnel_table(funnel: dict[str, Any]) -> str:
    rows = [
        ("Registry entries (latest version, not deleted)", funnel.get("entries")),
        ("Entries with a remote endpoint", funnel.get("remote_entries")),
        ("Package-only entries", funnel.get("package_only_entries")),
        ("Remote URLs listed", funnel.get("remote_urls")),
        ("Unique hosts selected for the passive scan", funnel.get("unique_hosts")),
    ]
    lines = ["| Stage | Count |", "|---|---|"]
    lines += [f"| {label} | {'n/a' if v is None else v} |" for label, v in rows]
    excluded = funnel.get("excluded") or {}
    for reason, n in excluded.items():
        lines.append(f"| Excluded before scanning: {reason.replace('_', ' ')} | {n} |")
    for status, n in (funnel.get("host_statuses") or {}).items():
        lines.append(f"| Host outcome: {status.replace('_', ' ')} | {n} |")
    return "\n".join(lines)


def na_table(na: dict[str, dict[str, int]]) -> str:
    lines = [
        "| Check | Reached a result | With findings | Not applicable | Blocked (e.g. behind auth) | Error |",
        "|---|---|---|---|---|---|",
    ]
    for check, c in na.items():
        total = c.get("total") or 0

        def cell(k: str, c: dict[str, int] = c, total: int = total) -> str:
            return f"{c.get(k, 0)} ({pct(c.get(k, 0) / total if total else None)})"

        lines.append(
            f"| {check} | {cell('assessed')} | {cell('findings')} | {cell('n_a')} | {cell('blocked')} | {cell('error')} |"
        )
    return "\n".join(lines)


def accuracy_section(acc: dict[str, Any]) -> str:
    out: list[str] = []
    bench = acc.get("benchmark") or []
    if bench:
        out.append("| Dataset | Detector | n | False-positive rate | 95% CI | Recall | 95% CI |")
        out.append("|---|---|---|---|---|---|---|")
        for b in bench:
            out.append(
                f"| {b['dataset']} | {b['detector']} | {b['n']} | {pct(b['fp_rate'])} | "
                f"{pct(b['fp_rate_ci95'][0])} to {pct(b['fp_rate_ci95'][1])} | {pct(b['recall'])} | "
                f"{pct(b['recall_ci95'][0])} to {pct(b['recall_ci95'][1])} |"
            )
        out.append("")
        out.append(
            "A false-positive rate of 0 on a few dozen texts still allows a true rate of several "
            "percent: read the upper bound of the interval, not the point estimate."
        )
    else:
        out.append("The META-01 benchmark table (docs/benchmark.md) was not available for this run.")
    cal = acc.get("calibration")
    out.append("")
    if cal:
        for name, c in sorted(cal.items()):
            out.append(
                f"- Calibration fixture `{name}` ({c.get('description', '')}): status {c.get('status')}, "
                f"{c.get('findings', 0)} survey-profile finding(s), {c.get('requests', 0)} request(s)."
            )
    else:
        out.append("- Calibration against the in-repo fixtures was not run for this report.")
    return "\n".join(out)


# ----------------------------------------------------------------------------- SVG
def _svg_open(width: int, height: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}" '
        'font-family="system-ui, -apple-system, Segoe UI, sans-serif" font-size="12">',
        f"<title>{html.escape(title)}</title>",
        f'<rect width="{width}" height="{height}" fill="{BG}"/>',
        f'<text x="12" y="22" font-size="14" font-weight="600" fill="{INK}">{html.escape(title)}</text>',
    ]


def rate_chart(metrics: list[dict[str, Any]], title: str) -> str:
    """Horizontal bars (0-100%) with 95% CI whiskers; metrics without data are listed as n/a."""
    label_w, plot_w, row_h, top = 330, 360, 26, 44
    width = label_w + plot_w + 70
    height = top + row_h * max(1, len(metrics)) + 30
    parts = _svg_open(width, height, title)
    for tick in range(0, 101, 25):
        x = label_w + plot_w * tick / 100
        parts.append(f'<line x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{height - 26}" stroke="{GRID}"/>')
        parts.append(
            f'<text x="{x:.1f}" y="{height - 10}" text-anchor="middle" fill="{MUTED}">{tick}%</text>'
        )
    for i, m in enumerate(metrics):
        y = top + i * row_h
        label = m["label"] if len(m["label"]) <= 52 else m["label"][:51] + "…"
        parts.append(
            f'<text x="{label_w - 8}" y="{y + 15}" text-anchor="end" fill="{INK}">{html.escape(label)}</text>'
        )
        if m.get("rate") is None:
            parts.append(f'<text x="{label_w + 4}" y="{y + 15}" fill="{MUTED}">n/a (no hosts)</text>')
            continue
        w = plot_w * m["rate"]
        parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{w:.1f}" height="14" rx="2" fill="{BAR}"/>')
        lo, hi = m["ci95"]
        x1, x2 = label_w + plot_w * lo, label_w + plot_w * hi
        parts.append(f'<line x1="{x1:.1f}" y1="{y + 11}" x2="{x2:.1f}" y2="{y + 11}" stroke="{WHISKER}"/>')
        for x in (x1, x2):
            parts.append(f'<line x1="{x:.1f}" y1="{y + 6}" x2="{x:.1f}" y2="{y + 16}" stroke="{WHISKER}"/>')
        parts.append(
            f'<text x="{label_w + plot_w + 8}" y="{y + 15}" fill="{INK}">{pct(m["rate"], 0)} '
            f'<tspan fill="{MUTED}">n={m["denominator"]}</tspan></text>'
        )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def count_chart(counts: dict[str, int], title: str) -> str:
    label_w, plot_w, row_h, top = 230, 380, 24, 44
    width = label_w + plot_w + 60
    height = top + row_h * max(1, len(counts)) + 12
    parts = _svg_open(width, height, title)
    peak = max(counts.values(), default=0)
    if not counts:
        parts.append(f'<text x="12" y="{top + 14}" fill="{MUTED}">No data</text>')
    for i, (key, n) in enumerate(counts.items()):
        y = top + i * row_h
        w = plot_w * n / peak if peak else 0
        parts.append(
            f'<text x="{label_w - 8}" y="{y + 14}" text-anchor="end" fill="{INK}">{html.escape(key)}</text>'
        )
        parts.append(f'<rect x="{label_w}" y="{y + 3}" width="{w:.1f}" height="14" rx="2" fill="{BAR}"/>')
        parts.append(f'<text x="{label_w + w + 6:.1f}" y="{y + 14}" fill="{INK}">{n}</text>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


# ----------------------------------------------------------------------------- guard
def assert_no_identifiers(text: str, forbidden: Iterable[str], allowed: Iterable[str] = ()) -> None:
    allowed_set = {a.lower() for a in allowed}
    low = text.lower()
    leaked = sorted({f for f in forbidden if f and f.lower() not in allowed_set and f.lower() in low})
    if leaked:
        raise IdentifierLeakError(
            f"refusing to write the report: it names {len(leaked)} third-party identifier(s) "
            f"(first: {leaked[0]!r}). Remove them from the template, or pass --allow-host only for "
            "hosts that are ours or whose disclosed finding is fixed and whose operator agreed."
        )


def fixed_section(fixed_hosts: list[str], fixed_count: int) -> str:
    if not fixed_count:
        return "No disclosed issue had been confirmed fixed when this report was generated."
    text = f"{fixed_count} disclosed issue(s) were confirmed fixed by their operators before publication."
    if fixed_hosts:
        text += " Operators who agreed to be named: " + ", ".join(sorted(fixed_hosts)) + "."
    return text


def render(
    agg: dict[str, Any],
    out_dir: Path,
    *,
    template: str | None = None,
    forbidden: Iterable[str] = (),
    allowed_hosts: Iterable[str] = (),
    fixed_hosts: Iterable[str] = (),
    fixed_count: int = 0,
) -> list[Path]:
    """Write ``report.md`` and the SVG charts into ``out_dir``; returns the written paths."""
    tmpl = template if template is not None else default_template()
    metrics = agg.get("metrics") or []
    headline = [m for m in metrics if m["id"] not in ("negotiated", "missing_prm_any")]
    allowed = [*OUR_HOSTS, *allowed_hosts, *fixed_hosts]
    charts = {
        "chart-headline.svg": rate_chart(headline, "Remote MCP endpoints: headline rates (95% CI)"),
        "chart-protocols.svg": count_chart(
            agg.get("protocol_versions") or {}, "Protocol revisions negotiated"
        ),
        "chart-edges.svg": count_chart(agg.get("edge_providers") or {}, "Edge providers detected"),
    }
    static = agg.get("static") or {}
    values: dict[str, str] = {
        "generated_at": str(agg.get("generated_at", "")),
        "scanner_version": str(agg.get("scanner_version", "")),
        "survey_checks": ", ".join(agg.get("survey_checks") or []),
        "per_host_interval": f"{PER_HOST_INTERVAL:g}",
        "max_concurrency": str(MAX_CONCURRENCY),
        "min_cell": str(agg.get("min_cell", "")),
        "funnel_table": funnel_table(agg.get("funnel") or {}),
        "headline_table": metrics_table(metrics),
        "static_table": metrics_table(static.get("metrics") or []),
        "na_table": na_table(agg.get("na_rates") or {}),
        "protocol_table": counts_table(agg.get("protocol_versions") or {}, "Revision"),
        "flavour_table": counts_table(agg.get("flavours") or {}, "Negotiation"),
        "edge_table": counts_table(agg.get("edge_providers") or {}, "Edge"),
        "accuracy_section": accuracy_section(agg.get("accuracy") or {}),
        "fixed_section": fixed_section(list(fixed_hosts), fixed_count),
        "chart_headline": "![Headline rates with 95% confidence intervals](chart-headline.svg)",
        "chart_protocols": "![Protocol revisions negotiated](chart-protocols.svg)",
        "chart_edges": "![Edge providers detected](chart-edges.svg)",
    }
    unknown = sorted({m for m in PLACEHOLDER.findall(tmpl) if m not in values})
    if unknown:
        raise ValueError(f"unknown template placeholder(s): {', '.join(unknown)}")
    report = PLACEHOLDER.sub(lambda m: values[m.group(1)], tmpl)
    forbidden_list = list(forbidden)
    for text in [report, *charts.values()]:
        assert_no_identifiers(text, forbidden_list, allowed)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    path = out_dir / "report.md"
    path.write_text(report, encoding="utf-8")
    written.append(path)
    for name, svg in charts.items():
        p = out_dir / name
        p.write_text(svg, encoding="utf-8")
        written.append(p)
    return written
