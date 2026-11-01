"""``mcpprobe registry-report {fetch,scan,calibrate,aggregate,recheck,reaggregate,render}``.

Also ``python -m mcpprobe.registry``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import click

from mcpprobe.registry.batch import BatchConfig
from mcpprobe.registry.common import MAX_CONCURRENCY, RECHECK_CHECKS, WorkDir
from mcpprobe.registry.fetch import (
    DEFAULT_API_PATH,
    DEFAULT_BASE,
    DEFAULT_PAGE_LIMIT,
    FetchStoppedError,
    fetch_registry,
)
from mcpprobe.registry.pipeline import (
    StageError,
    aggregate_stage,
    calibrate_stage,
    reaggregate_stage,
    recheck_stage,
    render_stage,
    scan_stage,
)
from mcpprobe.registry.render import IdentifierLeakError

WORKDIR = click.option(
    "--workdir",
    "-w",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("registry-report"),
    show_default=True,
    help="Working directory holding all state (private: contains hosts; never publish it).",
)
DRY_RUN = click.option(
    "--dry-run", is_flag=True, help="Show what would happen; send nothing and write nothing."
)


def _echo(obj: Any) -> None:
    click.echo(json.dumps(obj, indent=2, sort_keys=True, default=str))


@click.group("registry-report", context_settings={"help_option_names": ["-h", "--help"]})
def registry_report() -> None:
    """Build the anonymised "State of MCP server security" report from the official MCP Registry.

    Stages: fetch -> scan -> (calibrate) -> aggregate -> render. Each is resumable from --workdir.
    After a scanner update: recheck (passive, selected hosts only) -> reaggregate -> render.
    """


@registry_report.command("fetch")
@WORKDIR
@DRY_RUN
@click.option("--base", default=DEFAULT_BASE, show_default=True, help="Registry base URL.")
@click.option("--api-path", default=DEFAULT_API_PATH, show_default=True, help="List endpoint path.")
@click.option("--limit", default=DEFAULT_PAGE_LIMIT, show_default=True, help="Entries per page.")
@click.option("--max-pages", type=int, default=None, help="Stop after this many pages (resume later).")
@click.option("--restart", is_flag=True, help="Discard saved pages and cursor and fetch from the start.")
def fetch_cmd(
    workdir: Path, dry_run: bool, base: str, api_path: str, limit: int, max_pages: int | None, restart: bool
) -> None:
    """Page through the registry list API (1 request/s) into WORKDIR/entries.jsonl."""
    try:
        res = asyncio.run(
            fetch_registry(
                WorkDir(workdir),
                base=base,
                api_path=api_path,
                limit=limit,
                max_pages=max_pages,
                dry_run=dry_run,
                restart=restart,
            )
        )
    except FetchStoppedError as exc:
        raise click.ClickException(str(exc)) from exc
    _echo(
        {
            "pages_fetched_now": res.pages_fetched,
            "pages_total": res.pages_total,
            "done": res.done,
            "entries": res.entries,
            "notes": res.notes,
        }
    )


@registry_report.command("scan")
@WORKDIR
@DRY_RUN
@click.option(
    "--exclude-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Hosts never to scan, one per line (*.example.com for a zone). Add every opt-out request received by email.",
)
@click.option(
    "--concurrency",
    default=MAX_CONCURRENCY,
    show_default=True,
    type=click.IntRange(1, MAX_CONCURRENCY),
    help="Hosts scanned in parallel (hard maximum 8).",
)
@click.option("--limit", type=int, default=None, help="Scan at most this many new hosts in this run.")
@click.option("--timeout", default=15.0, show_default=True, help="Per-request timeout in seconds.")
def scan_cmd(
    workdir: Path,
    dry_run: bool,
    exclude_file: Path | None,
    concurrency: int,
    limit: int | None,
    timeout: float,
) -> None:
    """Select targets, run static checks, then passively scan remote hosts (checkpointed to scan.jsonl)."""
    cfg = BatchConfig(concurrency=concurrency, timeout=timeout)
    try:
        res = asyncio.run(
            scan_stage(WorkDir(workdir), exclusions_file=exclude_file, cfg=cfg, limit=limit, dry_run=dry_run)
        )
    except StageError as exc:
        raise click.ClickException(str(exc)) from exc
    batch = res.batch
    _echo(
        {
            "selection": res.selection.summary,
            "static_records": res.static_records,
            "already_done": batch.already_done if batch else 0,
            "scanned_now": batch.scanned_now if batch else 0,
            "remaining": batch.remaining if batch else None,
            "statuses_now": dict(batch.statuses) if batch else {},
            "plan": batch.plan if batch else {},
            "notes": res.notes,
        }
    )


@registry_report.command("calibrate")
@WORKDIR
@DRY_RUN
def calibrate_cmd(workdir: Path, dry_run: bool) -> None:
    """Run the survey profile against the in-repo fixtures (localhost only) for the accuracy section."""
    try:
        out = asyncio.run(calibrate_stage(WorkDir(workdir), dry_run=dry_run))
    except StageError as exc:
        raise click.ClickException(str(exc)) from exc
    _echo({k: {"status": v.get("status"), "findings": v.get("findings")} for k, v in out.items()})


@registry_report.command("aggregate")
@WORKDIR
@DRY_RUN
@click.option(
    "--benchmark",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="docs/benchmark.md to take the META-01 false-positive rate from (default: the repository's).",
)
def aggregate_cmd(workdir: Path, dry_run: bool, benchmark: Path | None) -> None:
    """Compute anonymised aggregates (aggregates.json) and the PRIVATE disclosure queue."""
    try:
        agg, n_disclose = aggregate_stage(WorkDir(workdir), benchmark=benchmark, dry_run=dry_run)
    except StageError as exc:
        raise click.ClickException(str(exc)) from exc
    _echo(
        {
            "host_statuses": agg["funnel"].get("host_statuses"),
            "metrics": {m["id"]: f"{m['numerator']}/{m['denominator']}" for m in agg["metrics"]},
            "disclosure_queue_hosts": n_disclose,
            "disclosure_by_priority": (agg.get("disclosure") or {}).get("by_priority"),
            "written": not dry_run,
        }
    )


@registry_report.command("recheck")
@WORKDIR
@DRY_RUN
@click.option(
    "--from-queue",
    is_flag=True,
    help="Only hosts in the PRIVATE disclosure queue (run reaggregate first). Default: every scanned "
    "host on which one of --checks reached a result (its tool list was visible).",
)
@click.option(
    "--checks",
    default=",".join(RECHECK_CHECKS),
    show_default=True,
    help="Comma-separated survey-profile checks to re-run.",
)
@click.option(
    "--exclude-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Hosts never to contact, one per line (*.example.com for a zone).",
)
@click.option(
    "--concurrency",
    default=MAX_CONCURRENCY,
    show_default=True,
    type=click.IntRange(1, MAX_CONCURRENCY),
    help="Hosts rechecked in parallel (hard maximum 8).",
)
@click.option("--limit", type=int, default=None, help="Recheck at most this many hosts in this run.")
@click.option("--timeout", default=15.0, show_default=True, help="Per-request timeout in seconds.")
@click.option(
    "--new-pass",
    is_flag=True,
    help="Archive the current pass (recheck.jsonl) and check every selected host again.",
)
def recheck_cmd(
    workdir: Path,
    dry_run: bool,
    from_queue: bool,
    checks: str,
    exclude_file: Path | None,
    concurrency: int,
    limit: int | None,
    timeout: float,
    new_pass: bool,
) -> None:
    """Re-run passive survey checks on selected hosts with this scanner (checkpointed to recheck.jsonl).

    Same rules as scan: opt-out first, identifying User-Agent, 1 request/s per provider,
    at most 8 hosts, public pinned addresses, same origin, stop on 429/403, no bodies kept.
    """
    cfg = BatchConfig(concurrency=concurrency, timeout=timeout)
    try:
        res = asyncio.run(
            recheck_stage(
                WorkDir(workdir),
                from_queue=from_queue,
                checks=[c.strip() for c in checks.split(",") if c.strip()],
                exclusions_file=exclude_file,
                cfg=cfg,
                limit=limit,
                dry_run=dry_run,
                new_pass=new_pass,
            )
        )
    except StageError as exc:
        raise click.ClickException(str(exc)) from exc
    _echo(
        {
            "checks": res.checks,
            "selected_hosts": res.hosts,
            "already_done": res.batch.already_done,
            "rechecked_now": res.batch.scanned_now,
            "remaining": res.batch.remaining,
            "statuses_now": dict(res.batch.statuses),
            "plan": res.batch.plan,
            "notes": res.notes,
        }
    )


@registry_report.command("reaggregate")
@WORKDIR
@DRY_RUN
@click.option(
    "--benchmark",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="docs/benchmark.md to take the META-01 false-positive rate from (default: the repository's).",
)
def reaggregate_cmd(workdir: Path, dry_run: bool, benchmark: Path | None) -> None:
    """Offline: re-run static checks, merge scan + recheck outcomes, rebuild aggregates and the queue.

    Sends nothing. Prints before/after counts for every metric and the queue priorities.
    """
    try:
        out = asyncio.run(reaggregate_stage(WorkDir(workdir), benchmark=benchmark, dry_run=dry_run))
    except StageError as exc:
        raise click.ClickException(str(exc)) from exc
    _echo(out)


@registry_report.command("render")
@WORKDIR
@DRY_RUN
@click.option(
    "--out", type=click.Path(file_okay=False, path_type=Path), default=None, help="Default: WORKDIR/report."
)
@click.option(
    "--template", type=click.Path(dir_okay=False, path_type=Path), default=None, help="Markdown template."
)
@click.option("--allow-host", multiple=True, help="A host that is ours and may be named (repeatable).")
@click.option(
    "--name-fixed",
    is_flag=True,
    help="Name hosts whose disclosed finding is fixed AND whose queue entry has may_name: true.",
)
def render_cmd(
    workdir: Path,
    dry_run: bool,
    out: Path | None,
    template: Path | None,
    allow_host: tuple[str, ...],
    name_fixed: bool,
) -> None:
    """Write report.md and SVG charts; refuses if any third-party identifier would appear."""
    try:
        paths = render_stage(
            WorkDir(workdir),
            out_dir=out,
            template=template,
            allow_hosts=allow_host,
            name_fixed=name_fixed,
            dry_run=dry_run,
        )
    except (StageError, IdentifierLeakError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    _echo({"written" if not dry_run else "would_write": [str(p) for p in paths]})


def main() -> None:
    registry_report(prog_name="python -m mcpprobe.registry")
