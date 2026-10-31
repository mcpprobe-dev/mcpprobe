"""Stage functions behind ``mcpprobe registry-report``; each reads and writes the working directory."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from mcpprobe.registry.aggregate import aggregate, default_benchmark_path, disclosure_queue
from mcpprobe.registry.batch import BatchConfig, BatchResult, GuardState, HostPacer, run_batch
from mcpprobe.registry.common import (
    HostStatus,
    WorkDir,
    is_finding,
    read_json,
    read_jsonl,
    write_json,
    write_jsonl,
)
from mcpprobe.registry.render import render
from mcpprobe.registry.select import Exclusions, Selection, select_targets
from mcpprobe.registry.static import run_static


class StageError(Exception):
    """A stage cannot run (missing input from an earlier stage, unavailable fixtures...)."""


def _entries(wd: WorkDir) -> list[dict[str, Any]]:
    if not wd.entries.exists():
        raise StageError(f"{wd.entries} not found: run 'registry-report fetch' first")
    return list(read_jsonl(wd.entries))


@dataclass(slots=True)
class ScanStageResult:
    selection: Selection
    static_records: int
    batch: BatchResult | None
    notes: list[str] = field(default_factory=list)


async def scan_stage(
    wd: WorkDir,
    *,
    exclusions_file: Path | None = None,
    max_urls_per_host: int = 1,
    cfg: BatchConfig | None = None,
    limit: int | None = None,
    dry_run: bool = False,
    pacer: HostPacer | None = None,
    state: GuardState | None = None,
) -> ScanStageResult:
    """select -> static -> batch. Selection and static assessment are offline and recomputed each run."""
    entries = _entries(wd)
    selection = select_targets(entries, Exclusions.load(exclusions_file), max_urls_per_host=max_urls_per_host)
    static_records = await run_static(entries)
    if dry_run:
        batch = await run_batch(selection.targets, wd.scan, cfg, limit=limit, dry_run=True)
        return ScanStageResult(selection, len(static_records), batch, ["dry run: nothing written or sent"])
    write_jsonl(wd.targets, selection.targets)
    write_json(wd.selection, selection.summary)
    write_jsonl(wd.static, static_records)
    batch = await run_batch(selection.targets, wd.scan, cfg, limit=limit, pacer=pacer, state=state)
    return ScanStageResult(selection, len(static_records), batch)


def merge_disclosures(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the operator-maintained fields (notified_at, fixed_at, may_name, notes) across re-aggregation."""
    keep = ("notified_at", "fixed_at", "may_name", "contact", "notes")
    previous = {d.get("host"): d for d in old}
    merged = []
    for d in new:
        p = previous.pop(d["host"], {})
        merged.append({**d, **{k: p[k] for k in keep if p.get(k) is not None}})
    # Hosts no longer in the scan (e.g. re-scanned clean) stay on the list until closed by hand.
    merged.extend(previous.values())
    return merged


def aggregate_stage(
    wd: WorkDir, *, benchmark: Path | None = None, dry_run: bool = False
) -> tuple[dict[str, Any], int]:
    if not wd.scan.exists():
        raise StageError(f"{wd.scan} not found: run 'registry-report scan' first")
    records = list(read_jsonl(wd.scan))
    if wd.targets.exists():
        # Only hosts still selected: a host added to the exclusion file after it was scanned
        # (an operator who asked to be left out) drops out of the aggregates on the next scan run.
        selected = {str(t.get("host")) for t in read_jsonl(wd.targets)}
        records = [r for r in records if str(r.get("host")) in selected]
    bench_path = benchmark or default_benchmark_path()
    agg = aggregate(
        records,
        read_jsonl(wd.static),
        read_json(wd.selection) if wd.selection.exists() else None,
        benchmark_text=bench_path.read_text(encoding="utf-8") if bench_path.exists() else None,
        calibration=read_json(wd.calibration) if wd.calibration.exists() else None,
    )
    queue = disclosure_queue(records)
    if not dry_run:
        write_json(wd.aggregates, agg)
        old = read_json(wd.disclosure_queue) if wd.disclosure_queue.exists() else []
        write_json(wd.disclosure_queue, merge_disclosures(old, queue))
    return agg, len(queue)


def identifiers(wd: WorkDir) -> set[str]:
    """Every third-party host, URL and registry server name the working directory knows about."""
    out: set[str] = set()
    for path in (wd.entries,):
        for e in read_jsonl(path):
            out.add(str(e.get("name") or ""))
            for r in e.get("remotes") or []:
                out.add(str(r.get("url") or ""))
                out.add((urlsplit(str(r.get("url") or "")).hostname or "").lower())
    for path in (wd.targets, wd.scan):
        for t in read_jsonl(path):
            out.add(str(t.get("host") or ""))
            out.update(str(u) for u in t.get("urls") or [])
            out.add(str(t.get("url") or ""))
            out.update(str(n) for n in t.get("entries") or [])
    out.discard("")
    return out


def render_stage(
    wd: WorkDir,
    *,
    out_dir: Path | None = None,
    template: Path | None = None,
    allow_hosts: Iterable[str] = (),
    name_fixed: bool = False,
    dry_run: bool = False,
) -> list[Path]:
    if not wd.aggregates.exists():
        raise StageError(f"{wd.aggregates} not found: run 'registry-report aggregate' first")
    agg = read_json(wd.aggregates)
    queue = read_json(wd.disclosure_queue) if wd.disclosure_queue.exists() else []
    fixed = [d for d in queue if d.get("fixed_at")]
    fixed_hosts = [d["host"] for d in fixed if name_fixed and d.get("may_name") is True]
    target = out_dir or wd.report_dir
    if dry_run:
        # Render into memory-only scratch inside the workdir, then discard: validates the
        # template and runs the identifier guard without leaving files behind.
        import tempfile

        with tempfile.TemporaryDirectory(dir=wd.root) as tmp:
            paths = render(
                agg,
                Path(tmp),
                template=template.read_text(encoding="utf-8") if template else None,
                forbidden=identifiers(wd),
                allowed_hosts=allow_hosts,
                fixed_hosts=fixed_hosts,
                fixed_count=len(fixed),
            )
            return [target / p.name for p in paths]
    return render(
        agg,
        target,
        template=template.read_text(encoding="utf-8") if template else None,
        forbidden=identifiers(wd),
        allowed_hosts=allow_hosts,
        fixed_hosts=fixed_hosts,
        fixed_count=len(fixed),
    )


# ----------------------------------------------------------------------------- calibration
CALIBRATION_FIXTURES = {
    "hardened": "known-good reference server: auth required, RFC 9728, security headers",
    "demo": "known-bad replica of the public demo: no auth, poisoned shell tool",
    "trifecta": "conformant 2026-07-28 server without auth whose tools form a lethal trifecta",
    "html": "an ordinary web site that does not speak MCP",
}


class _RouteTo(httpx.AsyncBaseTransport):
    """Send every request to a local fixture port (Host header and path kept)."""

    def __init__(self, port: int) -> None:
        self.port = port
        self._inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.url = request.url.copy_with(scheme="http", host="127.0.0.1", port=self.port)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


class _VirtualClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds
        await asyncio.sleep(0)


async def calibrate_stage(wd: WorkDir, *, dry_run: bool = False) -> dict[str, Any]:
    """Run the survey profile against the in-repo fixtures (repository checkout only).

    Everything stays on 127.0.0.1: the fixtures listen locally and the routing transport
    rewrites every connection to them, so the placeholder address the resolver returns is
    never contacted.
    """
    try:
        from tests.fake_server import FakeMcpServer, make_config
    except ImportError as exc:  # installed from a wheel: tests/ is not shipped
        raise StageError("calibration needs a repository checkout (tests/fake_server.py)") from exc
    if dry_run:
        return {
            name: {"description": d, "status": "not run (dry run)"}
            for name, d in CALIBRATION_FIXTURES.items()
        }
    servers = {}
    try:
        for name in CALIBRATION_FIXTURES:
            host = f"{name}.calibration-fixture.example"
            servers[host] = FakeMcpServer(make_config(name, public_base=f"https://{host}")).start()

        async def resolver(_host: str) -> list[str]:
            return ["93.184.215.14"]  # placeholder public address; never connected to

        clock = _VirtualClock()
        cfg = BatchConfig(
            txt_lookup=lambda _name: [],
            resolver=resolver,
            transport_factory=lambda h: _RouteTo(servers[h].port),
            clock=clock,
            sleep=clock.sleep,
            scanner_rate=1000.0,
            _unsafe_allow_any_rate=True,
        )
        targets = [
            {"host": h, "urls": [f"https://{h}/mcp"], "transports": ["streamable-http"], "entries": []}
            for h in servers
        ]
        checkpoint = wd.ensure().root / "calibration-scan.jsonl"
        checkpoint.unlink(missing_ok=True)
        await run_batch(targets, checkpoint, cfg)
        out: dict[str, Any] = {}
        for rec in read_jsonl(checkpoint):
            name = str(rec["host"]).split(".", 1)[0]
            outcomes = rec.get("outcomes") or {}
            out[name] = {
                "description": CALIBRATION_FIXTURES[name],
                "status": rec["status"],
                "findings": sum(1 for o in outcomes.values() if is_finding(o)),
                "outcomes": outcomes,
                "requests": rec.get("requests", 0),
            }
        checkpoint.unlink(missing_ok=True)
        hardened = out.get("hardened", {})
        if hardened.get("status") != HostStatus.SCANNED.value or hardened.get("findings"):
            raise StageError(f"calibration failed: the hardened fixture produced {hardened}")
        write_json(wd.calibration, out)
        return out
    finally:
        for srv in servers.values():
            srv.stop()
