"""Registry report pipeline: fetch -> select -> static -> batch -> aggregate -> render.

Everything runs offline: the registry is a MockTransport over tests/data/registry, the
remote endpoints are the in-repo fake servers (demo/hardened/trifecta/html presets)
reached through a routing transport, DNS is a dict, and the clock is virtual.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner

from mcpprobe import POLICY_URL
from mcpprobe.cli import cli
from mcpprobe.registry.aggregate import (
    aggregate,
    crosstabs,
    disclosure_queue,
    disclosure_summary,
    merge_rechecks,
    parse_benchmark,
    public_disclosure_counts,
    wilson,
)
from mcpprobe.registry.batch import (
    AddressRefused,
    BatchConfig,
    GuardState,
    HostPacer,
    OffTargetRefused,
    PoliteTransport,
    run_batch,
)
from mcpprobe.registry.common import (
    MAX_CONCURRENCY,
    SURVEY_CHECKS,
    WorkDir,
    is_public_address,
    rate_key,
    read_jsonl,
    write_jsonl,
)
from mcpprobe.registry.fetch import FetchStoppedError, fetch_registry, normalise_item
from mcpprobe.registry.pipeline import (
    StageError,
    aggregate_stage,
    calibrate_stage,
    identifiers,
    merge_disclosures,
    reaggregate_stage,
    recheck_stage,
    render_stage,
    scan_stage,
)
from mcpprobe.registry.render import IdentifierLeakError, render
from mcpprobe.registry.select import Exclusions, select_targets
from mcpprobe.registry.static import run_static
from tests.conftest import RouteToFixture
from tests.fake_server import FakeMcpServer, make_config

DATA = Path(__file__).parent / "data" / "registry"
PAGES = [json.loads((DATA / f"page-{i}.json").read_text()) for i in (1, 2)]
BENCHMARK = Path(__file__).parents[1] / "docs" / "benchmark.md"

#: host -> fake-server preset
PRESET_HOSTS = {
    "demo.example.org": "demo",
    "hardened.example.net": "hardened",
    "trifecta.example.com": "trifecta",
    "html.example.io": "html",
}
OPT_OUT_HOST = "mcp.optout.example.dev"
REBIND_HOST = "rebind.example.app"
#: Placeholder public addresses (never connected to: the routing transport replaces them).
DNS = {h: ["93.184.215.14"] for h in [*PRESET_HOSTS, OPT_OUT_HOST]} | {
    REBIND_HOST: ["93.184.215.20", "10.0.0.7"]
}


class VirtualClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds
        await asyncio.sleep(0)


def registry_transport(
    calls: list[httpx.Request], fail_second_with: int | None = None
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        cursor = request.url.params.get("cursor")
        if cursor is None:
            return httpx.Response(200, json=PAGES[0])
        if fail_second_with:
            return httpx.Response(fail_second_with, json={"error": "slow down"})
        assert cursor == PAGES[0]["metadata"]["nextCursor"]
        return httpx.Response(200, json=PAGES[1])

    return httpx.MockTransport(handler)


async def no_sleep(_s: float) -> None:
    return None


def opt_out_txt(name: str) -> list[str]:
    return ['"mcpprobe-opt-out=all"'] if name == "_mcpprobe.optout.example.dev" else []


async def fake_resolver(host: str) -> list[str]:
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


@pytest.fixture(scope="module")
def servers():
    started = {
        host: FakeMcpServer(make_config(preset, public_base=f"https://{host}")).start()
        for host, preset in PRESET_HOSTS.items()
    }
    yield started
    for srv in started.values():
        srv.stop()


def batch_config(servers: dict[str, FakeMcpServer], clock: VirtualClock, **kw: Any) -> BatchConfig:
    def factory(host: str) -> httpx.AsyncBaseTransport:
        if host in servers:
            return RouteToFixture(servers[host].port)
        # Opted-out and private hosts must never get this far; fail loudly if they do.
        return httpx.MockTransport(lambda r: pytest.fail(f"request sent to {r.url.host}"))

    return BatchConfig(
        txt_lookup=opt_out_txt,
        resolver=fake_resolver,
        transport_factory=factory,
        clock=clock,
        sleep=clock.sleep,
        scanner_rate=1000.0,
        _unsafe_allow_any_rate=True,
        **kw,
    )


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory, servers):
    """Full run over the fixture registry, shared by the assertions below."""
    wd = WorkDir(tmp_path_factory.mktemp("registry-report"))
    calls: list[httpx.Request] = []
    asyncio.run(fetch_registry(wd, httpx_transport=registry_transport(calls), sleep=no_sleep))
    clock = VirtualClock()
    pacer = HostPacer(clock=clock, sleep=clock.sleep)
    state = GuardState()
    res = asyncio.run(scan_stage(wd, cfg=batch_config(servers, clock), pacer=pacer, state=state))
    asyncio.run(calibrate_stage(wd))
    aggregate_stage(wd, benchmark=BENCHMARK)
    paths = render_stage(wd)
    records = {r["host"]: r for r in read_jsonl(wd.scan)}
    return {
        "wd": wd,
        "calls": calls,
        "res": res,
        "pacer": pacer,
        "state": state,
        "records": records,
        "paths": paths,
    }


# ----------------------------------------------------------------------------- fetch
def test_fetch_follows_cursor_and_normalises(pipeline):
    calls = pipeline["calls"]
    assert [c.url.path for c in calls] == ["/v0.1/servers", "/v0.1/servers"]
    assert calls[1].url.params["cursor"] == "org.example.demo/demo-sse:1.0.0"
    assert calls[0].url.params["version"] == "latest"
    assert POLICY_URL in calls[0].headers["user-agent"]
    entries = list(read_jsonl(pipeline["wd"].entries))
    assert len(entries) == 10
    poisoned = next(e for e in entries if e["name"].endswith("poisoned-npm"))
    assert (
        poisoned["packages"][0]["registry_type"] == "npm" and poisoned["tools"][0]["name"] == "notes_search"
    )


def test_normalise_accepts_flat_item_and_skips_non_latest():
    flat = {"name": "x.y/z", "version": "2", "remotes": [{"type": "sse", "url": "https://z.example/sse"}]}
    assert normalise_item(flat)["remotes"][0]["type"] == "sse"
    assert normalise_item({"nope": 1}) is None


def test_fetch_stops_on_429_and_resumes_from_cursor(tmp_path):
    wd = WorkDir(tmp_path)
    calls: list[httpx.Request] = []
    with pytest.raises(FetchStoppedError, match="429"):
        asyncio.run(fetch_registry(wd, httpx_transport=registry_transport(calls, 429), sleep=no_sleep))
    state = json.loads(wd.fetch_state.read_text())
    assert state["next_cursor"] and state["pages"] == 1 and not state["done"]
    calls2: list[httpx.Request] = []
    res = asyncio.run(fetch_registry(wd, httpx_transport=registry_transport(calls2), sleep=no_sleep))
    assert len(calls2) == 1 and "cursor" in calls2[0].url.params
    assert res.done and res.entries == 10


def test_fetch_dry_run_sends_and_writes_nothing(tmp_path):
    calls: list[httpx.Request] = []
    res = asyncio.run(
        fetch_registry(WorkDir(tmp_path), httpx_transport=registry_transport(calls), dry_run=True)
    )
    assert calls == [] and res.planned_url and "/v0.1/servers?" in res.planned_url
    assert not (tmp_path / "entries.jsonl").exists()


# ----------------------------------------------------------------------------- select / static
def test_select_splits_dedupes_and_excludes(pipeline):
    sel = pipeline["res"].selection
    s = sel.summary
    assert (s["entries"], s["remote_entries"], s["package_only_entries"]) == (10, 8, 2)
    assert s["excluded"] == {"duplicate_host": 1, "ip_literal": 1}
    hosts = {t["host"] for t in sel.targets}
    assert hosts == {*PRESET_HOSTS, OPT_OUT_HOST, REBIND_HOST}
    demo = next(t for t in sel.targets if t["host"] == "demo.example.org")
    assert demo["transports"] == ["streamable-http"] and len(demo["entries"]) == 2


def test_select_exclusion_list_and_local_names():
    entries = [
        {"name": "a/1", "remotes": [{"type": "streamable-http", "url": "https://x.blocked.example/mcp"}]},
        {"name": "a/2", "remotes": [{"type": "streamable-http", "url": "https://{tenant}.example.com/mcp"}]},
        {"name": "a/3", "remotes": [{"type": "streamable-http", "url": "http://localhost:8080/mcp"}]},
        {"name": "a/4", "remotes": [{"type": "streamable-http", "url": "https://svc.internal/mcp"}]},
        {
            "name": "a/5",
            "remotes": [{"type": "stdio", "url": "https://ignored.example/mcp"}],
            "packages": [{}],
        },
    ]
    sel = select_targets(entries, Exclusions.parse(["# operators who asked", "*.blocked.example"]))
    assert sel.targets == []
    assert sel.summary["excluded"] == {"excluded_by_list": 1, "templated_url": 1, "local_name": 2}
    assert sel.summary["package_only_entries"] == 1


def test_select_funnel_adds_up_with_repeated_urls():
    """remote_urls - sum(excluded) == unique_hosts: a repeated URL is counted, not dropped silently."""
    same = "https://same.example.com/mcp"
    entries = [
        {"name": "b/1", "remotes": [{"type": "streamable-http", "url": same}]},
        # The same URL listed by a second entry, and again as SSE by a third.
        {"name": "b/2", "remotes": [{"type": "streamable-http", "url": same}]},
        {"name": "b/3", "remotes": [{"type": "streamable-http", "url": same}, {"type": "sse", "url": same}]},
        # Another URL on a host already selected.
        {"name": "b/4", "remotes": [{"type": "sse", "url": "https://same.example.com/sse"}]},
        {"name": "b/5", "remotes": [{"type": "streamable-http", "url": "https://other.example.net/mcp"}]},
        {"name": "b/6", "remotes": [{"type": "streamable-http", "url": "https://{tenant}.example.com/mcp"}]},
        {"name": "b/7", "remotes": [{"type": "streamable-http", "url": "http://10.0.0.1/mcp"}]},
        {"name": "b/8", "remotes": [{"type": "streamable-http", "url": "https://svc.local/mcp"}]},
    ]
    s = select_targets(entries).summary
    assert s["remote_urls"] == 9
    assert s["excluded"] == {
        "duplicate_url": 3,
        "duplicate_host": 1,
        "templated_url": 1,
        "ip_literal": 1,
        "local_name": 1,
    }
    assert s["unique_hosts"] == s["selected_urls"] == 2
    assert s["remote_urls"] - sum(s["excluded"].values()) == s["unique_hosts"]
    same_target = next(t for t in select_targets(entries).targets if t["host"] == "same.example.com")
    assert same_target["entries"] == ["b/1", "b/2", "b/3", "b/4"]


def test_select_funnel_adds_up_on_fixture_registry(pipeline):
    s = pipeline["res"].selection.summary
    assert s["remote_urls"] - sum(s["excluded"].values()) == s["unique_hosts"] == s["selected_urls"]


def test_static_checks_on_registry_tool_definitions(pipeline):
    static = {r["name"]: r for r in read_jsonl(pipeline["wd"].static)}
    assert len(static) == 10
    poisoned = static["io.github.fixture-user/poisoned-npm"]
    assert poisoned["assessable"] and poisoned["kind"] == "package_only"
    assert poisoned["outcomes"]["META-01"] in ("high", "medium", "critical")
    plain = static["io.github.fixture-user/plain-pypi"]
    assert not plain["assessable"] and set(plain["outcomes"].values()) == {"not_assessable"}
    assert "no tool definitions" in plain["reason"]
    # Description text is never stored, only outcomes.
    assert "conversation history" not in pipeline["wd"].static.read_text()


def test_static_names_only_is_not_assessable():
    entry = {"name": "t/x", "remotes": [], "packages": [{}], "tools": None, "tool_names_only": True}
    [rec] = asyncio.run(run_static([entry]))
    assert not rec["assessable"] and "names only" in rec["reason"]


# ----------------------------------------------------------------------------- batch
def test_batch_outcomes_per_host(pipeline):
    r = pipeline["records"]
    demo = r["demo.example.org"]
    assert demo["status"] == "scanned"
    assert demo["outcomes"]["AUTH-01"] == "critical"
    assert demo["outcomes"]["META-01"] == "high"
    assert demo["outcomes"]["META-07"] == "high"
    assert demo["edge"] == "aws-api-gateway" and demo["protocol_version"] == "2025-11-25"
    hardened = r["hardened.example.net"]
    assert hardened["status"] == "scanned" and hardened["auth_required"] is True
    assert not [
        o for o in hardened["outcomes"].values() if o in ("critical", "high", "medium", "low", "info")
    ]
    assert hardened["outcomes"]["META-01"] == "blocked"  # tools are behind auth: never "passed"
    trifecta = r["trifecta.example.com"]
    assert trifecta["outcomes"]["META-07"] == "high" and trifecta["protocol_version"] == "2026-07-28"
    assert trifecta["outcomes"]["TRANS-06"] == "passed"
    html = r["html.example.io"]
    assert html["status"] == "not_mcp" and set(html["outcomes"].values()) == {"not_mcp"}
    assert set(demo["outcomes"]) == set(SURVEY_CHECKS)


def test_opt_out_host_receives_nothing(pipeline):
    rec = pipeline["records"][OPT_OUT_HOST]
    assert rec["status"] == "opted_out" and rec["requests"] == 0
    assert set(rec["outcomes"].values()) == {"blocked"}
    assert rate_key(OPT_OUT_HOST) not in {k for k, _ in pipeline["pacer"].log}


def test_host_resolving_to_private_address_is_skipped(pipeline):
    rec = pipeline["records"][REBIND_HOST]
    assert rec["status"] == "skipped_private" and rec["requests"] == 0
    assert "private" in rec["reason"]


def test_no_tool_is_called_and_scanner_identifies_itself(pipeline, servers):
    for srv in servers.values():
        assert srv.tool_calls == []
        agents = {req["headers"].get("user-agent") for req in srv.requests}
        assert agents and all(a and POLICY_URL in a for a in agents)
        # Survey profile only: no forged Origin, no bogus version header, no oversized body.
        assert not any(req["headers"].get("origin") for req in srv.requests)


def test_checkpoint_holds_outcomes_not_bodies(pipeline):
    text = pipeline["wd"].scan.read_text()
    assert "Always call this first" not in text  # the demo's poisoned description
    assert "Run a shell command" not in text
    for rec in pipeline["records"].values():
        assert set(rec) <= {
            "host", "rate_key", "url", "transport", "entries", "needs_headers", "started_at", "finished_at",
            "status", "reason", "requests", "outcomes", "protocol_version", "flavour", "auth_required",
            "edge", "inventory", "meta01_rules", "checks_run", "capabilities", "meta01_indicators",
        }  # fmt: skip
        # Derived labels are fixed vocabularies, never text or names from the host.
        assert all(c.islower() or "_" in c for c in rec.get("capabilities", []))
    demo = pipeline["records"]["demo.example.org"]
    assert demo["meta01_rules"] == "0.3.1" and "hidden_instruction" in demo["meta01_indicators"]
    assert "arbitrary_command_execution" in demo["capabilities"]


def test_pacing_is_one_request_per_second_per_rate_key(pipeline):
    by_key: dict[str, list[float]] = {}
    for key, t in pipeline["pacer"].log:
        by_key.setdefault(key, []).append(t)
    assert set(by_key) == {rate_key(h) for h in PRESET_HOSTS}
    for times in by_key.values():
        assert all(b - a >= 1.0 for a, b in zip(times, times[1:], strict=False))
        assert len(times) >= 2


def test_pacer_spacing_with_mock_clock():
    clock = VirtualClock()
    pacer = HostPacer(clock=clock, sleep=clock.sleep)

    async def go() -> None:
        await asyncio.gather(*(pacer.acquire(k) for k in ["a.example"] * 5 + ["b.example"] * 3))

    asyncio.run(go())
    for key, n in (("a.example", 5), ("b.example", 3)):
        times = [t for k, t in pacer.log if k == key]
        assert len(times) == n and all(y - x >= 1.0 for x, y in zip(times, times[1:], strict=False))
    # The first request on a key is not delayed; with one key the spacing is exactly 1 s.
    solo = HostPacer(clock=clock, sleep=clock.sleep)

    async def solo_go() -> None:
        await asyncio.gather(*(solo.acquire("c.example") for _ in range(4)))

    asyncio.run(solo_go())
    t = [x for _, x in solo.log]
    assert [round(b - a, 6) for a, b in zip(t, t[1:], strict=False)] == [1.0] * 3
    with pytest.raises(ValueError):
        HostPacer(interval=0.5)


def test_concurrency_is_capped_at_eight(tmp_path, monkeypatch):
    import mcpprobe.registry.batch as batch

    active = 0
    peak = 0

    async def fake_scan(target, cfg, state, pacer):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return {"host": target["host"], "status": "scanned", "outcomes": {}}

    monkeypatch.setattr(batch, "scan_target", fake_scan)
    targets = [{"host": f"h{i}.example{i}.com", "urls": ["https://x/mcp"]} for i in range(30)]
    res = asyncio.run(run_batch(targets, tmp_path / "scan.jsonl", BatchConfig(concurrency=50)))
    assert res.scanned_now == 30 and peak == MAX_CONCURRENCY
    with pytest.raises(ValueError):
        BatchConfig(concurrency=0).effective_concurrency()


def test_stop_on_429_for_the_whole_rate_key(tmp_path):
    srv = FakeMcpServer(make_config("secure", rate_limit=True, rate_limit_per_sec=0)).start()
    try:
        clock = VirtualClock()
        state = GuardState()
        hosts = ["a.throttled.example", "b.throttled.example"]
        cfg = BatchConfig(
            txt_lookup=lambda _n: [],
            resolver=lambda _h: asyncio.sleep(0, result=["93.184.215.14"]),
            transport_factory=lambda _h: RouteToFixture(srv.port),
            clock=clock,
            sleep=clock.sleep,
            scanner_rate=1000.0,
            _unsafe_allow_any_rate=True,
        )
        targets = [{"host": h, "urls": [f"https://{h}/mcp"]} for h in hosts]
        asyncio.run(run_batch(targets, tmp_path / "scan.jsonl", cfg, state=state))
        recs = {r["host"]: r for r in read_jsonl(tmp_path / "scan.jsonl")}
        assert recs[hosts[0]]["status"] == "blocked" and "429" in recs[hosts[0]]["reason"]
        assert recs[hosts[1]]["status"] == "blocked" and recs[hosts[1]]["requests"] == 0
        # Opt-out document, negotiation until the first 429, then nothing more for either host:
        # every request the fixture saw came from host a, before the stop.
        assert len(srv.requests) == recs[hosts[0]]["requests"] <= 3
        assert srv.requests[0]["path"] == "/.well-known/mcpprobe-opt-out"
        assert state.stopped == {"throttled.example": "HTTP 429"}
    finally:
        srv.stop()


def test_guard_stops_on_403_pins_address_and_refuses_off_target():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(403)

    async def resolver(_h: str) -> list[str]:
        return ["93.184.215.14"]

    state = GuardState()
    clock = VirtualClock()
    guard = PoliteTransport(
        httpx.MockTransport(handler),
        target_host="svc.example.com",
        pacer=HostPacer(clock=clock, sleep=clock.sleep),
        state=state,
        resolver=resolver,
    )

    async def go() -> None:
        async with httpx.AsyncClient(transport=guard) as client:
            resp = await client.get("https://svc.example.com/.well-known/mcpprobe-opt-out")
            assert resp.status_code == 403
            with pytest.raises(httpx.TransportError, match="stopped after HTTP 403"):
                await client.get("https://svc.example.com/mcp")
            with pytest.raises(OffTargetRefused):
                await client.get("https://other.example.net/")

    asyncio.run(go())
    assert len(seen) == 1
    assert seen[0].url.host == "93.184.215.14"
    assert seen[0].headers["host"] == "svc.example.com"
    assert seen[0].extensions["sni_hostname"] == "svc.example.com"
    assert state.stopped == {"example.com": "HTTP 403"}


def test_guard_refuses_unresolvable_and_non_public_addresses():
    for addrs, bad in [
        (["127.0.0.1"], True),
        (["100.64.0.1"], True),
        (["::ffff:10.0.0.1"], True),
        (["1.1.1.1"], False),
    ]:
        assert is_public_address(addrs[0]) is (not bad)

    async def resolver(_h: str) -> list[str]:
        raise OSError("NXDOMAIN")

    guard = PoliteTransport(
        httpx.MockTransport(lambda r: httpx.Response(200)),
        target_host="gone.example",
        pacer=HostPacer(),
        state=GuardState(),
        resolver=resolver,
    )

    async def go() -> None:
        async with httpx.AsyncClient(transport=guard) as client:
            with pytest.raises(AddressRefused):
                await client.get("https://gone.example/mcp")

    asyncio.run(go())


def test_resume_from_checkpoint(tmp_path, servers):
    wd = WorkDir(tmp_path)
    asyncio.run(fetch_registry(wd, httpx_transport=registry_transport([]), sleep=no_sleep))
    clock = VirtualClock()
    first = asyncio.run(scan_stage(wd, cfg=batch_config(servers, clock), limit=2))
    assert first.batch is not None and first.batch.scanned_now == 2 and first.batch.remaining == 4
    with wd.scan.open("a") as fh:
        fh.write('{"host": "torn-line-from-a-crash')  # a crash mid-write
    before = {h: len(s.requests) for h, s in servers.items()}
    second = asyncio.run(scan_stage(wd, cfg=batch_config(servers, clock)))
    assert second.batch is not None and second.batch.already_done == 2 and second.batch.scanned_now == 4
    hosts = [r["host"] for r in read_jsonl(wd.scan)]
    assert len(hosts) == len(set(hosts)) == 6
    third = asyncio.run(scan_stage(wd, cfg=batch_config(servers, clock)))
    assert third.batch is not None and third.batch.scanned_now == 0
    done_first = {r["host"] for r in list(read_jsonl(wd.scan))[:2]}
    for host in done_first & set(servers):
        # Hosts finished in the first run were not contacted again.
        assert len(servers[host].requests) == before[host]


def test_resume_keeps_a_refusing_rate_key_stopped(tmp_path):
    cp = tmp_path / "scan.jsonl"
    write_jsonl(cp, [{"host": "a.slow.example", "rate_key": "slow.example", "status": "blocked"}])
    state = GuardState()
    res = asyncio.run(
        run_batch(
            [{"host": "b.slow.example", "urls": ["https://b.slow.example/mcp"]}],
            cp,
            BatchConfig(transport_factory=lambda _h: pytest.fail("contacted")),
            state=state,
        )
    )
    assert res.statuses == {"blocked": 1} and "slow.example" in state.stopped


def test_scan_dry_run_sends_and_writes_nothing(tmp_path):
    wd = WorkDir(tmp_path)
    asyncio.run(fetch_registry(wd, httpx_transport=registry_transport([]), sleep=no_sleep))
    res = asyncio.run(
        scan_stage(wd, cfg=BatchConfig(transport_factory=lambda _h: pytest.fail("contacted")), dry_run=True)
    )
    assert res.batch is not None and res.batch.plan["hosts"] == 6 and res.batch.plan["est_seconds"] > 0
    assert not wd.scan.exists() and not wd.targets.exists()


# ----------------------------------------------------------------------------- aggregate / render
def test_wilson_interval():
    lo, hi = wilson(0, 40)
    assert lo == 0.0 and 0.08 < hi < 0.09
    lo, hi = wilson(50, 100)
    assert abs(lo - 0.404) < 0.002 and abs(hi - 0.596) < 0.002
    assert wilson(0, 0) == (0.0, 0.0)


def test_benchmark_parsing_gives_measured_fp_rate():
    rows = parse_benchmark(BENCHMARK.read_text())
    held = next(r for r in rows if r["dataset"] == "mcpprobe held-out set" and "medium" in r["detector"])
    assert held["fp"] == 0 and held["tn"] == 40 and held["fp_rate"] == 0.0
    assert 0.08 < held["fp_rate_ci95"][1] < 0.09


def test_aggregates_are_anonymised(pipeline):
    agg = json.loads(pipeline["wd"].aggregates.read_text())
    text = json.dumps(agg)
    for ident in identifiers(pipeline["wd"]):
        assert ident not in text
    m = {x["id"]: x for x in agg["metrics"]}
    # demo and trifecta answer without auth; hardened requires it.
    assert (m["no_auth"]["numerator"], m["no_auth"]["denominator"]) == (2, 3)
    assert (m["toxic_flow"]["numerator"], m["toxic_flow"]["denominator"]) == (2, 2)
    assert m["no_auth"]["ci95"][0] < 2 / 3 < m["no_auth"]["ci95"][1]
    assert agg["funnel"]["host_statuses"] == {
        "not_mcp": 1, "opted_out": 1, "scanned": 3, "skipped_private": 1,
    }  # fmt: skip
    # Three distinct revisions/edges on three hosts: every cell is under 3, so all merge into "other".
    assert list(agg["protocol_versions"]) == ["other (categories under 3 hosts)"]
    assert agg["accuracy"]["calibration"]["hardened"]["findings"] == 0
    assert agg["accuracy"]["calibration"]["demo"]["findings"] > 0
    assert agg["na_rates"]["META-01"]["blocked"] == 1


def test_rendered_report_contains_no_hostnames(pipeline):
    wd = pipeline["wd"]
    assert {p.name for p in pipeline["paths"]} == {
        "report.md", "chart-headline.svg", "chart-protocols.svg", "chart-edges.svg",
    }  # fmt: skip
    idents = identifiers(wd)
    assert "demo.example.org" in idents and "io.github.fixture-user/poisoned-npm" in idents
    for path in pipeline["paths"]:
        text = path.read_text()
        for ident in idents:
            assert ident not in text, f"{ident} leaked into {path.name}"
    report = (wd.report_dir / "report.md").read_text()
    assert "{{" not in report
    for section in ("## Disclosure policy", "## What passive scanning cannot see", "## Limitations", "95%"):
        assert section in report
    assert "0.0%" in report  # the measured META-01 false-positive rate
    import xml.etree.ElementTree as ET

    for name in ("chart-headline.svg", "chart-protocols.svg", "chart-edges.svg"):
        svg = (wd.report_dir / name).read_text()
        root = ET.fromstring(svg)  # well-formed, standalone SVG
        assert (
            root.tag.endswith("svg")
            and "<script" not in svg
            and "http" not in svg.replace("http://www.w3.org/2000/svg", "")
        )


def test_render_refuses_a_template_that_names_a_host(pipeline, tmp_path):
    agg = json.loads(pipeline["wd"].aggregates.read_text())
    bad = "Worst offender: demo.example.org\n{{headline_table}}\n"
    with pytest.raises(IdentifierLeakError):
        render(agg, tmp_path / "out", template=bad, forbidden=identifiers(pipeline["wd"]))
    assert not (tmp_path / "out").exists()
    render(
        agg, tmp_path / "ok", template=bad, forbidden=["demo.example.org"], allowed_hosts=["demo.example.org"]
    )
    with pytest.raises(ValueError, match="unknown template placeholder"):
        render(agg, tmp_path / "x", template="{{no_such_thing}}")


def test_disclosure_queue_is_private_and_keeps_operator_fields(pipeline):
    wd = pipeline["wd"]
    queue = json.loads(wd.disclosure_queue.read_text())
    assert wd.disclosure_queue.name.startswith("PRIVATE-")
    assert {d["host"] for d in queue} == {"demo.example.org", "trifecta.example.com"}
    queue[0]["notified_at"] = "2026-11-02"
    merged = merge_disclosures(queue, disclosure_queue(pipeline["records"].values()))
    assert any(d.get("notified_at") == "2026-11-02" for d in merged)


def test_render_names_fixed_host_only_with_consent(pipeline, tmp_path):
    wd = pipeline["wd"]
    queue = json.loads(wd.disclosure_queue.read_text())
    for d in queue:
        d["fixed_at"] = "2026-12-01"
    queue[0]["may_name"] = True
    wd.disclosure_queue.write_text(json.dumps(queue))
    try:
        out = render_stage(wd, out_dir=tmp_path / "anon")
        text = out[0].read_text()
        assert "2 disclosed issue(s) were confirmed fixed" in text and queue[0]["host"] not in text
        named = render_stage(wd, out_dir=tmp_path / "named", name_fixed=True)
        text = named[0].read_text()
        assert queue[0]["host"] in text and queue[1]["host"] not in text
    finally:
        for d in queue:
            d.pop("fixed_at", None)
            d.pop("may_name", None)
        wd.disclosure_queue.write_text(json.dumps(queue))


def test_aggregate_without_scans_is_empty_not_wrong():
    agg = aggregate([], [])
    m = {x["id"]: x for x in agg["metrics"]}
    assert m["no_auth"]["rate"] is None and m["no_auth"]["ci95"] is None


# ----------------------------------------------------------------------------- CLI
def test_cli_dry_runs(tmp_path):
    runner = CliRunner()
    wd = tmp_path / "wd"
    result = runner.invoke(cli, ["registry-report", "fetch", "--workdir", str(wd), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "would GET https://registry.modelcontextprotocol.io/v0.1/servers" in result.output
    assert not (wd / "entries.jsonl").exists()
    asyncio.run(fetch_registry(WorkDir(wd), httpx_transport=registry_transport([]), sleep=no_sleep))
    result = runner.invoke(cli, ["registry-report", "scan", "--workdir", str(wd), "--dry-run"])
    assert result.exit_code == 0, result.output
    out = json.loads(result.output)
    assert out["plan"]["hosts"] == 6 and out["scanned_now"] == 0
    assert not (wd / "scan.jsonl").exists()
    result = runner.invoke(cli, ["registry-report", "scan", "--workdir", str(wd), "--concurrency", "9"])
    assert result.exit_code == 2
    result = runner.invoke(cli, ["registry-report", "aggregate", "--workdir", str(wd)])
    assert result.exit_code == 1 and "run 'registry-report scan' first" in result.output


def test_late_exclusion_drops_host_from_aggregates(tmp_path, servers):
    wd = WorkDir(tmp_path)
    asyncio.run(fetch_registry(wd, httpx_transport=registry_transport([]), sleep=no_sleep))
    asyncio.run(scan_stage(wd, cfg=batch_config(servers, VirtualClock())))
    agg, n = aggregate_stage(wd, benchmark=BENCHMARK)
    assert agg["funnel"]["host_statuses"]["scanned"] == 3 and n == 2
    excl = tmp_path / "exclusions.txt"
    excl.write_text("demo.example.org  # operator asked by email\n")
    rerun = asyncio.run(scan_stage(wd, exclusions_file=excl, cfg=batch_config(servers, VirtualClock())))
    assert rerun.batch is not None and rerun.batch.scanned_now == 0
    agg, n = aggregate_stage(wd, benchmark=BENCHMARK)
    assert agg["funnel"]["host_statuses"]["scanned"] == 2 and n == 1
    assert agg["funnel"]["excluded"]["excluded_by_list"] == 2  # the streamable-http and SSE URLs


# ----------------------------------------------------------------------------- disclosure criteria
def _rec(
    host: str, auth_required: bool = False, rules: str | None = "0.3.1", **outcomes: str
) -> dict[str, Any]:
    base = dict.fromkeys(SURVEY_CHECKS, "passed")
    base["AUTH-01"] = "passed" if auth_required else "critical"
    base.update({k.replace("_", "-"): v for k, v in outcomes.items()})
    return {
        "host": host,
        "url": f"https://{host}/mcp",
        "status": "scanned",
        "auth_required": auth_required,
        "outcomes": base,
        "meta01_rules": rules,
        "inventory": {"tools": 3},
        "finished_at": "2026-11-01T00:00:00+00:00",
    }


DISCLOSURE_CASES = [
    # (record, expected priority or None)
    (_rec("open-only.example"), None),
    (_rec("prm.example", True, AUTH_02="high"), None),
    (_rec("headers.example", TRANS_05="high"), None),
    (_rec("open-prm-headers.example", AUTH_02="high", TRANS_05="medium", META_06="medium"), None),
    (_rec("secret.example", True, META_05="high"), "P1"),
    (_rec("shell-open.example", META_03="critical"), "P2"),
    (_rec("shell-auth.example", True, META_03="high"), None),
    (_rec("jwt.example", True, AUTH_04="critical"), "P2"),
    (_rec("poison.example", True, META_01="high"), "P3"),
    (_rec("poison-old.example", rules=None, META_01="high"), None),
    (_rec("poison-medium.example", META_01="medium"), None),
    (_rec("trifecta-open.example", META_07="high"), "P4"),
    (_rec("trifecta-auth.example", True, META_07="medium"), None),
    (_rec("many.example", META_07="high", META_01="high", META_05="high"), "P1"),
]


@pytest.mark.parametrize(
    ("record", "expected"), DISCLOSURE_CASES, ids=[c[0]["host"] for c in DISCLOSURE_CASES]
)
def test_disclosure_criteria(record, expected):
    queue = disclosure_queue([record])
    if expected is None:
        assert queue == []
    else:
        [entry] = queue
        assert entry["priority"] == expected
        assert "AUTH-01" not in entry["checks"]  # descriptive context only, never a reason
        assert all(not r.startswith("AUTH-01") for r in entry["reasons"])


def test_disclosure_summary_counts_without_hosts():
    records = [r for r, _ in DISCLOSURE_CASES]
    queue = disclosure_queue(records)
    summary = disclosure_summary(queue, records)
    assert summary["by_priority"] == {"P1": 2, "P2": 2, "P3": 1, "P4": 1}
    assert summary["hosts"] == 6
    assert summary["meeting_criterion"] == {"P1": 2, "P2": 2, "P3": 2, "P4": 2}
    assert summary["meta01_high_on_older_rules_pending_recheck"] == 1
    # Open-only and other descriptive hosts had a high/critical outcome but do not qualify
    # (the one remaining host, an authenticated server with a medium trifecta, had none).
    assert summary["high_or_critical_but_not_qualifying"] == len(records) - 6 - 1
    text = json.dumps(summary)
    assert not [r["host"] for r in records if r["host"] in text]
    public = public_disclosure_counts(summary)
    assert public["by_priority"]["P3"] is None and public["by_priority"]["P1"] is None  # under MIN_CELL
    assert public["hosts"] == 6


def test_merge_disclosures_drops_untouched_legacy_entries():
    legacy = [
        {"host": "open-only.example", "checks": {"AUTH-01": "critical"}, "notified_at": None},
        {"host": "notified.example", "checks": {"AUTH-01": "critical"}, "notified_at": "2026-11-02"},
        {"host": "shell-open.example", "checks": {"AUTH-01": "critical"}, "notes": "contact found"},
    ]
    new = disclosure_queue([_rec("shell-open.example", META_03="critical")])
    merged = {d["host"]: d for d in merge_disclosures(legacy, new)}
    assert set(merged) == {"notified.example", "shell-open.example"}
    assert merged["notified.example"]["priority"] is None  # kept only because the operator was contacted
    assert merged["shell-open.example"]["priority"] == "P2"
    assert merged["shell-open.example"]["notes"] == "contact found"


def test_merge_rechecks_overlays_only_rechecked_checks():
    old = _rec("a.example", rules=None, META_01="high", META_03="critical", TRANS_05="high")
    blocked = {"host": "a.example", "status": "blocked", "outcomes": {}, "finished_at": "t3"}
    ok = {
        "host": "a.example",
        "status": "scanned",
        "checks_run": ["META-01", "META-03"],
        "outcomes": {"META-01": "passed", "META-03": "critical"},
        "auth_required": False,
        "meta01_rules": "0.3.1",
        "capabilities": ["arbitrary_command_execution", "exec"],
        "finished_at": "t2",
    }
    [m] = merge_rechecks([old], [ok, blocked])
    assert m["outcomes"]["META-01"] == "passed" and m["outcomes"]["TRANS-05"] == "high"
    assert m["meta01_rules"] == "0.3.1" and m["recheck_status"] == "blocked"
    assert m["capabilities"] == ["arbitrary_command_execution", "exec"]
    # Now requires auth, observed by a recheck that did not re-run AUTH-01: no longer open.
    [m2] = merge_rechecks([old], [{**ok, "auth_required": True}])
    assert m2["open_observed"] is False and disclosure_queue([m2]) == []


def test_crosstabs_split_by_auth_and_suppress_small_cells():
    records = [_rec(f"o{i}.example", META_03="critical" if i < 4 else "low", META_07="high" if i < 2 else "passed")
               for i in range(10)]  # fmt: skip
    records += [_rec(f"a{i}.example", True, META_03="high" if i < 1 else "passed") for i in range(4)]
    records[0]["capabilities"] = ["exec"]
    records[1]["capabilities"] = ["network"]
    ct = crosstabs(records)
    dang = {m["id"]: m for m in ct["dangerous_capability_by_auth"]}
    assert (
        dang["dangerous_capability_open"]["numerator"],
        dang["dangerous_capability_open"]["denominator"],
    ) == (4, 10)
    assert dang["dangerous_capability_auth"]["numerator"] is None  # 1 host: withheld
    assert dang["dangerous_capability_auth"]["suppressed"]
    toxic = {m["id"]: m for m in ct["toxic_flow_by_auth"]}
    assert toxic["toxic_flow_open"]["numerator"] is None  # 2 hosts: withheld
    cap = {m["id"]: m for m in ct["open_capability"]}
    assert cap["open_write_exec"]["denominator"] == 2 and cap["open_write_exec"]["numerator"] is None
    assert cap["open_high_impact"]["numerator"] == 10
    assert ct["tool_count_distribution"]["buckets"]["2-5"] == 10


def test_meta01_rates_exclude_outcomes_from_older_rules():
    records = [_rec(f"n{i}.example", META_01="medium") for i in range(3)]
    records += [_rec(f"s{i}.example", rules=None, META_01="high") for i in range(5)]
    agg = aggregate(records, [])
    m = {x["id"]: x for x in agg["metrics"]}
    assert (m["poisoning_any"]["numerator"], m["poisoning_any"]["denominator"]) == (3, 3)
    assert m["poisoning_high"]["numerator"] == 0
    assert agg["meta01_rules"]["hosts_by_rules"]["current"] == 3


# ----------------------------------------------------------------------------- recheck / reaggregate
@pytest.fixture()
def scanned_wd(tmp_path, servers):
    wd = WorkDir(tmp_path)
    asyncio.run(fetch_registry(wd, httpx_transport=registry_transport([]), sleep=no_sleep))
    asyncio.run(scan_stage(wd, cfg=batch_config(servers, VirtualClock())))
    # Pretend the scan ran with the 0.3.0 rules: META-01 outcomes carry no rules revision.
    rows = []
    for r in read_jsonl(wd.scan):
        r.pop("meta01_rules", None)
        rows.append(r)
    write_jsonl(wd.scan, rows)
    return wd


def test_reaggregate_is_offline_and_reports_stale_meta01(scanned_wd, servers):
    for srv in servers.values():
        srv.requests.clear()
    out = asyncio.run(reaggregate_stage(scanned_wd, benchmark=BENCHMARK))
    assert all(not srv.requests for srv in servers.values())  # nothing sent
    assert out["metrics"]["poisoning_any"]["after"] == "0/0"
    assert out["by_priority"] == {"P1": 0, "P2": 1, "P3": 0, "P4": 1}
    assert out["meta01_high_on_older_rules_pending_recheck"] == 0  # demo is already queued (P2)
    assert out["static_records"] == 10
    summary = json.loads(scanned_wd.disclosure_summary.read_text())
    assert "demo.example.org" not in json.dumps(summary)
    assert not scanned_wd.disclosure_summary.name.startswith("PRIVATE")


def test_recheck_from_queue_contacts_only_queued_hosts(scanned_wd, servers):
    reaggregate_stage_sync = asyncio.run
    reaggregate_stage_sync(reaggregate_stage(scanned_wd, benchmark=BENCHMARK))
    for srv in servers.values():
        srv.requests.clear()
    clock = VirtualClock()
    pacer = HostPacer(clock=clock, sleep=clock.sleep)
    res = asyncio.run(
        recheck_stage(
            scanned_wd,
            from_queue=True,
            checks=["META-01", "META-07", "META-03"],
            cfg=batch_config(servers, clock),
            pacer=pacer,
        )
    )
    assert res.hosts == 2 and res.batch.scanned_now == 2
    contacted = {h for h, srv in servers.items() if srv.requests}
    assert contacted == {"demo.example.org", "trifecta.example.com"}
    for srv in servers.values():
        assert all("mcpprobe" in req["headers"].get("user-agent", "") for req in srv.requests)
        assert not any(
            req.get("json", {}).get("method") == "tools/call" for req in srv.requests if req.get("json")
        )
    times: dict[str, list[float]] = {}
    for key, t in pacer.log:
        times.setdefault(key, []).append(t)
    for ts in times.values():
        assert all(b - a >= 1.0 for a, b in zip(ts, ts[1:], strict=False))
    recs = {r["host"]: r for r in read_jsonl(scanned_wd.recheck)}
    assert set(recs["demo.example.org"]["outcomes"]) == {"META-01", "META-07", "META-03"}
    assert recs["demo.example.org"]["meta01_rules"] == "0.3.1"
    out = asyncio.run(reaggregate_stage(scanned_wd, benchmark=BENCHMARK))
    assert out["metrics"]["poisoning_high"]["after"] == "1/2"
    # demo's run_command, rechecked with the 0.3.1 rules, is a P3 reason (demo stays P2 overall).
    summary = json.loads(scanned_wd.disclosure_summary.read_text())
    assert summary["by_reason"]["META-01 high"] == 1 and out["by_priority"]["P2"] == 1
    # Resume: a second run sends nothing; --new-pass archives and runs again.
    again = asyncio.run(recheck_stage(scanned_wd, from_queue=True, cfg=batch_config(servers, VirtualClock())))
    assert again.batch.scanned_now == 0
    fresh = asyncio.run(
        recheck_stage(scanned_wd, from_queue=True, new_pass=True, cfg=batch_config(servers, VirtualClock()))
    )
    assert fresh.batch.scanned_now == 2 and len(scanned_wd.recheck_files()) == 2


def test_recheck_selects_hosts_with_visible_tools_and_respects_refusals(scanned_wd, servers):
    rows = list(read_jsonl(scanned_wd.scan))
    for r in rows:
        if r["host"] == "trifecta.example.com":
            # A different host on the same provider refused us in the original scan.
            rows.append({**r, "host": "x.example.com", "status": "blocked", "outcomes": {}})
    write_jsonl(scanned_wd.scan, rows)
    dry = asyncio.run(recheck_stage(scanned_wd, dry_run=True, cfg=batch_config(servers, VirtualClock())))
    assert dry.hosts == 2 and dry.batch.plan["hosts"] == 2 and not scanned_wd.recheck.exists()
    for srv in servers.values():
        srv.requests.clear()
    res = asyncio.run(recheck_stage(scanned_wd, cfg=batch_config(servers, VirtualClock())))
    recs = {r["host"]: r for r in read_jsonl(scanned_wd.recheck)}
    assert recs["trifecta.example.com"]["status"] == "blocked"
    assert not servers["trifecta.example.com"].requests
    assert recs["demo.example.org"]["status"] == "scanned"
    assert res.batch.scanned_now == 2
    with pytest.raises(StageError, match="not survey-profile"):
        asyncio.run(recheck_stage(scanned_wd, checks=["AUTH-04"]))


def test_cli_recheck_and_reaggregate(scanned_wd):
    runner = CliRunner()
    wd = str(scanned_wd.root)
    result = runner.invoke(cli, ["registry-report", "reaggregate", "--workdir", wd, "--dry-run"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["written"] is False
    result = runner.invoke(cli, ["registry-report", "recheck", "--workdir", wd, "--from-queue", "--dry-run"])
    assert result.exit_code == 1 and "run 'registry-report reaggregate' first" in result.output
    runner.invoke(cli, ["registry-report", "reaggregate", "--workdir", wd])
    result = runner.invoke(
        cli,
        [
            "registry-report",
            "recheck",
            "--workdir",
            wd,
            "--from-queue",
            "--dry-run",
            "--checks",
            "META-01,META-07",
        ],
    )
    assert result.exit_code == 0, result.output
    out = json.loads(result.output)
    assert (
        out["selected_hosts"] == 2 and out["checks"] == ["META-01", "META-07"] and out["rechecked_now"] == 0
    )
    assert not (scanned_wd.recheck).exists()
