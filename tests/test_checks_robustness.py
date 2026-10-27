"""ERR-01 and DOS-01 end-to-end, including proof that DOS-01 stays within its bounds."""

from __future__ import annotations

import json

from mcpprobe.checks.robustness import BURST_REQUESTS, NESTING_DEPTH, OVERSIZED_ARG_BYTES, inspect_error_body
from mcpprobe.models import Severity
from tests.conftest import by_id, run, stdio_command


def test_err01_body_inspection():
    assert "python traceback" in inspect_error_body(
        'Traceback (most recent call last):\n  File "/x.py", line 1'
    )
    assert "javascript stack" in inspect_error_body("at handler (/app/server.js:10:5)")
    assert "framework version" in inspect_error_body("served by express/4.18.2")
    assert inspect_error_body('{"error":{"code":-32601,"message":"Method not found"}}') == []


async def test_err01_verbose_errors(make_server):
    async with make_server(verbose_errors=True, server_header="uvicorn/0.30.1") as srv:
        report = await run(srv.url, only=["ERR-01"])
    f = {x.title: x for x in by_id(report, "ERR-01")}
    main = f["Verbose error responses leak stack traces, paths or versions"]
    assert main.severity == Severity.MEDIUM
    assert {"python traceback", "internal path"} <= set(sum(main.details["leaks"].values(), []))
    assert f["Server header discloses software version"].severity == Severity.INFO


async def test_err01_clean_errors(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["ERR-01"])
    assert by_id(report, "ERR-01") == []


async def test_err01_stdio_clean():
    report = await run(stdio_command(), stdio=True, only=["ERR-01"])
    assert by_id(report, "ERR-01") == []


def _dos_requests(srv) -> list[dict]:
    return [r for r in srv.requests if r["method"] == "POST"]


async def test_dos01_is_bounded(make_server):
    async with make_server(enforce_size_limit=False) as srv:
        before = len(_dos_requests(srv))
        report = await run(srv.url, only=["DOS-01"])
        sent = len(_dos_requests(srv)) - before
    # Negotiation + inventory (initialize, initialized, tools/prompts/resources list) + exactly
    # one oversized, one nested and BURST_REQUESTS burst requests. Never more.
    assert BURST_REQUESTS == 20 and NESTING_DEPTH == 64 and OVERSIZED_ARG_BYTES == 1_000_000
    dos_records = [
        r for r in (report.findings[0].evidence if report.findings else []) if r.note and "DOS-01" in r.note
    ]
    assert sent <= 6 + 2 + BURST_REQUESTS
    [f] = by_id(report, "DOS-01")
    assert f.title == "No rate limiting observed" and f.severity == Severity.INFO
    assert f.details["requests"] == BURST_REQUESTS
    assert dos_records  # the burst evidence is attached


async def test_dos01_nesting_depth_exact(make_server):
    async with make_server() as srv:
        await run(srv.url, only=["DOS-01"])
    from mcpprobe.checks.robustness import nested

    depth, obj = 0, nested(NESTING_DEPTH)
    while "n" in obj:
        obj, depth = obj["n"], depth + 1
    assert depth == NESTING_DEPTH


async def test_dos01_rate_limited_server(make_server):
    async with make_server(rate_limit=True, rate_limit_per_sec=3) as srv:
        report = await run(srv.url, only=["DOS-01"])
    assert by_id(report, "DOS-01") == []
    assert any("rate limiting observed" in n for n in report.notes)


async def test_dos01_server_error_on_nesting(make_server):
    async with make_server(crash_on_deep_nesting=True) as srv:
        report = await run(srv.url, only=["DOS-01"])
    [f] = [x for x in by_id(report, "DOS-01") if x.title == "Server struggled with nesting request"]
    assert f.severity == Severity.MEDIUM and "HTTP 500" in f.description
    sent = json.loads(f.evidence[0].request_body)
    assert "_mcpprobe" in sent["params"]


async def test_dos01_size_limit_is_a_defence(make_server):
    async with make_server(rate_limit=True) as srv:  # default enforces a 256 KB limit -> 413
        report = await run(srv.url, only=["DOS-01"])
    assert by_id(report, "DOS-01") == []


async def test_dos01_stdio():
    report = await run(stdio_command(), stdio=True, only=["DOS-01"])
    assert by_id(report, "DOS-01") == []  # stdio has no HTTP 429 semantics; nothing broke
