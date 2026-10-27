"""End-to-end tests for TRANS-01..05 against the fake server."""

from __future__ import annotations

from mcpprobe.models import Confidence, Severity
from tests.conftest import by_id, run, status_of


async def test_trans01_origin_not_validated(make_server):
    async with make_server(origin_check=False) as srv:
        report = await run(srv.url, only=["TRANS-01"])
    [f] = by_id(report, "TRANS-01")
    assert f.severity == Severity.HIGH  # loopback -> DNS rebinding is the realistic path
    assert f.confidence == Confidence.HIGH
    assert f.evidence[0].request_headers["origin"] == "https://evil.example"
    assert "expected 403" in f.evidence_excerpt


async def test_trans01_origin_validated_is_clean(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["TRANS-01"])
    assert by_id(report, "TRANS-01") == []
    assert status_of(report, "TRANS-01").status.value == "ran"


async def test_trans01_indeterminate_behind_auth(make_server):
    async with make_server(require_auth=True, origin_check=False) as srv:
        report = await run(srv.url, only=["TRANS-01"])
    assert by_id(report, "TRANS-01") == []
    assert any("TRANS-01: indeterminate" in n for n in report.notes)


async def test_trans02_bogus_version_accepted(make_server):
    async with make_server(version_check=False) as srv:
        report = await run(srv.url, only=["TRANS-02"])
    [f] = by_id(report, "TRANS-02")
    assert f.severity == Severity.LOW
    assert f.evidence[0].request_headers["mcp-protocol-version"] == "1999-01-01"


async def test_trans02_bogus_version_rejected(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["TRANS-02"])
    assert by_id(report, "TRANS-02") == []


async def test_trans02_stateless_server(make_server):
    async with make_server(stateless_2026=True, session_mode="none", version_check=False) as srv:
        report = await run(srv.url, only=["TRANS-02"])
    assert report.fingerprint.flavour == "stateless-2026"
    assert len(by_id(report, "TRANS-02")) == 1


async def test_trans03_sequential_and_forged_sessions(make_server):
    async with make_server(session_mode="sequential", validate_session=False) as srv:
        report = await run(srv.url, only=["TRANS-03"])
    titles = {f.title for f in by_id(report, "TRANS-03")}
    assert titles == {"Session IDs are weak or predictable", "Forged session ID accepted"}
    weak = next(f for f in by_id(report, "TRANS-03") if f.title.startswith("Session IDs"))
    assert "session ids are sequential integers" in weak.details["problems"]


async def test_trans03_short_ids(make_server):
    async with make_server(session_mode="weak") as srv:
        report = await run(srv.url, only=["TRANS-03"])
    [f] = by_id(report, "TRANS-03")
    assert any("characters" in p for p in f.details["problems"])
    assert any("issued twice" in p for p in f.details["problems"])


async def test_trans03_secure_sessions_clean(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["TRANS-03"])
    assert by_id(report, "TRANS-03") == []


async def test_trans03_not_applicable_to_stateless(make_server):
    async with make_server(stateless_2026=True, session_mode="none") as srv:
        report = await run(srv.url, only=["TRANS-03"])
    assert by_id(report, "TRANS-03") == []
    assert status_of(report, "TRANS-03").status.value == "ran"


async def test_trans04_legacy_sse_only(make_server):
    async with make_server(legacy_sse=True, post_disabled=True, session_mode="none") as srv:
        report = await run(srv.url, only=["TRANS-04"])
    [f] = by_id(report, "TRANS-04")
    assert f.severity == Severity.INFO
    assert report.fingerprint.flavour == "legacy-sse"


async def test_trans04_legacy_alongside_streamable(make_server):
    async with make_server(legacy_sse=True) as srv:
        report = await run(srv.url, only=["TRANS-04"])
    [f] = by_id(report, "TRANS-04")
    assert "alongside" in f.description


async def test_trans04_modern_server_clean(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["TRANS-04"])
    assert by_id(report, "TRANS-04") == []


async def test_trans05_plain_http_and_headers(make_server):
    async with make_server(security_headers=False) as srv:
        report = await run(srv.url, only=["TRANS-05"])
    titles = {f.title: f for f in by_id(report, "TRANS-05")}
    plain = titles["MCP endpoint served over plain HTTP"]
    assert plain.severity == Severity.INFO  # loopback
    assert plain.details["local"] is True
    hdr = titles["Security headers missing on MCP endpoint"]
    assert hdr.details["missing"] == ["X-Content-Type-Options"]


async def test_trans05_headers_present(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["TRANS-05"])
    titles = {f.title for f in by_id(report, "TRANS-05")}
    assert "Security headers missing on MCP endpoint" not in titles


async def test_trans_checks_skipped_for_stdio():
    from tests.conftest import stdio_command

    report = await run(stdio_command(), stdio=True, only=["TRANS-01", "TRANS-02", "TRANS-03", "TRANS-04", "TRANS-05"])
    assert {status_of(report, c).status.value for c in ("TRANS-01", "TRANS-05")} == {"skipped"}
