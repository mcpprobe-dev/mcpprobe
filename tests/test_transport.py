from __future__ import annotations

import json

import pytest

from mcpprobe.models import EVIDENCE_BODY_LIMIT
from mcpprobe.transport import (
    PROTOCOL_2025_11_25,
    PROTOCOL_2026_07_28,
    EvidenceLog,
    HttpTransport,
    RateLimiter,
    StdioTransport,
    TransportError,
    ensure_url,
    fingerprint,
)
from mcpprobe.transport.http import parse_sse_block
from tests.conftest import stdio_command


def test_parse_sse_block_basic():
    ev = parse_sse_block(["event: message", 'data: {"a":', "data: 1}", "id: 7", ": comment"])
    assert ev is not None
    assert ev.event == "message"
    assert ev.data == '{"a":\n1}'
    assert ev.id == "7"
    assert parse_sse_block([]) is None


def test_ensure_url_rejects_non_http():
    with pytest.raises(TransportError):
        ensure_url("ftp://example.invalid/mcp")
    assert ensure_url("https://example.invalid/mcp").startswith("https://")


async def test_fingerprint_handshake_json(make_server):
    async with make_server() as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            fp = await fingerprint(t)
            assert fp.flavour == "handshake"
            assert fp.protocol_version == PROTOCOL_2025_11_25
            assert t.protocol_version == PROTOCOL_2025_11_25
            assert fp.session_id_seen
            assert fp.server_info["name"] == "fake-mcp"
            # discover was tried first and failed, then initialize succeeded
            assert [a["method"] for a in fp.attempts] == ["server/discover", "initialize"]
            resp = await t.rpc("tools/list")
            assert resp.ok
            assert len(resp.result["tools"]) == 2


async def test_fingerprint_handshake_sse_responses(make_server):
    async with make_server(sse_responses=True) as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            fp = await fingerprint(t)
            assert fp.flavour == "handshake"
            resp = await t.rpc("tools/list")
            assert resp.ok
            assert "text/event-stream" in resp.headers["content-type"]


async def test_fingerprint_stateless_2026(make_server):
    async with make_server(stateless_2026=True, session_mode="none") as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            fp = await fingerprint(t)
            assert fp.flavour == "stateless-2026"
            assert fp.protocol_version == PROTOCOL_2026_07_28
            assert len(fp.attempts) == 1
            resp = await t.rpc("tools/list")
            assert resp.ok
            sent = json.loads(resp.evidence.request_body)
            assert sent["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
            assert resp.evidence.request_headers["mcp-method"] == "tools/list"


async def test_fingerprint_auth_required(make_server):
    async with make_server(require_auth=True) as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            fp = await fingerprint(t)
            assert fp.auth_required
            assert "resource_metadata" in (fp.www_authenticate or "")
            assert fp.flavour == "unknown"


async def test_fingerprint_legacy_sse(make_server):
    async with make_server(legacy_sse=True, post_disabled=True, session_mode="none") as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            fp = await fingerprint(t)
            assert fp.flavour == "legacy-sse"
            assert fp.protocol_version == "2024-11-05"
            assert fp.attempts[-1]["method"] == "GET"


async def test_fingerprint_nothing_answers(make_server):
    async with make_server(post_disabled=True, session_mode="none") as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            fp = await fingerprint(t)
            assert fp.flavour == "unknown"
            assert fp.error


async def test_evidence_truncation_and_redaction(make_server):
    async with make_server() as srv:
        log = EvidenceLog()
        async with HttpTransport(
            srv.url,
            evidence=log,
            limiter=RateLimiter(1000),
            extra_headers={"Authorization": "Bearer supersecret"},
        ) as t:
            big = "x" * (EVIDENCE_BODY_LIMIT * 3)
            await t.rpc("tools/list", {"cursor": big}, protocol_version=PROTOCOL_2025_11_25)
        rec = log.records[-1]
        assert rec.request_truncated
        assert len(rec.request_body.encode()) <= EVIDENCE_BODY_LIMIT
        assert rec.request_headers["authorization"] == "Bearer <redacted>"
        assert rec.id.startswith("ev-")
        assert rec.status in (200, 400)


async def test_headers_override_and_drop(make_server):
    async with make_server() as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            await fingerprint(t)
            resp = await t.rpc("tools/list", headers_override={"Origin": "https://evil.example"})
            assert resp.status == 403
            resp = await t.rpc("tools/list", drop_headers=["Mcp-Session-Id"])
            assert resp.status == 400


async def test_rate_limiter_paces_requests():
    import time

    limiter = RateLimiter(rate=20, burst=1)
    start = time.monotonic()
    for _ in range(5):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.15  # 4 waits of 50 ms
    assert limiter.requests == 5
    with pytest.raises(ValueError):
        RateLimiter(rate=0)


async def test_stdio_transport_roundtrip():
    async with StdioTransport(stdio_command(), limiter=RateLimiter(1000)) as t:
        fp = await fingerprint(t)
        assert fp.flavour == "handshake"
        assert fp.transport == "stdio"
        resp = await t.rpc("tools/list")
        assert resp.ok and resp.result["tools"][0]["name"] == "echo"
        assert resp.evidence.transport == "stdio"
        assert resp.evidence.status is None


async def test_stdio_stateless():
    async with StdioTransport(stdio_command("--stateless"), limiter=RateLimiter(1000)) as t:
        fp = await fingerprint(t)
        assert fp.flavour == "stateless-2026"


async def test_stdio_bad_command():
    t = StdioTransport(["/nonexistent/binary/xyz"], limiter=RateLimiter(1000))
    with pytest.raises(TransportError):
        await t.start()
    with pytest.raises(TransportError):
        StdioTransport("")
