"""Protocol-version fingerprinting.

Order of attempts (see the MCP versioning page and the 2026-07-28 changelog):

1. ``server/discover`` with the 2026-07-28 ``_meta`` version (stateless revision).
2. ``initialize`` with ``2025-11-25``, then ``2025-06-18`` (handshake revisions);
   on success ``notifications/initialized`` is sent and any ``Mcp-Session-Id``
   is remembered.
3. For HTTP targets that answered 400/404/405 to every POST, a single GET is made
   to detect the deprecated 2024-11-05 HTTP+SSE transport (``endpoint`` event).

A 401 on any attempt marks the target as auth-protected and stops negotiation.
"""

from __future__ import annotations

from typing import Any

from mcpprobe.models import Fingerprint
from mcpprobe.transport.base import (
    CLIENT_INFO,
    HANDSHAKE_VERSIONS,
    META_SERVER_INFO_KEY,
    PROTOCOL_2026_07_28,
    RpcResponse,
    Transport,
)
from mcpprobe.transport.http import HttpTransport, parse_sse_block

LEGACY_STATUSES = {400, 404, 405}


def _attempt(version: str, method: str, resp: RpcResponse) -> dict[str, Any]:
    err = resp.rpc_error
    return {
        "version": version,
        "method": method,
        "status": resp.status,
        "ok": resp.ok,
        "rpc_error": (err or {}).get("message") if err else None,
        "transport_error": resp.error_text,
        "evidence": resp.evidence.id if resp.evidence else None,
    }


def _absorb_server_result(fp: Fingerprint, result: dict[str, Any]) -> None:
    meta = result.get("_meta")
    info = (meta.get(META_SERVER_INFO_KEY) if isinstance(meta, dict) else None) or result.get("serverInfo")
    if isinstance(info, dict):
        fp.server_info = info
    caps = result.get("capabilities")
    if isinstance(caps, dict):
        fp.capabilities = caps
    instr = result.get("instructions")
    if isinstance(instr, str):
        fp.instructions = instr


async def fingerprint(transport: Transport) -> Fingerprint:
    """Negotiate with the target and return what was learned."""
    fp = Fingerprint(transport=transport.name)
    statuses: list[int | None] = []

    # 1. Stateless 2026-07-28
    resp = await transport.rpc(
        "server/discover",
        {},
        protocol_version=PROTOCOL_2026_07_28,
        note="fingerprint: 2026-07-28 server/discover",
    )
    fp.attempts.append(_attempt(PROTOCOL_2026_07_28, "server/discover", resp))
    statuses.append(resp.status)
    if _is_unauthorised(resp):
        _mark_auth(fp, resp)
        return fp
    if resp.ok and resp.result is not None:
        fp.flavour = "stateless-2026"
        fp.protocol_version = PROTOCOL_2026_07_28
        transport.protocol_version = PROTOCOL_2026_07_28
        _absorb_server_result(fp, resp.result)
        fp.discover_result = resp.result
        versions = resp.result.get("supportedVersions")
        if isinstance(versions, list):
            fp.supported_versions = [v for v in versions if isinstance(v, str)]
        return fp

    # 2. Handshake revisions
    for version in sorted(HANDSHAKE_VERSIONS, reverse=True):
        resp = await transport.rpc(
            "initialize",
            {"protocolVersion": version, "capabilities": {}, "clientInfo": CLIENT_INFO},
            protocol_version=version,
            track_session=True,
            note=f"fingerprint: initialize {version}",
        )
        fp.attempts.append(_attempt(version, "initialize", resp))
        statuses.append(resp.status)
        if _is_unauthorised(resp):
            _mark_auth(fp, resp)
            return fp
        if resp.ok and resp.result is not None:
            negotiated = resp.result.get("protocolVersion")
            fp.protocol_version = str(negotiated) if negotiated else version
            # Speak the version the server answered with, so later requests match.
            transport.protocol_version = (
                fp.protocol_version if fp.protocol_version in HANDSHAKE_VERSIONS else version
            )
            fp.flavour = "handshake"
            _absorb_server_result(fp, resp.result)
            if isinstance(transport, HttpTransport) and transport.session_id:
                fp.session_id_seen = True
            await transport.notify("notifications/initialized")
            return fp

    # 3. Legacy HTTP+SSE
    if isinstance(transport, HttpTransport) and all(s in LEGACY_STATUSES for s in statuses if s):
        resp = await transport.legacy_sse_probe()
        fp.attempts.append(_attempt("2024-11-05", "GET", resp))
        if _is_unauthorised(resp):
            _mark_auth(fp, resp)
            return fp
        if resp.status == 200 and "text/event-stream" in resp.headers.get("content-type", ""):
            first = _first_event_name(resp.body)
            if first == "endpoint":
                fp.flavour = "legacy-sse"
                fp.protocol_version = "2024-11-05"
                return fp

    fp.error = "no supported protocol revision answered; see attempts"
    return fp


def _first_event_name(body: bytes) -> str | None:
    lines = body.decode("utf-8", errors="replace").split("\n")
    block: list[str] = []
    for line in lines:
        if line == "":
            if block:
                ev = parse_sse_block(block)
                return ev.event if ev else None
            continue
        block.append(line)
    ev = parse_sse_block(block) if block else None
    return ev.event if ev else None


def _is_unauthorised(resp: RpcResponse) -> bool:
    return resp.status == 401


def _mark_auth(fp: Fingerprint, resp: RpcResponse) -> None:
    fp.auth_required = True
    fp.www_authenticate = resp.headers.get("www-authenticate")
