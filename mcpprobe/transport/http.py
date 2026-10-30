"""Streamable HTTP transport (MCP 2025-03-26 onwards, including 2026-07-28).

One endpoint, JSON-RPC over POST, responses either ``application/json`` or an
SSE ``text/event-stream`` that is read until the matching response arrives.
Every exchange is written to the evidence log.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Iterable, Mapping
from typing import Any

import httpx

from mcpprobe import USER_AGENT
from mcpprobe.transport.base import (
    PROTOCOL_2026_07_28,
    RpcResponse,
    Transport,
    TransportError,
)
from mcpprobe.transport.evidence import EvidenceLog, is_sensitive_header
from mcpprobe.transport.ratelimit import RateLimiter

ACCEPT_BOTH = "application/json, text/event-stream"
#: Hard cap on how many SSE bytes we buffer for one response.
SSE_MAX_BYTES = 1_000_000


class SseEvent:
    """A parsed Server-Sent Event."""

    __slots__ = ("data", "event", "id")

    def __init__(self, event: str | None, data: str, event_id: str | None) -> None:
        self.event = event
        self.data = data
        self.id = event_id


def parse_sse_block(lines: Iterable[str]) -> SseEvent | None:
    """Parse one blank-line-delimited SSE block into an event (``None`` if empty)."""
    event: str | None = None
    data_parts: list[str] = []
    event_id: str | None = None
    for line in lines:
        if not line or line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if field == "event":
            event = value
        elif field == "data":
            data_parts.append(value)
        elif field == "id":
            event_id = value
    if not data_parts and event is None:
        return None
    return SseEvent(event, "\n".join(data_parts), event_id)


class HttpTransport(Transport):
    """Permissive streamable-HTTP MCP client used by all HTTP checks."""

    name = "http"

    def __init__(
        self,
        url: str,
        *,
        extra_headers: Mapping[str, str] | None = None,
        timeout: float = 15.0,
        evidence: EvidenceLog | None = None,
        limiter: RateLimiter | None = None,
        verify: bool | str = True,
        user_agent: str = USER_AGENT,
        httpx_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(evidence=evidence, limiter=limiter)
        self.url = url
        self.extra_headers = dict(extra_headers or {})
        self.timeout = timeout
        self.user_agent = user_agent
        self.session_id: str | None = None
        self.tls_version: str | None = None
        self.sessions_seen: list[str] = []
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=verify,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
            transport=httpx_transport,
        )

    # ------------------------------------------------------------------ headers
    def default_headers(
        self,
        method: str | None,
        *,
        protocol_version: str | None = None,
        include_session: bool = True,
    ) -> dict[str, str]:
        """Headers a conformant client would send for ``method``."""
        version = protocol_version or self.protocol_version
        headers: dict[str, str] = {
            "Accept": ACCEPT_BOTH,
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }
        if version:
            headers["MCP-Protocol-Version"] = version
        if version == PROTOCOL_2026_07_28 and method:
            headers["Mcp-Method"] = method
        if include_session and self.session_id and version != PROTOCOL_2026_07_28:
            headers["Mcp-Session-Id"] = self.session_id
        headers.update(self.extra_headers)
        return headers

    def credential_header_names(self) -> list[str]:
        """Operator-supplied headers that carry credentials (dropped for unauthenticated probes)."""
        return [k for k in self.extra_headers if is_credential_header(k)]

    # ------------------------------------------------------------------ raw I/O
    async def raw_request(
        self,
        http_method: str,
        *,
        body: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
        url: str | None = None,
        label: str = "raw",
        want_id: int | str | None = None,
        note: str | None = None,
        track_session: bool = False,
        stream_timeout: float | None = None,
    ) -> RpcResponse:
        """Send an arbitrary HTTP request to the endpoint and record it.

        If the response is an SSE stream it is read until a JSON-RPC message
        with id ``want_id`` is seen (or the stream ends / times out).
        """
        await self.limiter.acquire()
        target = url or self.url
        hdrs = dict(headers or {})
        data = body.encode("utf-8") if isinstance(body, str) else body
        started = time.monotonic()
        status: int | None = None
        resp_headers: dict[str, str] = {}
        collected = b""
        message: dict[str, Any] | None = None
        stream_messages: list[dict[str, Any]] = []
        error_text: str | None = None
        try:
            async with self._client.stream(http_method, target, content=data, headers=hdrs) as resp:
                status = resp.status_code
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                self._capture_tls(resp)
                ctype = resp_headers.get("content-type", "")
                if "text/event-stream" in ctype:
                    collected, stream_messages, message = await self._read_sse(
                        resp, want_id, stream_timeout or self.timeout
                    )
                else:
                    collected = await resp.aread()
                    message = _parse_jsonrpc(collected, want_id)
                    if message is not None:
                        stream_messages = [message]
        except httpx.HTTPError as exc:
            error_text = f"{type(exc).__name__}: {exc}"
        except TimeoutError:
            error_text = "stream timeout"
        elapsed_ms = (time.monotonic() - started) * 1000
        if track_session:
            sid = resp_headers.get("mcp-session-id")
            if sid:
                self.session_id = sid
                self.sessions_seen.append(sid)
        rec = self.evidence.record(
            transport="http",
            method=label,
            url=target,
            status=status,
            request_headers=hdrs,
            response_headers=resp_headers,
            request_body=data,
            response_body=collected,
            elapsed_ms=elapsed_ms,
            note=note,
            error=error_text,
        )
        return RpcResponse(
            method=label,
            status=status,
            headers=resp_headers,
            body=collected,
            message=message,
            evidence=rec,
            elapsed_ms=elapsed_ms,
            error_text=error_text,
            stream_messages=stream_messages,
        )

    def _capture_tls(self, resp: httpx.Response) -> None:
        if self.tls_version is not None:
            return
        try:
            stream = resp.extensions.get("network_stream")
            ssl_object = stream.get_extra_info("ssl_object") if stream else None
            if ssl_object is not None:
                self.tls_version = ssl_object.version()
        except Exception:  # pragma: no cover - best effort only
            self.tls_version = None

    async def _read_sse(
        self,
        resp: httpx.Response,
        want_id: int | str | None,
        timeout: float,
    ) -> tuple[bytes, list[dict[str, Any]], dict[str, Any] | None]:
        collected: list[str] = []
        total = 0
        block: list[str] = []
        messages: list[dict[str, Any]] = []
        matched: dict[str, Any] | None = None

        async def consume() -> None:
            nonlocal total, matched
            async for line in resp.aiter_lines():
                total += len(line) + 1
                if total <= SSE_MAX_BYTES:
                    collected.append(line)
                if line == "":
                    event = parse_sse_block(block)
                    block.clear()
                    if event is None or not event.data:
                        continue
                    msg = _parse_jsonrpc(event.data.encode("utf-8"), None)
                    if msg is not None:
                        messages.append(msg)
                        if want_id is not None and msg.get("id") == want_id:
                            matched = msg
                            return
                else:
                    block.append(line)
                if total > SSE_MAX_BYTES:
                    return
            if block:
                event = parse_sse_block(block)
                if event and event.data:
                    msg = _parse_jsonrpc(event.data.encode("utf-8"), None)
                    if msg is not None:
                        messages.append(msg)
                        if want_id is not None and msg.get("id") == want_id:
                            matched = msg

        try:
            await asyncio.wait_for(consume(), timeout)
        except TimeoutError:
            pass
        if matched is None and want_id is None and messages:
            matched = messages[-1]
        return "\n".join(collected).encode("utf-8"), messages, matched

    # ------------------------------------------------------------------ JSON-RPC
    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        note: str | None = None,
        headers_override: Mapping[str, str] | None = None,
        drop_headers: Iterable[str] = (),
        protocol_version: str | None = None,
        track_session: bool = False,
        include_session: bool = True,
        **kwargs: Any,
    ) -> RpcResponse:
        """POST a JSON-RPC request. ``headers_override`` lets checks send
        non-conformant headers; ``drop_headers`` removes defaults by name."""
        msg = self.build_message(method, params, protocol_version=protocol_version)
        hdrs = self.default_headers(
            method, protocol_version=protocol_version, include_session=include_session
        )
        for name in drop_headers:
            hdrs = {k: v for k, v in hdrs.items() if k.lower() != name.lower()}
        if headers_override:
            for k, v in headers_override.items():
                hdrs = {hk: hv for hk, hv in hdrs.items() if hk.lower() != k.lower()}
                hdrs[k] = v
        resp = await self.raw_request(
            "POST",
            body=json.dumps(msg),
            headers=hdrs,
            label=method,
            want_id=msg["id"],
            note=note,
            track_session=track_session,
        )
        resp.method = method
        return resp

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg = self.build_message(method, params, notification=True)
        await self.raw_request(
            "POST",
            body=json.dumps(msg),
            headers=self.default_headers(method),
            label=method,
            note="notification",
        )

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        note: str | None = None,
        label: str = "GET",
    ) -> RpcResponse:
        """Plain GET (well-known documents, opt-out, legacy SSE probe)."""
        hdrs = {"User-Agent": self.user_agent, "Accept": "application/json, text/plain, */*"}
        hdrs.update(headers or {})
        return await self.raw_request(
            "GET", headers=hdrs, url=url, label=label, note=note, stream_timeout=3.0
        )

    async def legacy_sse_probe(self) -> RpcResponse:
        """GET the endpoint as the deprecated 2024-11-05 HTTP+SSE transport would.

        A legacy server answers with an ``endpoint`` event. We read only the
        first event (3 s cap) and close the stream.
        """
        hdrs = {"User-Agent": self.user_agent, "Accept": "text/event-stream"}
        hdrs.update(self.extra_headers)
        return await self.raw_request(
            "GET", headers=hdrs, label="GET(sse)", note="legacy HTTP+SSE probe", stream_timeout=3.0
        )

    async def close(self) -> None:
        await self._client.aclose()


def is_credential_header(name: str) -> bool:
    """Headers an operator would use to authenticate (Authorization, Cookie, API-key style)."""
    lk = name.lower()
    return is_sensitive_header(lk) or lk.endswith("-auth") or lk == "x-authorization"


def _parse_jsonrpc(body: bytes, want_id: int | str | None) -> dict[str, Any] | None:
    """Parse a JSON-RPC response body (object or batch), picking the one for ``want_id``."""
    if not body:
        return None
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and (want_id is None or item.get("id") == want_id):
                return item
        return None
    if isinstance(data, dict) and "jsonrpc" in data:
        return data
    return None


def ensure_url(target: str) -> str:
    """Validate an HTTP(S) target."""
    try:
        parsed = httpx.URL(target)
    except httpx.InvalidURL as exc:
        raise TransportError(f"invalid URL: {target}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.host:
        raise TransportError(f"target must be an http(s) URL: {target}")
    return str(parsed)
