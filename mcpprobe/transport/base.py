"""Shared transport abstractions.

The scanner deliberately does **not** use an official MCP SDK client: checks
need to send malformed and non-conformant requests (bad ``Origin``, bogus
protocol version header, forged session IDs, wrong-audience tokens) that a
conformant client refuses to send. The transports here are thin and permissive.
"""

from __future__ import annotations

import abc
import itertools
import json
from dataclasses import dataclass, field
from typing import Any

from mcpprobe.models import EvidenceRecord
from mcpprobe.transport.evidence import EvidenceLog
from mcpprobe.transport.ratelimit import RateLimiter

#: Current (stateless) revision. ``server/discover`` replaces ``initialize``.
PROTOCOL_2026_07_28 = "2026-07-28"
#: Handshake-based revisions still widely deployed.
PROTOCOL_2025_11_25 = "2025-11-25"
PROTOCOL_2025_06_18 = "2025-06-18"

#: Order in which versions are tried during fingerprinting.
VERSION_PREFERENCE: tuple[str, ...] = (
    PROTOCOL_2026_07_28,
    PROTOCOL_2025_11_25,
    PROTOCOL_2025_06_18,
)

#: Versions that use the ``initialize`` handshake rather than ``server/discover``.
HANDSHAKE_VERSIONS: frozenset[str] = frozenset({PROTOCOL_2025_11_25, PROTOCOL_2025_06_18})

#: ``_meta`` key carrying the protocol version in 2026-07-28 requests.
META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"

CLIENT_INFO: dict[str, str] = {"name": "mcpprobe", "version": "0.1.0"}


class TransportError(Exception):
    """Raised when the target cannot be reached or spoken to at all."""


@dataclass(slots=True)
class RpcResponse:
    """Result of one JSON-RPC exchange, successful or not."""

    method: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    message: dict[str, Any] | None = None
    evidence: EvidenceRecord | None = None
    elapsed_ms: float = 0.0
    error_text: str | None = None
    #: All JSON-RPC messages seen in an SSE stream (the matching one is ``message``).
    stream_messages: list[dict[str, Any]] = field(default_factory=list)

    @property
    def result(self) -> dict[str, Any] | None:
        value = self.message.get("result") if self.message else None
        return value if isinstance(value, dict) else None

    @property
    def rpc_error(self) -> dict[str, Any] | None:
        value = self.message.get("error") if self.message else None
        return value if isinstance(value, dict) else None

    @property
    def ok(self) -> bool:
        """True when a JSON-RPC ``result`` came back (HTTP 2xx or stdio)."""
        return self.result is not None and (self.status is None or 200 <= self.status < 300)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def is_jsonrpc_error_body(body: bytes) -> bool:
    """Whether a body parses as a JSON-RPC error object (used by conformance checks)."""
    try:
        data = json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("error"), dict)


class Transport(abc.ABC):
    """Common interface over streamable HTTP and stdio."""

    name: str = "abstract"

    def __init__(self, evidence: EvidenceLog | None = None, limiter: RateLimiter | None = None) -> None:
        self.evidence = evidence if evidence is not None else EvidenceLog()
        self.limiter = limiter if limiter is not None else RateLimiter()
        self._ids = itertools.count(1)
        #: Negotiated protocol version; set by the fingerprinter.
        self.protocol_version: str | None = None

    def next_id(self) -> int:
        return next(self._ids)

    @property
    def stateless(self) -> bool:
        """True when speaking the 2026-07-28 stateless revision."""
        return self.protocol_version == PROTOCOL_2026_07_28

    def build_message(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        protocol_version: str | None = None,
        msg_id: int | None = None,
        notification: bool = False,
    ) -> dict[str, Any]:
        """Build a JSON-RPC message, adding the 2026-07-28 ``_meta`` version when needed."""
        version = protocol_version or self.protocol_version
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not notification:
            body["id"] = msg_id if msg_id is not None else self.next_id()
        p: dict[str, Any] = dict(params or {})
        if version == PROTOCOL_2026_07_28:
            meta = dict(p.get("_meta") or {})
            meta.setdefault(META_VERSION_KEY, version)
            p["_meta"] = meta
        if p or not notification:
            body["params"] = p
        return body

    @abc.abstractmethod
    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        note: str | None = None,
        **kwargs: Any,
    ) -> RpcResponse:
        """Send a request and wait for its response."""

    @abc.abstractmethod
    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a notification (no response expected)."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release connections or processes."""

    async def __aenter__(self) -> Transport:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
