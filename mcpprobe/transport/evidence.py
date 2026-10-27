"""Evidence collection: every request/response pair the scanner sends is logged."""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Mapping

from mcpprobe.models import EVIDENCE_BODY_LIMIT, EvidenceRecord, utcnow
from mcpprobe.redact import redact_secrets, redact_url

#: Response headers worth keeping in evidence (lower-case).
KEPT_RESPONSE_HEADERS: frozenset[str] = frozenset(
    {
        "content-type",
        "content-length",
        "www-authenticate",
        "mcp-session-id",
        "mcp-protocol-version",
        "server",
        "x-powered-by",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "cache-control",
        "retry-after",
        "location",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "allow",
        "date",
    }
)

#: Request headers worth keeping in evidence (lower-case).
KEPT_REQUEST_HEADERS: frozenset[str] = frozenset(
    {
        "accept",
        "content-type",
        "origin",
        "host",
        "user-agent",
        "authorization",
        "mcp-session-id",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
        "last-event-id",
    }
)

REDACTED = "<redacted>"


def _subset(headers: Mapping[str, str] | Iterable[tuple[str, str]], keep: frozenset[str]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    out: dict[str, str] = {}
    for key, value in items:
        lk = key.lower()
        if lk not in keep:
            continue
        if lk == "authorization":
            scheme = value.split(" ", 1)[0] if value else ""
            out[lk] = f"{scheme} {REDACTED}".strip()
        else:
            out[lk] = value
    return out


def truncate_body(body: bytes | str | None, limit: int = EVIDENCE_BODY_LIMIT) -> tuple[str, bool]:
    """Return ``(text, truncated)`` for a body: secrets redacted, at most ``limit`` UTF-8 bytes."""
    if body is None:
        return "", False
    raw = body if isinstance(body, bytes) else body.encode("utf-8", errors="replace")
    truncated = len(raw) > limit
    # Redact on a slightly larger window so a secret straddling the cut is still caught.
    text = redact_secrets(raw[: limit * 2].decode("utf-8", errors="replace"))
    encoded = text.encode("utf-8")
    if len(encoded) > limit:
        truncated = True
        text = encoded[:limit].decode("utf-8", errors="ignore")
    return text, truncated


class EvidenceLog:
    """Append-only list of :class:`EvidenceRecord` with sequential IDs."""

    def __init__(self) -> None:
        self._records: list[EvidenceRecord] = []
        self._counter = itertools.count(1)

    def record(
        self,
        *,
        transport: str,
        method: str,
        url: str | None = None,
        status: int | None = None,
        request_headers: Mapping[str, str] | None = None,
        response_headers: Mapping[str, str] | Iterable[tuple[str, str]] | None = None,
        request_body: bytes | str | None = None,
        response_body: bytes | str | None = None,
        elapsed_ms: float | None = None,
        note: str | None = None,
        error: str | None = None,
    ) -> EvidenceRecord:
        """Create, store and return a new evidence record."""
        req_text, req_trunc = truncate_body(request_body)
        resp_text, resp_trunc = truncate_body(response_body)
        rec = EvidenceRecord(
            id=f"ev-{next(self._counter):04d}",
            timestamp=utcnow(),
            transport=transport,
            method=method,
            url=redact_url(url) if url else url,
            status=status,
            request_headers=_subset(request_headers or {}, KEPT_REQUEST_HEADERS),
            response_headers=_subset(response_headers or {}, KEPT_RESPONSE_HEADERS),
            request_body=req_text,
            response_body=resp_text,
            request_truncated=req_trunc,
            response_truncated=resp_trunc,
            elapsed_ms=elapsed_ms,
            note=note,
            error=error,
        )
        self._records.append(rec)
        return rec

    @property
    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)
