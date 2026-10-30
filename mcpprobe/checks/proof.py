"""Builders for ``Finding.proof`` and ``Finding.verify``.

Proof is a human-readable excerpt that shows exactly what a finding is based
on. It is always built from parsed data (the parsed tool list, the response
header dict) and never by slicing a stored body, so the object being judged is
never cut off mid-way.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Iterable, Mapping
from typing import Any

from mcpprobe.checks._util import visible
from mcpprobe.models import EvidenceRecord

ACCEPT = "application/json, text/event-stream"
VERIFY_CLIENT = {"name": "verify", "version": "0"}


def pretty(obj: Any) -> str:
    """Stable, complete, indented JSON."""
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False)


def indent(text: str, prefix: str = "  ") -> str:
    return "\n".join(prefix + line if line else line for line in text.splitlines())


def header_lines(headers: Mapping[str, str]) -> list[str]:
    return [f"{k}: {visible(v)}" for k, v in sorted(headers.items())]


def _rpc_method(rec: EvidenceRecord) -> str | None:
    try:
        data = json.loads(rec.request_body)
    except ValueError:
        return None
    if isinstance(data, dict) and isinstance(data.get("method"), str):
        return str(data["method"])
    return None


def exchange(
    rec: EvidenceRecord | None,
    *,
    request_headers: Iterable[str] | None = None,
    response_headers: Iterable[str] | None = None,
    absent_request: Iterable[str] = (),
    result_lines: Iterable[str] = (),
) -> str:
    """Request line + chosen request headers, status + chosen response headers.

    ``request_headers``/``response_headers`` name the headers to show (``None``
    shows all). Headers listed in ``absent_request`` are printed as
    ``(not sent)`` when missing, which is how AUTH-01 shows the missing
    ``Authorization``. ``result_lines`` are extra, already-parsed facts.
    """
    if rec is None:
        return ""
    lines = [f"[{rec.id}] request"]
    verb = "POST" if rec.request_body else "GET"
    lines.append(f"  {verb} {rec.url or ''}".rstrip())
    wanted_req = {h.lower() for h in request_headers} if request_headers is not None else None
    for k, v in sorted(rec.request_headers.items()):
        if wanted_req is None or k in wanted_req:
            lines.append(f"  {k}: {visible(v)}")
    for name in absent_request:
        if name.lower() not in rec.request_headers:
            lines.append(f"  {name.lower()}: (not sent)")
    method = _rpc_method(rec)
    if method:
        lines.append(f"  JSON-RPC method: {method}")
    lines.append("response")
    if rec.status is None:
        lines.append(f"  no HTTP response ({rec.error or 'transport error'})")
    else:
        lines.append(f"  HTTP {rec.status}")
    wanted_resp = {h.lower() for h in response_headers} if response_headers is not None else None
    for k, v in sorted(rec.response_headers.items()):
        if wanted_resp is None or k in wanted_resp:
            lines.append(f"  {k}: {visible(v)}")
    if wanted_resp is not None:
        for name in sorted(wanted_resp):
            if name not in rec.response_headers:
                lines.append(f"  {name}: (absent)")
    lines.extend(f"  {line}" for line in result_lines)
    return "\n".join(lines)


def header_set(rec: EvidenceRecord, required: Iterable[str]) -> str:
    """Complete response header set, with each required-but-missing header marked MISSING."""
    lines = [f"[{rec.id}] {rec.method} {rec.url or ''} -> HTTP {rec.status}", "response headers (complete):"]
    lines += [f"  {line}" for line in header_lines(rec.response_headers)]
    missing = [h for h in required if h.lower() not in rec.response_headers]
    for h in missing:
        lines.append(f"  {h}: MISSING")
    return "\n".join(lines)


# ----------------------------------------------------------------------------- verify lines
def _q(value: str) -> str:
    return shlex.quote(value)


def curl_rpc(
    url: str,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    protocol_version: str | None = "2025-11-25",
    auth_placeholder: bool = False,
    include_headers: bool = True,
    jq: str | None = None,
    expect: str = "",
) -> str:
    """A copy-pasteable curl line for one JSON-RPC request."""
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    parts = ["curl", "-si" if include_headers else "-s", "-X", "POST", _q(url)]
    hdrs: dict[str, str] = {"content-type": "application/json", "accept": ACCEPT}
    if protocol_version:
        hdrs["MCP-Protocol-Version"] = protocol_version
    if auth_placeholder:
        hdrs["Authorization"] = "Bearer $TOKEN"
    for k, v in (headers or {}).items():
        hdrs = {hk: hv for hk, hv in hdrs.items() if hk.lower() != k.lower()}
        hdrs[k] = v
    for k, v in hdrs.items():
        if v == "Bearer $TOKEN":
            parts += ["-H", f'"{k}: {v}"']
        else:
            parts += ["-H", _q(f"{k}: {v}")]
    parts += ["-d", _q(json.dumps(body, separators=(",", ":")))]
    line = " ".join(parts)
    if jq:
        line += f" | jq {_q(jq)}"
    if expect:
        line += f"  # expect {expect}"
    return line


def modern_params(version: str = "2026-07-28", **extra: Any) -> dict[str, Any]:
    """Params for a 2026-07-28 request: the required ``_meta`` plus ``extra``."""
    meta = {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return {**extra, "_meta": meta}


def initialize_params(version: str = "2025-11-25") -> dict[str, Any]:
    return {"protocolVersion": version, "capabilities": {}, "clientInfo": VERIFY_CLIENT}


def rescan(target: str, check_id: str, *, stdio: bool = False) -> str:
    if stdio:
        return f"mcpprobe --stdio {_q(target)} --only {check_id}  # expect no {check_id} finding"
    return f"mcpprobe {_q(target)} --only {check_id}  # expect no {check_id} finding"
