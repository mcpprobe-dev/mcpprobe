"""TRANS-01..05: streamable-HTTP transport conformance and hygiene (passive)."""

from __future__ import annotations

import itertools
import secrets
from typing import Any

from mcpprobe.checks._util import host_of, is_local_or_private, shannon_entropy
from mcpprobe.checks.base import Check, ScanContext, evidence_of
from mcpprobe.models import Confidence, EvidenceRecord, Finding, Severity, Standards
from mcpprobe.transport import PROTOCOL_2025_11_25, PROTOCOL_2026_07_28, RpcResponse
from mcpprobe.transport.base import CLIENT_INFO, is_jsonrpc_error_body
from mcpprobe.transport.fingerprint import _first_event_name

EVIL_ORIGIN = "https://evil.example"
BOGUS_VERSION = "1999-01-01"
MIN_SESSION_LENGTH = 16
MIN_SESSION_ENTROPY_BITS = 3.0


def _negotiation_request(ctx: ScanContext) -> tuple[str, dict[str, Any], str]:
    """A request that is valid on any revision and needs no session."""
    if ctx.fingerprint.flavour == "stateless-2026":
        return "server/discover", {}, PROTOCOL_2026_07_28
    version = ctx.fingerprint.protocol_version or PROTOCOL_2025_11_25
    if version == "2024-11-05":
        version = PROTOCOL_2025_11_25
    return (
        "initialize",
        {"protocolVersion": version, "capabilities": {}, "clientInfo": CLIENT_INFO},
        version,
    )


class Trans01OriginValidation(Check):
    id = "TRANS-01"
    title = "Origin header not validated (DNS-rebinding exposure)"
    severity = Severity.MEDIUM
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025"])
    description = (
        "Sends a normal negotiation request with 'Origin: https://evil.example'. The transport "
        "spec says servers MUST validate Origin and return 403 on an invalid one; otherwise a web "
        "page can drive a locally running MCP server through the victim's browser (DNS rebinding)."
    )
    evidence_type = "The POST with the foreign Origin header and the non-403 response."
    false_positive_notes = (
        "If the server answers 401 before looking at Origin the check is indeterminate and no "
        "finding is raised (see scan notes). Reverse proxies that strip Origin will cause a "
        "finding against the proxied endpoint even if the application validates it."
    )
    fix = (
        "Reject requests whose Origin is not on an allow-list with HTTP 403 before processing "
        "the body. For local servers also bind to 127.0.0.1 rather than 0.0.0.0."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        if http is None or ctx.fingerprint.flavour == "legacy-sse":
            return []
        method, params, version = _negotiation_request(ctx)
        resp = await http.rpc(
            method,
            params,
            protocol_version=version,
            include_session=False,
            headers_override={"Origin": EVIL_ORIGIN},
            note="TRANS-01 foreign Origin",
        )
        if resp.status == 403:
            return []
        if resp.status == 401:
            ctx.notes.append("TRANS-01: indeterminate, server returned 401 before Origin validation")
            return []
        if resp.status is None:
            return []
        local = is_local_or_private(host_of(ctx.target))
        reflected = resp.headers.get("access-control-allow-origin")
        details: dict[str, Any] = {"status": resp.status, "origin": EVIL_ORIGIN}
        if reflected:
            details["access_control_allow_origin"] = reflected
        return [
            self.finding(
                description=(
                    f"A request with Origin {EVIL_ORIGIN} was answered with HTTP {resp.status} "
                    f"instead of 403. The server does not validate Origin as the transport spec requires."
                    + (
                        " The server runs on a loopback/private address, where DNS rebinding from a "
                        "browser is the realistic attack path."
                        if local
                        else ""
                    )
                ),
                severity=Severity.HIGH if local else Severity.MEDIUM,
                confidence=Confidence.HIGH if resp.result is not None else Confidence.MEDIUM,
                evidence=evidence_of(resp),
                location=ctx.target,
                details=details,
            )
        ]


class Trans02ProtocolVersionHandling(Check):
    id = "TRANS-02"
    title = "Unsupported MCP-Protocol-Version header not rejected"
    severity = Severity.LOW
    applies_to = frozenset({"http"})
    standards = Standards()
    description = (
        "Sends a request with 'MCP-Protocol-Version: 1999-01-01'. The spec requires HTTP 400 "
        "(or, on 2026-07-28, an UnsupportedProtocolVersionError). Accepting any version string "
        "suggests the server ignores version negotiation entirely."
    )
    evidence_type = "The request with the bogus version header and the response."
    false_positive_notes = (
        "Pre-2025-06-18 servers never defined the header, so an older server that ignores it is "
        "noted at low severity only."
    )
    fix = "Validate MCP-Protocol-Version against the supported list and reply 400 when it is unknown."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        if http is None or ctx.fingerprint.flavour in {"legacy-sse", "unknown"}:
            return []
        method, params, _ = _negotiation_request(ctx)
        resp = await http.rpc(
            method,
            params,
            include_session=False,
            headers_override={"MCP-Protocol-Version": BOGUS_VERSION},
            note="TRANS-02 bogus protocol version",
        )
        if resp.status == 400 or (resp.rpc_error is not None) or is_jsonrpc_error_body(resp.body):
            return []
        if resp.status is None or resp.status in (401, 403):
            return []
        return [
            self.finding(
                description=(
                    f"'MCP-Protocol-Version: {BOGUS_VERSION}' was answered with HTTP {resp.status} "
                    "and a normal result instead of 400."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH if resp.result is not None else Confidence.MEDIUM,
                evidence=evidence_of(resp),
                location=ctx.target,
                details={"status": resp.status},
            )
        ]


class Trans03SessionIdQuality(Check):
    id = "TRANS-03"
    title = "Weak, predictable or unvalidated Mcp-Session-Id"
    severity = Severity.HIGH
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025"])
    description = (
        "Collects three session IDs from repeated initialize requests and checks length, "
        "character set, Shannon entropy and sequentiality. Then sends tools/list with a random "
        "forged session ID, expecting 400 or 404. Only runs on handshake revisions that issue "
        "Mcp-Session-Id (sessions were removed in 2026-07-28)."
    )
    evidence_type = "The initialize responses (session header) and the forged-session request."
    false_positive_notes = (
        "Entropy is estimated from three samples, so the test is conservative: only IDs shorter "
        "than 16 characters, obviously sequential, or with very low per-character entropy are flagged."
    )
    fix = (
        "Generate session IDs with a CSPRNG (at least 128 bits, e.g. UUIDv4 or 32 random bytes "
        "base64url), store them server-side, and answer 404 for unknown IDs."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        fp = ctx.fingerprint
        if http is None or fp.flavour != "handshake" or not fp.session_id_seen:
            return []
        findings: list[Finding] = []
        version = fp.protocol_version or PROTOCOL_2025_11_25
        ids: list[str] = list(http.sessions_seen)
        responses: list[RpcResponse] = []
        while len(ids) < 3:
            resp = await http.rpc(
                "initialize",
                {"protocolVersion": version, "capabilities": {}, "clientInfo": CLIENT_INFO},
                include_session=False,
                note="TRANS-03 collect session id",
            )
            responses.append(resp)
            sid = resp.headers.get("mcp-session-id")
            if not sid:
                break
            ids.append(sid)
        problems: list[str] = []
        if ids:
            shortest = min(len(s) for s in ids)
            if shortest < MIN_SESSION_LENGTH:
                problems.append(f"shortest session id is {shortest} characters")
            if any(not all(0x21 <= ord(ch) <= 0x7E for ch in s) for s in ids):
                problems.append("session id contains characters outside visible ASCII")
            entropy = shannon_entropy("".join(ids))
            if entropy < MIN_SESSION_ENTROPY_BITS:
                problems.append(f"low per-character entropy ({entropy:.2f} bits)")
            if len(ids) >= 2 and all(s.isdigit() for s in ids):
                diffs = [abs(int(b) - int(a)) for a, b in itertools.pairwise(ids)]
                if all(d <= 1000 for d in diffs):
                    problems.append("session ids are sequential integers")
            if len(set(ids)) < len(ids):
                problems.append("the same session id was issued twice")
        if problems:
            findings.append(
                self.finding(
                    title="Session IDs are weak or predictable",
                    description="Observed Mcp-Session-Id values are not cryptographically secure: "
                    + "; ".join(problems)
                    + ".",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=evidence_of(*responses),
                    location=ctx.target,
                    details={
                        "samples": [s[:8] + "…" if len(s) > 8 else s for s in ids],
                        "problems": problems,
                    },
                )
            )
        forged = secrets.token_urlsafe(24)
        resp = await http.rpc(
            "tools/list",
            {},
            include_session=False,
            headers_override={"Mcp-Session-Id": forged},
            note="TRANS-03 forged session id",
        )
        if resp.status is not None and 200 <= resp.status < 300 and resp.result is not None:
            findings.append(
                self.finding(
                    title="Forged session ID accepted",
                    description=(
                        "tools/list with a random, never-issued Mcp-Session-Id was answered with a "
                        "result. The server does not validate session IDs (spec: 404 for unknown sessions)."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=evidence_of(resp),
                    location=ctx.target,
                )
            )
        return findings


class Trans04DeprecatedTransport(Check):
    id = "TRANS-04"
    title = "Deprecated HTTP+SSE (2024-11-05) transport in use"
    severity = Severity.INFO
    applies_to = frozenset({"http"})
    standards = Standards()
    description = (
        "Reports when the endpoint answers a GET with an SSE 'endpoint' event, i.e. the "
        "2024-11-05 HTTP+SSE transport that was deprecated in 2025-03-26 and formally classified "
        "Deprecated in 2026-07-28. Also noted when the negotiated revision predates 2025-06-18."
    )
    evidence_type = "The GET request and the first SSE event."
    false_positive_notes = "Informational only."
    fix = "Migrate to Streamable HTTP (single endpoint, POST per message) and current protocol revision."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        fp = ctx.fingerprint
        if http is None:
            return []
        findings: list[Finding] = []
        if fp.flavour == "legacy-sse":
            ev = [ctx.evidence.records[-1]] if ctx.evidence.records else []
            findings.append(
                self.finding(
                    description="The server only speaks the deprecated HTTP+SSE transport.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    location=ctx.target,
                )
            )
            return findings
        resp = await http.legacy_sse_probe()
        if resp.status == 200 and "text/event-stream" in resp.headers.get("content-type", ""):
            if _first_event_name(resp.body) == "endpoint":
                findings.append(
                    self.finding(
                        description="GET on the MCP endpoint returns a legacy 'endpoint' SSE event; "
                        "the deprecated transport is still served alongside Streamable HTTP.",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        evidence=evidence_of(resp),
                        location=ctx.target,
                    )
                )
        if fp.protocol_version and fp.protocol_version < "2025-06-18":
            findings.append(
                self.finding(
                    title="Pre-2025-06-18 protocol revision negotiated",
                    description=f"The server negotiated protocol revision {fp.protocol_version}, "
                    "which predates the current authorization and transport requirements.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    location=ctx.target,
                )
            )
        return findings


class Trans05TlsAndHeaders(Check):
    id = "TRANS-05"
    title = "Plain HTTP, weak TLS or missing security headers"
    severity = Severity.HIGH
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP01:2025"])
    description = (
        "Flags non-loopback endpoints served over plain HTTP (bearer tokens in clear), TLS "
        "versions below 1.2 observed on the connection, and missing Strict-Transport-Security / "
        "X-Content-Type-Options headers on the MCP endpoint responses."
    )
    evidence_type = "Response headers of the negotiation/tools/list exchange and the observed TLS version."
    false_positive_notes = (
        "Loopback plain-HTTP is reported as informational. Header checks look at the MCP endpoint "
        "only; a CDN may add headers on other paths."
    )
    fix = (
        "Serve the endpoint over HTTPS with TLS 1.2+ only, add Strict-Transport-Security and "
        "X-Content-Type-Options: nosniff."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        if http is None:
            return []
        findings: list[Finding] = []
        host = host_of(ctx.target)
        local = is_local_or_private(host)
        scheme = ctx.target.split(":", 1)[0].lower()
        sample = _sample_evidence(ctx)
        if scheme == "http":
            findings.append(
                self.finding(
                    title="MCP endpoint served over plain HTTP",
                    description=(
                        "The endpoint is reachable over unencrypted HTTP; bearer tokens, session IDs "
                        "and tool data travel in the clear."
                        + (
                            " The host is a loopback/private address, so this is informational."
                            if local
                            else ""
                        )
                    ),
                    severity=Severity.INFO if local else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=[sample] if sample else [],
                    location=ctx.target,
                    details={"scheme": scheme, "local": local},
                )
            )
        if http.tls_version and http.tls_version in {"TLSv1", "TLSv1.1", "SSLv3"}:
            findings.append(
                self.finding(
                    title="Weak TLS version negotiated",
                    description=f"The connection negotiated {http.tls_version}.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    location=ctx.target,
                    details={"tls_version": http.tls_version},
                )
            )
        if sample is not None:
            headers = sample.response_headers
            missing = []
            if scheme == "https" and "strict-transport-security" not in headers:
                missing.append("Strict-Transport-Security")
            if "x-content-type-options" not in headers:
                missing.append("X-Content-Type-Options")
            if missing:
                findings.append(
                    self.finding(
                        title="Security headers missing on MCP endpoint",
                        description="Responses lack: " + ", ".join(missing) + ".",
                        severity=Severity.LOW if scheme == "https" else Severity.INFO,
                        confidence=Confidence.HIGH,
                        evidence=[sample],
                        location=ctx.target,
                        details={"missing": missing},
                    )
                )
        return findings


def _sample_evidence(ctx: ScanContext) -> EvidenceRecord | None:
    if ctx.inventory.tools_evidence is not None:
        return ctx.inventory.tools_evidence
    for rec in ctx.evidence.records:
        if rec.transport == "http" and rec.status is not None and rec.url == ctx.target:
            return rec
    return None
