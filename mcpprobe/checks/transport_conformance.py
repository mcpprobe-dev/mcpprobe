"""TRANS-01..05: streamable-HTTP transport conformance and hygiene (passive)."""

from __future__ import annotations

import itertools
import secrets
from typing import Any

from mcpprobe.checks import proof
from mcpprobe.checks._util import shannon_entropy
from mcpprobe.checks.base import Check, NotApplicable, ScanContext, evidence_of, evidence_summary
from mcpprobe.environment import EDGE_LABELS
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
        "Sends a normal negotiation request with 'Origin: https://evil.example' and one with "
        "'Origin: null'. The transport spec says servers MUST validate Origin and return 403 on "
        "an invalid one; otherwise a web page can drive the server through the victim's browser "
        "(DNS rebinding). Requests without an Origin header are not tested: non-browser clients "
        "do not send one."
    )
    evidence_type = "Each POST with a foreign Origin header and the non-403 response."
    false_positive_notes = (
        "If the server answers 401 (or 429) before looking at Origin the check is not applicable "
        "and says so. Reverse proxies that strip Origin will cause a finding against the proxied "
        "endpoint even if the application validates it."
    )
    fix = (
        "Reject any request whose Origin header is present and not on an allow-list with HTTP 403, "
        "before processing the body, including 'Origin: null'. Allow requests with no Origin header."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        if http is None or ctx.fingerprint.flavour == "legacy-sse":
            raise NotApplicable(
                "the endpoint speaks the legacy HTTP+SSE transport; the Origin probe targets Streamable HTTP."
            )
        method, params, version = _negotiation_request(ctx)
        accepted: list[tuple[str, RpcResponse]] = []
        blocked: list[str] = []
        for origin in (EVIL_ORIGIN, "null"):
            resp = await http.rpc(
                method,
                params,
                protocol_version=version,
                include_session=False,
                headers_override={"Origin": origin},
                note=f"TRANS-01 Origin: {origin}",
            )
            if resp.status == 403:
                continue
            if resp.status in (401, 429):
                blocked.append(f"Origin {origin} -> HTTP {resp.status}")
                continue
            if resp.status is None:
                raise RuntimeError(f"Origin probe failed at the transport level: {resp.error_text}")
            accepted.append((origin, resp))
        if not accepted:
            if blocked:
                ctx.notes.append("TRANS-01: " + "; ".join(blocked))
                if len(blocked) == 2:
                    raise NotApplicable(
                        "The server answered "
                        + " and ".join(b.split(" -> ")[1] for b in blocked)
                        + " before Origin validation could be observed; re-run with credentials.",
                        blocked=True,
                    )
            return []
        local = not ctx.is_public
        first = accepted[0][1]
        reflected = first.headers.get("access-control-allow-origin")
        details: dict[str, Any] = {
            "accepted": {o: r.status for o, r in accepted},
            "origin": accepted[0][0],
            "status": first.status,
        }
        if reflected:
            details["access_control_allow_origin"] = reflected
        shown = " and ".join(f"Origin: {o} (HTTP {r.status})" for o, r in accepted)
        fix = self.fix + " Non-browser MCP clients do not send Origin, so an allow-list does not break them."
        if local:
            fix += " For a local server, also bind to 127.0.0.1 rather than 0.0.0.0."
        return [
            self.finding(
                description=(
                    f"Requests with {shown} were answered instead of rejected with 403. The server "
                    "does not validate Origin as the transport spec requires."
                    + (
                        " The server runs on a loopback/private address, where DNS rebinding from a "
                        "browser is the realistic attack path."
                        if local
                        else ""
                    )
                ),
                severity=Severity.HIGH if local else Severity.MEDIUM,
                confidence=Confidence.HIGH if first.result is not None else Confidence.MEDIUM,
                confidence_reason=None
                if first.result is not None
                else "The response was not 403 but carried no JSON-RPC result, so the request may still have been refused later.",
                evidence=evidence_of(*(r for _, r in accepted)),
                excerpt=evidence_summary(
                    evidence_of(first),
                    f"sent Origin: {accepted[0][0]}; expected 403"
                    + ("; got a JSON-RPC result" if first.result is not None else ""),
                ),
                location=ctx.target,
                details=details,
                fix=fix,
                affected=[f"Origin: {o}" for o, _ in accepted],
                proof="\n\n".join(
                    proof.exchange(
                        r.evidence,
                        request_headers=["origin", "content-type"],
                        response_headers=["content-type", "access-control-allow-origin"],
                        result_lines=[
                            "result: "
                            + ("JSON-RPC result returned" if r.result is not None else "no JSON-RPC result")
                        ],
                    )
                    for _, r in accepted
                ),
                verify=proof.curl_rpc(
                    ctx.target,
                    method,
                    params,
                    protocol_version=version,
                    headers={"Origin": EVIL_ORIGIN},
                    auth_placeholder=ctx.fingerprint.credentials_supplied,
                    expect="HTTP 403 (repeat with -H 'Origin: null', also 403)",
                ),
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
        "noted at low severity only. A 401/429 before the header is read makes the check not applicable."
    )
    fix = (
        "Validate the MCP-Protocol-Version header against the versions you support and reply 400 "
        "when it is unknown. Separately, when initialize asks for a protocolVersion you do not "
        "support, answer with the latest version you do support and let the client decide; never "
        "echo back whatever the client asked for."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        fp = ctx.fingerprint
        if http is None or fp.flavour == "legacy-sse" or (fp.flavour == "unknown" and not fp.auth_required):
            raise NotApplicable(
                "no Streamable HTTP protocol revision was negotiated, so there is no version header to test."
            )
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
        if resp.status is None:
            raise RuntimeError(f"version probe failed at the transport level: {resp.error_text}")
        if resp.status in (401, 403, 429):
            raise NotApplicable(
                f"The server answered HTTP {resp.status} before the version header could be "
                "evaluated; re-run with credentials.",
                blocked=True,
            )
        echoed = None
        if isinstance(resp.result, dict) and resp.result.get("protocolVersion") == BOGUS_VERSION:
            echoed = BOGUS_VERSION
        return [
            self.finding(
                description=(
                    f"'MCP-Protocol-Version: {BOGUS_VERSION}' was answered with HTTP {resp.status} "
                    "and a normal result instead of 400."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH if resp.result is not None else Confidence.MEDIUM,
                confidence_reason=None
                if resp.result is not None
                else "The response was not 400 but carried no JSON-RPC result.",
                evidence=evidence_of(resp),
                excerpt=evidence_summary(
                    evidence_of(resp), f"sent MCP-Protocol-Version: {BOGUS_VERSION}; expected 400"
                ),
                location=ctx.target,
                details={"status": resp.status},
                affected=["MCP-Protocol-Version"],
                proof=proof.exchange(
                    resp.evidence,
                    request_headers=["mcp-protocol-version", "content-type"],
                    response_headers=["content-type"],
                    result_lines=[
                        "result: "
                        + ("JSON-RPC result returned" if resp.result is not None else "no JSON-RPC result")
                    ]
                    + ([f"result.protocolVersion: {echoed} (unknown version echoed back)"] if echoed else []),
                ),
                verify=proof.curl_rpc(
                    ctx.target,
                    method,
                    params,
                    protocol_version=BOGUS_VERSION,
                    auth_placeholder=ctx.fingerprint.credentials_supplied,
                    expect="HTTP 400",
                ),
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
        if http is None:
            raise NotApplicable("not an HTTP target.")
        if fp.flavour == "stateless-2026":
            raise NotApplicable(
                "The 2026-07-28 revision has no sessions, so there is no Mcp-Session-Id to assess."
            )
        if fp.flavour != "handshake" or not fp.session_id_seen:
            raise NotApplicable(
                "The server issued no Mcp-Session-Id during initialize (stateless transport), so "
                "there is no session identifier to assess."
            )
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
                    excerpt=evidence_summary(
                        evidence_of(*responses),
                        "Mcp-Session-Id values observed: " + ", ".join(s[:12] for s in ids),
                    ),
                    location=ctx.target,
                    details={
                        "samples": [s[:8] + "…" if len(s) > 8 else s for s in ids],
                        "problems": problems,
                    },
                    affected=["Mcp-Session-Id"],
                    proof="Mcp-Session-Id values issued by successive initialize requests:\n"
                    + "\n".join(f"  {s}" for s in ids)
                    + "\nProblems:\n"
                    + "\n".join(f"  - {p}" for p in problems),
                    verify=proof.rescan(ctx.target, self.id),
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
                    excerpt=evidence_summary(
                        evidence_of(resp), "tools/list with a never-issued Mcp-Session-Id returned a result"
                    ),
                    location=ctx.target,
                    affected=["Mcp-Session-Id"],
                    proof=proof.exchange(
                        resp.evidence,
                        request_headers=["mcp-session-id"],
                        response_headers=["content-type"],
                        result_lines=[
                            "result: JSON-RPC result returned for a session the server never issued"
                        ],
                    ),
                    verify=proof.curl_rpc(
                        ctx.target,
                        "tools/list",
                        {},
                        protocol_version=version,
                        headers={"Mcp-Session-Id": "forged-session-id"},
                        auth_placeholder=fp.credentials_supplied,
                        expect="HTTP 404",
                    ),
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
            raise NotApplicable("not an HTTP target.")
        findings: list[Finding] = []
        sse_verify = f"curl -s -N -m 3 -H 'Accept: text/event-stream' {ctx.target} | head -3  # expect no 'event: endpoint'"
        if fp.flavour == "legacy-sse":
            ev = [ctx.evidence.records[-1]] if ctx.evidence.records else []
            findings.append(
                self.finding(
                    description="The server only speaks the deprecated HTTP+SSE transport.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    location=ctx.target,
                    proof=proof.exchange(ev[0] if ev else None, response_headers=["content-type"]),
                    verify=sse_verify,
                )
            )
            return findings
        resp = await http.legacy_sse_probe()
        if resp.status is None:
            raise RuntimeError(f"legacy SSE probe failed at the transport level: {resp.error_text}")
        if resp.status in (401, 403, 429) and fp.protocol_version is None:
            raise NotApplicable(
                f"The GET probe for the legacy transport was answered with HTTP {resp.status}, so it "
                "could not be determined whether the deprecated HTTP+SSE transport is served.",
                blocked=True,
            )
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
                        proof=proof.exchange(
                            resp.evidence,
                            response_headers=["content-type"],
                            result_lines=["first SSE event: endpoint"],
                        ),
                        verify=sse_verify,
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
                    proof=f"initialize result.protocolVersion: {fp.protocol_version}",
                    verify=proof.curl_rpc(
                        ctx.target,
                        "initialize",
                        proof.initialize_params(),
                        include_headers=False,
                        jq=".result.protocolVersion",
                        expect="2025-06-18 or later",
                    ),
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
        "X-Content-Type-Options: nosniff. Where an edge (API Gateway, CloudFront, Cloudflare, "
        "Vercel) is detected the fix text says where to configure it."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        if http is None:
            raise NotApplicable("not an HTTP target.")
        findings: list[Finding] = []
        local = not ctx.is_public
        scheme = ctx.target.split(":", 1)[0].lower()
        sample = _sample_evidence(ctx)
        edge = ctx.environment.edge
        edge_label = EDGE_LABELS.get(edge or "", "")
        verify_headers = (
            f"curl -s -D - -o /dev/null -X POST {ctx.target} -H 'content-type: application/json' "
            '-d \'{"jsonrpc":"2.0","id":1,"method":"ping"}\' '
            "| grep -iE 'strict-transport-security|x-content-type-options'  # expect both headers"
        )
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
                    excerpt=f"target URL scheme is http: {ctx.target}",
                    location=ctx.target,
                    details={"scheme": scheme, "local": local},
                    fix="Serve the endpoint over HTTPS only (TLS 1.2 or later) and redirect or refuse plain HTTP.",
                    affected=[ctx.target],
                    proof=f"target URL: {ctx.target} (scheme http)",
                    verify=f"curl -sI {ctx.target.replace('http://', 'https://', 1)}  # expect a TLS response; plain http should be refused or redirected",
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
                    fix=_tls_fix(edge, edge_label),
                    affected=[http.tls_version],
                    proof=f"negotiated TLS version: {http.tls_version}",
                    verify=f"curl -sI --tls-max 1.1 {ctx.target}  # expect a TLS handshake failure",
                )
            )
        if sample is None:
            if findings:
                return findings
            raise NotApplicable(
                "no response from the MCP endpoint was captured, so its headers could not be inspected."
            )
        headers = sample.response_headers
        required = (["Strict-Transport-Security"] if scheme == "https" else []) + ["X-Content-Type-Options"]
        missing = [h for h in required if h.lower() not in headers]
        if missing:
            proof_text = proof.header_set(sample, required)
            proof_text += f"\nTLS version: {http.tls_version or 'not observed'}"
            if edge_label:
                proof_text += f"\nEdge: {edge_label} (identified by {', '.join(ctx.environment.signals)})"
            findings.append(
                self.finding(
                    title="Security headers missing on MCP endpoint",
                    description="Responses lack: " + ", ".join(missing) + ".",
                    severity=Severity.LOW if scheme == "https" else Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence=[sample],
                    excerpt=evidence_summary(
                        [sample],
                        "response headers: "
                        + (", ".join(f"{k}: {v}" for k, v in sorted(headers.items())) or "(none)")
                        + "; missing "
                        + ", ".join(missing),
                    ),
                    location=ctx.target,
                    details={"missing": missing, "headers_seen": sorted(headers)},
                    fix=_headers_fix(missing, edge, edge_label),
                    affected=missing,
                    proof=proof_text,
                    verify=verify_headers,
                )
            )
        return findings


def _tls_fix(edge: str | None, label: str) -> str:
    if edge == "aws-api-gateway":
        return (
            f"The endpoint sits behind {label}: TLS is terminated there, not in application code. "
            "Set the custom domain's security policy to TLS 1.2 or later."
        )
    if edge == "cloudflare":
        return "Set Minimum TLS Version to 1.2 under SSL/TLS > Edge Certificates in Cloudflare."
    if edge == "aws-cloudfront":
        return "Use a CloudFront viewer security policy of TLSv1.2_2021 or later."
    return "Allow only TLS 1.2 and 1.3 on the server or load balancer that terminates TLS."


def _headers_fix(missing: list[str], edge: str | None, label: str) -> str:
    want = []
    if "Strict-Transport-Security" in missing:
        want.append("Strict-Transport-Security: max-age=63072000; includeSubDomains")
    if "X-Content-Type-Options" in missing:
        want.append("X-Content-Type-Options: nosniff")
    base = "Add " + " and ".join(want) + " to every response, including errors (401/403/404)."
    if edge == "aws-api-gateway":
        return (
            base + f" The apigw-requestid header shows {label} in front: TLS is already terminated there "
            "(keep the custom domain's security policy at TLS 1.2 or later), so set these headers in "
            "the application's responses, or put CloudFront in front with a response headers policy "
            "that adds them."
        )
    if edge == "aws-cloudfront":
        return (
            base
            + " Attach a CloudFront response headers policy (for example the managed SecurityHeadersPolicy)."
        )
    if edge == "cloudflare":
        return (
            base
            + " In Cloudflare, enable HSTS under SSL/TLS > Edge Certificates and add nosniff with a response header Transform Rule."
        )
    if edge == "vercel":
        return base + " On Vercel, add them with the 'headers' setting in vercel.json."
    return base


def _sample_evidence(ctx: ScanContext) -> EvidenceRecord | None:
    if ctx.inventory.tools_evidence is not None:
        return ctx.inventory.tools_evidence
    for rec in ctx.evidence.records:
        if rec.transport == "http" and rec.status is not None and rec.url == ctx.target:
            return rec
    return None
