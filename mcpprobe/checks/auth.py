"""AUTH-01..04: authentication and OAuth 2.1 conformance checks (passive).

Spec references: MCP 2025-11-25 Authorization (RFC 9728 Protected Resource
Metadata, RFC 8414 AS metadata, PKCE S256, RFC 8707 audience binding, no
token passthrough, no tokens in query strings).
"""

from __future__ import annotations

import json
import secrets
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt

from mcpprobe.checks._util import (
    host_of,
    is_local_or_private,
    origin_of,
    parse_www_authenticate,
    try_json,
    well_known_urls,
)
from mcpprobe.checks.base import Check, ScanContext, evidence_of, evidence_summary
from mcpprobe.checks.capability import classify_tools
from mcpprobe.models import Confidence, Finding, Severity, Standards
from mcpprobe.transport import PROTOCOL_2025_11_25, PROTOCOL_2026_07_28, RpcResponse
from mcpprobe.transport.base import CLIENT_INFO


class Auth01NoAuthentication(Check):
    """The endpoint served ``initialize``/``tools/list`` without any credentials."""

    id = "AUTH-01"
    title = "Remote MCP endpoint accepts requests without authentication"
    severity = Severity.HIGH
    applies_to = frozenset({"http"})
    standards = Standards(
        mcp=["MCP07:2025"],
        asi=["ASI03"],
        llm_2025=["LLM03:2025", "LLM06:2025"],
        llm_2026=["LLM04:2026", "LLM03:2026"],
    )
    description = (
        "POSTs initialize (or server/discover) and tools/list with no Authorization header. "
        "If the server answers with a tool list, anyone who can reach the endpoint can drive "
        "its tools. Missing authentication was the single most common issue in public MCP "
        "server studies."
    )
    evidence_type = "The unauthenticated tools/list request and the 200 response."
    false_positive_notes = (
        "Servers protected by a network boundary (VPN, mTLS at a proxy, IP allow-list) will "
        "still be flagged because the scanner only sees what the endpoint returns. Local "
        "development servers bound to loopback are reported at reduced severity but are still "
        "exposed to DNS-rebinding and browser-based attacks (see CVE-2025-49596 class)."
    )
    fix = (
        "Put the endpoint behind OAuth 2.1 as described in the MCP authorization spec: return "
        "401 with WWW-Authenticate pointing at RFC 9728 protected-resource metadata, validate "
        "token audience, and reject requests without a valid bearer token. For local servers, "
        "bind to 127.0.0.1 and still require a token."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        fp = ctx.fingerprint
        if fp.auth_required:
            return []
        if fp.flavour == "unknown" and not ctx.inventory.tools:
            return []
        if not ctx.inventory.tools and ctx.inventory.tools_error:
            return []
        classes = classify_tools(ctx.inventory.tools)
        dangerous = sorted(n for n, c in classes.items() if c.dangerous)
        local = is_local_or_private(host_of(ctx.target))
        if local:
            severity = Severity.HIGH if dangerous else Severity.MEDIUM
        else:
            severity = Severity.CRITICAL if dangerous else Severity.HIGH
        where = "a loopback/private address" if local else "a public address"
        desc = (
            f"The server at {where} answered {fp.flavour or 'MCP'} negotiation and tools/list "
            f"without any credentials, exposing {len(ctx.inventory.tools)} tool(s)."
        )
        if dangerous:
            desc += f" Tools with dangerous capability classes: {', '.join(dangerous)}."
        ev = [e for e in [ctx.inventory.tools_evidence] if e]
        names = ctx.tool_names()
        shown = ", ".join(names[:8]) + (f" (+{len(names) - 8} more)" if len(names) > 8 else "")
        return [
            self.finding(
                description=desc,
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=ev,
                excerpt=evidence_summary(
                    ev, f"no Authorization header sent; {len(names)} tools listed: {shown}"
                ),
                location=ctx.target,
                details={"tools": ctx.tool_names(), "dangerous_tools": dangerous, "local": local},
            )
        ]


class Auth02MissingProtectedResourceMetadata(Check):
    """Auth-protected server without discoverable RFC 9728 metadata."""

    id = "AUTH-02"
    title = "Protected resource metadata (RFC 9728) missing or invalid"
    severity = Severity.HIGH
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025"])
    description = (
        "On a 401 the scanner parses WWW-Authenticate for resource_metadata, then tries "
        "/.well-known/oauth-protected-resource[/path] and the host root. The document must be "
        "JSON with a non-empty authorization_servers list. Without it, conformant clients cannot "
        "start the OAuth flow and users are pushed toward pasting long-lived static tokens."
    )
    evidence_type = "The 401 response headers and each metadata GET with its status/body."
    false_positive_notes = (
        "Servers that use a non-OAuth scheme (API keys at a gateway) will be flagged; the MCP "
        "spec still expects RFC 9728 metadata for HTTP transports."
    )
    fix = (
        "Serve /.well-known/oauth-protected-resource (path-aware variant preferred) with "
        "'resource' and 'authorization_servers', and include "
        'WWW-Authenticate: Bearer resource_metadata="<url>" on every 401.'
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        fp = ctx.fingerprint
        http = ctx.http
        if not fp.auth_required or http is None:
            return []
        findings: list[Finding] = []
        params = parse_www_authenticate(fp.www_authenticate)
        hint = params.get("resource_metadata")
        responses: list[RpcResponse] = []
        prm: dict[str, Any] | None = None
        prm_url: str | None = None
        candidates: list[str] = []
        if hint:
            candidates.append(hint)
        candidates += [
            u for u in well_known_urls(ctx.target, "oauth-protected-resource") if u not in candidates
        ]
        # Only follow hints on the target's own origin (the spec requires that anyway).
        target_origin = origin_of(ctx.target)
        for url in candidates:
            if origin_of(url) != target_origin:
                ctx.notes.append(f"AUTH-02: ignored resource_metadata hint on another origin: {url}")
                continue
            resp = await http.get(url, note="AUTH-02 protected resource metadata")
            responses.append(resp)
            if resp.status == 200:
                doc = try_json(resp.body)
                if isinstance(doc, dict):
                    prm, prm_url = doc, url
                    break
        if prm is None:
            findings.append(
                self.finding(
                    description=(
                        "The server requires authentication (401) but no RFC 9728 protected "
                        "resource metadata document could be found via WWW-Authenticate or the "
                        "well-known locations."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=evidence_of(*responses),
                    location=ctx.target,
                    details={"www_authenticate": fp.www_authenticate, "tried": candidates},
                )
            )
            return findings
        ctx.shared["prm"] = prm
        ctx.shared["prm_url"] = prm_url
        servers = prm.get("authorization_servers")
        problems: list[str] = []
        if not isinstance(servers, list) or not servers:
            problems.append("authorization_servers missing or empty")
        elif not all(isinstance(s, str) and s.startswith(("https://", "http://")) for s in servers):
            problems.append("authorization_servers contains non-URL entries")
        if "resource" not in prm:
            problems.append("'resource' field missing")
        if problems:
            findings.append(
                self.finding(
                    description=f"Protected resource metadata at {prm_url} is invalid: "
                    + "; ".join(problems)
                    + ".",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=evidence_of(*responses),
                    location=prm_url,
                    details={"problems": problems},
                )
            )
        if not hint:
            findings.append(
                self.finding(
                    title="401 response lacks resource_metadata hint in WWW-Authenticate",
                    description=(
                        "The 401 response did not carry a WWW-Authenticate header with "
                        "resource_metadata. Metadata was found at the well-known location, but "
                        "clients that rely on the header hint will fail to discover it."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence=evidence_of(*responses),
                    location=ctx.target,
                    details={"www_authenticate": fp.www_authenticate},
                )
            )
        return findings


class Auth03AuthorizationServerMetadata(Check):
    """Authorization server metadata: PKCE S256 and HTTPS endpoints."""

    id = "AUTH-03"
    title = "Authorization server metadata weak or missing (PKCE S256 / HTTPS)"
    severity = Severity.HIGH
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025", "MCP01:2025"])
    description = (
        "For each authorization server listed in the protected resource metadata, fetches "
        "/.well-known/oauth-authorization-server (RFC 8414, path-aware) then "
        "/.well-known/openid-configuration. Flags a missing document, a "
        "code_challenge_methods_supported list without S256 (MCP clients MUST refuse to proceed), "
        "and non-HTTPS endpoints. This may make one GET to a third-party host; disable with "
        "--no-follow-as."
    )
    evidence_type = "Each metadata GET with status and body."
    false_positive_notes = (
        "Some authorization servers support PKCE but omit code_challenge_methods_supported; "
        "per the MCP spec that is still a conformance failure for clients."
    )
    fix = (
        "Publish RFC 8414 metadata with code_challenge_methods_supported including S256 and "
        "HTTPS-only endpoints. If you use a third-party identity provider, confirm it exposes "
        "the metadata document at the issuer URL you advertise."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        prm = ctx.shared.get("prm")
        if http is None or not isinstance(prm, dict):
            return []
        servers = [s for s in prm.get("authorization_servers") or [] if isinstance(s, str)]
        findings: list[Finding] = []
        target_host = host_of(ctx.target)
        for issuer in servers[:3]:
            if host_of(issuer) != target_host and not ctx.options.follow_authorization_server:
                ctx.notes.append(f"AUTH-03: not fetching third-party AS metadata ({issuer}) (--no-follow-as)")
                continue
            responses: list[RpcResponse] = []
            doc: dict[str, Any] | None = None
            for url in _as_metadata_urls(issuer):
                resp = await http.get(url, note="AUTH-03 authorization server metadata")
                responses.append(resp)
                if resp.status == 200:
                    candidate = try_json(resp.body)
                    if isinstance(candidate, dict):
                        doc = candidate
                        break
            if doc is None:
                findings.append(
                    self.finding(
                        title="Authorization server metadata not found",
                        description=f"No RFC 8414 / OpenID metadata document found for {issuer}.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence=evidence_of(*responses),
                        location=issuer,
                    )
                )
                continue
            methods = doc.get("code_challenge_methods_supported")
            if not isinstance(methods, list) or "S256" not in methods:
                findings.append(
                    self.finding(
                        title="PKCE S256 not advertised by authorization server",
                        description=(
                            f"{issuer} does not list S256 in code_challenge_methods_supported "
                            f"(got {methods!r}). MCP clients MUST refuse to proceed without it."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence=evidence_of(*responses),
                        location=issuer,
                        details={"code_challenge_methods_supported": methods},
                    )
                )
            insecure = [
                f"{k}={v}"
                for k, v in doc.items()
                if k.endswith("_endpoint")
                and isinstance(v, str)
                and v.startswith("http://")
                and not is_local_or_private(host_of(v))
            ]
            if insecure:
                findings.append(
                    self.finding(
                        title="Authorization server advertises plain-HTTP endpoints",
                        description=f"{issuer} metadata contains non-HTTPS endpoints: " + ", ".join(insecure),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence=evidence_of(*responses),
                        location=issuer,
                        details={"insecure_endpoints": insecure},
                    )
                )
            if isinstance(doc.get("issuer"), str) and doc["issuer"].rstrip("/") != issuer.rstrip("/"):
                findings.append(
                    self.finding(
                        title="Authorization server issuer mismatch",
                        description=f"Metadata issuer {doc['issuer']!r} differs from advertised {issuer!r}.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        evidence=evidence_of(*responses),
                        location=issuer,
                    )
                )
        return findings


def _as_metadata_urls(issuer: str) -> list[str]:
    parts = urlsplit(issuer)
    root = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    path = parts.path.rstrip("/")
    urls = []
    if path:
        urls.append(f"{root}/.well-known/oauth-authorization-server{path}")
        urls.append(f"{root}{path}/.well-known/openid-configuration")
    urls.append(f"{root}/.well-known/oauth-authorization-server")
    urls.append(f"{root}/.well-known/openid-configuration")
    return urls


class Auth04TokenAudienceAndPassthrough(Check):
    """Self-minted wrong-audience tokens must be rejected; tokens in query strings too."""

    id = "AUTH-04"
    title = "Server accepts a self-minted token with the wrong audience/issuer"
    severity = Severity.CRITICAL
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025", "MCP01:2025"], asi=["ASI03"])
    description = (
        "Mints two syntactically valid JWTs the server cannot have issued (HS256 with a random "
        "scanner key, and alg=none) with a foreign issuer and audience, and presents them as "
        "Bearer tokens. Any non-401/403 answer means the server is not validating signature or "
        "audience (RFC 8707). Also presents the token in the access_token query parameter, "
        "which the spec forbids. Only self-minted tokens are used; no real credentials."
    )
    evidence_type = "Each probe request (token redacted) and the response status/body."
    false_positive_notes = (
        "A proxy that strips Authorization and answers 200 for health reasons could be flagged; "
        "check the response body in the evidence actually contains an MCP result."
    )
    fix = (
        "Validate the token signature against the authorization server's keys, require 'aud' to "
        "equal this server's canonical URI (RFC 8707), reject alg=none, and never read tokens "
        "from query strings."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        http = ctx.http
        fp = ctx.fingerprint
        if http is None or not fp.auth_required:
            return []
        findings: list[Finding] = []
        method, params, version = _probe_request(ctx)
        now_claims = {
            "iss": "https://mcpprobe.invalid/scanner",
            "aud": "https://not-the-target.invalid",
            "sub": "mcpprobe-probe",
            "scope": "mcp:tools",
            "jti": secrets.token_hex(8),
        }
        hs256 = jwt.encode(now_claims, secrets.token_hex(32), algorithm="HS256")
        alg_none = jwt.encode(now_claims, "", algorithm="none")
        header_accepted: list[RpcResponse] = []
        for label, token in (("HS256/random-key", hs256), ("alg=none", alg_none)):
            resp = await http.rpc(
                method,
                params,
                protocol_version=version,
                include_session=False,
                headers_override={"Authorization": f"Bearer {token}"},
                note=f"AUTH-04 self-minted token ({label})",
            )
            if _accepted(resp):
                header_accepted.append(resp)
                findings.append(
                    self.finding(
                        description=(
                            f"A self-minted JWT ({label}) with iss/aud pointing at scanner-controlled "
                            f"values was accepted: HTTP {resp.status} with "
                            f"{'an MCP result' if resp.result is not None else 'a non-401 body'}."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH if resp.result is not None else Confidence.MEDIUM,
                        evidence=evidence_of(resp),
                        location=ctx.target,
                        details={"probe": label, "claims": now_claims},
                    )
                )
        # Token in query string (spec: MUST NOT be accepted).
        qs_url = _with_query(ctx.target, "access_token", hs256)
        resp = await http.raw_request(
            "POST",
            body=_body_for(http, method, params, version),
            headers=http.default_headers(method, protocol_version=version, include_session=False),
            url=qs_url,
            label=method,
            note="AUTH-04 token in query string",
        )
        if _accepted(resp) and not header_accepted:
            findings.append(
                self.finding(
                    title="Bearer token accepted via URI query string",
                    description=(
                        "The server answered a request carrying the token only in the access_token "
                        "query parameter. The MCP spec forbids tokens in URI query strings because "
                        "they leak into logs and referrers."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence=evidence_of(resp),
                    location=ctx.target,
                )
            )
        return findings


def _probe_request(ctx: ScanContext) -> tuple[str, dict[str, Any], str]:
    if ctx.fingerprint.flavour == "stateless-2026":
        return "server/discover", {}, PROTOCOL_2026_07_28
    return (
        "initialize",
        {"protocolVersion": PROTOCOL_2025_11_25, "capabilities": {}, "clientInfo": CLIENT_INFO},
        PROTOCOL_2025_11_25,
    )


def _body_for(http: Any, method: str, params: dict[str, Any], version: str) -> str:
    return json.dumps(http.build_message(method, params, protocol_version=version))


def _accepted(resp: RpcResponse) -> bool:
    """A 2xx answer means the credential was accepted (401/403 is the expected rejection)."""
    return resp.status is not None and 200 <= resp.status < 300 and resp.error_text is None


def _with_query(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    query = f"{parts.query}&{key}={value}" if parts.query else f"{key}={value}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
