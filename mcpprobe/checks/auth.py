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

from mcpprobe.checks import proof
from mcpprobe.checks._util import (
    host_of,
    is_local_or_private,
    origin_of,
    parse_www_authenticate,
    try_json,
    well_known_urls,
)
from mcpprobe.checks.base import Check, NotApplicable, ScanContext, evidence_of, evidence_summary
from mcpprobe.checks.capability import classify_tools
from mcpprobe.models import Confidence, Finding, Severity, Standards
from mcpprobe.policy import OptOutError, check_dns_opt_out
from mcpprobe.transport import PROTOCOL_2025_11_25, PROTOCOL_2026_07_28, RpcResponse
from mcpprobe.transport.base import CLIENT_INFO


def protected_resource_metadata_url(target: str) -> str:
    """The path-aware RFC 9728 URL a server should advertise for ``target``."""
    return well_known_urls(target, "oauth-protected-resource")[0]


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
        "its tools. When the operator supplies credentials with --header, one extra request is "
        "sent with those credentials removed, so a protected server is not misreported. "
        "Passes only when the endpoint answers 401/403 without credentials."
    )
    evidence_type = "The unauthenticated request (Authorization shown as not sent) and the response."
    false_positive_notes = (
        "Servers protected by a network boundary (VPN, mTLS at a proxy, IP allow-list) will "
        "still be flagged because the scanner only sees what the endpoint returns. Local "
        "development servers bound to loopback are reported at reduced severity but are still "
        "exposed to DNS-rebinding and browser-based attacks (see CVE-2025-49596 class)."
    )
    fix = (
        "Put the endpoint behind OAuth 2.1 as described in the MCP authorization spec: return "
        '401 with WWW-Authenticate: Bearer resource_metadata="<RFC 9728 metadata URL>", '
        "validate each token's signature, issuer, expiry and audience, and reject requests "
        "without a valid bearer token. Authentication does not make a dangerous tool safe."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        fp = ctx.fingerprint
        if fp.auth_required:
            return []  # tested: the endpoint answered 401/403 without credentials
        inv = ctx.inventory
        if not inv.tools and inv.tools_error:
            rec = inv.tools_evidence
            if rec is not None and rec.status in (401, 403):
                return []  # tested: tools/list itself is protected
            raise NotApplicable(
                "negotiation succeeded without credentials but tools/list failed "
                f"({inv.tools_error}), so it could not be determined whether tools are reachable "
                "without credentials."
            )
        classes = classify_tools(inv.tools)
        dangerous = sorted(n for n, c in classes.items() if c.dangerous)
        arbitrary = sorted(n for n, c in classes.items() if c.arbitrary)
        local = not ctx.is_public
        if local:
            severity = Severity.HIGH if dangerous else Severity.MEDIUM
        else:
            severity = Severity.CRITICAL if dangerous else Severity.HIGH
        where = "a loopback/private address" if local else "a public address"
        probe = ctx.shared.get("unauth_probe")
        names = ctx.tool_names()
        if fp.credentials_supplied and probe is not None:
            desc = (
                f"With the operator-supplied credentials removed, the server at {where} still "
                f"answered {probe.method} with HTTP {probe.status}. The same endpoint lists "
                f"{len(names)} tool(s), so the credentials are not required."
            )
            ev = evidence_of(probe)
            result_lines = [
                f"result: {'JSON-RPC result returned' if probe.result is not None else 'non-401 body'}"
            ]
        else:
            desc = (
                f"The server at {where} answered {fp.flavour or 'MCP'} negotiation and tools/list "
                f"without any credentials, exposing {len(names)} tool(s)."
            )
            ev = [e for e in [inv.tools_evidence] if e]
            result_lines = [f"result.tools ({len(names)}): {', '.join(names) or '(none)'}"]
        if dangerous:
            desc += f" Tools with dangerous capability classes: {', '.join(dangerous)}."
        shown = ", ".join(names[:8]) + (f" (+{len(names) - 8} more)" if len(names) > 8 else "")
        prm = protected_resource_metadata_url(ctx.target)
        fix = (
            "Require an OAuth 2.1 bearer token on every request, as the MCP authorization spec "
            "describes. Answer requests without a valid token with HTTP 401 and exactly this header:\n"
            f'  WWW-Authenticate: Bearer resource_metadata="{prm}"\n'
            "serve RFC 9728 metadata at that URL (AUTH-02), and validate each token's signature, "
            "issuer, expiry and audience (RFC 8707: aud must be this server) before handling the request."
        )
        if ctx.environment.edge:
            fix += (
                " If a gateway authorizer rejects requests before your code runs, make sure its 401 "
                "still carries that WWW-Authenticate header, or MCP clients cannot start the OAuth flow."
            )
        if arbitrary or dangerous:
            risky = arbitrary or dangerous
            them = "them" if len(risky) > 1 else "it"
            fix += (
                f" Authentication does not make {', '.join(risky)} safe: any authenticated client, "
                f"or a prompt-injected model acting for one, can still call {them}. Remove or "
                f"sandbox {them} first (META-03)."
            )
        if local:
            fix += " For a local development server, also bind to 127.0.0.1 rather than 0.0.0.0."
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
                details={"tools": names, "dangerous_tools": dangerous, "local": local},
                fix=fix,
                affected=names,
                proof=proof.exchange(
                    ev[0] if ev else None,
                    absent_request=["Authorization"],
                    result_lines=[
                        *result_lines,
                        "www-authenticate: (absent; a protected server answers 401 with it)",
                    ],
                ),
                verify=proof.curl_rpc(
                    ctx.target,
                    "initialize",
                    proof.initialize_params(),
                    expect=f'HTTP 401 with WWW-Authenticate: Bearer resource_metadata="{prm}"',
                ),
            )
        ]


class Auth02MissingProtectedResourceMetadata(Check):
    """RFC 9728 metadata must be discoverable; missing metadata is this check's finding condition."""

    id = "AUTH-02"
    title = "Protected resource metadata (RFC 9728) missing or invalid"
    severity = Severity.HIGH
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025"])
    description = (
        "Parses WWW-Authenticate for resource_metadata (when the server answers 401), then tries "
        "/.well-known/oauth-protected-resource[/path] and the host root. The document must be "
        "JSON with a non-empty authorization_servers list. Without it, conformant clients cannot "
        "start the OAuth flow and users are pushed toward pasting long-lived static tokens. A "
        "server that requires no authentication and serves no metadata is reported too (medium, "
        "the discovery half of AUTH-01)."
    )
    evidence_type = "The 401 response headers and each metadata GET with its status."
    false_positive_notes = (
        "Servers that use a non-OAuth scheme (API keys at a gateway) will be flagged; the MCP "
        "spec still expects RFC 9728 metadata for HTTP transports. A deliberately public, "
        "read-only server with no authentication will also be flagged; AUTH-01 is the root cause."
    )
    fix = (
        "Serve /.well-known/oauth-protected-resource (path-aware variant preferred) with "
        "'resource' and 'authorization_servers', and include "
        'WWW-Authenticate: Bearer resource_metadata="<url>" on every 401.'
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        fp = ctx.fingerprint
        http = ctx.http
        if http is None:
            raise NotApplicable("not an HTTP target.")
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
        if not responses:
            raise NotApplicable("no same-origin metadata URL could be requested.")
        if all(r.status is None for r in responses):
            raise RuntimeError(
                "every metadata request failed at the transport level: "
                + "; ".join(r.error_text or "no response" for r in responses)
            )
        gets = [
            f"GET {r.evidence.url if r.evidence else '?'} -> "
            + (
                f"HTTP {r.status} {r.headers.get('content-type', '').split(';')[0]}".rstrip()
                if r.status
                else str(r.error_text)
            )
            for r in responses
        ]
        suggested = protected_resource_metadata_url(ctx.target)
        verify = f'curl -si {suggested}  # expect HTTP 200, JSON with "resource" and a non-empty "authorization_servers"'
        if prm is None:
            statuses = ", ".join(f"HTTP {r.status}" if r.status else "no response" for r in responses)
            www = (
                ["", f"WWW-Authenticate on the 401: {fp.www_authenticate or '(absent)'}"]
                if fp.auth_required
                else []
            )
            proof_text = "\n".join(["Metadata requests:", *(f"  {g}" for g in gets), *www])
            if fp.auth_required:
                findings.append(
                    self.finding(
                        description=(
                            "The server requires authentication (401) but no RFC 9728 protected "
                            "resource metadata document could be found via WWW-Authenticate or the "
                            f"well-known locations ({statuses})."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence=evidence_of(*responses),
                        location=ctx.target,
                        details={"www_authenticate": fp.www_authenticate, "tried": candidates},
                        affected=[c for c in candidates if origin_of(c) == target_origin],
                        proof=proof_text,
                        verify=verify,
                    )
                )
            else:
                local = not ctx.is_public
                findings.append(
                    self.finding(
                        description=(
                            "No RFC 9728 protected resource metadata is served at either well-known "
                            f"location ({statuses}), and the server requires no authentication. "
                            "A client therefore has no way to discover how to authenticate; this is "
                            "the discovery half of AUTH-01 and is fixed together with it."
                        ),
                        severity=Severity.LOW if local else Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence=evidence_of(*responses),
                        location=ctx.target,
                        details={"tried": candidates, "auth_required": False},
                        fix=(
                            "When you add authentication (AUTH-01), serve RFC 9728 metadata at "
                            f"{suggested} with 'resource' set to {ctx.target} and "
                            "'authorization_servers' listing your OAuth issuer, and point to it from "
                            f'every 401: WWW-Authenticate: Bearer resource_metadata="{suggested}".'
                        ),
                        affected=[c for c in candidates if origin_of(c) == target_origin],
                        proof=proof_text,
                        verify=verify,
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
        doc_proof = f"GET {prm_url} -> HTTP 200\n" + proof.indent(proof.pretty(prm))
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
                    affected=[str(prm_url)],
                    proof=doc_proof + "\nProblems:\n" + "\n".join(f"  - {p}" for p in problems),
                    verify=verify,
                )
            )
        if fp.auth_required and not hint:
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
                    confidence_reason=(
                        "Spec-conformant clients fall back to the well-known location, so the "
                        "practical impact depends on the client."
                    ),
                    evidence=evidence_of(*responses),
                    location=ctx.target,
                    details={"www_authenticate": fp.www_authenticate},
                    fix=f'Send WWW-Authenticate: Bearer resource_metadata="{prm_url}" on every 401.',
                    affected=["WWW-Authenticate"],
                    proof=f"WWW-Authenticate on the 401: {fp.www_authenticate or '(absent)'}\n" + doc_proof,
                    verify=proof.curl_rpc(
                        ctx.target,
                        "initialize",
                        proof.initialize_params(),
                        expect=f'HTTP 401 with WWW-Authenticate: Bearer resource_metadata="{prm_url}"',
                    ),
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
        if http is None:
            raise NotApplicable("not an HTTP target.")
        if not isinstance(prm, dict):
            if not ctx.fingerprint.auth_required:
                raise NotApplicable(
                    "The server accepts requests without authentication (AUTH-01) and advertises no "
                    "authorization server, so there is no authorization server metadata to assess.",
                    related_to="AUTH-01",
                )
            raise NotApplicable(
                "No authorization server could be discovered because the protected resource "
                "metadata is missing (AUTH-02).",
                related_to="AUTH-02",
            )
        servers = [s for s in prm.get("authorization_servers") or [] if isinstance(s, str)]
        if not servers:
            raise NotApplicable(
                "The protected resource metadata lists no authorization server (AUTH-02).",
                related_to="AUTH-02",
            )
        findings: list[Finding] = []
        target_host = host_of(ctx.target)
        assessed = 0
        for issuer in servers[:3]:
            issuer_host = host_of(issuer)
            if issuer_host != target_host:
                if not ctx.options.follow_authorization_server:
                    ctx.notes.append(
                        f"AUTH-03: not fetching third-party AS metadata ({issuer}) (--no-follow-as)"
                    )
                    continue
                # A different host gets the same courtesy as the target: honour its opt-out first.
                try:
                    ctx.notes.extend(await check_dns_opt_out(issuer_host, ctx.options.txt_lookup))
                except OptOutError:
                    ctx.notes.append(
                        f"AUTH-03: {issuer_host} has opted out of mcpprobe; AS metadata not fetched"
                    )
                    continue
            assessed += 1
            responses: list[RpcResponse] = []
            doc: dict[str, Any] | None = None
            doc_url = ""
            for url in _as_metadata_urls(issuer):
                resp = await http.get(url, note="AUTH-03 authorization server metadata")
                responses.append(resp)
                if resp.status == 200:
                    candidate = try_json(resp.body)
                    if isinstance(candidate, dict):
                        doc, doc_url = candidate, url
                        break
            meta_url = _as_metadata_urls(issuer)[0]
            verify = f"curl -s {meta_url} | jq '.code_challenge_methods_supported'  # expect a list containing \"S256\""
            if doc is None:
                findings.append(
                    self.finding(
                        title="Authorization server metadata not found",
                        description=f"No RFC 8414 / OpenID metadata document found for {issuer}.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence=evidence_of(*responses),
                        location=issuer,
                        affected=[issuer],
                        proof="Metadata requests:\n"
                        + "\n".join(
                            f"  GET {r.evidence.url if r.evidence else '?'} -> "
                            + (f"HTTP {r.status}" if r.status else str(r.error_text))
                            for r in responses
                        ),
                        verify=verify,
                    )
                )
                continue
            doc_proof = f"GET {doc_url} -> HTTP 200\n" + proof.indent(proof.pretty(doc))
            # Shared with AUTH-05/AUTH-06, which read the same document and send nothing.
            ctx.shared.setdefault("as_metadata", []).append(
                {"issuer": issuer, "url": doc_url, "doc": doc, "evidence": responses[-1].evidence}
            )
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
                        affected=[issuer],
                        proof=doc_proof,
                        verify=verify,
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
                        affected=insecure,
                        proof=doc_proof,
                        verify=f"curl -s {doc_url} | jq 'with_entries(select(.key|endswith(\"_endpoint\")))'  # expect only https:// URLs",
                    )
                )
            if isinstance(doc.get("issuer"), str) and doc["issuer"].rstrip("/") != issuer.rstrip("/"):
                findings.append(
                    self.finding(
                        title="Authorization server issuer mismatch",
                        description=f"Metadata issuer {doc['issuer']!r} differs from advertised {issuer!r}.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        confidence_reason=(
                            "A trailing-slash or case difference can be harmless, but RFC 8414 requires "
                            "an exact match and strict clients will refuse it."
                        ),
                        evidence=evidence_of(*responses),
                        location=issuer,
                        affected=[issuer],
                        proof=doc_proof,
                        verify=f"curl -s {doc_url} | jq -r .issuer  # expect exactly {issuer}",
                    )
                )
        if assessed == 0:
            raise NotApplicable(
                "Every advertised authorization server is on a third-party host that was not "
                "contacted (--no-follow-as or the host opted out); see scan notes.",
                blocked=True,
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
        if http is None:
            raise NotApplicable("not an HTTP target.")
        if not fp.auth_required:
            raise NotApplicable(
                "The server accepts requests with no token at all (AUTH-01), so there is no token "
                "validation to test.",
                related_to="AUTH-01",
            )
        findings: list[Finding] = []
        method, params, version = _probe_request(ctx)
        creds = http.credential_header_names()
        statuses: list[int | None] = []
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
                drop_headers=[c for c in creds if c.lower() != "authorization"],
                note=f"AUTH-04 self-minted token ({label})",
            )
            statuses.append(resp.status)
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
                        confidence_reason=None
                        if resp.result is not None
                        else "The response was 2xx but carried no JSON-RPC result, so acceptance is inferred from the status only.",
                        evidence=evidence_of(resp),
                        location=ctx.target,
                        details={"probe": label, "claims": now_claims},
                        affected=[label],
                        proof=proof.exchange(
                            resp.evidence,
                            request_headers=["authorization", "content-type"],
                            response_headers=["content-type", "www-authenticate"],
                            result_lines=[
                                f"token claims: {json.dumps(now_claims, sort_keys=True)}",
                                "result: "
                                + ("JSON-RPC result returned" if resp.result is not None else "non-401 body"),
                            ],
                        ),
                        verify=proof.curl_rpc(
                            ctx.target,
                            method,
                            params,
                            protocol_version=version,
                            headers={"Authorization": f"Bearer {alg_none}"},
                            expect="HTTP 401 (a self-minted alg=none token must be rejected)",
                        ),
                    )
                )
        # Token in query string (spec: MUST NOT be accepted).
        qs_url = _with_query(ctx.target, "access_token", hs256)
        qs_headers = {
            k: v
            for k, v in http.default_headers(method, protocol_version=version, include_session=False).items()
            if k not in creds
        }
        resp = await http.raw_request(
            "POST",
            body=_body_for(http, method, params, version),
            headers=qs_headers,
            url=qs_url,
            label=method,
            note="AUTH-04 token in query string",
        )
        statuses.append(resp.status)
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
                    confidence_reason=(
                        "The token was self-minted, so acceptance may mean the server ignores the "
                        "query parameter entirely rather than reading a token from it."
                    ),
                    evidence=evidence_of(resp),
                    location=ctx.target,
                    affected=["access_token query parameter"],
                    proof=proof.exchange(
                        resp.evidence,
                        request_headers=["content-type"],
                        response_headers=["content-type"],
                        absent_request=["Authorization"],
                    ),
                    verify=f"curl -si -X POST '{ctx.target}?access_token=x' -H 'content-type: application/json' "
                    f'-d \'{{"jsonrpc":"2.0","id":1,"method":"ping"}}\'  # expect HTTP 401',
                )
            )
        if not findings and not any(s in (401, 403) for s in statuses):
            raise NotApplicable(
                "The forged-token probes were answered with "
                + ", ".join(f"HTTP {s}" if s else "no response" for s in statuses)
                + " rather than 401/403, so token validation could not be observed.",
                blocked=True,
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
