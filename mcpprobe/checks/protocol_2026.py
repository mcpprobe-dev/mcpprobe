"""Checks for rules introduced by the 2026-07-28 (stateless) revision of the MCP spec.

TRANS-06 server/discover result, TRANS-07 unadvertised earlier revision accepted,
TRANS-08 Mcp-Method header/body mismatch, TRANS-09 ttlMs/cacheScope caching hints,
AUTH-05 RFC 9207 ``iss`` advertisement, AUTH-06 deprecated Dynamic Client
Registration. Every rule was checked against the specification text on
modelcontextprotocol.io (2026-07-28 changelog, Streamable HTTP transport,
Versioning, Discovery, Caching, Authorization and Client Registration pages).

Each check is not applicable when the server speaks an earlier revision (the rule
does not exist there) or when the revision could not be determined. AUTH-05/06
send nothing: they read the authorization server metadata AUTH-03 fetched.
"""

from __future__ import annotations

import json
from typing import Any

from mcpprobe.checks import proof
from mcpprobe.checks.base import Check, NotApplicable, ScanContext, evidence_of, evidence_summary
from mcpprobe.models import Confidence, EvidenceRecord, Finding, Severity, Standards
from mcpprobe.transport import PROTOCOL_2026_07_28, RpcResponse
from mcpprobe.transport.base import (
    CLIENT_INFO,
    EARLIER_REVISIONS,
    ERROR_HEADER_MISMATCH,
    ERROR_UNSUPPORTED_PROTOCOL_VERSION,
    META_CAPABILITIES_KEY,
    META_CLIENT_INFO_KEY,
    META_SERVER_INFO_KEY,
    META_VERSION_KEY,
)

SPEC = "https://modelcontextprotocol.io/specification/2026-07-28"
SPEC_HTTP = f"{SPEC}/basic/transports/streamable-http"
SPEC_DISCOVER = f"{SPEC}/server/discover"
SPEC_VERSIONING = f"{SPEC}/basic/versioning"
SPEC_CACHING = f"{SPEC}/server/utilities/caching"
SPEC_AUTH = f"{SPEC}/basic/authorization"
SPEC_REGISTRATION = f"{SPEC}/basic/authorization/client-registration"

BLOCKING_STATUSES = (401, 403, 429)


def require_2026(ctx: ScanContext, rule: str) -> None:
    """Raise :class:`NotApplicable` unless the server was negotiated on 2026-07-28."""
    fp = ctx.fingerprint
    if fp.flavour == "stateless-2026":
        return
    if fp.flavour in {"handshake", "legacy-sse"}:
        how = "the initialize handshake" if fp.flavour == "handshake" else "the deprecated HTTP+SSE transport"
        raise NotApplicable(
            f"The server speaks protocol revision {fp.protocol_version or 'unknown'} through {how} and "
            f"did not answer server/discover with a result; {rule} was introduced in 2026-07-28 and "
            "does not apply to earlier revisions."
        )
    if fp.auth_required and not fp.credentials_supplied:
        raise NotApplicable(
            "server/discover was answered with HTTP 401, so the protocol revision (and with it whether "
            f"{rule} applies) could not be determined; re-run with credentials.",
            blocked=True,
        )
    raise NotApplicable(f"No protocol revision was negotiated, so it is unknown whether {rule} applies.")


def _discover_evidence(ctx: ScanContext) -> EvidenceRecord | None:
    for attempt in ctx.fingerprint.attempts:
        if attempt.get("method") == "server/discover":
            ev_id = attempt.get("evidence")
            for rec in ctx.evidence.records:
                if rec.id == ev_id:
                    return rec
    return None


def _modern_meta(version: str) -> dict[str, Any]:
    return {
        META_VERSION_KEY: version,
        META_CAPABILITIES_KEY: {},
        META_CLIENT_INFO_KEY: dict(CLIENT_INFO),
    }


def _error_code(resp: RpcResponse) -> int | None:
    err = resp.rpc_error
    code = err.get("code") if err else None
    return code if isinstance(code, int) else None


def _outcome(resp: RpcResponse) -> str:
    code = _error_code(resp)
    if resp.status is None:
        return f"no HTTP response ({resp.error_text})"
    return (
        f"HTTP {resp.status}"
        + (f", JSON-RPC error {code}" if code is not None else "")
        + (", JSON-RPC result returned" if resp.result is not None else "")
    )


# ----------------------------------------------------------------------------- TRANS-06
class Trans06ServerDiscover(Check):
    id = "TRANS-06"
    title = "server/discover result incomplete (2026-07-28)"
    severity = Severity.LOW
    applies_to = frozenset({"http", "stdio"})
    standards = Standards()
    description = (
        "A 2026-07-28 server MUST implement server/discover. The scanner's first request is "
        "server/discover; when it is answered, its result is checked for what the revision "
        "requires: supportedVersions (a list of version strings that includes the 2026-07-28 "
        "revision the request was served under), a capabilities object and resultType "
        "'complete'. A missing _meta['io.modelcontextprotocol/serverInfo'] (SHOULD) is reported as "
        "informational. Caching hints on the same result are checked by TRANS-09. Not applicable "
        "to servers that speak an earlier revision through initialize."
    )
    evidence_type = "The fingerprinting server/discover request and its complete result."
    false_positive_notes = (
        "A server that answers server/discover under an earlier result shape (for example a "
        "'protocolVersions' key from a pre-release draft) is reported, because 2026-07-28 clients "
        "read 'supportedVersions'."
    )
    fix = (
        "Return the DiscoverResult defined in the 2026-07-28 schema: "
        '{"resultType":"complete","supportedVersions":["2026-07-28", ...],"capabilities":{...},'
        '"_meta":{"io.modelcontextprotocol/serverInfo":{"name":...,"version":...}},'
        '"ttlMs":...,"cacheScope":"public"} '
        f"({SPEC_DISCOVER})."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        require_2026(ctx, "server/discover")
        result = ctx.fingerprint.discover_result
        if not isinstance(result, dict):
            raise NotApplicable("The server/discover result was not kept, so it cannot be assessed.")
        must: list[str] = []
        should: list[str] = []
        versions = result.get("supportedVersions")
        if not isinstance(versions, list) or not versions or not all(isinstance(v, str) for v in versions):
            legacy = [k for k in ("protocolVersions", "versions") if k in result]
            must.append(
                "supportedVersions is missing or not a non-empty list of strings"
                + (f" (found non-standard key {', '.join(legacy)})" if legacy else "")
            )
        elif PROTOCOL_2026_07_28 not in versions:
            must.append(
                f"supportedVersions {json.dumps(versions)} does not include {PROTOCOL_2026_07_28}, "
                "although the request was served under that revision"
            )
        if not isinstance(result.get("capabilities"), dict):
            must.append("capabilities is missing or not an object")
        if result.get("resultType") != "complete":
            must.append(
                "resultType is "
                + (json.dumps(result["resultType"]) if "resultType" in result else "missing")
                + ' (required: "complete")'
            )
        meta = result.get("_meta")
        if not (isinstance(meta, dict) and isinstance(meta.get(META_SERVER_INFO_KEY), dict)):
            should.append(f"_meta['{META_SERVER_INFO_KEY}'] is missing (SHOULD)")
        if not must and not should:
            return []
        ev = _discover_evidence(ctx)
        evs = [ev] if ev else []
        problems = must + should
        return [
            self.finding(
                description="The server/discover result does not match the 2026-07-28 DiscoverResult: "
                + "; ".join(problems)
                + ".",
                severity=Severity.LOW if must else Severity.INFO,
                confidence=Confidence.HIGH,
                evidence=evs,
                excerpt=evidence_summary(evs, "; ".join(problems)),
                location="server/discover",
                affected=["server/discover"],
                details={"problems": must, "recommendations": should},
                proof="server/discover result (complete):\n"
                + proof.indent(proof.pretty(result))
                + "\nProblems:\n"
                + "\n".join(f"  - {p}" for p in problems),
                verify=self._verify(ctx),
            )
        ]

    @staticmethod
    def _verify(ctx: ScanContext) -> str:
        if ctx.http is None:
            return proof.rescan(ctx.target, "TRANS-06", stdio=True)
        return proof.curl_rpc(
            ctx.target,
            "server/discover",
            proof.modern_params(),
            protocol_version=PROTOCOL_2026_07_28,
            headers={"Mcp-Method": "server/discover"},
            include_headers=False,
            auth_placeholder=ctx.fingerprint.credentials_supplied,
            jq=".result | {resultType, supportedVersions, capabilities, _meta}",
            expect='resultType "complete", supportedVersions including "2026-07-28", a capabilities object',
        )


# ----------------------------------------------------------------------------- TRANS-07
class Trans07UnadvertisedVersionAccepted(Check):
    id = "TRANS-07"
    title = "Protocol version the server does not advertise is accepted (downgrade)"
    severity = Severity.LOW
    applies_to = frozenset({"http"})
    standards = Standards()
    description = (
        "Takes supportedVersions from the server/discover result and sends one more server/discover "
        "declared (in _meta and in the MCP-Protocol-Version header) as the newest earlier revision "
        "the server does not list (2025-11-25, 2025-06-18 or 2025-03-26). The spec says a server "
        "that does not implement the requested version MUST answer HTTP 400 with "
        "UnsupportedProtocolVersionError (-32022). Serving the request anyway means a client or "
        "intermediary can push the server onto a revision it claims not to support, without the "
        "header validation and other protections of 2026-07-28. One request, no tool is called."
    )
    evidence_type = (
        "The server/discover result (supportedVersions) and the downgraded request with its response."
    )
    false_positive_notes = (
        "A dual-era server that does serve the older revision but forgot to list it is reported "
        "too; listing it in supportedVersions is then the fix. Not applicable when every earlier "
        "revision is advertised."
    )
    fix = (
        "Reject any request whose declared protocol version is not in your supportedVersions with "
        'HTTP 400 and {"code":-32022,"message":"Unsupported protocol version","data":'
        '{"supported":[...],"requested":"..."}}, before doing any work '
        f"({SPEC_VERSIONING}). If you do serve the older revision, list it in supportedVersions."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        require_2026(ctx, "version rejection against supportedVersions")
        http = ctx.http
        if http is None:
            raise NotApplicable("not an HTTP target.")
        supported = ctx.fingerprint.supported_versions
        if not supported:
            raise NotApplicable(
                "server/discover did not return supportedVersions (TRANS-06), so there is no "
                "advertised version list to test against.",
                related_to="TRANS-06",
            )
        candidates = [v for v in EARLIER_REVISIONS if v not in supported]
        if not candidates:
            raise NotApplicable(
                "The server advertises every earlier revision ("
                + ", ".join(EARLIER_REVISIONS)
                + "), so there is no unadvertised version to send."
            )
        version = candidates[0]
        resp = await http.rpc(
            "server/discover",
            {"_meta": _modern_meta(version)},
            protocol_version=version,
            include_session=False,
            headers_override={"Mcp-Method": "server/discover"},
            note=f"TRANS-07 server/discover declared as unadvertised {version}",
        )
        if resp.status is None:
            raise RuntimeError(f"version probe failed at the transport level: {resp.error_text}")
        if resp.status in BLOCKING_STATUSES:
            raise NotApplicable(
                f"The server answered HTTP {resp.status} before the declared version could be "
                "evaluated; re-run with credentials.",
                blocked=True,
            )
        code = _error_code(resp)
        if resp.status == 400 and code == ERROR_UNSUPPORTED_PROTOCOL_VERSION:
            return []
        accepted = resp.result is not None and 200 <= resp.status < 300
        verify = proof.curl_rpc(
            ctx.target,
            "server/discover",
            proof.modern_params(version),
            protocol_version=version,
            headers={"Mcp-Method": "server/discover"},
            auth_placeholder=ctx.fingerprint.credentials_supplied,
            expect=f"HTTP 400 with error code {ERROR_UNSUPPORTED_PROTOCOL_VERSION}",
        )
        lines = [
            f"server/discover supportedVersions: {json.dumps(supported)}",
            "",
            proof.exchange(
                resp.evidence,
                request_headers=["mcp-protocol-version", "mcp-method"],
                response_headers=["content-type"],
                result_lines=[
                    f"declared version: {version} (not in supportedVersions)",
                    "outcome: " + _outcome(resp),
                ],
            ),
        ]
        if accepted:
            desc = (
                f"A request declared as protocol version {version}, which the server does not list in "
                f"supportedVersions ({', '.join(supported)}), was served (HTTP {resp.status} with a "
                "result) instead of being rejected with UnsupportedProtocolVersionError."
            )
            severity = Severity.LOW
            title = None
        else:
            desc = (
                f"A request declared as unadvertised protocol version {version} was refused ({_outcome(resp)}) "
                f"but not with HTTP 400 and UnsupportedProtocolVersionError ({ERROR_UNSUPPORTED_PROTOCOL_VERSION}), "
                "so a dual-era client cannot tell which versions to retry with."
            )
            severity = Severity.INFO
            title = "Unadvertised protocol version refused without UnsupportedProtocolVersionError"
        return [
            self.finding(
                title=title,
                description=desc,
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=evidence_of(resp),
                excerpt=evidence_summary(evidence_of(resp), f"declared {version}; {_outcome(resp)}"),
                location=ctx.target,
                affected=[f"MCP-Protocol-Version: {version}"],
                details={
                    "declared": version,
                    "supported": supported,
                    "status": resp.status,
                    "error_code": code,
                },
                proof="\n".join(lines),
                verify=verify,
            )
        ]


# ----------------------------------------------------------------------------- TRANS-08
class Trans08HeaderBodyMismatch(Check):
    id = "TRANS-08"
    title = "Mcp-Method header not validated against the request body (2026-07-28)"
    severity = Severity.MEDIUM
    applies_to = frozenset({"http"})
    standards = Standards()
    description = (
        "2026-07-28 requires clients to mirror the JSON-RPC method into an Mcp-Method header, and "
        "servers that process the body MUST reject a request whose headers are missing or do not "
        "match the body with HTTP 400 and HeaderMismatch (-32020); otherwise a gateway that routes, "
        "rate-limits or authorises on the header can be bypassed by a body that says something "
        "else. Sends two server/discover requests: one with 'Mcp-Method: tools/list' and one with "
        "no Mcp-Method header. Mcp-Name is not tested, because it is only defined for tools/call, "
        "resources/read and prompts/get, which a passive scan does not send."
    )
    evidence_type = "Both probe requests (headers shown) and their responses."
    false_positive_notes = (
        "A server that rejects the probes with another 4xx is reported as informational only. "
        "When a gateway in front rejects mismatches itself, the finding concerns the server behind "
        "it only if the gateway can be bypassed."
    )
    fix = (
        "Before dispatching, compare Mcp-Method (and, for tools/call, resources/read and "
        "prompts/get, the decoded Mcp-Name) with the body; when a required header is missing or "
        'differs, answer HTTP 400 with {"code":-32020,"message":"Header mismatch: ..."} '
        f"({SPEC_HTTP}#server-validation)."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        require_2026(ctx, "Mcp-Method header validation")
        http = ctx.http
        if http is None:
            raise NotApplicable("not an HTTP target.")
        probes: list[tuple[str, RpcResponse]] = []
        mismatch = await http.rpc(
            "server/discover",
            {},
            include_session=False,
            headers_override={"Mcp-Method": "tools/list"},
            note="TRANS-08 Mcp-Method: tools/list on a server/discover body",
        )
        probes.append(("mismatched Mcp-Method (header tools/list, body server/discover)", mismatch))
        missing = await http.rpc(
            "server/discover",
            {},
            include_session=False,
            drop_headers=["Mcp-Method"],
            note="TRANS-08 Mcp-Method header omitted",
        )
        probes.append(("missing Mcp-Method header", missing))
        for _, resp in probes:
            if resp.status is None:
                raise RuntimeError(f"header probe failed at the transport level: {resp.error_text}")
        if all(r.status in BLOCKING_STATUSES for _, r in probes):
            raise NotApplicable(
                "Both probes were answered with "
                + " and ".join(f"HTTP {r.status}" for _, r in probes)
                + " before header validation could be observed; re-run with credentials.",
                blocked=True,
            )
        accepted = [
            (label, r) for label, r in probes if r.result is not None and 200 <= (r.status or 0) < 300
        ]
        wrong_code = [
            (label, r)
            for label, r in probes
            if (label, r) not in accepted
            and r.status not in BLOCKING_STATUSES
            and not (r.status == 400 and _error_code(r) == ERROR_HEADER_MISMATCH)
        ]
        if not accepted and not wrong_code:
            return []
        if accepted:
            severity = Severity.MEDIUM if accepted[0][1] is mismatch else Severity.LOW
            desc = (
                "The server processed "
                + " and ".join(f"a request with a {label}" for label, _ in accepted)
                + " instead of rejecting it with HTTP 400 and HeaderMismatch (-32020). Anything in front "
                "of the server that trusts the header (routing, rate limits, per-method policy) sees a "
                "different request from the one the server executes."
            )
            title = None
        else:
            severity = Severity.INFO
            desc = (
                "Header validation failures were refused, but not with HTTP 400 and HeaderMismatch "
                "(-32020): " + "; ".join(f"{label}: {_outcome(r)}" for label, r in wrong_code) + "."
            )
            title = "Header mismatch refused without HeaderMismatch (-32020)"
        shown = accepted or wrong_code
        return [
            self.finding(
                title=title,
                description=desc,
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=evidence_of(*(r for _, r in shown)),
                excerpt=evidence_summary(
                    evidence_of(shown[0][1]), "; ".join(f"{label}: {_outcome(r)}" for label, r in shown)
                ),
                location=ctx.target,
                affected=[label for label, _ in shown],
                details={label: {"status": r.status, "error_code": _error_code(r)} for label, r in probes},
                proof="\n\n".join(
                    proof.exchange(
                        r.evidence,
                        request_headers=["mcp-method", "mcp-protocol-version"],
                        absent_request=["Mcp-Method"],
                        response_headers=["content-type"],
                        result_lines=[f"probe: {label}", "outcome: " + _outcome(r)],
                    )
                    for label, r in probes
                ),
                verify=proof.curl_rpc(
                    ctx.target,
                    "server/discover",
                    proof.modern_params(),
                    protocol_version=PROTOCOL_2026_07_28,
                    headers={"Mcp-Method": "tools/list"},
                    auth_placeholder=ctx.fingerprint.credentials_supplied,
                    expect=f"HTTP 400 with error code {ERROR_HEADER_MISMATCH}",
                ),
            )
        ]


# ----------------------------------------------------------------------------- TRANS-09
_CACHEABLE_LISTS = ("tools/list", "prompts/list", "resources/list")


class Trans09CachingHints(Check):
    id = "TRANS-09"
    title = "ttlMs / cacheScope caching hints missing or invalid (2026-07-28)"
    severity = Severity.LOW
    applies_to = frozenset({"http", "stdio"})
    standards = Standards()
    description = (
        "2026-07-28 servers MUST include caching hints on complete results of server/discover, "
        "tools/list, prompts/list and resources/list (among others): ttlMs, a number of "
        "milliseconds that MUST be >= 0, and cacheScope, either 'public' or 'private'. Checks the "
        "results the scan already received; sends nothing. A missing cacheScope leaves shared "
        "gateways to guess whether a list may be served to other users."
    )
    evidence_type = "The server/discover and list results the scan already received."
    false_positive_notes = (
        "Only the first page of each list is checked. A public cacheScope on an authenticated "
        "server is allowed by the spec when the list is the same for every user, so it is not reported."
    )
    fix = (
        'Add "ttlMs": <milliseconds, >= 0> and "cacheScope": "public" (identical for every user) or '
        '"private" (depends on the caller\'s authorization) to every cacheable result '
        f"({SPEC_CACHING})."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        require_2026(ctx, "ttlMs/cacheScope")
        sources: dict[str, dict[str, Any]] = {}
        if isinstance(ctx.fingerprint.discover_result, dict):
            sources["server/discover"] = ctx.fingerprint.discover_result
        for method in _CACHEABLE_LISTS:
            fields = ctx.inventory.result_fields.get(method)
            if isinstance(fields, dict):
                sources[method] = fields
        if not sources:
            raise NotApplicable("No cacheable result was received, so there are no caching hints to check.")
        problems: dict[str, list[str]] = {}
        for method, result in sources.items():
            if result.get("resultType", "complete") != "complete":
                continue
            found: list[str] = []
            ttl = result.get("ttlMs")
            if "ttlMs" not in result:
                found.append("ttlMs missing")
            elif isinstance(ttl, bool) or not isinstance(ttl, int | float):
                found.append(f"ttlMs is {json.dumps(ttl)}, not a number")
            elif ttl < 0:
                found.append(f"ttlMs is {ttl}, must be >= 0")
            scope = result.get("cacheScope")
            if "cacheScope" not in result:
                found.append("cacheScope missing")
            elif scope not in ("public", "private"):
                found.append(f'cacheScope is {json.dumps(scope)}, must be "public" or "private"')
            if found:
                problems[method] = found
        if not problems:
            return []
        evidence_by_method = {
            "server/discover": _discover_evidence(ctx),
            "tools/list": ctx.inventory.tools_evidence,
            "prompts/list": ctx.inventory.prompts_evidence,
            "resources/list": ctx.inventory.resources_evidence,
        }
        evs = [e for m in problems if (e := evidence_by_method.get(m)) is not None]
        lines = []
        for method, result in sources.items():
            shown = ", ".join(
                f"{k}: {json.dumps(result[k]) if k in result else '(absent)'}"
                for k in ("resultType", "ttlMs", "cacheScope")
            )
            lines.append(f"{method} result: {shown}")
            lines += [f"  - {p}" for p in problems.get(method, [])]
        summary = "; ".join(f"{m}: {', '.join(p)}" for m, p in problems.items())
        verify = (
            proof.rescan(ctx.target, self.id, stdio=True)
            if ctx.http is None
            else proof.curl_rpc(
                ctx.target,
                "tools/list",
                proof.modern_params(),
                protocol_version=PROTOCOL_2026_07_28,
                headers={"Mcp-Method": "tools/list"},
                include_headers=False,
                auth_placeholder=ctx.fingerprint.credentials_supplied,
                jq=".result | {ttlMs, cacheScope}",
                expect='a ttlMs >= 0 and cacheScope "public" or "private" (same for server/discover and the other lists)',
            )
        )
        return [
            self.finding(
                description=f"Cacheable results lack valid caching hints: {summary}.",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=evs,
                excerpt=evidence_summary(evs, summary),
                location=", ".join(problems),
                affected=list(problems),
                details={"problems": problems},
                proof="\n".join(lines),
                verify=verify,
            )
        ]


# ----------------------------------------------------------------------------- AUTH-05 / AUTH-06
def _as_documents(ctx: ScanContext, rule: str) -> list[dict[str, Any]]:
    require_2026(ctx, rule)
    docs = ctx.shared.get("as_metadata") or []
    if docs:
        return list(docs)
    if not ctx.fingerprint.auth_required:
        raise NotApplicable(
            "The server accepts requests without authentication (AUTH-01) and advertises no "
            "authorization server, so there is no authorization server metadata to read.",
            related_to="AUTH-01",
        )
    raise NotApplicable(
        "No authorization server metadata document was read (see AUTH-02/AUTH-03), so there is "
        "nothing to assess.",
        related_to="AUTH-03",
        blocked=True,
    )


class Auth05IssuerIdentification(Check):
    id = "AUTH-05"
    title = "Authorization server does not advertise RFC 9207 iss support (2026-07-28)"
    severity = Severity.LOW
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025"])
    description = (
        "2026-07-28 says MCP authorization servers SHOULD include the RFC 9207 'iss' parameter in "
        "authorization responses and, when they do, MUST advertise "
        "authorization_response_iss_parameter_supported: true in their metadata; clients reject a "
        "response without iss only when that flag is true. Reads the authorization server metadata "
        "AUTH-03 already fetched and reports a flag that is absent or not true. Sends nothing. The "
        "revision says this SHOULD is expected to become a MUST."
    )
    evidence_type = "The authorization server metadata document AUTH-03 fetched."
    false_positive_notes = (
        "The spec allows a server to emit iss before it updates its metadata; such a server is "
        "reported until the flag is published, because clients key their rejection on the flag."
    )
    fix = (
        "Include iss in every authorization response, error responses too (RFC 9207 section 2), and "
        'publish "authorization_response_iss_parameter_supported": true in the authorization server '
        f"metadata ({SPEC_AUTH}#authorization-response-validation). With a hosted identity provider, "
        "enable its issuer-identification option."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        docs = _as_documents(ctx, "RFC 9207 iss advertisement")
        bad = [d for d in docs if d["doc"].get("authorization_response_iss_parameter_supported") is not True]
        if not bad:
            return []
        evs = [d["evidence"] for d in bad if d.get("evidence") is not None]
        issuers = [str(d["issuer"]) for d in bad]
        return [
            self.finding(
                description=(
                    "Authorization server metadata for "
                    + ", ".join(issuers)
                    + " does not set authorization_response_iss_parameter_supported to true ("
                    + "; ".join(
                        "value " + json.dumps(d["doc"]["authorization_response_iss_parameter_supported"])
                        if "authorization_response_iss_parameter_supported" in d["doc"]
                        else "absent"
                        for d in bad
                    )
                    + "). Clients therefore accept authorization responses without iss, which leaves "
                    "the mix-up attack RFC 9207 closes open when a client talks to more than one "
                    "authorization server."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=evs,
                excerpt=evidence_summary(evs, "authorization_response_iss_parameter_supported not true"),
                location=issuers[0],
                affected=issuers,
                proof="\n\n".join(
                    f"GET {d['url']} -> HTTP 200\n"
                    + proof.indent(proof.pretty(d["doc"]))
                    + "\nauthorization_response_iss_parameter_supported: "
                    + (
                        json.dumps(d["doc"]["authorization_response_iss_parameter_supported"])
                        if "authorization_response_iss_parameter_supported" in d["doc"]
                        else "(absent)"
                    )
                    for d in bad
                ),
                verify=f"curl -s {bad[0]['url']} | jq .authorization_response_iss_parameter_supported  # expect true",
            )
        ]


class Auth06DynamicClientRegistration(Check):
    id = "AUTH-06"
    title = "Deprecated Dynamic Client Registration offered (2026-07-28)"
    severity = Severity.LOW
    applies_to = frozenset({"http"})
    standards = Standards(mcp=["MCP07:2025"])
    description = (
        "2026-07-28 deprecates OAuth Dynamic Client Registration (RFC 7591) in favour of Client ID "
        "Metadata Documents, which authorization servers SHOULD support. Reads the authorization "
        "server metadata AUTH-03 already fetched: a registration_endpoint without "
        "client_id_metadata_document_supported: true is low (clients have only the deprecated path); "
        "a registration_endpoint next to CIMD support is informational (kept for backwards "
        "compatibility). No registration request is sent."
    )
    evidence_type = "The authorization server metadata document AUTH-03 fetched."
    false_positive_notes = (
        "Keeping DCR for older clients is allowed; the informational finding is a reminder to plan "
        "its removal, not a defect. An authorization server that supports neither DCR nor CIMD "
        "(pre-registration only) is not reported here."
    )
    fix = (
        "Support Client ID Metadata Documents and advertise "
        '"client_id_metadata_document_supported": true; keep registration_endpoint only while '
        "older clients still need it, and plan its removal "
        f"({SPEC_REGISTRATION}). Open registration endpoints also deserve rate limits and "
        "redirect-URI validation."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        docs = _as_documents(ctx, "the Dynamic Client Registration deprecation")
        dcr = [d for d in docs if isinstance(d["doc"].get("registration_endpoint"), str)]
        if not dcr:
            return []
        only_dcr = [d for d in dcr if d["doc"].get("client_id_metadata_document_supported") is not True]
        shown = only_dcr or dcr
        evs = [d["evidence"] for d in shown if d.get("evidence") is not None]
        issuers = [str(d["issuer"]) for d in shown]
        if only_dcr:
            desc = (
                "Authorization server "
                + ", ".join(issuers)
                + " offers Dynamic Client Registration (registration_endpoint) and does not advertise "
                "client_id_metadata_document_supported: true, so clients can only use the registration "
                "mechanism 2026-07-28 deprecates."
            )
            severity = Severity.LOW
            title = None
        else:
            desc = (
                "Authorization server "
                + ", ".join(issuers)
                + " still offers deprecated Dynamic Client Registration alongside Client ID Metadata "
                "Documents; this is allowed for backwards compatibility."
            )
            severity = Severity.INFO
            title = "Deprecated Dynamic Client Registration still enabled alongside CIMD"
        return [
            self.finding(
                title=title,
                description=desc,
                severity=severity,
                confidence=Confidence.HIGH,
                evidence=evs,
                excerpt=evidence_summary(
                    evs,
                    "; ".join(
                        f"registration_endpoint={d['doc']['registration_endpoint']}, "
                        f"client_id_metadata_document_supported={json.dumps(d['doc'].get('client_id_metadata_document_supported'))}"
                        for d in shown
                    ),
                ),
                location=issuers[0],
                affected=issuers,
                proof="\n\n".join(
                    f"GET {d['url']} -> HTTP 200\n"
                    + f"  registration_endpoint: {d['doc']['registration_endpoint']}\n"
                    + "  client_id_metadata_document_supported: "
                    + (
                        json.dumps(d["doc"]["client_id_metadata_document_supported"])
                        if "client_id_metadata_document_supported" in d["doc"]
                        else "(absent)"
                    )
                    for d in shown
                ),
                verify=(
                    f"curl -s {shown[0]['url']} | jq '{{registration_endpoint, client_id_metadata_document_supported}}'"
                    "  # expect client_id_metadata_document_supported: true (and, eventually, no registration_endpoint)"
                ),
            )
        ]
