"""Scan orchestrator: transport -> opt-out -> fingerprint -> inventory -> checks -> report."""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from mcpprobe import USER_AGENT, __version__
from mcpprobe.authz import AuthorisationError, AuthorisationRecord, require_active_authorisation
from mcpprobe.chains import build_chains
from mcpprobe.checks import Check, NotApplicable, ScanContext, ScanOptions, select_checks
from mcpprobe.dnsutil import TxtLookup
from mcpprobe.environment import detect_environment
from mcpprobe.governance import governance_items
from mcpprobe.models import (
    CheckMode,
    CheckResult,
    CheckStatus,
    EvidenceRecord,
    Fingerprint,
    Inventory,
    ScanReport,
    utcnow,
)
from mcpprobe.policy import DEFAULT_RATE, check_opt_out, clamp_rate
from mcpprobe.transport import (
    PROTOCOL_2025_11_25,
    PROTOCOL_2026_07_28,
    EvidenceLog,
    HttpTransport,
    RateLimiter,
    RpcResponse,
    StdioTransport,
    Transport,
    TransportError,
    ensure_url,
    fingerprint,
)
from mcpprobe.transport.base import CLIENT_INFO

MAX_LIST_PAGES = 10


@dataclass(slots=True)
class ScanConfig:
    """Everything needed to run one scan."""

    target: str
    stdio: bool = False
    stdio_env: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    timeout: float = 15.0
    rate: float = DEFAULT_RATE
    options: ScanOptions = field(default_factory=ScanOptions)
    only: Iterable[str] | None = None
    skip: Iterable[str] | None = None
    authorisation: AuthorisationRecord | None = None
    user_agent: str = USER_AGENT
    verify_tls: bool | str = True
    #: DNS TXT resolver for the opt-out check (injected in tests).
    txt_lookup: TxtLookup | None = None
    #: Test-suite escape hatch for the 10 req/s ceiling. Not exposed on the CLI.
    _unsafe_allow_any_rate: bool = False
    #: Test-suite hook: an httpx transport that routes requests (e.g. to a local fixture).
    _httpx_transport: Any = None

    def effective_rate(self) -> float:
        if self._unsafe_allow_any_rate:
            return self.rate
        return clamp_rate(self.rate)


def build_transport(config: ScanConfig, evidence: EvidenceLog, limiter: RateLimiter) -> Transport:
    if config.stdio:
        return StdioTransport(
            config.target,
            env=config.stdio_env,
            timeout=config.timeout,
            evidence=evidence,
            limiter=limiter,
        )
    return HttpTransport(
        ensure_url(config.target),
        extra_headers=config.headers,
        timeout=config.timeout,
        evidence=evidence,
        limiter=limiter,
        verify=config.verify_tls,
        user_agent=config.user_agent,
        httpx_transport=config._httpx_transport,
    )


async def _list_all(
    transport: Transport, method: str, key: str
) -> tuple[list[dict[str, Any]], str | None, Any]:
    """Paginate a ``*/list`` method; returns (items, error, first evidence)."""
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    first_evidence = None
    for _ in range(MAX_LIST_PAGES):
        params: dict[str, Any] = {"cursor": cursor} if cursor else {}
        resp = await transport.rpc(method, params, note=f"inventory {method}")
        if first_evidence is None:
            first_evidence = resp.evidence
        if not resp.ok:
            err = resp.rpc_error
            text = err.get("message") if err else (resp.error_text or f"HTTP {resp.status}")
            return items, str(text), first_evidence
        result = resp.result or {}
        page = result.get(key)
        if isinstance(page, list):
            items.extend(x for x in page if isinstance(x, dict))
        cursor = result.get("nextCursor")
        if not cursor:
            break
    return items, None, first_evidence


async def collect_inventory(transport: Transport, fp: Fingerprint) -> Inventory:
    inv = Inventory()
    if (fp.auth_required and not fp.credentials_supplied) or fp.flavour in {"unknown", "legacy-sse"}:
        inv.tools_error = "not listed: " + ("authentication required" if fp.auth_required else fp.flavour)
        return inv
    inv.tools, inv.tools_error, inv.tools_evidence = await _list_all(transport, "tools/list", "tools")
    caps = fp.capabilities if isinstance(fp.capabilities, dict) else {}
    # Only ask for prompts/resources when advertised (or capabilities unknown) to avoid noise.
    if not caps or "prompts" in caps:
        inv.prompts, inv.prompts_error, inv.prompts_evidence = await _list_all(
            transport, "prompts/list", "prompts"
        )
    if not caps or "resources" in caps:
        inv.resources, inv.resources_error, inv.resources_evidence = await _list_all(
            transport, "resources/list", "resources"
        )
    return inv


async def probe_unauthenticated(transport: HttpTransport, fp: Fingerprint) -> RpcResponse | None:
    """When the operator supplied credentials, check whether the endpoint also answers without them.

    Negotiation used the operator's credentials, so ``fp.auth_required`` would
    otherwise be False even on a well-protected server. One request is sent with
    the credential headers removed; a 401 marks the endpoint as auth-protected.
    """
    creds = transport.credential_header_names()
    if not creds or fp.auth_required:
        return None
    fp.credentials_supplied = True
    if fp.flavour == "stateless-2026":
        method, params, version = "server/discover", {}, PROTOCOL_2026_07_28
    else:
        version = transport.protocol_version or PROTOCOL_2025_11_25
        method = "initialize"
        params = {"protocolVersion": version, "capabilities": {}, "clientInfo": CLIENT_INFO}
    resp = await transport.rpc(
        method,
        params,
        protocol_version=version,
        include_session=False,
        drop_headers=creds,
        note="unauthenticated probe (operator credentials removed)",
    )
    fp.attempts.append(
        {
            "version": version,
            "method": f"{method} (without operator credentials)",
            "status": resp.status,
            "ok": resp.ok,
            "rpc_error": None,
            "transport_error": resp.error_text,
            "evidence": resp.evidence.id if resp.evidence else None,
        }
    )
    if resp.status in (401, 403):
        fp.auth_required = True
        fp.www_authenticate = resp.headers.get("www-authenticate")
    return resp


def classify_non_mcp(fp: Fingerprint, records: list[EvidenceRecord], transport: str) -> tuple[str, str]:
    """Return ``(target_kind, what was observed)`` for a target that did not negotiate MCP."""
    by_id = {r.id: r for r in records}
    observed: list[str] = []
    any_response = False
    for attempt in fp.attempts:
        rec = by_id.get(str(attempt.get("evidence")))
        label = str(attempt.get("method"))
        if rec is None:
            continue
        if transport == "http":
            if rec.status is None:
                observed.append(f"{label} -> {rec.error or 'no response'}")
                continue
            any_response = True
            ctype = rec.response_headers.get("content-type", "no content-type").split(";")[0].strip()
            observed.append(f"{label} -> HTTP {rec.status} {ctype}")
        else:
            if rec.error and not rec.response_body:
                observed.append(f"{label} -> {rec.error}")
                continue
            any_response = True
            observed.append(f"{label} -> no JSON-RPC result")
    if not any_response:
        return "unreachable", "; ".join(dict.fromkeys(observed)) or (fp.error or "no response")
    return "not_mcp", "; ".join(dict.fromkeys(observed))


async def run_check(check: Check, ctx: ScanContext) -> CheckResult:
    """Run one check under the gating rules and wrap the outcome."""
    result = CheckResult(check_id=check.id, title=check.title, mode=check.mode, status=CheckStatus.RAN)
    if not check.applies(ctx):
        result.status = CheckStatus.SKIPPED
        result.reason = f"not applicable to {ctx.transport.name} transport"
        return result
    if check.mode == CheckMode.ACTIVE:
        try:
            require_active_authorisation(ctx.authorisation)
        except AuthorisationError:
            result.status = CheckStatus.SKIPPED
            result.reason = "requires --active and verified ownership"
            return result
    started = time.monotonic()
    try:
        result.findings = await check.run(ctx)
    except NotApplicable as exc:
        result.status = CheckStatus.NOT_APPLICABLE
        result.reason = exc.reason
        result.related_to = exc.related_to
    except NotImplementedError as exc:
        result.status = CheckStatus.NOT_IMPLEMENTED
        result.reason = str(exc)
    except PermissionError as exc:
        result.status = CheckStatus.SKIPPED
        result.reason = str(exc)
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.reason = f"{type(exc).__name__}: {exc}"
    result.duration_ms = (time.monotonic() - started) * 1000
    return result


async def run_scan(config: ScanConfig) -> tuple[ScanReport, EvidenceLog]:
    """Execute a full scan. Raises TransportError/OptOutError for fatal conditions.

    A target that answers but does not speak MCP (or never answers) yields a
    report with ``target_kind`` 'not_mcp' / 'unreachable' and every check
    marked not applicable; nothing is reported as passed.
    """
    evidence = EvidenceLog()
    try:
        limiter = RateLimiter(rate=config.effective_rate())
    except ValueError as exc:
        raise TransportError(str(exc)) from exc
    started = utcnow()
    transport = build_transport(config, evidence, limiter)
    options = config.options
    if options.txt_lookup is None:
        options.txt_lookup = config.txt_lookup
    if config.stdio:
        options.stdio_command = list(transport.argv)  # type: ignore[attr-defined]
        options.stdio_env = dict(config.stdio_env)
    report = ScanReport(
        version=__version__,
        target=config.target,
        mode=options.mode,
        started_at=started,
        attestations=governance_items(),
    )
    async with transport:
        if isinstance(transport, HttpTransport):
            # Must be the very first thing that happens: DNS opt-out, then the
            # well-known document, before any MCP request.
            report.notes.extend(await check_opt_out(transport, transport.url, config.txt_lookup))
        fp = await fingerprint(transport)
        report.fingerprint = fp
        if fp.flavour == "unknown" and not fp.auth_required:
            kind, observed = classify_non_mcp(fp, evidence.records, transport.name)
            report.target_kind = kind
            reason = ("Not an MCP server: " if kind == "not_mcp" else "Target unreachable: ") + observed
            fp.error = reason
            report.notes.append(reason)
            report.environment = detect_environment(config.target, evidence.records, transport=transport.name)
            for check in select_checks(config.only, config.skip):
                report.checks.append(
                    CheckResult(
                        check_id=check.id,
                        title=check.title,
                        mode=check.mode,
                        status=CheckStatus.NOT_APPLICABLE,
                        reason=reason,
                    )
                )
            report.finished_at = utcnow()
            report.evidence_count = len(evidence)
            return report, evidence
        unauth_probe: RpcResponse | None = None
        if isinstance(transport, HttpTransport):
            unauth_probe = await probe_unauthenticated(transport, fp)
        inventory = await collect_inventory(transport, fp)
        report.inventory_summary = inventory.summary()
        target_url = transport.url if isinstance(transport, HttpTransport) else config.target
        environment = detect_environment(target_url, evidence.records, transport=transport.name)
        report.environment = environment
        ctx = ScanContext(
            target=target_url,
            transport=transport,
            fingerprint=fp,
            inventory=inventory,
            evidence=evidence,
            options=options,
            authorisation=config.authorisation,
            environment=environment,
        )
        if unauth_probe is not None:
            ctx.shared["unauth_probe"] = unauth_probe
        for check in select_checks(config.only, config.skip):
            result = await run_check(check, ctx)
            report.checks.append(result)
            report.findings.extend(result.findings)
        report.notes.extend(ctx.notes)
        report.chains = build_chains(report, ctx)
    report.finished_at = utcnow()
    report.evidence_count = len(evidence)
    report.findings.sort(key=lambda f: (-f.severity.rank, f.id, f.location or ""))
    return report, evidence
