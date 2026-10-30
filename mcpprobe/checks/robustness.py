"""ERR-01 (verbose errors) and DOS-01 (bounded unbounded-consumption probes)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from typing import Any

from mcpprobe.checks import proof
from mcpprobe.checks.base import Check, NotApplicable, ScanContext, evidence_of, evidence_summary
from mcpprobe.environment import EDGE_LABELS
from mcpprobe.models import Confidence, Finding, Severity, Standards
from mcpprobe.transport import HttpTransport, RpcResponse, StdioTransport

# --------------------------------------------------------------------------- ERR-01
_STACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("python traceback", re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\.py\", line \d+")),
    (
        "javascript stack",
        re.compile(r"\bat [\w.$<>\[\] ]+ \([^)]*\.(?:js|ts|mjs|cjs):\d+:\d+\)|node_modules[\\/]"),
    ),
    ("java stack", re.compile(r"\bat [\w.$]+\([\w$]+\.java:\d+\)")),
    ("go panic", re.compile(r"\bgoroutine \d+ \[|\bpanic: |[\w/]+\.go:\d+")),
    ("dotnet stack", re.compile(r"\bat [\w.`]+\([^)]*\) in [A-Za-z]:\\[^:]+:line \d+")),
    (
        "internal path",
        re.compile(
            r"(?<![\w:])(?:/home/\w+/|/Users/\w+/|/usr/(?:local|lib)/|/srv/|/var/www/|/opt/|[A-Z]:\\\\?(?:Users|inetpub)\\)"
        ),
    ),
]
_FRAMEWORK_VERSION = re.compile(
    r"\b(uvicorn|starlette|fastapi|express|werkzeug|flask|django|gunicorn|hypercorn|aiohttp|tornado|"
    r"spring|rails|koa|fastify|hono|nestjs|axum|actix|gin|echo|nginx|apache|tomcat|jetty|kestrel)\b[/ ]v?(\d+\.\d+[\w.-]*)",
    re.I,
)
_SERVER_HEADER_VERSION = re.compile(r"^[\w.-]+/\d+(?:\.\d+)+")


def inspect_error_body(text: str) -> list[str]:
    """Return the categories of sensitive detail present in an error body."""
    found = [label for label, pat in _STACK_PATTERNS if pat.search(text)]
    if _FRAMEWORK_VERSION.search(text):
        found.append("framework version")
    return found


class Err01VerboseErrors(Check):
    id = "ERR-01"
    title = "Verbose error responses leak stack traces, paths or versions"
    severity = Severity.MEDIUM
    standards = Standards(mcp=["MCP08:2025"], llm_2025=["LLM02:2025"], llm_2026=["LLM02:2026"])
    description = (
        "Sends three malformed requests: truncated JSON, an unknown method and a request whose "
        "params is a string instead of an object. Error bodies and the Server header are "
        "inspected for stack traces, internal file paths and framework version strings."
    )
    evidence_type = "Each malformed request and the error response body."
    false_positive_notes = (
        "A Server header with a version is reported as Info. Framework names without versions "
        "are not reported."
    )
    fix = (
        "Return generic JSON-RPC errors (-32700/-32600/-32601/-32602) without 'data' containing "
        "exceptions, log details server-side, and strip the Server header version at the proxy."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        responses: list[RpcResponse] = []
        t = ctx.transport
        # 1. truncated JSON
        bad_json = '{"jsonrpc": "2.0", "id": 9001, "method": '
        if isinstance(t, HttpTransport):
            responses.append(
                await t.raw_request(
                    "POST",
                    body=bad_json,
                    headers=t.default_headers("tools/list"),
                    label="malformed-json",
                    note="ERR-01 truncated JSON",
                )
            )
        elif isinstance(t, StdioTransport):
            resp = await t.send_raw(
                bad_json, label="malformed-json", want_id=None, note="ERR-01 truncated JSON"
            )
            await asyncio.sleep(0.3)
            if t.unsolicited:
                resp.body = json.dumps(t.unsolicited[-1]).encode()
            responses.append(resp)
        # 2. unknown method
        responses.append(await t.rpc("mcpprobe/does_not_exist", {}, note="ERR-01 unknown method"))
        # 3. wrong param type
        wrong = json.dumps(
            {"jsonrpc": "2.0", "id": t.next_id(), "method": "tools/list", "params": "not-an-object"}
        )
        if isinstance(t, HttpTransport):
            responses.append(
                await t.raw_request(
                    "POST",
                    body=wrong,
                    headers=t.default_headers("tools/list"),
                    label="wrong-param-type",
                    want_id=json.loads(wrong)["id"],
                    note="ERR-01 wrong param type",
                )
            )
        elif isinstance(t, StdioTransport):
            responses.append(
                await t.send_raw(
                    wrong,
                    label="wrong-param-type",
                    want_id=json.loads(wrong)["id"],
                    note="ERR-01 wrong param type",
                )
            )

        if responses and all(r.status in (401, 403) for r in responses):
            raise NotApplicable(
                "Every malformed request was rejected at authentication (HTTP 401/403), so the "
                "server's error handling behind authentication could not be observed; re-run with credentials.",
                blocked=True,
            )
        if responses and all(r.status is None and not r.body for r in responses):
            raise RuntimeError("every malformed request failed at the transport level")
        leaks: dict[str, list[str]] = {}
        leak_proof: list[str] = []
        for resp in responses:
            text = resp.body.decode("utf-8", errors="replace")
            cats = inspect_error_body(text)
            if cats:
                leaks[resp.method] = cats
                leak_proof.append(_leak_proof(resp, text, cats))
        if leaks:
            all_cats = sorted({c for cs in leaks.values() for c in cs})
            only_version = all_cats == ["framework version"]
            findings.append(
                self.finding(
                    description="Error responses contained "
                    + ", ".join(all_cats)
                    + " (probes: "
                    + ", ".join(leaks)
                    + ").",
                    severity=Severity.LOW if only_version else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=evidence_of(*[r for r in responses if r.method in leaks]),
                    location=ctx.target,
                    details={"leaks": leaks},
                    affected=list(leaks),
                    proof="\n\n".join(leak_proof),
                    verify=(
                        f"curl -s -X POST {ctx.target} -H 'content-type: application/json' "
                        '-d \'{"jsonrpc": "2.0", "id": 9001, "method": \'  '
                        "# expect a generic -32700 Parse error with no stack trace, path or version"
                    )
                    if ctx.http is not None
                    else proof.rescan(ctx.target, self.id, stdio=True),
                )
            )
        server_header = next((r.headers.get("server") for r in responses if r.headers.get("server")), None)
        if server_header and _SERVER_HEADER_VERSION.match(server_header):
            findings.append(
                self.finding(
                    title="Server header discloses software version",
                    description=f"Server: {server_header}",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence=evidence_of(responses[0]) if responses else [],
                    location=ctx.target,
                    details={"server": server_header},
                    affected=["Server"],
                    proof=f"response header: server: {server_header}",
                    verify=f"curl -s -D - -o /dev/null {ctx.target} | grep -i '^server:'  # expect no version number",
                )
            )
        return findings


def _leak_proof(resp: RpcResponse, text: str, cats: list[str]) -> str:
    head = f"[{resp.evidence.id if resp.evidence else '?'}] {resp.method} -> " + (
        f"HTTP {resp.status}" if resp.status is not None else "stdio"
    )
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if parsed is not None and len(text) <= 16384:
        body = proof.indent(proof.pretty(parsed))
    else:
        hits = [
            line
            for line in text.splitlines()
            if any(p.search(line) for _, p in _STACK_PATTERNS) or _FRAMEWORK_VERSION.search(line)
        ]
        body = "\n".join(f"  {line}" for line in hits) + f"\n  ({len(text.splitlines())} lines in total)"
    return f"{head}\nleaks: {', '.join(cats)}\nresponse body:\n{body}"


# --------------------------------------------------------------------------- DOS-01
#: Hard limits. These are the *maximum* the check will ever send.
OVERSIZED_ARG_BYTES = 1_000_000
NESTING_DEPTH = 64
BURST_REQUESTS = 20
SLOW_THRESHOLD_MS = 5000.0


def nested(depth: int) -> dict[str, Any]:
    obj: dict[str, Any] = {"leaf": True}
    for _ in range(depth):
        obj = {"n": obj}
    return obj


class Dos01UnboundedConsumption(Check):
    id = "DOS-01"
    title = "No visible limits on request size, nesting or rate"
    severity = Severity.LOW
    #: A 429 during the burst is the evidence this check looks for, not a reason to stop.
    handles_rate_limit = True
    standards = Standards(asi=["ASI08"], llm_2025=["LLM10:2025"], llm_2026=["LLM06:2026"])
    description = (
        "Three bounded probes, never more: (1) one tools/list whose 'cursor' is a 1 MB string, "
        "(2) one tools/list with params nested 64 levels deep, (3) 20 tools/list requests sent "
        "at the scan rate cap (5 req/s by default). A 5xx, a transport failure or a response "
        "slower than 5 s on (1)/(2) is reported; absence of any 429 during (3) is reported as "
        "informational. No tools are called."
    )
    evidence_type = "The oversized/nested requests (truncated) and timing; the burst responses' statuses."
    false_positive_notes = (
        "The burst runs inside the scanner's own rate cap, so 'no 429 observed' is indicative "
        "only (low confidence) and many well-run servers legitimately allow 5 req/s. A 413 or "
        "connection reset on the oversized probe is treated as a correct defence."
    )
    fix = (
        "Enforce a request body limit (e.g. 1 MB) and JSON depth limit at the edge, return 413/400 "
        "promptly, and rate-limit per client/session with 429 and Retry-After."
    )

    def _fix(self, ctx: ScanContext) -> str:
        edge = ctx.environment.edge
        label = EDGE_LABELS.get(edge or "", "")
        if edge == "aws-api-gateway":
            return (
                self.fix + f" {label} is in front (apigw-requestid header): set stage or route throttling "
                "(rate and burst) there, which answers 429 before your code runs. The gateway's own "
                "payload cap (10 MB) is far above what an MCP request needs, so still enforce a 1 MB "
                "limit and a JSON depth limit in the handler."
            )
        if edge == "cloudflare":
            return (
                self.fix
                + " On Cloudflare, a rate limiting rule on the MCP path can return the 429 at the edge."
            )
        if edge == "aws-cloudfront":
            return (
                self.fix
                + " With CloudFront in front, an AWS WAF rate-based rule can return the 429 at the edge."
            )
        return self.fix

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        t = ctx.transport
        probes: list[tuple[str, RpcResponse]] = []
        # (1) one oversized argument
        big = await t.rpc(
            "tools/list", {"cursor": "A" * OVERSIZED_ARG_BYTES}, note="DOS-01 oversized cursor (1 MB)"
        )
        probes.append(("oversized", big))
        # (2) deep nesting
        deep = await t.rpc(
            "tools/list", {"cursor": None, "_mcpprobe": nested(NESTING_DEPTH)}, note="DOS-01 nesting depth 64"
        )
        probes.append(("nesting", deep))
        for label, resp in probes:
            problem = _problem(resp)
            if problem:
                findings.append(
                    self.finding(
                        title=f"Server struggled with {label} request",
                        description=f"The {label} probe produced: {problem}. Input limits may be missing.",
                        severity=Severity.LOW if "slow" in problem else Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        confidence_reason=(
                            "A single slow or failing response can be transient; the probe was sent once."
                        ),
                        fix=self._fix(ctx),
                        affected=[label],
                        proof=proof.exchange(resp.evidence, response_headers=["content-type", "retry-after"])
                        + f"\nelapsed: {resp.elapsed_ms:.0f} ms; problem: {problem}",
                        verify=proof.rescan(ctx.target, self.id, stdio=ctx.http is None),
                        evidence=evidence_of(resp),
                        excerpt=evidence_summary(
                            evidence_of(resp), f"{label} probe -> {problem} after {resp.elapsed_ms:.0f} ms"
                        ),
                        location=ctx.target,
                        details={"probe": label, "status": resp.status, "elapsed_ms": resp.elapsed_ms},
                    )
                )
        # (3) bounded burst
        statuses: list[int | None] = []
        burst_responses: list[RpcResponse] = []
        # A 429 during the burst is the signal this probe looks for, so it is not waited out.
        with t.raw_429() if isinstance(t, HttpTransport) else contextlib.nullcontext():
            for i in range(BURST_REQUESTS):
                resp = await t.rpc("tools/list", {}, note=f"DOS-01 burst {i + 1}/{BURST_REQUESTS}")
                burst_responses.append(resp)
                statuses.append(resp.status)
                if resp.status == 429:
                    break
        all_probe_statuses = [big.status, deep.status, *statuses]
        if isinstance(t, HttpTransport) and all(s in (401, 403) for s in all_probe_statuses):
            raise NotApplicable(
                "Every probe was rejected at authentication (HTTP 401/403), so limits behind "
                "authentication could not be observed; re-run with credentials.",
                blocked=True,
            )
        if isinstance(t, HttpTransport):
            if 429 in statuses:
                ctx.notes.append(f"DOS-01: rate limiting observed after {statuses.index(429) + 1} requests")
            else:
                findings.append(
                    self.finding(
                        title="No rate limiting observed",
                        description=f"{len(statuses)} tools/list requests at the scan rate cap were all accepted "
                        "(no 429). Indicative only; the scanner never exceeds its own cap.",
                        severity=Severity.INFO,
                        confidence=Confidence.LOW,
                        confidence_reason=(
                            f"Indicative only: the burst stays inside the scanner's own cap of "
                            f"{t.limiter.rate:g} req/s, and many well-run servers legitimately allow that rate."
                        ),
                        fix=self._fix(ctx),
                        affected=["rate limiting"],
                        proof=(
                            f"{len(statuses)} x tools/list at {t.limiter.rate:g} req/s\nstatuses: "
                            + ", ".join(
                                f"HTTP {st} x{statuses.count(st)}"
                                if st
                                else f"no response x{statuses.count(st)}"
                                for st in sorted(set(statuses), key=lambda v: v or 0)
                            )
                            + "\nno 429 and no Retry-After header observed\n\n"
                            + proof.exchange(
                                burst_responses[-1].evidence if burst_responses else None,
                                request_headers=["content-type"],
                                response_headers=["content-type", "retry-after"],
                            )
                        ),
                        verify=(
                            "for i in $(seq 1 50); do "
                            + proof.curl_rpc(ctx.target, "ping", None, include_headers=False).replace(
                                "curl -s ", "curl -s -o /dev/null -w '%{http_code}\\n' ", 1
                            )
                            + "; done | sort | uniq -c  # expect some 429 responses"
                        ),
                        evidence=evidence_of(burst_responses[0], burst_responses[-1])
                        if burst_responses
                        else [],
                        excerpt=f"{len(statuses)} x tools/list at {t.limiter.rate:g} req/s, statuses: "
                        + ", ".join(sorted({str(s) for s in statuses})),
                        location=ctx.target,
                        details={"requests": len(statuses), "rate_cap": t.limiter.rate},
                    )
                )
        return findings


def _problem(resp: RpcResponse) -> str | None:
    if resp.error_text and "timeout" in resp.error_text.lower():
        return f"timeout ({resp.error_text})"
    if resp.status is not None and resp.status >= 500:
        return f"HTTP {resp.status}"
    if resp.elapsed_ms > SLOW_THRESHOLD_MS:
        return f"slow response ({resp.elapsed_ms:.0f} ms)"
    if resp.status is None and resp.error_text and resp.result is None and resp.rpc_error is None:
        # stdio: server died or stopped answering
        return f"stdio transport error ({resp.error_text})"
    return None
