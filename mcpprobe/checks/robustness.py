"""ERR-01 (verbose errors) and DOS-01 (bounded unbounded-consumption probes)."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from mcpprobe.checks.base import Check, ScanContext, evidence_of, evidence_summary
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

        leaks: dict[str, list[str]] = {}
        for resp in responses:
            text = resp.body.decode("utf-8", errors="replace")
            cats = inspect_error_body(text)
            if cats:
                leaks[resp.method] = cats
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
                )
            )
        return findings


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
        for i in range(BURST_REQUESTS):
            resp = await t.rpc("tools/list", {}, note=f"DOS-01 burst {i + 1}/{BURST_REQUESTS}")
            burst_responses.append(resp)
            statuses.append(resp.status)
            if resp.status == 429:
                break
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
                        evidence=evidence_of(burst_responses[-1]) if burst_responses else [],
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
