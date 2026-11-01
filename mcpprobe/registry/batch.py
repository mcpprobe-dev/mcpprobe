"""Polite, resumable batch scan of remote registry endpoints with the survey profile.

Guarantees, enforced in code rather than by convention:

* **Opt-out first.** Each host goes through :func:`mcpprobe.scanner.run_scan`, which
  checks the DNS TXT opt-out (no packet to the host) and then
  ``/.well-known/mcpprobe-opt-out`` before any MCP request (:mod:`mcpprobe.policy`).
* **Survey profile only** (:data:`~mcpprobe.registry.common.SURVEY_CHECKS`): requests an
  ordinary MCP client sends; no tool is ever called (no check in the profile calls one, and
  active mode is never enabled).
* **1 request/second per rate key** (:func:`~mcpprobe.registry.common.rate_key`, the last
  two DNS labels) through :class:`HostPacer`, and at most :data:`MAX_CONCURRENCY` hosts at
  once. One worker owns a rate key at a time, so a provider hosting many entries sees one
  sequential client.
* **Public addresses only.** :class:`PoliteTransport` resolves every host itself, refuses
  loopback/private/reserved addresses, and pins the connection to the address it checked
  (TLS still verifies the hostname via SNI), so DNS rebinding cannot redirect a request.
* **Same origin only.** Requests to any host other than the target are refused.
* **Stop on 429/403.** The first HTTP 429 or 403 stops all further requests to that rate
  key for the rest of the run (and for resumed runs); Retry-After is not waited out.
* **No bodies kept.** Evidence lives in memory for the duration of one host's scan; the
  checkpoint holds outcomes, counts, the negotiated revision, the edge label, the META-01
  rules revision and derived labels (capability classes, META-01 indicator kinds) only:
  never a description, tool name or other text from the host.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections import Counter, defaultdict
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from mcpprobe import USER_AGENT
from mcpprobe.checks import ScanOptions
from mcpprobe.checks.poisoning import RULES_VERSION as META01_RULES
from mcpprobe.models import CheckStatus, ScanReport, Severity, utcnow
from mcpprobe.policy import OptOutError
from mcpprobe.registry.common import (
    MAX_CONCURRENCY,
    PER_HOST_INTERVAL,
    SURVEY_CHECKS,
    HostStatus,
    Outcome,
    append_jsonl,
    findings_outcome,
    is_public_address,
    rate_key,
    read_jsonl,
)
from mcpprobe.scanner import ScanConfig, run_scan
from mcpprobe.transport import TransportError

Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]
Resolver = Callable[[str], Awaitable[list[str]]]
#: Builds the innermost httpx transport for a host (tests route it to a local fixture).
TransportFactory = Callable[[str], httpx.AsyncBaseTransport]

#: Requests one survey-profile scan sends to a host. Measured on the in-repo fixtures: 3
#: (auth-protected) to 7 (open server: opt-out document, negotiation, three list methods,
#: RFC 9728 well-known paths); a server that rejects every negotiation attempt costs up to
#: about 10. The estimate uses the upper end.
EST_REQUESTS_PER_HOST = 10
#: Wall-clock cap on one host's scan.
HOST_TIMEOUT = 300.0
#: Status codes that make us stop talking to a rate key.
STOP_STATUSES = frozenset({429, 403})


class HostStopped(httpx.TransportError):
    """We stopped sending to this rate key (it answered 429/403 earlier)."""


class AddressRefused(httpx.TransportError):
    """The host resolved to a non-public address, or could not be resolved."""


class OffTargetRefused(httpx.TransportError):
    """A request to a host other than the scan target was refused."""


async def default_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def _real_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


class HostPacer:
    """At most one request per ``interval`` seconds per key. Clock and sleep are injectable."""

    def __init__(
        self, interval: float = PER_HOST_INTERVAL, clock: Clock | None = None, sleep: Sleep | None = None
    ) -> None:
        if interval < PER_HOST_INTERVAL:
            raise ValueError(f"per-host interval must be at least {PER_HOST_INTERVAL:g} s")
        self.interval = interval
        self.clock = clock or time.monotonic
        self.sleep = sleep or _real_sleep
        self._next: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        #: (key, time) of every request let through, for tests and run statistics.
        self.log: list[tuple[str, float]] = []

    async def acquire(self, key: str) -> None:
        async with self._locks[key]:
            now = self.clock()
            due = self._next.get(key)
            if due is not None and due > now:
                await self.sleep(due - now)
                now = self.clock()
            self._next[key] = now + self.interval
            self.log.append((key, now))


@dataclass(slots=True)
class GuardState:
    """Shared across all hosts in a run."""

    #: rate key -> why we stopped ("HTTP 429", "HTTP 403").
    stopped: dict[str, str] = field(default_factory=dict)
    #: host -> pinned address.
    resolved: dict[str, str] = field(default_factory=dict)
    #: host -> why it was refused (non-public address, resolution failure).
    refused: dict[str, str] = field(default_factory=dict)
    requests: Counter[str] = field(default_factory=Counter)


class PoliteTransport(httpx.AsyncBaseTransport):
    """httpx transport enforcing target-only, public-address-only, paced, stop-on-refusal traffic."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        *,
        target_host: str,
        pacer: HostPacer,
        state: GuardState,
        resolver: Resolver,
        pin: bool = True,
    ) -> None:
        self.inner = inner
        self.target_host = target_host.lower().rstrip(".")
        self.pacer = pacer
        self.state = state
        self.resolver = resolver
        self.pin = pin

    async def _address(self, host: str) -> str:
        if host in self.state.refused:
            raise AddressRefused(self.state.refused[host])
        if host in self.state.resolved:
            return self.state.resolved[host]
        try:
            addresses = await self.resolver(host)
        except (OSError, UnicodeError) as exc:
            self.state.refused[host] = f"could not resolve: {type(exc).__name__}"
            raise AddressRefused(self.state.refused[host]) from exc
        if not addresses:
            self.state.refused[host] = "no address"
            raise AddressRefused("no address")
        if not all(is_public_address(a) for a in addresses):
            # Any non-public answer disqualifies the host: never pick "the public one".
            self.state.refused[host] = "resolves to a loopback, private or reserved address"
            raise AddressRefused(self.state.refused[host])
        self.state.resolved[host] = addresses[0]
        return addresses[0]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = (request.url.host or "").lower().rstrip(".")
        if host != self.target_host:
            raise OffTargetRefused(f"request to {host} refused: only the target host may be contacted")
        key = rate_key(host)
        if key in self.state.stopped:
            raise HostStopped(f"stopped after {self.state.stopped[key]}")
        address = await self._address(host)
        await self.pacer.acquire(key)
        if key in self.state.stopped:  # another request on this key was refused while we waited
            raise HostStopped(f"stopped after {self.state.stopped[key]}")
        if self.pin:
            # Connect to the address we vetted; the Host header is already set, and SNI /
            # certificate verification still use the hostname.
            request.url = request.url.copy_with(host=address)
            request.extensions = {**request.extensions, "sni_hostname": host}
        self.state.requests[host] += 1
        response = await self.inner.handle_async_request(request)
        if response.status_code in STOP_STATUSES:
            self.state.stopped.setdefault(key, f"HTTP {response.status_code}")
        return response

    async def aclose(self) -> None:
        await self.inner.aclose()


@dataclass(slots=True)
class BatchConfig:
    concurrency: int = MAX_CONCURRENCY
    per_host_interval: float = PER_HOST_INTERVAL
    timeout: float = 15.0
    host_timeout: float = HOST_TIMEOUT
    checks: tuple[str, ...] = SURVEY_CHECKS
    user_agent: str = USER_AGENT
    txt_lookup: Callable[[str], list[str]] | None = None
    resolver: Resolver | None = None
    transport_factory: TransportFactory | None = None
    clock: Clock | None = None
    sleep: Sleep | None = None
    pin_addresses: bool = True
    #: Rate of the scanner's own limiter. The pacer is the real per-host guarantee; tests
    #: raise this (with ``_unsafe_allow_any_rate``) so they do not sleep in real time.
    scanner_rate: float = PER_HOST_INTERVAL
    _unsafe_allow_any_rate: bool = False

    def effective_concurrency(self) -> int:
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        return min(self.concurrency, MAX_CONCURRENCY)


def _outcomes_for(status: HostStatus, checks: Iterable[str]) -> dict[str, str]:
    value = {
        HostStatus.UNREACHABLE: Outcome.UNREACHABLE.value,
        HostStatus.NOT_MCP: Outcome.NOT_MCP.value,
        HostStatus.ERROR: Outcome.ERROR.value,
    }.get(status, Outcome.BLOCKED.value)
    return dict.fromkeys(checks, value)


def outcomes_from_report(report: ScanReport) -> dict[str, str]:
    out: dict[str, str] = {}
    for result in report.checks:
        if result.status == CheckStatus.RAN:
            out[result.check_id] = findings_outcome(f.severity.value for f in result.findings)
        elif result.status == CheckStatus.NOT_APPLICABLE:
            out[result.check_id] = Outcome.BLOCKED.value if result.blocked else Outcome.NOT_APPLICABLE.value
        elif result.status == CheckStatus.ERROR:
            out[result.check_id] = Outcome.ERROR.value
        else:
            out[result.check_id] = Outcome.NOT_APPLICABLE.value
    return out


def derived_labels(report: ScanReport) -> dict[str, Any]:
    """Labels (never host text) for cross-tabs: capability classes and META-01 indicator kinds."""
    capabilities: set[str] = set()
    meta01: set[str] = set()
    for result in report.checks:
        for f in result.findings:
            details = f.details or {}
            if result.check_id == "META-03":
                for kinds in (details.get("arbitrary") or {}).values():
                    capabilities.update(str(k) for k in kinds)
                capabilities.update(str(k) for k in (details.get("by_class") or {}))
            elif result.check_id == "META-01" and f.severity.rank >= Severity.MEDIUM.rank:
                meta01.update(
                    str(i.get("kind"))
                    for i in details.get("indicators") or []
                    if str(i.get("severity")) in ("medium", "high", "critical")
                )
    ran = {r.check_id for r in report.checks if r.status == CheckStatus.RAN}
    out: dict[str, Any] = {}
    if "META-03" in ran:
        out["capabilities"] = sorted(capabilities)
    if "META-01" in ran:
        out["meta01_indicators"] = sorted(meta01)
    return out


async def scan_target(
    target: dict[str, Any], cfg: BatchConfig, state: GuardState, pacer: HostPacer
) -> dict[str, Any]:
    """Scan one host's first URL; returns the checkpoint record (no bodies, no text from the host)."""
    host = str(target["host"])
    key = rate_key(host)
    url = str(target["urls"][0])
    record: dict[str, Any] = {
        "host": host,
        "rate_key": key,
        "url": url,
        "transport": (target.get("transports") or [""])[0],
        "entries": list(target.get("entries") or []),
        "needs_headers": bool(target.get("needs_headers")),
        "started_at": utcnow().isoformat(),
    }

    def finish(status: HostStatus, reason: str | None = None, **extra: Any) -> dict[str, Any]:
        record.update(status=status.value, reason=reason, requests=state.requests.get(host, 0), **extra)
        record.setdefault("outcomes", _outcomes_for(status, cfg.checks))
        record["finished_at"] = utcnow().isoformat()
        return record

    if key in state.stopped:
        return finish(HostStatus.BLOCKED, f"rate key stopped earlier ({state.stopped[key]}); nothing sent")
    inner = cfg.transport_factory(host) if cfg.transport_factory else httpx.AsyncHTTPTransport(verify=True)
    guard = PoliteTransport(
        inner,
        target_host=host,
        pacer=pacer,
        state=state,
        resolver=cfg.resolver or default_resolver,
        pin=cfg.pin_addresses,
    )
    config = ScanConfig(
        target=url,
        timeout=cfg.timeout,
        rate=cfg.scanner_rate,
        options=ScanOptions(follow_authorization_server=False, write_baseline=False, timeout=cfg.timeout),
        only=list(cfg.checks),
        user_agent=cfg.user_agent,
        txt_lookup=cfg.txt_lookup,
        max_rate_limit_wait=0.0,
        _unsafe_allow_any_rate=cfg._unsafe_allow_any_rate,
        _httpx_transport=guard,
    )
    try:
        report, _evidence = await asyncio.wait_for(run_scan(config), timeout=cfg.host_timeout)
    except OptOutError:
        return finish(HostStatus.OPTED_OUT, "operator opted out (DNS TXT or well-known document)")
    except TransportError as exc:
        if host in state.refused:
            return finish(HostStatus.SKIPPED_PRIVATE, state.refused[host])
        return finish(HostStatus.UNREACHABLE, type(exc).__name__)
    except TimeoutError:
        return finish(HostStatus.ERROR, f"host scan exceeded {cfg.host_timeout:g} s")
    except Exception as exc:
        return finish(HostStatus.ERROR, type(exc).__name__)
    finally:
        await guard.aclose()
    # Order matters: a refusal or stop overrides whatever the (now partial) report says.
    if host in state.refused:
        return finish(HostStatus.SKIPPED_PRIVATE, state.refused[host])
    if key in state.stopped:
        return finish(HostStatus.BLOCKED, f"stopped after {state.stopped[key]}")
    if report.target_kind == "not_mcp":
        return finish(HostStatus.NOT_MCP, "answered, but not as an MCP server")
    if report.target_kind == "unreachable":
        return finish(HostStatus.UNREACHABLE, "no MCP negotiation succeeded")
    fp = report.fingerprint
    return finish(
        HostStatus.SCANNED,
        None,
        outcomes=outcomes_from_report(report),
        protocol_version=fp.protocol_version if fp else None,
        flavour=fp.flavour if fp else None,
        auth_required=bool(fp.auth_required) if fp else None,
        edge=report.environment.edge if report.environment else None,
        inventory=dict(report.inventory_summary or {}),
        meta01_rules=META01_RULES if "META-01" in cfg.checks else None,
        checks_run=list(cfg.checks),
        **derived_labels(report),
    )


def group_by_rate_key(targets: Iterable[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for t in targets:
        groups[rate_key(str(t["host"]))].append(t)
    # Largest groups first: they bound the total runtime, so start them early.
    return sorted(groups.values(), key=lambda g: (-len(g), rate_key(str(g[0]["host"]))))


@dataclass(slots=True)
class BatchResult:
    scanned_now: int = 0
    already_done: int = 0
    remaining: int = 0
    statuses: Counter[str] = field(default_factory=Counter)
    plan: dict[str, Any] = field(default_factory=dict)


def plan(targets: list[dict[str, Any]], cfg: BatchConfig) -> dict[str, Any]:
    """Runtime estimate: the larger of (total work / workers) and (largest rate-key group)."""
    groups = group_by_rate_key(targets)
    workers = min(cfg.effective_concurrency(), max(1, len(groups)))
    per_host = EST_REQUESTS_PER_HOST * cfg.per_host_interval
    total = len(targets) * per_host
    largest = (len(groups[0]) if groups else 0) * per_host
    seconds = max(total / workers, largest) if targets else 0.0
    return {
        "hosts": len(targets),
        "rate_keys": len(groups),
        "largest_rate_key_group": len(groups[0]) if groups else 0,
        "workers": workers,
        "est_requests": len(targets) * EST_REQUESTS_PER_HOST,
        "est_seconds": round(seconds),
        "est_hours": round(seconds / 3600, 2),
    }


async def run_batch(
    targets: list[dict[str, Any]],
    checkpoint: Path,
    cfg: BatchConfig | None = None,
    *,
    limit: int | None = None,
    dry_run: bool = False,
    pacer: HostPacer | None = None,
    state: GuardState | None = None,
) -> BatchResult:
    """Scan every target not yet in ``checkpoint`` (JSONL, one record per host, appended as each finishes)."""
    cfg = cfg or BatchConfig()
    workers = cfg.effective_concurrency()
    state = state or GuardState()
    done: set[str] = set()
    for rec in read_jsonl(checkpoint):
        done.add(str(rec.get("host")))
        if rec.get("status") == HostStatus.BLOCKED.value:
            # Stay stopped across resumes: a provider that refused us once is not retried.
            state.stopped.setdefault(str(rec.get("rate_key")), "a refusal in an earlier run")
    todo = [t for t in targets if t["host"] not in done]
    if limit is not None:
        todo = todo[: max(0, limit)]
    result = BatchResult(already_done=len(done & {t["host"] for t in targets}))
    result.plan = plan(todo, cfg)
    if dry_run:
        result.remaining = len(todo)
        return result
    pacer = pacer or HostPacer(cfg.per_host_interval, cfg.clock, cfg.sleep)
    queue: asyncio.Queue[list[dict[str, Any]]] = asyncio.Queue()
    for group in group_by_rate_key(todo):
        queue.put_nowait(group)
    lock = asyncio.Lock()

    async def worker() -> None:
        while True:
            try:
                group = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            for target in group:
                rec = await scan_target(target, cfg, state, pacer)
                async with lock:
                    append_jsonl(checkpoint, rec)
                    result.scanned_now += 1
                    result.statuses[rec["status"]] += 1

    await asyncio.gather(*(worker() for _ in range(min(workers, max(1, queue.qsize())))))
    result.remaining = len([t for t in targets if t["host"] not in done]) - result.scanned_now
    return result
