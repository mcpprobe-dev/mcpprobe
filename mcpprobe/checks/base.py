"""Plugin framework for checks.

A check is a class with an ``id``, ``title``, default ``severity``, a
``standards`` mapping, a ``mode`` (passive or active) and an async
``run(ctx) -> list[Finding]``. The orchestrator decides whether a check may run
(active checks require the authorisation gate) and records a
:class:`~mcpprobe.models.CheckResult` for every check, including skipped ones,
so reports show coverage honestly.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcpprobe.models import (
    CheckMode,
    Confidence,
    EvidenceRecord,
    Finding,
    Fingerprint,
    Inventory,
    Severity,
    Standards,
)
from mcpprobe.transport import EvidenceLog, HttpTransport, Transport

if TYPE_CHECKING:
    from mcpprobe.authz import AuthorisationRecord

#: Signature of the optional LLM-judge hook. It receives the text under review
#: and a short task description and returns ``None`` (abstain) or a verdict.
JudgeFn = Callable[[str, str], "JudgeVerdict | None"]


@dataclass(slots=True)
class JudgeVerdict:
    """Verdict from an optional second-opinion judge (no network call is made by mcpprobe)."""

    suspicious: bool
    rationale: str = ""
    confidence: Confidence = Confidence.LOW


@dataclass(slots=True)
class ScanOptions:
    """User-controlled knobs that checks may consult."""

    mode: CheckMode = CheckMode.PASSIVE
    baseline_path: str | None = None
    write_baseline: bool = True
    judge: JudgeFn | None = None
    excluded_tools: set[str] = field(default_factory=set)
    #: AUTH-03 fetches the authorization server's metadata, which may live on a
    #: third-party host. Set False to keep all traffic on the target host.
    follow_authorization_server: bool = True
    #: Environment passed to a stdio server (scanned by META-05 for secrets).
    stdio_env: dict[str, str] = field(default_factory=dict)
    stdio_command: list[str] = field(default_factory=list)
    timeout: float = 15.0
    #: DNS TXT resolver used for opt-out checks on third-party hosts (injected in tests).
    txt_lookup: Callable[[str], list[str]] | None = None


class ScanContext:
    """Everything a check needs: the negotiated transport, the inventory and options."""

    def __init__(
        self,
        *,
        target: str,
        transport: Transport,
        fingerprint: Fingerprint,
        inventory: Inventory,
        evidence: EvidenceLog,
        options: ScanOptions | None = None,
        authorisation: AuthorisationRecord | None = None,
    ) -> None:
        self.target = target
        self.transport = transport
        self.fingerprint = fingerprint
        self.inventory = inventory
        self.evidence = evidence
        self.options = options or ScanOptions()
        self.authorisation = authorisation
        self.notes: list[str] = []
        #: Scratch space for checks to share derived data (e.g. META-03 classes).
        self.shared: dict[str, Any] = {}

    @property
    def http(self) -> HttpTransport | None:
        return self.transport if isinstance(self.transport, HttpTransport) else None

    @property
    def is_http(self) -> bool:
        return self.http is not None

    @property
    def active_allowed(self) -> bool:
        """Active checks may run only when the authorisation gate produced a verified record."""
        return (
            self.options.mode == CheckMode.ACTIVE
            and self.authorisation is not None
            and self.authorisation.verified
        )

    def tool_names(self) -> list[str]:
        return [str(t.get("name", "")) for t in self.inventory.tools]


class Check(abc.ABC):
    """Base class for all checks. Subclasses set the class attributes and implement ``run``."""

    id: str = "BASE-00"
    title: str = ""
    severity: Severity = Severity.MEDIUM
    standards: Standards = Standards()
    mode: CheckMode = CheckMode.PASSIVE
    #: Which transports the check makes sense for.
    applies_to: frozenset[str] = frozenset({"http", "stdio"})
    #: One-paragraph description for CHECKS.md and SARIF rule help.
    description: str = ""
    #: What the evidence consists of (used in docs).
    evidence_type: str = ""
    #: Known false-positive conditions (used in docs and attached to findings).
    false_positive_notes: str = ""
    #: Default remediation text.
    fix: str = ""

    @abc.abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute the check and return zero or more findings."""

    def finding(
        self,
        *,
        description: str,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.HIGH,
        evidence: list[EvidenceRecord] | None = None,
        location: str | None = None,
        fix: str | None = None,
        details: dict[str, Any] | None = None,
        title: str | None = None,
        excerpt: str | None = None,
    ) -> Finding:
        """Build a :class:`Finding` pre-filled from the check's metadata.

        ``excerpt`` overrides the evidence excerpt that is otherwise derived from
        the first evidence record.
        """
        records = [e for e in (evidence or []) if e is not None]
        return Finding(
            id=self.id,
            title=title or self.title,
            severity=severity or self.severity,
            confidence=confidence,
            standards=self.standards,
            description=description,
            fix=fix or self.fix,
            evidence=records,
            evidence_excerpt=excerpt if excerpt is not None else evidence_excerpt(records),
            location=location,
            details=details or {},
            false_positive_notes=self.false_positive_notes or None,
        )

    def applies(self, ctx: ScanContext) -> bool:
        return ctx.transport.name in self.applies_to


class ActiveCheck(Check):
    """Base for checks that may call tools or send probe payloads.

    Subclasses must call :meth:`require_active` first. The orchestrator also
    refuses to run active checks without authorisation, so this is a second
    line of defence inside the check itself.
    """

    mode = CheckMode.ACTIVE

    @staticmethod
    def require_active(ctx: ScanContext) -> None:
        if not ctx.active_allowed:
            raise PermissionError("active check requires --active with a verified authorisation record")


EXCERPT_BODY_CHARS = 240


def evidence_excerpt(records: list[EvidenceRecord]) -> str:
    """One-line summary of the first evidence record: request, status and a body snippet."""
    if not records:
        return ""
    rec = records[0]
    head = rec.method
    if rec.url and rec.transport == "http":
        head += f" {rec.url}"
    if rec.status is not None:
        head += f" -> HTTP {rec.status}"
    elif rec.error:
        head += f" -> {rec.error}"
    body = " ".join(rec.response_body.split())
    if len(body) > EXCERPT_BODY_CHARS:
        body = body[: EXCERPT_BODY_CHARS - 1] + "\u2026"
    extra = f" (+{len(records) - 1} more)" if len(records) > 1 else ""
    return f"[{rec.id}] {head}" + (f": {body}" if body else "") + extra


def evidence_summary(records: list[EvidenceRecord], summary: str) -> str:
    """``[ev-0005] tools/list -> HTTP 200: <summary>`` for checks that know what matters."""
    if not records:
        return summary
    rec = records[0]
    head = rec.method + (f" -> HTTP {rec.status}" if rec.status is not None else "")
    return f"[{rec.id}] {head}: {summary}"


def evidence_of(*responses: Any) -> list[EvidenceRecord]:
    """Collect evidence records from RpcResponse objects, ignoring ``None``."""
    out: list[EvidenceRecord] = []
    for r in responses:
        rec = getattr(r, "evidence", None)
        if rec is not None:
            out.append(rec)
    return out
