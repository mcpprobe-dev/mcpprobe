"""Core data models shared by the transport, checks and reporters.

Everything a reporter needs to render is a pydantic model so that the JSON
report is a faithful, schema-stable serialisation of what the scanner saw.
"""

from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

#: Maximum number of body bytes retained per request/response in evidence.
#: Proof excerpts are always built from parsed data, never from this copy.
EVIDENCE_BODY_LIMIT = 64 * 1024

#: Version of the JSON report schema (see docs/report-schema.md).
REPORT_SCHEMA_VERSION = "0.2"


class Severity(str, Enum):
    """Finding severity, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank so severities can be compared (``info`` = 0)."""
        return _SEVERITY_ORDER.index(self)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class Confidence(str, Enum):
    """How sure the scanner is that a finding is a true positive."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CheckMode(str, Enum):
    """Passive checks only send requests a client might send plus benign
    malformed ones; active checks need explicit authorisation."""

    PASSIVE = "passive"
    ACTIVE = "active"


class Standards(BaseModel):
    """Mapping of a check onto the four OWASP artefacts.

    IDs are kept verbatim as published. The OWASP MCP Top 10 is still a beta
    list, so its IDs carry a ``(beta)`` suffix in rendered output.
    """

    mcp: list[str] = Field(default_factory=list, description="OWASP MCP Top 10, e.g. MCP07:2025")
    asi: list[str] = Field(default_factory=list, description="OWASP Agentic Top 10, e.g. ASI03")
    llm_2025: list[str] = Field(default_factory=list, description="OWASP LLM Top 10 2025")
    llm_2026: list[str] = Field(default_factory=list, description="OWASP LLM Top 10 2026")

    def as_tags(self) -> list[str]:
        """Flatten to a list of strings suitable for SARIF ``tags``."""
        tags = [f"{m} (beta)" for m in self.mcp]
        tags += list(self.asi)
        tags += list(self.llm_2026)
        tags += list(self.llm_2025)
        return tags


class EvidenceRecord(BaseModel):
    """One request/response pair observed by the transport.

    Bodies are truncated to :data:`EVIDENCE_BODY_LIMIT` bytes. Every header is
    kept; values of credential-bearing headers (Authorization, Cookie,
    Set-Cookie, anything named like a token, key or secret) are redacted.
    """

    id: str
    timestamp: dt.datetime
    transport: str = Field(description="'http' or 'stdio'")
    method: str = Field(description="JSON-RPC method, or HTTP verb for non-RPC requests")
    url: str | None = None
    status: int | None = Field(default=None, description="HTTP status; None for stdio")
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""
    request_truncated: bool = False
    response_truncated: bool = False
    elapsed_ms: float | None = None
    note: str | None = None
    error: str | None = Field(default=None, description="Transport-level error, if any")


class Finding(BaseModel):
    """A single security finding produced by a check."""

    id: str = Field(description="Check ID, e.g. AUTH-01")
    title: str
    severity: Severity
    confidence: Confidence
    standards: Standards
    description: str = Field(description="What was observed and why it matters")
    fix: str = Field(description="Plain-English remediation")
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    evidence_excerpt: str = Field(
        default="",
        description="Short human-readable excerpt of the evidence (request, status, body snippet)",
    )
    location: str | None = Field(
        default=None,
        description="Where in the target the issue lives (tool name, header, URL path...)",
    )
    details: dict[str, Any] = Field(default_factory=dict)
    false_positive_notes: str | None = None
    confidence_reason: str | None = Field(
        default=None, description="Why the confidence is what it is; always set when confidence is not high"
    )
    verify: str | None = Field(default=None, description="One runnable line that confirms the fix")
    affected: list[str] = Field(
        default_factory=list, description="Tools, headers or paths affected by this root cause"
    )
    proof: str = Field(
        default="",
        description="Multi-line excerpt that proves the finding, built from parsed data, never truncated mid-object",
    )
    evidence_ids: list[str] = Field(
        default_factory=list, description="IDs of the supporting evidence records"
    )

    @property
    def fingerprint(self) -> str:
        """Stable identity for de-duplication across scans (used in SARIF)."""
        return f"{self.id}:{self.location or '-'}"


class CheckStatus(str, Enum):
    """Outcome of running one check, independent of whether it found anything."""

    RAN = "ran"
    SKIPPED = "skipped"
    NOT_IMPLEMENTED = "not_implemented"
    ERROR = "error"
    #: Preconditions absent (nothing to test). Never counts as a pass.
    NOT_APPLICABLE = "not_applicable"


class CheckResult(BaseModel):
    """Coverage record for a check: what ran, what was skipped and why."""

    check_id: str
    title: str
    mode: CheckMode
    status: CheckStatus
    reason: str | None = None
    related_to: str | None = Field(
        default=None, description="Check whose result makes this one not applicable, e.g. AUTH-01"
    )
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: float | None = None

    @property
    def passed(self) -> bool:
        """True only when the check actually ran and found nothing."""
        return self.status == CheckStatus.RAN and not self.findings


class Fingerprint(BaseModel):
    """What the transport learned about the target during negotiation."""

    transport: str
    protocol_version: str | None = None
    flavour: str = Field(
        default="unknown",
        description="'stateless-2026' | 'handshake' | 'legacy-sse' | 'unknown'",
    )
    auth_required: bool = False
    www_authenticate: str | None = None
    session_id_seen: bool = False
    credentials_supplied: bool = Field(
        default=False,
        description="The operator supplied credential headers; auth_required then reflects an unauthenticated probe",
    )
    server_info: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    instructions: str | None = None
    attempts: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class Inventory(BaseModel):
    """Tools, prompts and resources listed by the server."""

    tools: list[dict[str, Any]] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    tools_error: str | None = None
    prompts_error: str | None = None
    resources_error: str | None = None
    tools_evidence: EvidenceRecord | None = None
    prompts_evidence: EvidenceRecord | None = None
    resources_evidence: EvidenceRecord | None = None

    def summary(self) -> dict[str, int]:
        return {
            "tools": len(self.tools),
            "prompts": len(self.prompts),
            "resources": len(self.resources),
        }


class AttestationItem(BaseModel):
    """A governance item that cannot be assessed by an automated scan.

    Reported honestly as "attestation only" with a short checklist, rather
    than faking coverage.
    """

    id: str
    title: str
    standards: Standards
    reason: str = Field(description="Why a black-box scan cannot assess this")
    checklist: list[str] = Field(default_factory=list)
    status: str = "attestation-only"


class Chain(BaseModel):
    """Several findings that together form one attack path."""

    id: str
    title: str
    severity: Severity
    finding_ids: list[str] = Field(description="Check IDs of the constituent findings")
    narrative: str


class Environment(BaseModel):
    """Where the target appears to run (derived from response headers and the host)."""

    edge: str | None = Field(
        default=None,
        description="'aws-api-gateway' | 'aws-cloudfront' | 'cloudflare' | 'vercel' | None",
    )
    public: bool = False
    signals: list[str] = Field(default_factory=list, description="Headers that identified the edge")


class ScanReport(BaseModel):
    """Top-level report document."""

    schema_version: str = REPORT_SCHEMA_VERSION
    scanner: str = "mcpprobe"
    version: str
    target_kind: str = Field(
        default="mcp", description="'mcp' | 'not_mcp' | 'unreachable'; checks only run against 'mcp'"
    )
    target: str
    mode: CheckMode
    started_at: dt.datetime
    finished_at: dt.datetime | None = None
    fingerprint: Fingerprint | None = None
    inventory_summary: dict[str, int] = Field(default_factory=dict)
    checks: list[CheckResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attestations: list[AttestationItem] = Field(default_factory=list)
    chains: list[Chain] = Field(default_factory=list)
    environment: Environment | None = None
    evidence_count: int = 0
    authorisation_record: str | None = Field(
        default=None, description="Path of the authorisation record JSON, if active mode"
    )
    notes: list[str] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        """Number of findings per severity (all five keys always present)."""
        out = {s.value: 0 for s in _SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def coverage(self) -> dict[str, int]:
        """Check outcomes. ``passed`` counts only checks that ran and found nothing."""
        out = {
            "passed": 0,
            "with_findings": 0,
            "not_applicable": 0,
            "skipped": 0,
            "not_implemented": 0,
            "error": 0,
        }
        for c in self.checks:
            if c.status == CheckStatus.RAN:
                out["passed" if not c.findings else "with_findings"] += 1
            else:
                out[c.status.value] += 1
        return out

    def max_severity(self) -> Severity | None:
        """Highest severity present, or ``None`` when there are no findings."""
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


def utcnow() -> dt.datetime:
    """Timezone-aware UTC now (kept here so tests can monkeypatch one place)."""
    return dt.datetime.now(dt.UTC)
