"""Shared constants, outcome labels, working-directory layout and JSONL helpers."""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

#: Hard ceiling on concurrent host scans, whatever the operator asks for.
MAX_CONCURRENCY = 8
#: Minimum seconds between two requests to the same rate key (1 request per second).
PER_HOST_INTERVAL = 1.0

#: The survey profile: the passive checks whose requests are what an ordinary MCP client
#: sends (negotiation, the ``*/list`` methods, the RFC 9728 well-known document) or that
#: only read what negotiation already returned. Every other passive check sends a
#: deliberately malformed or forged request (bad Origin, bogus version, forged session ID,
#: self-minted JWT, truncated JSON, oversized/deep payloads, a 20-request burst), contacts a
#: third-party authorization server, or writes a baseline; those are fine for an owner
#: scanning their own server and are left out of a survey of servers we do not own.
SURVEY_CHECKS: tuple[str, ...] = (
    "AUTH-01",  # answers without credentials (reads negotiation result)
    "AUTH-02",  # RFC 9728 protected-resource metadata (GET well-known on the same host)
    "TRANS-05",  # plain HTTP / response security headers (reads headers already received)
    "TRANS-06",  # server/discover completeness (reads negotiation result)
    "TRANS-09",  # ttlMs / cacheScope on list results (reads inventory)
    "META-01",  # tool-description poisoning (static, inventory)
    "META-03",  # dangerous capability surface (static, inventory)
    "META-04",  # schema hygiene (static, inventory)
    "META-05",  # secrets in metadata (static, inventory)
    "META-06",  # tool annotation lint (static, inventory)
    "META-07",  # toxic flow / lethal trifecta (static, inventory)
)

#: Checks a ``recheck`` re-runs by default: the ones that read the tool list, whose rules can
#: change between releases without the server changing.
RECHECK_CHECKS: tuple[str, ...] = ("META-01", "META-03", "META-05", "META-07")

#: Capability classes (META-03 labels) that write, execute or move data: the "write/exec-capable"
#: cross-tab. ``arbitrary_*`` are the free-form shell/file capabilities META-03 rates high.
WRITE_EXEC_CAPABILITIES: frozenset[str] = frozenset(
    {
        "exec",
        "file_write",
        "database_write",
        "email",
        "payments",
        "arbitrary_command_execution",
        "arbitrary_file_read",
        "arbitrary_file_write",
    }
)

#: Checks that work on tool definitions alone (no request at all).
STATIC_CHECKS: tuple[str, ...] = ("META-01", "META-06", "META-07")


class Outcome(str, Enum):
    """Per-check outcome stored in the checkpoint. Severities are stored as their value."""

    PASSED = "passed"
    NOT_APPLICABLE = "n_a"
    BLOCKED = "blocked"
    UNREACHABLE = "unreachable"
    NOT_MCP = "not_mcp"
    NOT_ASSESSABLE = "not_assessable"
    ERROR = "error"


#: Finding outcomes are the severity value of the most severe finding.
SEVERITY_OUTCOMES = ("critical", "high", "medium", "low", "info")


class HostStatus(str, Enum):
    """What happened to one remote host as a whole."""

    SCANNED = "scanned"
    OPTED_OUT = "opted_out"
    BLOCKED = "blocked"  # HTTP 429 or 403: we stopped for this host (and its rate key)
    SKIPPED_PRIVATE = "skipped_private"  # resolved to a loopback/private/reserved address
    UNREACHABLE = "unreachable"
    NOT_MCP = "not_mcp"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class WorkDir:
    """Layout of a report working directory. Everything in it is private working state."""

    root: Path

    @property
    def pages(self) -> Path:
        return self.root / "registry"

    @property
    def fetch_state(self) -> Path:
        return self.root / "fetch-state.json"

    @property
    def entries(self) -> Path:
        return self.root / "entries.jsonl"

    @property
    def targets(self) -> Path:
        return self.root / "targets.jsonl"

    @property
    def selection(self) -> Path:
        return self.root / "selection.json"

    @property
    def static(self) -> Path:
        return self.root / "static.jsonl"

    @property
    def scan(self) -> Path:
        return self.root / "scan.jsonl"

    @property
    def calibration(self) -> Path:
        return self.root / "calibration.json"

    @property
    def aggregates(self) -> Path:
        return self.root / "aggregates.json"

    @property
    def recheck(self) -> Path:
        """The current recheck pass (resumable checkpoint)."""
        return self.root / "recheck.jsonl"

    def recheck_files(self) -> list[Path]:
        """Earlier passes (``recheck-<UTC time>.jsonl``, oldest first), then the current one."""
        archived = sorted(self.root.glob("recheck-*.jsonl"))
        return [*archived, *([self.recheck] if self.recheck.exists() else [])]

    @property
    def disclosure_summary(self) -> Path:
        """Counts only (no host): safe to share, unlike the PRIVATE queue."""
        return self.root / "disclosure-summary.json"

    @property
    def disclosure_queue(self) -> Path:
        return self.root / "PRIVATE-disclosure-queue.json"

    @property
    def report_dir(self) -> Path:
        return self.root / "report"

    def ensure(self) -> WorkDir:
        self.root.mkdir(parents=True, exist_ok=True)
        return self


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Yield the JSON objects of a JSONL file, skipping blank and torn (partially written) lines."""
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue  # a line torn by a crash mid-write; that host is simply redone
            if isinstance(obj, dict):
                yield obj


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    """Atomically replace ``path`` with ``rows``; returns the row count."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    n = 0
    with tmp.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            n += 1
    os.replace(tmp, path)
    return n


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    """Append one row and fsync, so a crash loses at most the row being written.

    If an earlier crash left a torn last line (no trailing newline), start a new line
    first so the torn fragment cannot swallow this row.
    """
    torn = False
    if path.exists() and path.stat().st_size:
        with path.open("rb") as fh:
            fh.seek(-1, os.SEEK_END)
            torn = fh.read(1) != b"\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(("\n" if torn else "") + json.dumps(row, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def write_json(path: Path, obj: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def is_public_address(address: str) -> bool:
    """True only for globally routable unicast addresses (not loopback, private, CGNAT, reserved...)."""
    try:
        ip = ipaddress.ip_address(address.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def rate_key(host: str) -> str:
    """The key requests are paced and stopped by: the last two DNS labels.

    Without a public-suffix list this over-groups (``a.co.uk`` and ``b.co.uk`` share
    ``co.uk``), which only makes the scan slower and more conservative: many registry
    entries live on per-server subdomains of one hosting provider, and the provider
    should see 1 request per second from us in total, not 1 per subdomain.
    """
    h = host.lower().rstrip(".")
    if is_ip_literal(h):
        return h
    labels = h.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else h


def findings_outcome(severities: Iterable[str]) -> str:
    """``passed`` for no findings, otherwise the most severe finding's severity value."""
    order = {s: i for i, s in enumerate(SEVERITY_OUTCOMES)}
    worst = min((s for s in severities if s in order), key=lambda s: order[s], default=None)
    return worst or Outcome.PASSED.value


def is_finding(outcome: str | None) -> bool:
    return outcome in SEVERITY_OUTCOMES


def is_assessed(outcome: str | None) -> bool:
    """A check that ran to a conclusion: passed or a finding (never n/a, blocked...)."""
    return outcome == Outcome.PASSED.value or is_finding(outcome)
