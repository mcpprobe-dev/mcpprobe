"""Authorisation gate for active mode.

Active checks call tools or send probe payloads, so they are allowed only when:

1. the operator states who authorised the scan (``--authorised-by``) and the
   agreed scope (``--scope``), **and**
2. ownership verification passes:

   * ``dns-txt``: a TXT record ``mcpprobe-verification=<token>`` exists on the
     target host (or ``_mcpprobe-challenge.<host>``). The token is generated
     locally with ``mcpprobe token <host>`` and stored under the user's config
     directory, or supplied with ``--token``.
   * ``local``: only for stdio targets, which the operator runs on their own
     machine.

Every active scan writes an authorisation record JSON next to the report. The
record is the evidence that the scan was authorised (who, what, which proof,
when, with which limits). Passive mode never consults this module, but the
ownership rule in README.md applies to every mode.

This is a gate in code, not policy: :func:`authorise` raises
:class:`AuthorisationError` and the scanner refuses to run active checks
without a verified record.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mcpprobe import __version__
from mcpprobe.models import CheckMode, utcnow

TXT_PREFIX = "mcpprobe-verification="
CHALLENGE_LABEL = "_mcpprobe-challenge"
VERIFY_METHODS = ("dns-txt", "local")

#: Resolver signature: name -> list of TXT strings. Injected in tests.
TxtLookup = Callable[[str], list[str]]


class AuthorisationError(Exception):
    """Raised when active mode is requested without a valid authorisation."""


class VerificationResult(BaseModel):
    method: str
    verified: bool
    detail: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class AuthorisationRecord(BaseModel):
    """Written next to the report for every active scan."""

    timestamp: str
    scanner_version: str = __version__
    target: str
    transport: str
    mode: CheckMode
    authorised_by: str | None
    scope: str | None
    operator_reference: str | None = None
    verification: VerificationResult
    excluded_tools: list[str] = Field(default_factory=list)
    rate_cap_rps: float
    max_concurrent_tool_calls: int = 1
    token_fingerprint: str | None = Field(
        default=None, description="sha256 prefix of the verification token, never the token itself"
    )

    @property
    def verified(self) -> bool:
        return self.verification.verified


# ----------------------------------------------------------------------------- tokens
def generate_token() -> str:
    """32 random bytes, base32 lower-case without padding (52 chars)."""
    return base64.b32encode(secrets.token_bytes(32)).decode("ascii").rstrip("=").lower()


def token_store_path() -> Path:
    override = os.environ.get("MCPPROBE_TOKEN_STORE")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "mcpprobe" / "verification-tokens.json"


def _load_store(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_token(host: str, token: str, path: Path | None = None) -> Path:
    path = path or token_store_path()
    store = _load_store(path)
    store[host.lower()] = {"token": token, "created_at": utcnow().isoformat()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True), "utf-8")
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return path


def load_token(host: str, path: Path | None = None) -> str | None:
    entry = _load_store(path or token_store_path()).get(host.lower())
    if isinstance(entry, dict) and isinstance(entry.get("token"), str):
        return entry["token"]
    return None


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def expected_txt_record(token: str) -> str:
    return TXT_PREFIX + token


# ------------------------------------------------------------------------- verifiers
def default_txt_lookup(name: str) -> list[str]:
    """Resolve TXT records with dnspython; returns [] on NXDOMAIN/no answer."""
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        raise AuthorisationError(f"DNS lookup failed for {name}: {exc}") from exc
    out: list[str] = []
    for rdata in answers:
        strings = getattr(rdata, "strings", None)
        if strings is None:
            out.append(str(rdata).strip('"'))
        else:
            out.append(b"".join(strings).decode("utf-8", errors="replace"))
    return out


def verify_dns_txt(host: str, token: str, lookup: TxtLookup | None = None) -> VerificationResult:
    """Check ``mcpprobe-verification=<token>`` on ``host`` or ``_mcpprobe-challenge.host``."""
    if not host:
        return VerificationResult(method="dns-txt", verified=False, detail="target has no host name")
    lookup = lookup or default_txt_lookup
    expected = expected_txt_record(token)
    seen: dict[str, list[str]] = {}
    for name in (host, f"{CHALLENGE_LABEL}.{host}"):
        records = lookup(name)
        # Keep only our own records in the snapshot; other TXT data is not ours to store.
        seen[name] = [r for r in records if r.startswith(TXT_PREFIX)]
        if expected in records:
            return VerificationResult(
                method="dns-txt",
                verified=True,
                detail=f"TXT record found at {name}",
                evidence={"name": name, "records": seen[name], "checked_at": utcnow().isoformat()},
            )
    return VerificationResult(
        method="dns-txt",
        verified=False,
        detail=f"no TXT record {TXT_PREFIX}<token> found on {host} or {CHALLENGE_LABEL}.{host}",
        evidence={"records_seen": seen, "checked_at": utcnow().isoformat()},
    )


def verify_local(transport: str) -> VerificationResult:
    if transport != "stdio":
        return VerificationResult(
            method="local",
            verified=False,
            detail="'local' verification is only valid for stdio targets the operator runs themselves",
        )
    return VerificationResult(
        method="local",
        verified=True,
        detail="stdio package executed locally by the operator",
        evidence={"checked_at": utcnow().isoformat()},
    )


# ------------------------------------------------------------------------------ gate
def authorise(
    *,
    target: str,
    transport: str,
    host: str,
    active: bool,
    authorised_by: str | None,
    scope: str | None,
    verify_method: str | None,
    token: str | None = None,
    excluded_tools: Iterable[str] = (),
    rate_cap_rps: float,
    reference: str | None = None,
    lookup: TxtLookup | None = None,
    token_store: Path | None = None,
) -> AuthorisationRecord:
    """Build the authorisation record; raise :class:`AuthorisationError` if active mode is not allowed.

    For passive mode the function still returns a record (unverified, for the
    report), but never raises.
    """
    mode = CheckMode.ACTIVE if active else CheckMode.PASSIVE
    fingerprint: str | None = None
    if not active:
        verification = VerificationResult(method="none", verified=False, detail="passive mode; no verification")
        return _record(target, transport, mode, authorised_by, scope, reference, verification,
                       excluded_tools, rate_cap_rps, None)

    missing = [name for name, value in (("--authorised-by", authorised_by), ("--scope", scope)) if not value]
    if missing:
        raise AuthorisationError("active mode requires " + " and ".join(missing))
    if verify_method not in VERIFY_METHODS:
        raise AuthorisationError(
            f"active mode requires --verify {{{'|'.join(VERIFY_METHODS)}}} (got {verify_method!r})"
        )
    if verify_method == "local":
        verification = verify_local(transport)
    else:
        token = token or load_token(host, token_store)
        if not token:
            raise AuthorisationError(
                f"no verification token for {host}; run 'mcpprobe token {host}' and publish the TXT record, "
                "or pass --token"
            )
        fingerprint = token_fingerprint(token)
        verification = verify_dns_txt(host, token, lookup)
    if not verification.verified:
        raise AuthorisationError(f"ownership verification failed: {verification.detail}")
    return _record(target, transport, mode, authorised_by, scope, reference, verification,
                   excluded_tools, rate_cap_rps, fingerprint)


def _record(
    target: str,
    transport: str,
    mode: CheckMode,
    authorised_by: str | None,
    scope: str | None,
    reference: str | None,
    verification: VerificationResult,
    excluded_tools: Iterable[str],
    rate_cap_rps: float,
    fingerprint: str | None,
) -> AuthorisationRecord:
    return AuthorisationRecord(
        timestamp=utcnow().isoformat(),
        target=target,
        transport=transport,
        mode=mode,
        authorised_by=authorised_by,
        scope=scope,
        operator_reference=reference,
        verification=verification,
        excluded_tools=sorted(set(excluded_tools)),
        rate_cap_rps=rate_cap_rps,
        token_fingerprint=fingerprint,
    )


def record_path_for(report_path: str | os.PathLike[str] | None) -> Path:
    """``<report>.authorisation.json`` next to the report, or a timestamped file in cwd."""
    if report_path:
        p = Path(report_path)
        return p.with_name(p.stem + ".authorisation.json")
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    return Path(f"mcpprobe-authorisation-{stamp}.json")


def write_record(record: AuthorisationRecord, report_path: str | os.PathLike[str] | None) -> Path:
    path = record_path_for(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record.model_dump_json(indent=2), "utf-8")
    return path


def require_active_authorisation(record: AuthorisationRecord | None) -> AuthorisationRecord:
    """Second gate used by the orchestrator right before running active checks."""
    if record is None or record.mode != CheckMode.ACTIVE or not record.verified:
        raise AuthorisationError("active checks refused: no verified authorisation record")
    return record
