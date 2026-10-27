"""Check registry.

``ALL_CHECKS`` lists every check class in execution order. Passive checks run
by default; active ones are stubs gated behind the authorisation record.
"""

from __future__ import annotations

from collections.abc import Iterable

from mcpprobe.checks.active_stubs import ACTIVE_STUBS
from mcpprobe.checks.auth import (
    Auth01NoAuthentication,
    Auth02MissingProtectedResourceMetadata,
    Auth03AuthorizationServerMetadata,
    Auth04TokenAudienceAndPassthrough,
)
from mcpprobe.checks.base import (
    ActiveCheck,
    Check,
    JudgeFn,
    JudgeVerdict,
    ScanContext,
    ScanOptions,
)
from mcpprobe.checks.baseline import Meta02RugPullBaseline
from mcpprobe.checks.metadata import (
    Meta03DangerousCapabilitySurface,
    Meta04SchemaHygiene,
    Meta05SecretsInMetadata,
)
from mcpprobe.checks.poisoning import Meta01ToolDescriptionPoisoning
from mcpprobe.checks.robustness import Dos01UnboundedConsumption, Err01VerboseErrors
from mcpprobe.checks.transport_conformance import (
    Trans01OriginValidation,
    Trans02ProtocolVersionHandling,
    Trans03SessionIdQuality,
    Trans04DeprecatedTransport,
    Trans05TlsAndHeaders,
)

PASSIVE_CHECKS: list[type[Check]] = [
    Auth01NoAuthentication,
    Auth02MissingProtectedResourceMetadata,
    Auth03AuthorizationServerMetadata,
    Auth04TokenAudienceAndPassthrough,
    Trans01OriginValidation,
    Trans02ProtocolVersionHandling,
    Trans03SessionIdQuality,
    Trans04DeprecatedTransport,
    Trans05TlsAndHeaders,
    Meta01ToolDescriptionPoisoning,
    Meta02RugPullBaseline,
    Meta03DangerousCapabilitySurface,
    Meta04SchemaHygiene,
    Meta05SecretsInMetadata,
    Err01VerboseErrors,
    Dos01UnboundedConsumption,
]

ALL_CHECKS: list[type[Check]] = [*PASSIVE_CHECKS, *ACTIVE_STUBS]

_BY_ID: dict[str, type[Check]] = {c.id: c for c in ALL_CHECKS}


def get_check(check_id: str) -> type[Check]:
    try:
        return _BY_ID[check_id.upper()]
    except KeyError as exc:
        raise KeyError(f"unknown check id: {check_id}") from exc


def select_checks(only: Iterable[str] | None = None, skip: Iterable[str] | None = None) -> list[Check]:
    """Instantiate checks, honouring ``--only`` / ``--skip`` lists."""
    only_set = {s.upper() for s in only} if only else None
    skip_set = {s.upper() for s in skip} if skip else set()
    for cid in (only_set or set()) | skip_set:
        get_check(cid)  # raise on typos
    out: list[Check] = []
    for cls in ALL_CHECKS:
        if only_set is not None and cls.id not in only_set:
            continue
        if cls.id in skip_set:
            continue
        out.append(cls())
    return out


__all__ = [
    "ALL_CHECKS",
    "PASSIVE_CHECKS",
    "ActiveCheck",
    "Check",
    "JudgeFn",
    "JudgeVerdict",
    "ScanContext",
    "ScanOptions",
    "get_check",
    "select_checks",
]
