"""Static tool-definition checks (META-01, META-06, META-07) for every registry entry.

The registry's ``server.json`` has no tool list: clients read tools from the running
server. Some publishers repeat tool definitions under
``_meta["io.modelcontextprotocol.registry/publisher-provided"]``; when full definitions
(name plus description/inputSchema/annotations) are there, the three checks run on them
exactly as they would on a ``tools/list`` result. Otherwise the entry is recorded as
``not_assessable`` with the reason. A ``package_tools`` hook can supply definitions
from package metadata; none is wired in by default because package registries do not
publish MCP tool lists and installing a package to list its tools would execute
third-party code.

Only outcomes are stored, never the description text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from mcpprobe.checks import NotApplicable, ScanContext, get_check
from mcpprobe.checks.poisoning import RULES_VERSION as META01_RULES
from mcpprobe.models import Fingerprint, Inventory
from mcpprobe.registry.common import STATIC_CHECKS, Outcome, findings_outcome
from mcpprobe.transport import EvidenceLog, RpcResponse, Transport

#: Supplies tool definitions for an entry from its package metadata, or None.
PackageTools = Callable[[dict[str, Any]], list[dict[str, Any]] | None]


class _NoNetworkTransport(Transport):
    """A transport that refuses to send anything: the static checks must not need one."""

    name = "registry-metadata"

    async def rpc(self, method: str, params: dict[str, Any] | None = None, **kwargs: Any) -> RpcResponse:
        raise RuntimeError(f"static assessment attempted a request ({method})")

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise RuntimeError(f"static assessment attempted a notification ({method})")

    async def close(self) -> None:
        return None


async def assess_tools(tools: list[dict[str, Any]], checks: Iterable[str] = STATIC_CHECKS) -> dict[str, str]:
    """Run the static checks on tool definitions; returns check id -> outcome."""
    transport = _NoNetworkTransport()
    ctx = ScanContext(
        target="registry-metadata",
        transport=transport,
        fingerprint=Fingerprint(transport=transport.name, flavour="unknown"),
        inventory=Inventory(tools=list(tools)),
        evidence=EvidenceLog(),
    )
    out: dict[str, str] = {}
    for check_id in checks:
        check = get_check(check_id)()
        try:
            findings = await check.run(ctx)
        except NotApplicable:
            out[check_id] = Outcome.NOT_APPLICABLE.value
            continue
        except Exception:
            out[check_id] = Outcome.ERROR.value
            continue
        out[check_id] = findings_outcome(f.severity.value for f in findings)
    return out


async def assess_entry(entry: dict[str, Any], package_tools: PackageTools | None = None) -> dict[str, Any]:
    """Static record for one entry: kind, whether assessable, where tools came from, outcomes."""
    kind = "remote" if entry.get("remotes") else ("package_only" if entry.get("packages") else "other")
    tools = entry.get("tools")
    source = "registry_meta" if tools else None
    if not tools and package_tools is not None:
        tools = package_tools(entry)
        source = "package_metadata" if tools else None
    record: dict[str, Any] = {
        "name": entry["name"],
        "kind": kind,
        "tool_source": source,
        "meta01_rules": META01_RULES,
    }
    if not tools:
        reason = (
            "registry entry lists tool names only, without descriptions or annotations"
            if entry.get("tool_names_only")
            else "no tool definitions in the registry entry or its package metadata"
        )
        record.update(
            assessable=False,
            reason=reason,
            n_tools=0,
            outcomes={c: Outcome.NOT_ASSESSABLE.value for c in STATIC_CHECKS},
        )
        return record
    record.update(assessable=True, reason=None, n_tools=len(tools), outcomes=await assess_tools(tools))
    return record


async def run_static(
    entries: Iterable[dict[str, Any]], package_tools: PackageTools | None = None
) -> list[dict[str, Any]]:
    return [await assess_entry(e, package_tools) for e in entries]
