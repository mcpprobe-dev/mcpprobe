"""META-02: canonical hashing of the server's listed surface and rug-pull diffing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mcpprobe.checks._util import canonical_json
from mcpprobe.checks.base import Check, ScanContext
from mcpprobe.models import Confidence, Finding, Severity, Standards, utcnow

BASELINE_FORMAT_VERSION = 1


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _key(item: dict[str, Any], fallback: str) -> str:
    return str(item.get("name") or item.get("uri") or fallback)


def build_snapshot(ctx: ScanContext) -> dict[str, Any]:
    """Canonical snapshot and per-item hashes of tools, prompts, resources and instructions."""
    items: dict[str, Any] = {"tools": {}, "prompts": {}, "resources": {}, "instructions": None}
    for kind in ("tools", "prompts", "resources"):
        for idx, entry in enumerate(getattr(ctx.inventory, kind)):
            items[kind][_key(entry, f"#{idx}")] = sha256_hex(canonical_json(entry))
    if ctx.fingerprint.instructions:
        items["instructions"] = sha256_hex(ctx.fingerprint.instructions)
    snapshot = {
        "tools": ctx.inventory.tools,
        "prompts": ctx.inventory.prompts,
        "resources": ctx.inventory.resources,
        "instructions": ctx.fingerprint.instructions,
    }
    return {
        "format": BASELINE_FORMAT_VERSION,
        "target": ctx.target,
        "created_at": utcnow().isoformat(),
        "overall_sha256": sha256_hex(canonical_json(snapshot)),
        "items": items,
        "snapshot": snapshot,
    }


def diff_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Return added/removed/changed names per kind plus changed fields for tools."""
    out: dict[str, Any] = {}
    old_items = old.get("items") or {}
    new_items = new.get("items") or {}
    for kind in ("tools", "prompts", "resources"):
        o = old_items.get(kind) or {}
        n = new_items.get(kind) or {}
        changed = sorted(k for k in o.keys() & n.keys() if o[k] != n[k])
        entry: dict[str, Any] = {
            "added": sorted(n.keys() - o.keys()),
            "removed": sorted(o.keys() - n.keys()),
            "changed": changed,
        }
        if kind == "tools" and changed:
            old_tools = {_key(t, ""): t for t in (old.get("snapshot") or {}).get("tools") or []}
            new_tools = {_key(t, ""): t for t in (new.get("snapshot") or {}).get("tools") or []}
            fields: dict[str, list[str]] = {}
            for name in changed:
                a, b = old_tools.get(name, {}), new_tools.get(name, {})
                fields[name] = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            entry["changed_fields"] = fields
        out[kind] = entry
    out["instructions_changed"] = old_items.get("instructions") != new_items.get("instructions")
    out["any_change"] = out["instructions_changed"] or any(
        out[k]["added"] or out[k]["removed"] or out[k]["changed"] for k in ("tools", "prompts", "resources")
    )
    return out


class Meta02RugPullBaseline(Check):
    id = "META-02"
    title = "Tool surface changed since the stored baseline (rug-pull indicator)"
    severity = Severity.MEDIUM
    standards = Standards(mcp=["MCP03:2025"], asi=["ASI04"])
    description = (
        "Computes SHA-256 over the canonical JSON of each tool, prompt and resource definition "
        "and the server instructions. With --baseline FILE the current snapshot is compared to "
        "the stored one and any added, removed or changed definition is reported (a changed "
        "description after approval is the classic 'rug pull'). The snapshot is then written "
        "back to the file. Also notes when the server advertises tools.listChanged."
    )
    evidence_type = "The current tools/list response plus per-item hashes and the diff."
    false_positive_notes = (
        "Any legitimate release that edits a description will trigger the diff; the finding "
        "says what changed so the reviewer can decide. Servers that embed timestamps or random "
        "data in descriptions will change on every scan."
    )
    fix = (
        "Treat tool definitions as code: version them, review changes, and have clients pin and "
        "re-approve definitions when the hash changes."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        current = build_snapshot(ctx)
        ctx.shared["baseline_current"] = current
        ctx.notes.append(
            f"META-02: surface hash {current['overall_sha256'][:16]}... "
            f"({len(current['items']['tools'])} tools)"
        )
        caps = ctx.fingerprint.capabilities or {}
        tools_caps = caps.get("tools") if isinstance(caps, dict) else None
        if isinstance(tools_caps, dict) and tools_caps.get("listChanged"):
            findings.append(
                self.finding(
                    title="Server can change its tool list mid-session (listChanged)",
                    description="The server advertises tools.listChanged, so definitions may change "
                    "after a client has approved them. Clients should re-review on change.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    location="capabilities.tools.listChanged",
                )
            )
        path = ctx.options.baseline_path
        if not path:
            return findings
        file = Path(path)
        if file.exists():
            try:
                previous = json.loads(file.read_text("utf-8"))
            except (OSError, ValueError) as exc:
                ctx.notes.append(f"META-02: could not read baseline {path}: {exc}")
                previous = None
            if isinstance(previous, dict):
                if previous.get("target") != ctx.target:
                    ctx.notes.append(
                        f"META-02: baseline target {previous.get('target')!r} differs from {ctx.target!r}"
                    )
                diff = diff_snapshots(previous, current)
                findings.extend(self._findings_from_diff(ctx, diff, previous))
        if ctx.options.write_baseline:
            try:
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(json.dumps(current, indent=2, sort_keys=True), "utf-8")
                ctx.notes.append(f"META-02: baseline written to {path}")
            except OSError as exc:
                ctx.notes.append(f"META-02: could not write baseline {path}: {exc}")
        return findings

    def _findings_from_diff(
        self, ctx: ScanContext, diff: dict[str, Any], previous: dict[str, Any]
    ) -> list[Finding]:
        if not diff["any_change"]:
            ctx.notes.append("META-02: no change since baseline " + str(previous.get("created_at")))
            return []
        out: list[Finding] = []
        ev = [ctx.inventory.tools_evidence] if ctx.inventory.tools_evidence else []
        tools = diff["tools"]
        for name in tools["changed"]:
            fields = tools.get("changed_fields", {}).get(name, [])
            sev = Severity.MEDIUM if ("description" in fields or "inputSchema" in fields) else Severity.LOW
            out.append(
                self.finding(
                    description=f"Tool '{name}' changed since baseline {previous.get('created_at')}: "
                    f"fields {', '.join(fields) or 'unknown'}.",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    location=f"tools[{name}]",
                    details={"changed_fields": fields},
                )
            )
        if tools["added"]:
            out.append(
                self.finding(
                    title="New tools appeared since baseline",
                    description="Added tools: " + ", ".join(tools["added"]) + ".",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    location="tools",
                    details={"added": tools["added"]},
                )
            )
        if tools["removed"]:
            out.append(
                self.finding(
                    title="Tools removed since baseline",
                    description="Removed tools: " + ", ".join(tools["removed"]) + ".",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    location="tools",
                    details={"removed": tools["removed"]},
                )
            )
        for kind in ("prompts", "resources"):
            d = diff[kind]
            if d["added"] or d["removed"] or d["changed"]:
                out.append(
                    self.finding(
                        title=f"{kind.capitalize()} changed since baseline",
                        description=f"{kind}: added {d['added']}, removed {d['removed']}, changed {d['changed']}.",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        location=kind,
                        details=d,
                    )
                )
        if diff["instructions_changed"]:
            out.append(
                self.finding(
                    title="Server instructions changed since baseline",
                    description="The 'instructions' text returned at negotiation differs from the baseline.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    location="initialize.instructions",
                )
            )
        return out
