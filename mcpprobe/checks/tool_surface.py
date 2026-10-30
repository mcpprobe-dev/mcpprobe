"""META-06 (tool annotation lint) and META-07 (toxic-flow / lethal-trifecta classification).

Both read only the tools/list response the inventory already holds; neither sends
a request of its own. Capability classes come from :mod:`mcpprobe.checks.capability`
(keyword classification of names, descriptions and schemas), so contradictions and
roles are reported at medium confidence with the reason stated.
"""

from __future__ import annotations

import json
from typing import Any

from mcpprobe.checks import proof
from mcpprobe.checks.base import Check, NotApplicable, ScanContext, evidence_summary
from mcpprobe.checks.capability import (
    ROLE_PRIVATE,
    ROLE_SEND,
    ROLE_UNTRUSTED,
    Classification,
    classify_tools,
    looks_destructive,
    looks_mutating,
    looks_read_only,
    toxic_roles,
)
from mcpprobe.models import Confidence, Finding, Severity, Standards

ANTHROPIC_POLICY_URL = "https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy"
OPENAI_REVIEW_URL = "https://developers.openai.com/plugins/deploy/app-review.md"

HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def _require_tools(ctx: ScanContext) -> None:
    if not ctx.inventory.tools:
        ctx.require_metadata()
        raise NotApplicable(
            "the server lists no tools, so there are no tool annotations or capabilities to assess."
        )


def _verify_tools(ctx: ScanContext, check_id: str, jq: str, expect: str) -> str:
    if ctx.http is None:
        return proof.rescan(ctx.target, check_id, stdio=True)
    modern = ctx.fingerprint.flavour == "stateless-2026"
    return proof.curl_rpc(
        ctx.target,
        "tools/list",
        proof.modern_params() if modern else {},
        protocol_version="2026-07-28" if modern else "2025-11-25",
        headers={"Mcp-Method": "tools/list"} if modern else None,
        include_headers=False,
        auth_placeholder=ctx.fingerprint.credentials_supplied,
        jq=jq,
        expect=expect,
    )


def _looks(cls: Classification) -> str:
    if "arbitrary_command_execution" in cls.arbitrary:
        return "command execution"
    return cls.primary.replace("_", " ")


# ----------------------------------------------------------------------------- META-06
class Meta06ToolAnnotationLint(Check):
    id = "META-06"
    title = "Tool annotations missing or inconsistent with the tool"
    severity = Severity.MEDIUM
    standards = Standards()
    description = (
        "Reads each tool's annotations from tools/list. Reported as missing: readOnlyHint, "
        "openWorldHint and a title (tool.title or annotations.title) on every tool, and "
        "destructiveHint and idempotentHint on every tool not marked readOnlyHint:true (the spec "
        "says those two are meaningful only when readOnlyHint is false). Reported as "
        "inconsistent: readOnlyHint:true on a tool that looks like it executes, writes, deletes, "
        "sends or pays; destructiveHint:false on a tool that looks like it executes, deletes or "
        "overwrites; openWorldHint:false on a tool that reaches the network; a hint that is not a "
        "boolean; and, as low-severity noise, destructiveHint:true on a tool that only appears to "
        "read. Medium when a dangerous-class tool is mislabelled, low when annotations are merely "
        "missing. One finding lists every affected tool. Anthropic's directory policy (5E) and "
        "OpenAI's app review both require accurate annotations."
    )
    evidence_type = (
        "The tools/list response; each affected tool's name, title and annotations are shown as proof."
    )
    false_positive_notes = (
        "The capability behind a contradiction is inferred from keywords in the tool's name, "
        "description and parameter names, so a narrowly scoped tool (for example 'delete_draft' "
        "that only removes the caller's own draft) may be misread. Missing annotations are a plain "
        "observation. Annotations are hints that clients must treat as untrusted; correcting them "
        "does not change what a tool can do."
    )
    fix = (
        "Give every tool a title and set readOnlyHint and openWorldHint explicitly; for tools that "
        "are not read-only also set destructiveHint and idempotentHint. Make each value true to the "
        "implementation: readOnlyHint:true only when nothing is modified, destructiveHint:true for "
        "anything that executes, deletes or overwrites, openWorldHint:true for tools that reach the "
        "internet or other external systems. Anthropic's Software Directory Policy (5E, "
        f"{ANTHROPIC_POLICY_URL}) requires all applicable annotations, and OpenAI's app review "
        f"({OPENAI_REVIEW_URL}) checks readOnlyHint, destructiveHint and openWorldHint for accuracy."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        _require_tools(ctx)
        classes = ctx.shared.get("capabilities") or classify_tools(ctx.inventory.tools)
        missing: dict[str, list[str]] = {}
        wrong: dict[str, list[str]] = {}
        noise: dict[str, list[str]] = {}
        by_name: dict[str, dict[str, Any]] = {}
        for tool in ctx.inventory.tools:
            name = str(tool.get("name", "?"))
            by_name[name] = tool
            cls: Classification = classes.get(name) or Classification(name=name)
            raw = tool.get("annotations")
            ann: dict[str, Any] = raw if isinstance(raw, dict) else {}
            miss: list[str] = []
            bad: list[str] = []
            for hint in HINTS:
                if hint in ann and not isinstance(ann[hint], bool):
                    bad.append(f"{hint} is {json.dumps(ann[hint])}, not a boolean")
            read_only = ann.get("readOnlyHint") is True
            if "readOnlyHint" not in ann:
                miss.append("readOnlyHint")
            if not read_only:
                miss += [h for h in ("destructiveHint", "idempotentHint") if h not in ann]
            if "openWorldHint" not in ann:
                miss.append("openWorldHint")
            if not (tool.get("title") or ann.get("title")):
                miss.append("title")
            if read_only and looks_mutating(tool, cls):
                bad.append(f"readOnlyHint=true but the tool looks like {_looks(cls)}")
            if ann.get("destructiveHint") is False and looks_destructive(cls):
                bad.append(f"destructiveHint=false but the tool looks like {_looks(cls)}")
            if ann.get("openWorldHint") is False and "network" in cls.classes:
                bad.append("openWorldHint=false but the tool appears to make network requests")
            if not read_only and ann.get("destructiveHint") is True and looks_read_only(tool, cls):
                noise.setdefault(name, []).append(
                    f"destructiveHint=true but the tool only appears to read ({', '.join(cls.classes)})"
                )
            if miss:
                missing[name] = miss
            if bad:
                wrong[name] = bad
        affected = [n for n in by_name if n in missing or n in wrong or n in noise]
        if not affected:
            return []
        severity = Severity.MEDIUM if wrong else Severity.LOW
        heuristic = bool(wrong or noise)
        parts: list[str] = []
        if wrong:
            parts.append(
                "Annotations contradict the tool's apparent capability: "
                + "; ".join(f"'{n}': " + "; ".join(wrong[n]) for n in wrong)
                + ". Clients that trust annotations may skip the user's approval for these tools."
            )
        if missing:
            parts.append(
                f"{len(missing)} of {len(by_name)} tool(s) lack annotations: "
                + "; ".join(f"'{n}': {', '.join(missing[n])}" for n in missing)
                + "."
            )
        if noise:
            parts.append(
                "Over-cautious labels (noise, not a risk): "
                + "; ".join(f"'{n}': " + "; ".join(noise[n]) for n in noise)
                + "."
            )
        blocks = []
        for n in affected:
            tool = by_name[n]
            lines = [
                f"tools[{n}]:",
                f"  title: {json.dumps(tool.get('title')) if tool.get('title') is not None else '(absent)'}",
                "  annotations: "
                + (
                    json.dumps(tool.get("annotations"), sort_keys=True)
                    if "annotations" in tool
                    else "(absent)"
                ),
            ]
            if tool.get("description"):
                lines.append(f"  description: {tool.get('description')}")
            if n in classes and classes[n].classes:
                lines.append(f"  apparent capability: {', '.join(classes[n].classes)}")
            for label, table in (("missing", missing), ("inconsistent", wrong), ("noise", noise)):
                for item in table.get(n, []):
                    lines.append(f"  - {label}: {item}")
            blocks.append("\n".join(lines))
        ev = [ctx.inventory.tools_evidence] if ctx.inventory.tools_evidence else []
        return [
            self.finding(
                title=(
                    "Tool annotations contradict the tool's apparent capability"
                    if wrong
                    else "Tool annotations missing"
                ),
                description=" ".join(parts),
                severity=severity,
                confidence=Confidence.MEDIUM if heuristic else Confidence.HIGH,
                confidence_reason=(
                    "Missing annotations are observed directly; the contradictions are judged against a "
                    "capability inferred from keywords in the name, description and parameter names, "
                    "which can misread a narrowly scoped tool."
                    if heuristic
                    else None
                ),
                evidence=ev,
                excerpt=evidence_summary(
                    ev, "; ".join(f"{n}: annotations={by_name[n].get('annotations')}" for n in affected)
                ),
                location="tools[*].annotations",
                affected=affected,
                details={
                    "missing": missing,
                    "inconsistent": wrong,
                    "noise": noise,
                    "tools_total": len(by_name),
                },
                proof="\n\n".join(blocks),
                verify=_verify_tools(
                    ctx,
                    self.id,
                    ".result.tools[] | {name, title, annotations}",
                    "a title and readOnlyHint/destructiveHint/idempotentHint/openWorldHint on each tool, "
                    "matching what it does",
                ),
            )
        ]


# ----------------------------------------------------------------------------- META-07
_ROLE_LABEL = {
    ROLE_PRIVATE: "access to private data",
    ROLE_UNTRUSTED: "intake of untrusted content",
    ROLE_SEND: "a way to send data out",
}


class Meta07ToxicFlow(Check):
    id = "META-07"
    title = "Toxic flow: private data, untrusted content and external send on one server"
    severity = Severity.MEDIUM
    standards = Standards(asi=["ASI01"], llm_2025=["LLM01:2025"], llm_2026=["LLM01:2026"])
    description = (
        "Classifies every advertised tool into three roles from its capability class and wording: "
        "access to private data (files, databases, credentials, the user's mail), intake of "
        "untrusted content (fetching URLs, web search, reading mail or messages written by others) "
        "and a way to send data out (sending e-mail or messages, HTTP posts, webhooks, uploads). A "
        "tool advertising arbitrary command execution counts for all three; arbitrary file read "
        "counts as private data. When one server offers all three roles, text planted in the "
        "untrusted content can instruct the model to read the private data and send it away: the "
        "'lethal trifecta' of prompt injection. Medium, high when the HTTP endpoint needs no "
        "authentication. One finding lists the tools in each role. No tool is called."
    )
    evidence_type = "The tools/list response; each role lists its tools and the wording that put them there."
    false_positive_notes = (
        "Roles are inferred from names, descriptions and capability keywords, not from behaviour. A "
        "'fetch' tool restricted to one internal API, or a 'send' tool that only notifies the "
        "signed-in user, is still counted. Conversely a fetch tool with a free-form URL can leak "
        "data through the URL itself; that path is not counted as a send role."
    )
    fix = (
        "Break the trifecta: split the tools across separate servers (or separate client "
        "configurations) so no single agent session combines private data, untrusted content and "
        "an outbound channel; or gate the send tool behind explicit per-call user confirmation and "
        "an allow-list of destinations; or constrain the intake tool to trusted sources. Keep the "
        "server authenticated so nobody else can drive the combination."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        _require_tools(ctx)
        classes = ctx.shared.get("capabilities") or classify_tools(ctx.inventory.tools)
        roles: dict[str, dict[str, str]] = {ROLE_PRIVATE: {}, ROLE_UNTRUSTED: {}, ROLE_SEND: {}}
        by_name: dict[str, dict[str, Any]] = {}
        for tool in ctx.inventory.tools:
            name = str(tool.get("name", "?"))
            by_name[name] = tool
            cls: Classification = classes.get(name) or Classification(name=name)
            for role, why in toxic_roles(tool, cls).items():
                roles[role][name] = why
        ctx.shared["toxic_roles"] = roles
        if not all(roles.values()):
            return []
        fp = ctx.fingerprint
        unauth = ctx.is_http and not fp.auth_required
        involved = sorted({n for r in roles.values() for n in r})
        summary = "; ".join(f"{_ROLE_LABEL[r]}: {', '.join(sorted(roles[r]))}" for r in roles)
        desc = (
            f"This server combines all three ingredients of the lethal trifecta ({summary}). "
            "Content an attacker controls (a web page, an e-mail, a ticket) reaches the model through "
            "the intake tool and can instruct it to read the private data and pass it to the send "
            "tool; no vulnerability in the server's code is needed."
            + (
                " The endpoint answers without authentication (AUTH-01), so anyone who can reach it "
                "can drive the combination directly."
                if unauth
                else ""
            )
        )
        role_blocks = []
        for role, tools in roles.items():
            role_blocks.append(
                f"{_ROLE_LABEL[role]}:\n" + "\n".join(f"  - {n}: {why}" for n, why in sorted(tools.items()))
            )
        tool_blocks = [f"tools[{n}] description: {by_name[n].get('description', '')}" for n in involved]
        auth_line = "Authentication: " + (
            "none required (AUTH-01)"
            if unauth
            else ("required" if fp.auth_required else "not applicable (stdio)")
        )
        ev = [ctx.inventory.tools_evidence] if ctx.inventory.tools_evidence else []
        return [
            self.finding(
                description=desc,
                severity=Severity.HIGH if unauth else Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                confidence_reason=(
                    "Roles are inferred from each tool's advertised name, description and capability "
                    "keywords; no tool was called, so the reach of each tool is not confirmed."
                ),
                evidence=ev,
                excerpt=evidence_summary(ev, summary),
                location="tools",
                affected=involved,
                details={
                    "roles": {r: dict(sorted(t.items())) for r, t in roles.items()},
                    "unauthenticated": unauth,
                },
                proof="\n\n".join(role_blocks) + "\n\n" + "\n".join(tool_blocks) + "\n\n" + auth_line,
                verify=_verify_tools(
                    ctx,
                    self.id,
                    ".result.tools[].name",
                    "no single server listing a private-data tool, an untrusted-content tool and a send tool together",
                ),
            )
        ]
