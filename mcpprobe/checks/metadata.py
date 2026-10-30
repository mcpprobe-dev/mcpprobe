"""META-03, META-04, META-05: capability surface, schema hygiene and secrets in metadata."""

from __future__ import annotations

import json
import re
from typing import Any

from mcpprobe.checks import proof
from mcpprobe.checks._util import excerpt, shannon_entropy
from mcpprobe.checks.base import Check, NotApplicable, ScanContext, evidence_summary
from mcpprobe.checks.capability import (
    ARBITRARY_EXEC,
    ARBITRARY_FILE_READ,
    ARBITRARY_FILE_WRITE,
    DANGEROUS_CLASSES,
    Classification,
    classify_tools,
)
from mcpprobe.checks.poisoning import collect_text_items
from mcpprobe.models import Confidence, EvidenceRecord, Finding, Severity, Standards
from mcpprobe.redact import SECRET_PATTERNS, redact, redact_secrets

TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
RISKY_ARG_NAME = re.compile(
    r"(path|file|dir|folder|command|cmd|shell|script|url|uri|href|query|sql|code|expr|template|host|address)",
    re.I,
)


# ----------------------------------------------------------------------------- META-03
_CAPABILITY_LABEL = {
    ARBITRARY_EXEC: "arbitrary command execution",
    ARBITRARY_FILE_READ: "arbitrary file read",
    ARBITRARY_FILE_WRITE: "arbitrary file write",
}


def _tools_verify(ctx: ScanContext, jq: str, expect: str, check_id: str) -> str:
    if ctx.http is None:
        return proof.rescan(ctx.target, check_id, stdio=True)
    return proof.curl_rpc(
        ctx.target,
        "tools/list",
        {},
        include_headers=False,
        auth_placeholder=ctx.fingerprint.credentials_supplied,
        jq=jq,
        expect=expect,
    )


def _require_tools(ctx: ScanContext) -> None:
    if not ctx.inventory.tools:
        ctx.require_metadata()
        raise NotApplicable("the server lists no tools, so there is no tool capability or schema to assess.")


class Meta03DangerousCapabilitySurface(Check):
    id = "META-03"
    title = "Dangerous tool capability exposed or annotations contradict it"
    severity = Severity.HIGH
    standards = Standards(
        mcp=["MCP02:2025", "MCP05:2025"],
        asi=["ASI02", "ASI05"],
        llm_2025=["LLM06:2025"],
        llm_2026=["LLM03:2026"],
    )
    description = (
        "Classifies each tool by name, description and parameter names into capability classes. "
        "Tools that advertise arbitrary command execution, arbitrary file read or arbitrary file "
        "write (a shell/file capability selected by a free-form string argument with no enum, "
        "const or pattern) are rated high on their own and critical when the remote endpoint "
        "needs no authentication. Declared annotations are cross-checked (a command tool marked "
        "readOnlyHint:true is reported), and the remaining high-impact surface (network, e-mail, "
        "credentials, payments) is summarised at low severity. Passive scanning sees the "
        "advertised capability, not whether the implementation really executes: the rating is "
        "based on the name, description and schema, and no tool is called."
    )
    evidence_type = "The tools/list response; each affected tool's complete definition is shown as proof."
    false_positive_notes = (
        "Classification is keyword-based: a tool named 'delete_draft' that only removes the "
        "user's own draft will be classed 'delete'. A tool that advertises a shell but whose "
        "implementation is a stub is still reported, because clients and models act on the "
        "advertised capability."
    )
    fix = (
        "For arbitrary command execution or file access: remove the tool, or sandbox it and "
        "replace the free-form argument with an allow-list (enum) of commands or files. "
        "Annotations come after that. Make annotations truthful (destructiveHint:true for "
        "anything that executes or deletes); they help a careful client warn the user but do "
        "nothing about the risk."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        _require_tools(ctx)
        classes = classify_tools(ctx.inventory.tools)
        ctx.shared["capabilities"] = classes
        findings: list[Finding] = []
        ev = [ctx.inventory.tools_evidence] if ctx.inventory.tools_evidence else []
        by_name = {str(t.get("name", "")): t for t in ctx.inventory.tools}
        fp = ctx.fingerprint

        # 1. Arbitrary capabilities: high on their own, critical when unauthenticated and remote.
        arbitrary = {n: c.arbitrary for n, c in classes.items() if c.arbitrary}
        if arbitrary:
            unauth = ctx.is_http and not fp.auth_required
            critical = unauth and ctx.is_public
            kinds = sorted({k for caps in arbitrary.values() for k in caps})
            labels = [_CAPABILITY_LABEL[k] for k in kinds]
            title = (
                " and ".join(labels).capitalize() + " exposed" + (" without authentication" if unauth else "")
            )
            per_tool = "; ".join(
                f"{n}: "
                + ", ".join(f"{_CAPABILITY_LABEL[k]} via free-form '{a}'" for k, a in sorted(caps.items()))
                for n, caps in sorted(arbitrary.items())
            )
            desc = (
                f"The server advertises {', '.join(labels)} ({per_tool}). "
                + (
                    "The endpoint answers without authentication (AUTH-01), so anyone who can reach "
                    "it, or any model prompt-injected into calling the tool, can use it. "
                    if unauth
                    else "Any client allowed to call tools, or a model prompt-injected into calling "
                    "the tool, can use it. "
                )
                + "Passive scanning sees the advertised capability (name, description and input "
                "schema), not whether the implementation really executes; no tool was called."
            )
            proof_parts: list[str] = []
            for n in sorted(arbitrary):
                caps = arbitrary[n]
                proof_parts.append(
                    f"tools[{n}] (complete definition):\n"
                    + proof.indent(proof.pretty(by_name.get(n, {})))
                    + "\nAdvertised capability: "
                    + "; ".join(
                        f"{_CAPABILITY_LABEL[k]} (argument '{a}' is a free-form string: no enum, const or pattern)"
                        for k, a in sorted(caps.items())
                    )
                )
            proof_parts.append(
                "Authentication: "
                + (
                    "none required (AUTH-01)"
                    if unauth
                    else ("required" if fp.auth_required else "not applicable (stdio)")
                )
            )
            names = sorted(arbitrary)
            fix = (
                f"Remove {', '.join(names)}. A remote shell or unrestricted file access cannot be made "
                "safe by annotating it. If the capability is essential, run it in a sandbox with no "
                "credentials or network access and replace the free-form argument with an allow-list "
                "(an enum of permitted commands or files, checked again on the server). Only then add "
                "truthful annotations (destructiveHint:true, readOnlyHint:false), which help a careful "
                "client warn the user but do not reduce the risk."
            )
            if unauth:
                fix += (
                    " Adding authentication (AUTH-01) is necessary but not sufficient: any "
                    "authenticated client could still call the tool."
                )
            sel = " or ".join(f'.name=="{n}"' for n in names)
            findings.append(
                self.finding(
                    title=title,
                    description=desc,
                    severity=Severity.CRITICAL if critical else Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    confidence_reason=(
                        "Based on the advertised name, description and schema; a passive scan does "
                        "not call the tool, so it cannot confirm the implementation really executes."
                    ),
                    evidence=ev,
                    excerpt=evidence_summary(ev, per_tool),
                    location="tools",
                    details={
                        "arbitrary": {n: sorted(c) for n, c in arbitrary.items()},
                        "arguments": {n: dict(c) for n, c in arbitrary.items()},
                        "unauthenticated": unauth,
                    },
                    fix=fix,
                    affected=names,
                    proof="\n\n".join(proof_parts),
                    verify=_tools_verify(
                        ctx,
                        f".result.tools[] | select({sel}) | .name",
                        "no output (tools removed), or each argument constrained by an enum",
                        self.id,
                    ),
                )
            )

        # 2. Annotation contradictions (one finding listing every affected tool).
        contradictions: dict[str, list[str]] = {}
        for tool in ctx.inventory.tools:
            name = str(tool.get("name", "?"))
            cls: Classification = classes.get(name) or Classification(name=name)
            ann = tool.get("annotations")
            if not isinstance(ann, dict):
                continue
            problems: list[str] = []
            looks = "command execution" if cls.arbitrary.get(ARBITRARY_EXEC) else cls.primary
            if ann.get("readOnlyHint") is True and (cls.writes or ARBITRARY_EXEC in cls.arbitrary):
                problems.append(f"readOnlyHint=true but tool looks like {looks}")
            if ann.get("destructiveHint") is False and (
                any(c in {"exec", "delete", "file_write", "database_write"} for c in cls.classes)
                or ARBITRARY_EXEC in cls.arbitrary
            ):
                problems.append(f"destructiveHint=false but tool looks like {looks}")
            if ann.get("openWorldHint") is False and "network" in cls.classes:
                problems.append("openWorldHint=false but tool appears to make network requests")
            if problems:
                contradictions[name] = problems
        if contradictions:
            names = sorted(contradictions)
            findings.append(
                self.finding(
                    title="Tool annotations contradict the tool's apparent capability",
                    description="; ".join(f"Tool '{n}': " + "; ".join(contradictions[n]) for n in names)
                    + ". Clients that trust annotations may skip the user's approval for these tools.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    confidence_reason=(
                        "The capability is inferred from keywords in the name, description and "
                        "parameter names, which can misclassify a narrowly scoped tool."
                    ),
                    evidence=ev,
                    excerpt=evidence_summary(
                        ev, "; ".join(f"{n}: annotations={by_name[n].get('annotations')}" for n in names)
                    ),
                    location="tools[*].annotations",
                    details={
                        "tools": {
                            n: {
                                "problems": contradictions[n],
                                "annotations": by_name[n].get("annotations"),
                                "classes": classes[n].classes,
                                "matched_terms": classes[n].matched_terms,
                            }
                            for n in names
                        }
                    },
                    fix=(
                        "Make annotations truthful: readOnlyHint only for tools with no side effects, "
                        "destructiveHint:true for anything that deletes or executes, openWorldHint:true "
                        "for tools that reach the network."
                    ),
                    affected=names,
                    proof="\n\n".join(
                        f"tools[{n}]:\n  description: {by_name[n].get('description', '')}\n"
                        f"  annotations: {json.dumps(by_name[n].get('annotations'))}\n"
                        + "\n".join(f"  - {p}" for p in contradictions[n])
                        for n in names
                    ),
                    verify=_tools_verify(
                        ctx,
                        ".result.tools[] | {name, annotations}",
                        "annotations that match each tool's behaviour",
                        self.id,
                    ),
                )
            )

        # 3. Remaining high-impact surface (informational review prompt).
        rest = {n: c.classes for n, c in classes.items() if c.dangerous and n not in arbitrary}
        by_class: dict[str, list[str]] = {}
        for n, cl in rest.items():
            for c in cl:
                if c in DANGEROUS_CLASSES:
                    by_class.setdefault(c, []).append(n)
        if by_class:
            summary = "; ".join(f"{c}: {', '.join(sorted(ns))}" for c, ns in sorted(by_class.items()))
            affected = sorted({n for ns in by_class.values() for n in ns})
            findings.append(
                self.finding(
                    title="High-impact tool capabilities exposed",
                    description="Tools classified as high-impact: "
                    + summary
                    + ". Review that each is necessary, scoped and gated by user approval.",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    confidence_reason=(
                        "Keyword-based classification of names and descriptions; the tools were not called."
                    ),
                    evidence=ev,
                    excerpt=evidence_summary(ev, summary),
                    location="tools",
                    details={"by_class": by_class},
                    fix=(
                        "Keep only the tools you need, scope each to the narrowest resource it must "
                        "touch, and mark side effects with truthful annotations so clients ask the user."
                    ),
                    affected=affected,
                    proof="\n".join(
                        f"tools[{n}]: {classes[n].classes} matched {classes[n].matched_terms}"
                        for n in affected
                    ),
                    verify=proof.rescan(ctx.target, self.id, stdio=ctx.http is None),
                )
            )
        return findings


# ----------------------------------------------------------------------------- META-04
_CONSTRAINT_KEYS = ("enum", "pattern", "format", "maxLength", "const")


class Meta04SchemaHygiene(Check):
    id = "META-04"
    title = "Tool schema hygiene problems"
    severity = Severity.LOW
    standards = Standards(mcp=["MCP05:2025"])
    description = (
        "Checks tool names against [A-Za-z0-9_.-]{1,128} and for duplicates; checks that "
        "inputSchema is a JSON Schema object of type 'object'; flags free-form string arguments "
        "whose names suggest paths, commands, URLs or queries and that carry no enum, pattern, "
        "format or maxLength constraint. One finding lists every affected tool, with each tool's "
        "complete inputSchema and its specific problems (including arguments missing from "
        "'required' and additionalProperties not set to false). Missing outputSchema cannot be "
        "judged without calling the tool and is not reported."
    )
    evidence_type = "The tools/list response; each affected tool's complete inputSchema is shown as proof."
    false_positive_notes = (
        "An unconstrained 'query' string is often unavoidable (search tools); the finding is "
        "Low severity and meant as a review prompt, not a defect."
    )
    fix = (
        "Constrain every risky string argument (enum for a fixed set, pattern for a format, "
        "maxLength to bound size), list required arguments in 'required', set "
        "additionalProperties: false, and validate arguments on the server against the same "
        "schema instead of trusting the client to have done it."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        _require_tools(ctx)
        findings: list[Finding] = []
        ev = [ctx.inventory.tools_evidence] if ctx.inventory.tools_evidence else []
        seen: dict[str, int] = {}
        affected: dict[str, list[str]] = {}
        observations: dict[str, list[str]] = {}
        schemas: dict[str, Any] = {}
        severity = Severity.LOW
        for tool in ctx.inventory.tools:
            name = str(tool.get("name", ""))
            seen[name] = seen.get(name, 0) + 1
            problems: list[str] = []
            notes: list[str] = []
            if not TOOL_NAME_RE.match(name):
                problems.append("name violates [A-Za-z0-9_.-]{1,128}")
            schema = tool.get("inputSchema")
            if not isinstance(schema, dict):
                problems.append("inputSchema missing or not an object")
                severity = Severity.MEDIUM
            else:
                if schema.get("type") not in (None, "object"):
                    problems.append(f"inputSchema.type is {schema.get('type')!r}, expected 'object'")
                props = schema.get("properties")
                raw_required = schema.get("required")
                required: list[Any] = raw_required if isinstance(raw_required, list) else []
                if isinstance(props, dict):
                    for pname, pdef in props.items():
                        if not isinstance(pdef, dict):
                            continue
                        if (
                            pdef.get("type") == "string"
                            and RISKY_ARG_NAME.search(str(pname))
                            and not any(k in pdef for k in _CONSTRAINT_KEYS)
                        ):
                            problems.append(
                                f"'{pname}' is a free-form string with no enum, pattern, format or maxLength"
                            )
                            if pname not in required:
                                notes.append(f"'{pname}' is not listed in 'required'")
                if schema.get("additionalProperties") is not False:
                    notes.append("additionalProperties is not false (unknown arguments are allowed)")
            if problems:
                affected[name] = problems
                observations[name] = notes
                schemas[name] = schema
        if affected:
            names = list(affected)
            parts = []
            for n in names:
                block = f"tools[{n}].inputSchema (complete):\n" + proof.indent(proof.pretty(schemas[n]))
                block += "\nProblems:\n" + "\n".join(f"  - {p}" for p in affected[n])
                if observations[n]:
                    block += "\nAlso:\n" + "\n".join(f"  - {o}" for o in observations[n])
                parts.append(block)
            sel = " or ".join(f'.name=="{n}"' for n in names)
            findings.append(
                self.finding(
                    description=(
                        f"{len(names)} tool(s) have schema problems: "
                        + "; ".join(f"'{n}': " + "; ".join(affected[n]) for n in names)
                        + "."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    excerpt=evidence_summary(ev, "; ".join(f"{n}: {', '.join(affected[n])}" for n in names)),
                    location="tools",
                    details={
                        "tools": {
                            n: {"problems": affected[n], "observations": observations[n]} for n in names
                        },
                        "risky_arguments": {
                            n: [p.split("'")[1] for p in affected[n] if p.startswith("'")] for n in names
                        },
                    },
                    affected=names,
                    proof="\n\n".join(parts),
                    verify=_tools_verify(
                        ctx,
                        f".result.tools[] | select({sel}) | .inputSchema",
                        "enum/pattern/maxLength on each argument, a 'required' list and additionalProperties: false",
                        self.id,
                    ),
                )
            )
        dupes = sorted(n for n, c in seen.items() if c > 1)
        if dupes:
            findings.append(
                self.finding(
                    title="Duplicate tool names",
                    description="Tool names listed more than once: " + ", ".join(dupes) + ".",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=ev,
                    location="tools",
                    details={"duplicates": dupes},
                    fix="Give every tool a unique name; clients cannot tell duplicates apart.",
                    affected=dupes,
                    proof="\n".join(f"tools[{n}] listed {seen[n]} times" for n in dupes),
                    verify=_tools_verify(
                        ctx, "[.result.tools[].name] | group_by(.) | map(select(length>1))", "[]", self.id
                    ),
                )
            )
        return findings


# ----------------------------------------------------------------------------- META-05
_ENTROPY_TOKEN = re.compile(r"(?<![\w/+=-])[A-Za-z0-9_\-/+=]{24,}(?![\w/+=-])")
_SECRET_ENV_NAME = re.compile(r"(key|secret|token|password|passwd|pwd|credential|auth)", re.I)


def find_secrets(text: str) -> list[dict[str, Any]]:
    """Return pattern and entropy hits in ``text`` (values redacted)."""
    hits: list[dict[str, Any]] = []
    covered: list[tuple[int, int]] = []
    for label, pattern, sev in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(1) if m.lastindex else m.group(0)
            hits.append({"kind": label, "severity": sev.value, "value": redact(value), "confidence": "high"})
            covered.append(m.span())
    for m in _ENTROPY_TOKEN.finditer(text):
        if any(a <= m.start() < b for a, b in covered):
            continue
        token = m.group(0)
        if "/" in token and token.count("/") > 2:  # looks like a path
            continue
        has_digit = any(c.isdigit() for c in token)
        has_alpha = any(c.isalpha() for c in token)
        if has_digit and has_alpha and shannon_entropy(token) >= 4.2:
            hits.append(
                {
                    "kind": "high-entropy string",
                    "severity": Severity.LOW.value,
                    "value": redact(token),
                    "confidence": "low",
                }
            )
    return hits


class Meta05SecretsInMetadata(Check):
    id = "META-05"
    title = "Secret material in server metadata or configuration"
    severity = Severity.HIGH
    standards = Standards(mcp=["MCP01:2025"], llm_2025=["LLM02:2025"], llm_2026=["LLM02:2026"])
    description = (
        "Pattern and entropy scan for AWS/GitHub/Slack/Stripe/Google keys, private key blocks, "
        "JWTs, bearer tokens, connection strings with passwords and generic 'key=...' "
        "assignments across tool/prompt/resource descriptions, parameter descriptions, resource "
        "URIs, server instructions and, for stdio targets, the command line and environment "
        "supplied to the scanner. Matched values are redacted in the report."
    )
    evidence_type = "The listing response that contained the match; values redacted."
    false_positive_notes = (
        "Example keys from vendor documentation (for instance the AWS sample key IDs ending in EXAMPLE) match the patterns. "
        "High-entropy strings are reported at Low severity and low confidence; identifiers such "
        "as content hashes trigger them. Secrets in a stdio server's environment are expected "
        "(the spec says stdio servers take credentials from the environment) and are reported "
        "as Low so the operator can confirm least privilege."
    )
    fix = (
        "Remove secrets from descriptions and resources, rotate anything that was exposed, and "
        "pass credentials through the environment or a secret store, never through metadata."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.transport.name != "stdio":
            ctx.require_metadata()
        findings: list[Finding] = []
        evidence_map = {
            "tool": ctx.inventory.tools_evidence,
            "tool_param": ctx.inventory.tools_evidence,
            "prompt": ctx.inventory.prompts_evidence,
            "prompt_arg": ctx.inventory.prompts_evidence,
            "resource": ctx.inventory.resources_evidence,
        }
        for item in collect_text_items(ctx):
            hits = find_secrets(item.text)
            if hits:
                findings.append(
                    self._finding_for(item.path, hits, item.text, evidence_map.get(item.kind), ctx)
                )
        for res in ctx.inventory.resources:
            uri = res.get("uri")
            if isinstance(uri, str):
                hits = [h for h in find_secrets(uri) if h["kind"] != "high-entropy string"]
                if hits:
                    findings.append(
                        self._finding_for(
                            f"resources[{res.get('name') or uri}].uri",
                            hits,
                            uri,
                            ctx.inventory.resources_evidence,
                            ctx,
                        )
                    )
        # stdio: command line and environment supplied by the operator.
        if ctx.transport.name == "stdio":
            cmd = " ".join(ctx.options.stdio_command)
            hits = find_secrets(cmd)
            if hits:
                f = self._finding_for("stdio.command", hits, cmd, None, ctx)
                f.severity = Severity.MEDIUM
                f.description += " Secrets on the command line are visible in process listings."
                findings.append(f)
            env_hits: list[str] = []
            for key, value in ctx.options.stdio_env.items():
                if _SECRET_ENV_NAME.search(key) and value:
                    env_hits.append(f"{key}={redact(value)}")
                else:
                    for h in find_secrets(value):
                        if h["confidence"] == "high":
                            env_hits.append(f"{key}={h['value']} ({h['kind']})")
            if env_hits:
                findings.append(
                    self.finding(
                        title="Credentials passed to stdio server via environment",
                        description="Environment variables that look like credentials: "
                        + ", ".join(env_hits)
                        + ". This is the expected pattern for stdio servers; "
                        "confirm each credential is least-privilege and scoped to this server.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        confidence_reason=(
                            "Matched on variable names and value patterns; whether each credential is "
                            "over-privileged cannot be seen from outside."
                        ),
                        location="stdio.env",
                        details={"variables": env_hits},
                        affected=[h.split("=", 1)[0] for h in env_hits],
                        proof="Environment supplied to the stdio server (values redacted):\n"
                        + "\n".join(f"  {h}" for h in env_hits),
                        verify="Review each credential's scope in the issuing system; mcpprobe cannot verify it.",
                    )
                )
        return findings

    def _finding_for(
        self, path: str, hits: list[dict[str, Any]], text: str, ev: EvidenceRecord | None, ctx: ScanContext
    ) -> Finding:
        top = max((Severity(h["severity"]) for h in hits), key=lambda s: s.rank)
        confidence = Confidence.HIGH if any(h["confidence"] == "high" for h in hits) else Confidence.LOW
        return self.finding(
            description=f"{path} contains: "
            + "; ".join(f"{h['kind']} {h['value']}" for h in hits)
            + f'. Excerpt: "{excerpt(redact_secrets(text))}"',
            severity=top,
            confidence=confidence,
            confidence_reason=None
            if confidence == Confidence.HIGH
            else "Only a high-entropy string matched; identifiers such as hashes look the same.",
            evidence=[ev] if ev else [],
            excerpt=f'{path}: "{excerpt(redact_secrets(text), 240)}"',
            location=path,
            details={"hits": hits},
            affected=[path],
            proof=f"{path} (complete text, secrets redacted):\n  {redact_secrets(text)}\n\nMatched:\n"
            + "\n".join(f"  - {h['kind']}: {h['value']}" for h in hits),
            verify=proof.rescan(ctx.target, self.id, stdio=ctx.http is None),
        )
