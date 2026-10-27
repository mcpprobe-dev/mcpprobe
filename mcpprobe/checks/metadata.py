"""META-03, META-04, META-05: capability surface, schema hygiene and secrets in metadata."""

from __future__ import annotations

import json
import re
from typing import Any

from mcpprobe.checks._util import excerpt, shannon_entropy
from mcpprobe.checks.base import Check, ScanContext, evidence_summary
from mcpprobe.checks.capability import DANGEROUS_CLASSES, Classification, classify_tools
from mcpprobe.checks.poisoning import collect_text_items
from mcpprobe.models import Confidence, EvidenceRecord, Finding, Severity, Standards
from mcpprobe.redact import SECRET_PATTERNS, redact, redact_secrets

TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
RISKY_ARG_NAME = re.compile(
    r"(path|file|dir|folder|command|cmd|shell|script|url|uri|href|query|sql|code|expr|template|host|address)",
    re.I,
)


# ----------------------------------------------------------------------------- META-03
class Meta03DangerousCapabilitySurface(Check):
    id = "META-03"
    title = "Tool annotations contradict the tool's apparent capability"
    severity = Severity.MEDIUM
    standards = Standards(
        mcp=["MCP02:2025", "MCP05:2025"],
        asi=["ASI02", "ASI05"],
        llm_2025=["LLM06:2025"],
        llm_2026=["LLM03:2026"],
    )
    description = (
        "Classifies each tool by name, description and parameter names into capability classes "
        "(exec, file_write, file_read, database_*, network, email, credentials, payments, delete, "
        "search) and cross-checks the declared annotations: a tool that looks like it runs "
        "commands or sends e-mail but is marked readOnlyHint:true, or an exec/delete tool marked "
        "destructiveHint:false, is reported. A summary of the dangerous surface is reported at low "
        "severity. Annotations are treated as untrusted hints, as the spec requires of clients."
    )
    evidence_type = "The tools/list response; matched terms per tool are listed in details."
    false_positive_notes = (
        "Classification is keyword-based: a tool named 'delete_draft' that only removes the "
        "user's own draft will be classed 'delete'. Confidence is medium for contradictions and "
        "the dangerous-surface summary is informational."
    )
    fix = (
        "Make annotations truthful (readOnlyHint only for tools with no side effects, "
        "destructiveHint:true for anything that deletes or executes), and consider splitting "
        "broad tools into narrower ones so clients can gate approval."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        classes = classify_tools(ctx.inventory.tools)
        ctx.shared["capabilities"] = classes
        findings: list[Finding] = []
        ev = [ctx.inventory.tools_evidence] if ctx.inventory.tools_evidence else []
        for tool in ctx.inventory.tools:
            name = str(tool.get("name", "?"))
            cls: Classification = classes.get(name) or Classification(name=name)
            ann = tool.get("annotations")
            if not isinstance(ann, dict):
                continue
            problems: list[str] = []
            if ann.get("readOnlyHint") is True and cls.writes:
                problems.append(f"readOnlyHint=true but tool looks like {cls.primary}")
            if ann.get("destructiveHint") is False and any(
                c in {"exec", "delete", "file_write", "database_write"} for c in cls.classes
            ):
                problems.append(f"destructiveHint=false but tool looks like {cls.primary}")
            if ann.get("openWorldHint") is False and "network" in cls.classes:
                problems.append("openWorldHint=false but tool appears to make network requests")
            if problems:
                findings.append(
                    self.finding(
                        description=f"Tool '{name}': "
                        + "; ".join(problems)
                        + f". Matched terms: {cls.matched_terms}.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence=ev,
                        excerpt=evidence_summary(
                            ev,
                            f"tools[{name}] description={excerpt(str(tool.get('description', '')), 80)!r} annotations={ann}",
                        ),
                        location=f"tools[{name}].annotations",
                        details={
                            "classes": cls.classes,
                            "annotations": ann,
                            "matched_terms": cls.matched_terms,
                        },
                    )
                )
        dangerous = {n: c.classes for n, c in classes.items() if c.dangerous}
        if dangerous:
            by_class: dict[str, list[str]] = {}
            for n, cl in dangerous.items():
                for c in cl:
                    if c in DANGEROUS_CLASSES:
                        by_class.setdefault(c, []).append(n)
            findings.append(
                self.finding(
                    title="Dangerous capability surface exposed",
                    description="Tools classified as high-impact: "
                    + "; ".join(f"{c}: {', '.join(sorted(ns))}" for c, ns in sorted(by_class.items()))
                    + ". Review that each is necessary, scoped and gated by approval.",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence=ev,
                    excerpt=evidence_summary(
                        ev, "; ".join(f"{c}: {', '.join(sorted(ns))}" for c, ns in sorted(by_class.items()))
                    ),
                    location="tools",
                    details={"by_class": by_class},
                )
            )
        return findings


# ----------------------------------------------------------------------------- META-04
class Meta04SchemaHygiene(Check):
    id = "META-04"
    title = "Tool schema hygiene problems"
    severity = Severity.LOW
    standards = Standards(mcp=["MCP05:2025"])
    description = (
        "Checks tool names against [A-Za-z0-9_.-]{1,128} and for duplicates; checks that "
        "inputSchema is a JSON Schema object of type 'object'; flags free-form string arguments "
        "whose names suggest paths, commands, URLs or queries and that carry no enum, pattern, "
        "format or maxLength constraint. Missing outputSchema cannot be judged without calling "
        "the tool and is not reported."
    )
    evidence_type = "The tools/list response."
    false_positive_notes = (
        "An unconstrained 'query' string is often unavoidable (search tools); the finding is "
        "Low severity and meant as a review prompt, not a defect."
    )
    fix = (
        "Use valid names, give every tool an object inputSchema, and constrain risky string "
        "arguments with enum/pattern/format/maxLength so clients and servers can validate."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        ev = [ctx.inventory.tools_evidence] if ctx.inventory.tools_evidence else []
        seen: dict[str, int] = {}
        for tool in ctx.inventory.tools:
            name = str(tool.get("name", ""))
            seen[name] = seen.get(name, 0) + 1
            problems: list[str] = []
            if not TOOL_NAME_RE.match(name):
                problems.append("name violates [A-Za-z0-9_.-]{1,128}")
            schema = tool.get("inputSchema")
            risky: list[str] = []
            if not isinstance(schema, dict):
                problems.append("inputSchema missing or not an object")
            else:
                if schema.get("type") not in (None, "object"):
                    problems.append(f"inputSchema.type is {schema.get('type')!r}, expected 'object'")
                props = schema.get("properties")
                if isinstance(props, dict):
                    for pname, pdef in props.items():
                        if not isinstance(pdef, dict):
                            continue
                        if (
                            pdef.get("type") == "string"
                            and RISKY_ARG_NAME.search(str(pname))
                            and not any(
                                k in pdef for k in ("enum", "pattern", "format", "maxLength", "const")
                            )
                        ):
                            risky.append(str(pname))
            if risky:
                problems.append("unconstrained string arguments: " + ", ".join(risky))
            if problems:
                findings.append(
                    self.finding(
                        description=f"Tool '{name}': " + "; ".join(problems) + ".",
                        severity=Severity.MEDIUM
                        if "inputSchema missing or not an object" in problems
                        else Severity.LOW,
                        confidence=Confidence.HIGH,
                        evidence=ev,
                        excerpt=evidence_summary(
                            ev, f"tools[{name}].inputSchema = {excerpt(json.dumps(schema), 160)}"
                        ),
                        location=f"tools[{name}]",
                        details={"problems": problems, "risky_arguments": risky},
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
                findings.append(self._finding_for(item.path, hits, item.text, evidence_map.get(item.kind)))
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
                        )
                    )
        # stdio: command line and environment supplied by the operator.
        if ctx.transport.name == "stdio":
            cmd = " ".join(ctx.options.stdio_command)
            hits = find_secrets(cmd)
            if hits:
                f = self._finding_for("stdio.command", hits, cmd, None)
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
                        location="stdio.env",
                        details={"variables": env_hits},
                    )
                )
        return findings

    def _finding_for(
        self, path: str, hits: list[dict[str, Any]], text: str, ev: EvidenceRecord | None
    ) -> Finding:
        top = max((Severity(h["severity"]) for h in hits), key=lambda s: s.rank)
        confidence = Confidence.HIGH if any(h["confidence"] == "high" for h in hits) else Confidence.LOW
        return self.finding(
            description=f"{path} contains: "
            + "; ".join(f"{h['kind']} {h['value']}" for h in hits)
            + f'. Excerpt: "{excerpt(redact_secrets(text))}"',
            severity=top,
            confidence=confidence,
            evidence=[ev] if ev else [],
            excerpt=f'{path}: "{excerpt(redact_secrets(text), 240)}"',
            location=path,
            details={"hits": hits},
        )
