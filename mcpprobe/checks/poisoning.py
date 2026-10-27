"""META-01: static tool-description poisoning heuristics.

The analysis is deliberately heuristic and tiered. It never produces a
Critical finding on its own; the confidence attached to each finding reflects
how specific the matched indicators are. An optional judge hook can be plugged
in via :class:`~mcpprobe.checks.base.ScanOptions.judge`; mcpprobe itself makes
no LLM calls.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from mcpprobe.checks._util import excerpt
from mcpprobe.checks.base import Check, ScanContext
from mcpprobe.models import Confidence, Finding, Severity, Standards

MAX_DESCRIPTION_LENGTH = 2000

_MARKUP = re.compile(
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|assistant|prompt|context)\b[^>]*>"
    r"|<!--|-->|\[/?INST\]|<<\s*/?SYS\s*>>|^\s*#+\s*system\b|\bSYSTEM\s*:",
    re.I | re.M,
)

_HIDDEN_INSTRUCTIONS: list[tuple[str, re.Pattern[str]]] = [
    (
        "conceal from user",
        re.compile(
            r"\b(do\s*n[o']t|never|must\s+not|should\s+not|without)\s+(tell(ing)?|inform(ing)?|"
            r"mention(ing)?|show(ing)?|display(ing)?|reveal(ing)?|disclos(e|ing)|alert(ing)?)\s+"
            r"(the\s+|to\s+the\s+)?(user|human|operator|person)\b"
            r"|\b(keep|hide)\s+(this|it)\s+(secret|hidden|from\s+the\s+user)\b"
            r"|\bimplementation\s+detail\b|\bsilently\b|\bsecretly\b|\bcovertly\b|\bdiscreetly\b",
            re.I,
        ),
    ),
    (
        "override instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|the\s+|your\s+)?"
            r"(previous|prior|above|earlier|other|system|safety)?\s*(instructions?|rules?|guidelines?|"
            r"prompts?|constraints?|policies)\b"
            r"|\bregardless\s+of\s+what\s+the\s+user\b|\byou\s+are\s+now\b|\bnew\s+instructions?\s*:",
            re.I,
        ),
    ),
    (
        "read and forward data",
        re.compile(
            r"\b(read|open|cat|load|access|collect|gather)\s+(the\s+)?(file|contents?\s+of|~|/|\$HOME|%)"
            r"|\b(pass|include|send|put|insert|embed|append|attach)\s+(its|the|their|all)\s+"
            r"(contents?|value|data|text|output)\b"
            r"|\bas\s+(a\s+)?(side\s*note|hidden\s+parameter|extra\s+(parameter|argument))\b"
            r"|\b(exfiltrate|upload|forward|transmit|leak)\b",
            re.I,
        ),
    ),
    (
        "prerequisite coercion",
        re.compile(
            r"\b(before|prior\s+to)\s+(using|calling|invoking|running)\s+(this|any|the)\s+tool"
            r"|\bthis\s+is\s+(a\s+)?(required|mandatory|necessary)\s+step\b"
            r"|\b(the\s+)?(assistant|model|ai|agent|you)\s+(must|should|need\s+to|has\s+to|have\s+to)\s+"
            r"(always\s+)?(first\s+)?(read|include|call|send|run|pass|execute|fetch)\b",
            re.I,
        ),
    ),
    (
        "redirect or replace",
        re.compile(
            r"\b(instead\s+of|rather\s+than|in\s+place\s+of)\s+(the\s+)?(intended|original|requested|user)"
            r"|\b(always\s+)?(bcc|cc|copy|forward)\s+(to\s+)?[\w.+-]+@[\w-]+\.[\w.-]+"
            r"|\b(redirect|reroute|change)\s+(all\s+)?(emails?|messages?|payments?|requests?|output)\b"
            r"|\b(replace|substitute|swap)\s+(the\s+)?(recipient|address|url|destination|account)\b",
            re.I,
        ),
    ),
]

_SENSITIVE_PATHS = re.compile(
    r"(~|\$HOME|%USERPROFILE%|/home/\w+|/Users/\w+|C:\\Users\\\w+)?"
    r"([/\\]\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|[/\\]\.aws[/\\]credentials|\bmcp\.json\b|"
    r"[/\\]\.cursor\b|[/\\]\.claude\b|[/\\]\.config[/\\]|(^|[\s/\\\"'])\.env\b|/etc/(passwd|shadow|hosts)|"
    r"[/\\]\.npmrc\b|[/\\]\.pypirc\b|[/\\]\.git-credentials\b|[/\\]\.kube[/\\]config|"
    r"[/\\]\.docker[/\\]config\.json|\bwallet\.dat\b|\bkeychain\b|[/\\]\.gnupg\b|"
    r"[/\\]\.bash_history\b|[/\\]\.netrc\b|\b(private|secret)[_ ]?key\b|/proc/self/environ)",
    re.I,
)

_URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")

_ZERO_WIDTH = {
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0xFEFF,
    0x180E,
    0x00AD,
}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_TAG_BLOCK = range(0xE0000, 0xE0080)

_SHADOW_CONTEXT = re.compile(
    r"\b(instead|before|after|when|whenever|always|never|redirect|replace|modify|override|"
    r"intercept|wrap|in\s+place\s+of|rather\s+than|prefer|do\s+not\s+use|don't\s+use|ignore)\b",
    re.I,
)


@dataclass(slots=True)
class Indicator:
    kind: str
    severity: Severity
    confidence: Confidence
    detail: str
    matches: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TextItem:
    """A piece of server-supplied text under review."""

    kind: str  # tool | tool_param | prompt | prompt_arg | resource | instructions
    owner: str  # tool/prompt/resource name, or 'server'
    path: str  # human-readable location, e.g. tools[add].description
    text: str


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"):
        if name.startswith(script):
            return script
    return "OTHER"


def find_mixed_script_words(text: str) -> list[str]:
    """Words mixing Latin with Cyrillic/Greek/etc. letters (homoglyph smuggling)."""
    out: list[str] = []
    for word in re.findall(r"\w+", text):
        scripts = {s for s in (_script_of(c) for c in word) if s and s != "OTHER"}
        if "LATIN" in scripts and len(scripts) > 1:
            out.append(word)
    return out[:10]


def find_invisible_unicode(text: str) -> dict[str, int]:
    counts = {"zero_width": 0, "bidi_control": 0, "tag_characters": 0}
    for ch in text:
        cp = ord(ch)
        if cp in _ZERO_WIDTH:
            counts["zero_width"] += 1
        elif cp in _BIDI:
            counts["bidi_control"] += 1
        elif cp in _TAG_BLOCK:
            counts["tag_characters"] += 1
    return {k: v for k, v in counts.items() if v}


def _looks_like_base64(blob: str) -> bool:
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
    # Either decodes to mostly text (hidden instructions) or is long opaque data.
    return printable / max(1, len(decoded)) > 0.8 or len(blob) >= 120


def analyse_text(text: str, *, other_tool_names: Sequence[str] = (), own_name: str = "") -> list[Indicator]:
    """Run every heuristic over one text and return the indicators found."""
    indicators: list[Indicator] = []
    if not text:
        return indicators

    invisible = find_invisible_unicode(text)
    if invisible:
        indicators.append(
            Indicator(
                "invisible_unicode",
                Severity.HIGH,
                Confidence.HIGH,
                "invisible or direction-control Unicode characters present: "
                + ", ".join(f"{k}={v}" for k, v in invisible.items()),
            )
        )
    homoglyphs = find_mixed_script_words(text)
    if homoglyphs:
        indicators.append(
            Indicator(
                "homoglyph",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "words mix Latin with other scripts (possible homoglyph smuggling)",
                homoglyphs,
            )
        )

    markup = [m.group(0) for m in _MARKUP.finditer(text)]
    if markup:
        indicators.append(
            Indicator(
                "hidden_markup",
                Severity.HIGH,
                Confidence.MEDIUM,
                "prompt-style markup inside a description",
                sorted(set(markup))[:5],
            )
        )

    instruction_kinds: list[str] = []
    instruction_matches: list[str] = []
    for label, pattern in _HIDDEN_INSTRUCTIONS:
        found = [m.group(0) for m in pattern.finditer(text)]
        if found:
            instruction_kinds.append(label)
            instruction_matches.extend(found[:3])
    if instruction_kinds:
        strong = "conceal from user" in instruction_kinds or "override instructions" in instruction_kinds
        indicators.append(
            Indicator(
                "hidden_instruction",
                Severity.HIGH if strong or len(instruction_kinds) >= 2 else Severity.MEDIUM,
                Confidence.HIGH if strong and len(instruction_kinds) >= 2 else Confidence.MEDIUM,
                "imperative instructions aimed at the model: " + ", ".join(instruction_kinds),
                instruction_matches[:6],
            )
        )

    paths = sorted({m.group(0).strip() for m in _SENSITIVE_PATHS.finditer(text)})
    if paths:
        indicators.append(
            Indicator(
                "sensitive_path",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "references to credential or configuration file paths",
                paths[:6],
            )
        )

    lowered = text.lower()
    refs = []
    for name in other_tool_names:
        if not name or name == own_name or len(name) < 3:
            continue
        if re.search(rf"(?<![\w.]){re.escape(name.lower())}(?![\w.])", lowered):
            refs.append(name)
    if refs:
        shadowing = bool(_SHADOW_CONTEXT.search(text))
        indicators.append(
            Indicator(
                "cross_tool_reference",
                Severity.MEDIUM if shadowing else Severity.LOW,
                Confidence.MEDIUM if shadowing else Confidence.LOW,
                "mentions other tools"
                + (" with behaviour-modifying language (shadowing)" if shadowing else ""),
                refs[:6],
            )
        )

    urls = sorted({m.group(0) for m in _URL.finditer(text)})
    if urls:
        exfil = bool(re.search(r"\b(send|post|upload|forward|submit|report)\b", lowered))
        indicators.append(
            Indicator(
                "url",
                Severity.MEDIUM if exfil else Severity.LOW,
                Confidence.MEDIUM if exfil else Confidence.LOW,
                "URL inside description" + (" alongside send/upload wording" if exfil else ""),
                urls[:4],
            )
        )
    emails = sorted({m.group(0) for m in _EMAIL.finditer(text)})
    if emails and re.search(r"\b(bcc|cc|send|forward|copy)\b", lowered):
        indicators.append(
            Indicator(
                "email_redirect",
                Severity.HIGH,
                Confidence.MEDIUM,
                "email address with send/bcc/forward wording",
                emails[:3],
            )
        )

    blobs = [m.group(0) for m in _BASE64.finditer(text) if _looks_like_base64(m.group(0))]
    if blobs:
        indicators.append(
            Indicator(
                "base64_blob",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "base64-looking blob embedded in text",
                [b[:24] + "\u2026" for b in blobs[:3]],
            )
        )

    if len(text) > MAX_DESCRIPTION_LENGTH:
        indicators.append(
            Indicator(
                "excessive_length",
                Severity.LOW,
                Confidence.LOW,
                f"description is {len(text)} characters (limit {MAX_DESCRIPTION_LENGTH})",
            )
        )
    return indicators


def collect_text_items(ctx: ScanContext) -> list[TextItem]:
    """Gather every server-supplied natural-language string worth scanning."""
    items: list[TextItem] = []
    if ctx.fingerprint.instructions:
        items.append(
            TextItem("instructions", "server", "initialize.instructions", ctx.fingerprint.instructions)
        )
    for tool in ctx.inventory.tools:
        name = str(tool.get("name", "?"))
        for key in ("description", "title"):
            if isinstance(tool.get(key), str) and tool[key]:
                items.append(TextItem("tool", name, f"tools[{name}].{key}", tool[key]))
        schema = tool.get("inputSchema")
        if isinstance(schema, dict):
            for pname, pdef in (
                (schema.get("properties") or {}).items() if isinstance(schema.get("properties"), dict) else []
            ):
                if isinstance(pdef, dict) and isinstance(pdef.get("description"), str):
                    items.append(
                        TextItem(
                            "tool_param",
                            name,
                            f"tools[{name}].inputSchema.{pname}.description",
                            pdef["description"],
                        )
                    )
    for prompt in ctx.inventory.prompts:
        name = str(prompt.get("name", "?"))
        if isinstance(prompt.get("description"), str):
            items.append(TextItem("prompt", name, f"prompts[{name}].description", prompt["description"]))
        for arg in prompt.get("arguments") or []:
            if isinstance(arg, dict) and isinstance(arg.get("description"), str):
                items.append(
                    TextItem(
                        "prompt_arg",
                        name,
                        f"prompts[{name}].arguments[{arg.get('name')}]",
                        arg["description"],
                    )
                )
    for res in ctx.inventory.resources:
        name = str(res.get("name") or res.get("uri") or "?")
        for key in ("description", "title"):
            if isinstance(res.get(key), str) and res[key]:
                items.append(TextItem("resource", name, f"resources[{name}].{key}", res[key]))
    return items


class Meta01ToolDescriptionPoisoning(Check):
    id = "META-01"
    title = "Possible tool-description poisoning"
    severity = Severity.HIGH
    standards = Standards(
        mcp=["MCP03:2025"], asi=["ASI01", "ASI04"], llm_2025=["LLM01:2025"], llm_2026=["LLM01:2026"]
    )
    description = (
        "Scans every tool, prompt and resource description, every inputSchema parameter "
        "description and the server 'instructions' for: prompt-style markup (<IMPORTANT>, "
        "<system>), instructions aimed at the model (conceal from user, override instructions, "
        "read-and-forward, prerequisite coercion, redirect/replace), credential file paths, "
        "references to other tools with behaviour-modifying language (shadowing), URLs and "
        "e-mail addresses with send/BCC wording, base64 blobs, zero-width/bidi/tag Unicode, "
        "mixed-script homoglyphs and excessive length. Findings carry tiered confidence and "
        "are never rated Critical on heuristics alone."
    )
    evidence_type = "The tools/list (or prompts/resources/initialize) response and the matched excerpts."
    false_positive_notes = (
        "Legitimate guidance such as 'IMPORTANT: call authenticate before this tool' matches the "
        "markup and prerequisite heuristics at medium confidence. URLs to documentation and "
        "mentions of sibling tools without behaviour-modifying words are reported at low severity. "
        "Review the matched excerpts; use --judge to attach a second-opinion scorer."
    )
    fix = (
        "Remove any text addressed to the model rather than describing the tool. Keep descriptions "
        "short and factual, strip invisible Unicode, and never reference other servers' tools. "
        "Pin and hash approved descriptions in clients (see META-02)."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        names = ctx.tool_names()
        findings: list[Finding] = []
        evidence_map = {
            "tool": ctx.inventory.tools_evidence,
            "tool_param": ctx.inventory.tools_evidence,
            "prompt": ctx.inventory.prompts_evidence,
            "prompt_arg": ctx.inventory.prompts_evidence,
            "resource": ctx.inventory.resources_evidence,
            "instructions": None,
        }
        for item in collect_text_items(ctx):
            indicators = analyse_text(item.text, other_tool_names=names, own_name=item.owner)
            if ctx.options.judge is not None:
                verdict = ctx.options.judge(item.text, f"tool-description poisoning review for {item.path}")
                if verdict is not None and verdict.suspicious:
                    indicators.append(
                        Indicator(
                            "judge",
                            Severity.MEDIUM,
                            verdict.confidence,
                            "judge flagged: " + (verdict.rationale or "no rationale"),
                        )
                    )
            if not indicators:
                continue
            severity = max((i.severity for i in indicators), key=lambda s: s.rank)
            confidence = _combine_confidence(indicators)
            ev = evidence_map.get(item.kind)
            findings.append(
                self.finding(
                    description=(
                        f"{item.path}: "
                        + "; ".join(i.detail for i in indicators)
                        + f'. Excerpt: "{excerpt(item.text)}"'
                    ),
                    severity=severity,
                    confidence=confidence,
                    evidence=[ev] if ev else [],
                    excerpt=f'{item.path}: "{excerpt(item.text, 240)}"',
                    location=item.path,
                    details={
                        "indicators": [
                            {
                                "kind": i.kind,
                                "severity": i.severity.value,
                                "confidence": i.confidence.value,
                                "detail": i.detail,
                                "matches": i.matches,
                            }
                            for i in indicators
                        ],
                        "length": len(item.text),
                    },
                )
            )
        return findings


def _combine_confidence(indicators: list[Indicator]) -> Confidence:
    highs = sum(1 for i in indicators if i.confidence == Confidence.HIGH)
    mediums = sum(1 for i in indicators if i.confidence == Confidence.MEDIUM)
    if highs or mediums >= 3:
        return Confidence.HIGH
    if mediums:
        return Confidence.MEDIUM
    return Confidence.LOW


def tool_descriptions(tools: list[dict[str, Any]]) -> list[str]:
    """Convenience for callers that just want the descriptions."""
    return [str(t.get("description", "")) for t in tools]
