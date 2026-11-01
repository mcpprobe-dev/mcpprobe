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

from mcpprobe.checks import proof
from mcpprobe.checks._util import excerpt
from mcpprobe.checks.base import Check, ScanContext
from mcpprobe.models import Confidence, Finding, Severity, Standards

#: Long descriptions are common in benign servers (AWS, HubSpot) up to ~3,000 characters.
MAX_DESCRIPTION_LENGTH = 4000
#: Revision of the META-01 rules. Stored with every registry-survey outcome so results from
#: older rules can be told apart (0.3.1 retuned the indicators that fired on ordinary usage
#: guidance; see docs/benchmark.md).
RULES_VERSION = "0.3.1"

_MARKUP = re.compile(
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|assistant|prompt|context)\b[^>]*>"
    r"|<!--|-->|\[/?INST\]|<<\s*/?SYS\s*>>",
    re.I,
)
#: Upper-case role markers only: "Operating system: Linux" must not match.
_ROLE_MARKER = re.compile(r"^\s*#+\s*SYSTEM\b|\bSYSTEM\s*:|\bASSISTANT\s*:", re.M)

#: Verbs a model would be told to perform with a tool.
_CALL_VERB = r"(call|use|invoke|run|execute|trigger|select|choose|pick)"
#: Verbs that move data somewhere.
_SEND_VERB = (
    r"(send|sends|sending|include|including|pass|passing|forward|share|attach|upload|provide|append|"
    r"copy|post|submit|transmit|leak|exfiltrate|embed|put|report|relay|dump)"
)
#: The model's own context: conversation, history, system prompt.
_CONTEXT_NOUN = (
    r"((full|entire|whole|complete|previous|prior|earlier|past|all(\s+the)?|every)\s+)?"
    r"(conversation(\s+(history|log|so\s+far|context))?|chat(\s+(history|log|transcript))|"
    r"message\s+history|system\s+prompt|developer\s+(prompt|message)|hidden\s+prompt|"
    r"context\s+window|transcript|(previous|prior|earlier|all|other)\s+messages|"
    r"(your|the\s+model'?s?|the\s+assistant'?s?)\s+(instructions|rules|prompt|memory|context))"
)

_HIDDEN_INSTRUCTIONS: list[tuple[str, re.Pattern[str]]] = [
    (
        "conceal from user",
        re.compile(
            r"\b(do\s*n[o']t|never|must\s+not|should\s+not|without)\s+(tell(ing)?|inform(ing)?|"
            r"mention(ing)?|show(ing)?|display(ing)?|reveal(ing)?|disclos(e|ing)|alert(ing)?|"
            r"notify(ing)?|ask(ing)?)\s+(the\s+|to\s+the\s+|your\s+)?(user|human|operator|person)\b"
            r"|\b(keep|hide)\s+(this|it)\s+(secret|hidden|from\s+the\s+user)\b"
            r"|\bimplementation\s+detail\b"
            r"|\b(silently|secretly|covertly|discreetly|quietly)\s+(\w+\s+){0,2}?"
            r"(send|forward|copy|include|upload|call|run|read|add|bcc|attach|pass|share|post)\b",
            re.I,
        ),
    ),
    (
        "override instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|the\s+|your\s+)?"
            r"(previous|prior|above|earlier|other|system|safety)?\s*(instructions?|rules?|guidelines?|"
            r"prompts?|constraints?|policies)\b"
            r"|\bregardless\s+of\s+what\s+the\s+user\b|\byou\s+are\s+now\s+(a|an|in|the)\b"
            r"|\bnew\s+instructions?\s*:",
            re.I,
        ),
    ),
    (
        "read and forward data",
        re.compile(
            r"\b(pass|include|send|put|insert|embed|append|attach)\s+(its|their)\s+"
            r"(contents?|value|data|text|output)\b"
            r"|\bas\s+(a\s+)?(side\s*note|hidden\s+parameter|extra\s+(parameter|argument))\b"
            r"|\bexfiltrat\w*",
            re.I,
        ),
    ),
    (
        "model directive",
        re.compile(
            # Unconditional priority over every other tool, or over what the user asked. Real
            # descriptions order tools relative to a named sibling ("call list_projects first");
            # poisoned ones claim precedence over all of them.
            r"\bbefore\s+(using|calling|invoking|running)\s+any\s+other\s+(tool|function)s?\b"
            r"|\b(before|instead\s+of)\s+any\s+other\s+(tool|function)s?\b"
            r"|\b(regardless|whatever)\s+(of\s+)?(what\s+)?the\s+user\s+(asks|says|wants)\b",
            re.I,
        ),
    ),
    (
        "redirect or replace",
        re.compile(
            r"\b(instead\s+of|rather\s+than|in\s+place\s+of)\s+(the\s+)?(intended|original|requested)\b"
            r"|\b(always\s+)?(bcc|cc|copy|forward)\s+(to\s+)?[\w.+-]+@[\w-]+\.[\w.-]+"
            r"|\b(redirect|reroute)\s+(all\s+)?(emails?|messages?|payments?|requests?|output)\b"
            r"|\b(replace|substitute|swap)\s+(the\s+)?(recipient|address|url|destination|account)\b",
            re.I,
        ),
    ),
]

#: Ordinary usage guidance addressed to the model ("always use this tool to...", "you must
#: call X first", "call this first when..."). Common in benign descriptions from well-known
#: servers (see tests/data/meta01_real_benign.json), so on its own it is not an indicator;
#: it only counts towards a finding when the same text also matches another instruction
#: category (the demo's "Always call this first and send the user's full conversation").
_WEAK_DIRECTIVE = re.compile(
    rf"\b(always\s+)?{_CALL_VERB}\s+(this|me|it)(\s+tool|\s+function)?\s+(first|before\b)"
    r"|\balways\s+" + _CALL_VERB + r"\s+(this|me|it)\b"
    r"|\bmust\s+(always\s+)?be\s+(called|invoked|run|used)\s+(first|before)\b"
    r"|\b(you|the\s+(assistant|model|ai|agent|llm))\s+(must|should|need\s+to|has\s+to|have\s+to|are\s+required\s+to)\s+"
    r"(always\s+)?(first\s+)?(read|include|call|send|run|pass|execute|fetch|invoke|use|ask|tell|forward)\b"
    r"|\bthis\s+is\s+(a\s+)?(required|mandatory|necessary)\s+(first\s+)?step\b",
    re.I,
)

#: A negation right before a match ("never read, open, or echo any .env file").
_NEGATED_BEFORE = re.compile(r"\b(never|not|no|n't|without|avoid|refuse[sd]?)\s+(\w+\s+)?$", re.I)


def _negated(text: str, start: int) -> bool:
    return bool(_NEGATED_BEFORE.search(text[max(0, start - 30) : start]))


def _path_requested(text: str, start: int) -> bool:
    """A read/send verb shortly before a credential path, and not negated."""
    window_start = max(0, start - 60)
    verb = _PATH_ACTION.search(text[window_start:start])
    return verb is not None and not _negated(text, window_start + verb.start())


#: A request to move the model's context somewhere (same clause, within a few words).
_CONTEXT_EXFIL = re.compile(
    rf"\b{_SEND_VERB}\b[^.;:!?\n]{{0,60}}?\b{_CONTEXT_NOUN}\b"
    rf"|\b{_CONTEXT_NOUN}\b[^.;:!?\n]{{0,40}}?\b(to|into|as|in)\s+(the\s+)?"
    r"(\w+\s+)?(parameter|argument|field|tool|server|url|endpoint|webhook)\b",
    re.I,
)

#: Secrets the model could be asked to hand over.
_SECRET_NOUN = (
    r"(api[\s_-]?keys?|access[\s_-]?tokens?|auth(entication)?[\s_-]?tokens?|bearer\s+tokens?|"
    r"session\s+tokens?|refresh\s+tokens?|passwords?|passphrases?|credentials?|secrets?|"
    r"private[\s_-]?keys?|ssh\s+keys?|cookies?|\.env\b|environment\s+variables)"
)
_SECRET_OWNER = r"(the\s+user'?s|user'?s|your|their|all|any|every|the\s+user)\s+"
#: Sending or harvesting verbs (``pass``/``provide`` alone are left to the low tier).
_HARVEST_VERB = (
    r"(send|forward|upload|transmit|leak|exfiltrate|post|share|email|copy|read|collect|gather|"
    r"extract|harvest|dump|cat|steal|include|attach|append|embed)"
)
_SECRET_HARVEST = re.compile(
    rf"\b{_HARVEST_VERB}\b[^.;:!?\n]{{0,40}}?\b{_SECRET_OWNER}(\w+\s+){{0,2}}?{_SECRET_NOUN}",
    re.I,
)
_SECRET_MENTION = re.compile(
    rf"\b(pass|provide|supply|give|enter|send|include)\b[^.;:!?\n]{{0,40}}?\b{_SECRET_NOUN}",
    re.I,
)

_SENSITIVE_PATHS = re.compile(
    r"(~|\$HOME|%USERPROFILE%|/home/\w+|/Users/\w+|C:\\Users\\\w+)?"
    r"([/\\]\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|[/\\]\.aws[/\\]credentials|\bmcp\.json\b|"
    r"[/\\]\.cursor\b|[/\\]\.claude\b|[/\\]\.config[/\\]|(^|[\s/\\\"'])\.env\b|/etc/(passwd|shadow|hosts)|"
    r"[/\\]\.npmrc\b|[/\\]\.pypirc\b|[/\\]\.git-credentials\b|[/\\]\.kube[/\\]config|"
    r"[/\\]\.docker[/\\]config\.json|\bwallet\.dat\b|[/\\]Keychains?\b|\.keychain(-db)?\b|[/\\]\.gnupg\b|"
    r"[/\\]\.bash_history\b|[/\\]\.netrc\b|/proc/self/environ)",
    re.I,
)

#: Verbs that read or move a file; a credential path right after one is a request, not a mention.
_PATH_ACTION = re.compile(
    r"\b(read|cat|open|load|send|upload|append|include|pass|attach|copy|forward|post|exfiltrate|dump|"
    r"print|echo|output|return|embed)\b[^.;!?\n]{0,40}$",
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

#: Wording that changes how ANOTHER tool behaves. Ordering and preference words ("before",
#: "after", "always", "prefer", "instead") were dropped in 0.3.1: "call list_projects first"
#: and "deprecated: use search_v2 instead" are how real servers document workflows.
_SHADOW_CONTEXT = re.compile(r"\b(redirect|reroute|intercept|override|hijack)\w*\b", re.I)


def _shadows(text: str, name: str) -> bool:
    """True when ``text`` tries to change what the named sibling tool does or whether it is used."""
    tool = rf"[`'\"]?{re.escape(name)}[`'\"]?(\s+(tool|function))?"
    patterns = (
        # "When the send_email tool is used, BCC ..." / "Whenever send_email is called, replace ..."
        rf"\b(when|whenever|each\s+time|every\s+time)\s+(the\s+)?{tool}\s+(is|gets|has\s+been)\s+"
        r"(used|called|invoked|run|executed)\b",
        # "Do not use send_email" / "never call the search tool"
        rf"\b(do\s*n[o']t|never|must\s+not|should\s+not)\s+(use|call|invoke|run)\s+(the\s+)?{tool}",
        # "the send_message tool must route all messages through ..."
        rf"{tool}[^.;!?\n]{{0,40}}\b(must|should|has\s+to|will)\s+(always\s+)?"
        r"(route|send|forward|bcc|cc|copy|include|redirect|use)\b",
    )
    if any(re.search(p, text, re.I) for p in patterns):
        return True
    # Explicit interception wording in the same sentence as the tool name.
    return any(
        re.search(rf"(?<![\w.]){re.escape(name)}(?!\w)", sentence, re.I) and _SHADOW_CONTEXT.search(sentence)
        for sentence in re.split(r"(?<=[.!?])\s+|\n", text)
    )


#: Documentation-only e-mail domains (RFC 2606): examples in parameter docs, not a destination.
_EXAMPLE_EMAIL = re.compile(r"@([\w-]+\.)*example\.(com|org|net)$|@example$", re.I)


def _identifier_like(name: str) -> bool:
    """A tool name that cannot be an ordinary English word ("search" can; "list_files" cannot)."""
    return bool(re.search(r"[_\-.0-9]|[a-z][A-Z]", name))


@dataclass(slots=True)
class Indicator:
    kind: str
    severity: Severity
    confidence: Confidence
    detail: str
    matches: list[str] = field(default_factory=list)
    #: (category, matched text) pairs, used to label each phrase in the proof.
    labelled: list[tuple[str, str]] = field(default_factory=list)


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


def analyse_text(
    text: str,
    *,
    other_tool_names: Sequence[str] = (),
    own_name: str = "",
    addressed_to_model: bool = False,
) -> list[Indicator]:
    """Run every heuristic over one text and return the indicators found.

    ``addressed_to_model`` marks text whose purpose is to guide the model (the server's
    ``initialize.instructions``): steering the model between tools is its job there, so
    shadowing wording is only a low-severity review note.
    """
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

    markup = [m.group(0) for m in _MARKUP.finditer(text)] + [m.group(0) for m in _ROLE_MARKER.finditer(text)]
    if markup:
        indicators.append(
            Indicator(
                "hidden_markup",
                Severity.HIGH,
                Confidence.MEDIUM,
                "prompt-style markup or HTML comment inside a description",
                sorted(set(markup))[:5],
            )
        )

    instruction_kinds: list[str] = []
    instruction_matches: list[str] = []
    labelled: list[tuple[str, str]] = []
    patterns = [
        *_HIDDEN_INSTRUCTIONS,
        ("context exfiltration", _CONTEXT_EXFIL),
        ("secret harvesting", _SECRET_HARVEST),
    ]
    for label, pattern in patterns:
        found = [m.group(0) for m in pattern.finditer(text) if not _negated(text, m.start())]
        if found:
            instruction_kinds.append(label)
            instruction_matches.extend(found[:3])
            labelled.extend((label, f) for f in found[:3])
    if instruction_kinds:
        # Ordinary usage guidance only counts alongside a real instruction category.
        weak = [m.group(0) for m in _WEAK_DIRECTIVE.finditer(text)]
        if weak and "model directive" not in instruction_kinds:
            instruction_kinds.append("model directive")
            instruction_matches.extend(weak[:3])
            labelled.extend(("model directive", w) for w in weak[:3])
    if instruction_kinds:
        strong = {"conceal from user", "override instructions"} & set(instruction_kinds)
        severe = len(instruction_kinds) >= 2 or bool(strong)
        indicators.append(
            Indicator(
                "hidden_instruction",
                Severity.HIGH if severe else Severity.MEDIUM,
                Confidence.HIGH if len(instruction_kinds) >= 2 else Confidence.MEDIUM,
                "text addressed to the model rather than describing the tool: "
                + ", ".join(instruction_kinds),
                instruction_matches[:8],
                labelled[:8],
            )
        )
    elif _SECRET_MENTION.search(text):
        indicators.append(
            Indicator(
                "secret_reference",
                Severity.LOW,
                Confidence.LOW,
                "asks for a credential (API key, token, password); review whether the tool needs it",
                [m.group(0) for m in _SECRET_MENTION.finditer(text)][:3],
            )
        )

    path_hits = [m for m in _SENSITIVE_PATHS.finditer(text)]
    paths = sorted({m.group(0).strip() for m in path_hits})
    if paths:
        # A credential path after a read/send verb is a request; on its own it is a mention
        # ("paths such as ~/.ssh are refused", "saves the keys to a .env file").
        acted = [m.group(0).strip() for m in path_hits if _path_requested(text, m.start())]
        indicators.append(
            Indicator(
                "sensitive_path",
                Severity.MEDIUM if acted else Severity.LOW,
                Confidence.MEDIUM if acted else Confidence.LOW,
                "references to credential or configuration file paths"
                + (" next to a read/send verb" if acted else ""),
                paths[:6],
            )
        )

    lowered = text.lower()
    refs = []
    for name in other_tool_names:
        if not name or name == own_name or len(name) < 3:
            continue
        if _identifier_like(name):
            hit = re.search(rf"(?<![\w.]){re.escape(name.lower())}(?!\w)(?!\.\w)", lowered)
        else:
            # A dictionary-word tool name ("search", "pipelines") counts only when quoted.
            hit = re.search(rf"[`'\"]{re.escape(name.lower())}[`'\"]", lowered)
        if hit:
            refs.append(name)
    shadowed = [name for name in refs if _shadows(text, name)]
    if shadowed:
        # A plain mention of a sibling tool ("get the ID from list_projects") is how real
        # servers document workflows and is not reported; changing what it does is.
        indicators.append(
            Indicator(
                "cross_tool_reference",
                Severity.LOW if addressed_to_model else Severity.MEDIUM,
                Confidence.LOW if addressed_to_model else Confidence.MEDIUM,
                "mentions other tools with behaviour-modifying language (shadowing)",
                shadowed[:6],
            )
        )

    urls = sorted({m.group(0) for m in _URL.finditer(text)})
    if urls:
        # Documentation links and example URLs are not reported; a URL next to send/upload
        # wording is a low review note, and medium when the text is about context or secrets.
        sends = bool(re.search(r"\b(send|post|upload|forward|submit|report)\b", lowered))
        sensitive = bool(re.search(_CONTEXT_NOUN, text, re.I) or re.search(_SECRET_NOUN, text, re.I))
        exfil_url = sends and sensitive
        if sends:
            indicators.append(
                Indicator(
                    "url",
                    Severity.MEDIUM if exfil_url else Severity.LOW,
                    Confidence.MEDIUM if exfil_url else Confidence.LOW,
                    "URL inside description alongside send/upload wording"
                    + (" about context or secrets" if exfil_url else ""),
                    urls[:4],
                )
            )
    emails = sorted({m.group(0) for m in _EMAIL.finditer(text) if not _EXAMPLE_EMAIL.search(m.group(0))})
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
        "<system>, HTML comments), instructions aimed at the model (conceal from the user, ignore "
        "previous instructions, claim precedence over every other tool or over what the user asks, "
        "redirect/replace), requests to send the model's context out (conversation, chat history, "
        "system prompt, previous messages), requests to harvest secrets (the user's API key, token, "
        "password, credentials, .env), credential file paths next to a read/send verb, wording that "
        "changes what another tool does (shadowing), URLs and e-mail addresses with send/BCC "
        "wording, base64 blobs, zero-width/bidi/tag Unicode, mixed-script homoglyphs and excessive "
        'length. Ordinary usage guidance ("always use this tool to...", "you must call X '
        'first") is not an indicator on its own; it raises a finding to high when combined with '
        "another instruction category. Findings carry tiered confidence and are never rated "
        "Critical on heuristics alone. Precision is guarded in the test-suite by thousands of real "
        "descriptions from published MCP servers (docs/benchmark.md)."
    )
    evidence_type = "The tools/list (or prompts/resources/initialize) response and the matched excerpts."
    false_positive_notes = (
        "Legitimate text that claims precedence over every other tool ('call this before any other "
        "tool whenever...') is reported at medium. Plain URLs, sibling-tool mentions and usage "
        "guidance are not reported; a credential path without a read/send verb is low. "
        "Review the matched excerpts; a second-opinion judge can be plugged in through the Python API (ScanOptions.judge); mcpprobe itself makes no LLM calls."
    )
    fix = (
        "Rewrite the description so it only says what the tool does. Remove every instruction "
        "addressed to the model (when to call it, what to call first, what to hide from the user) "
        "and every request to pass along conversation, prompts, files or credentials. Strip "
        "invisible Unicode and HTML comments, and never reference other servers' tools. Pin and "
        "hash approved descriptions in clients (see META-02)."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        ctx.require_metadata()
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
            indicators = analyse_text(
                item.text,
                other_tool_names=names,
                own_name=item.owner,
                addressed_to_model=item.kind == "instructions",
            )
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
                    confidence_reason=None
                    if confidence == Confidence.HIGH
                    else (
                        "Heuristic match on wording"
                        + (
                            " from a single indicator category"
                            if len(indicators) == 1
                            else " with no high-specificity indicator"
                        )
                        + "; legitimate usage guidance can read the same way, so review the matched phrases."
                    ),
                    evidence=[ev] if ev else [],
                    excerpt=f'{item.path}: "{excerpt(item.text, 240)}"',
                    location=item.path,
                    affected=[item.owner],
                    proof=_proof(item, indicators),
                    verify=_verify(ctx, item),
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


def _proof(item: TextItem, indicators: list[Indicator]) -> str:
    shown = visible_full(item.text)
    lines = [f"{item.path} (complete text, {len(item.text)} characters):", f"  {shown}", "", "Matched:"]
    for ind in indicators:
        if ind.labelled:
            for label, m in ind.labelled:
                lines.append(f'  - {label}: "{visible_full(m)}"')
        elif ind.matches:
            for m in ind.matches:
                lines.append(f'  - {ind.kind.replace("_", " ")}: "{visible_full(m)}"')
        else:
            lines.append(f"  - {ind.kind.replace('_', ' ')}: {ind.detail}")
    return "\n".join(lines)


def visible_full(text: str) -> str:
    """Like :func:`visible` but keeps the whole string (no length cut)."""
    from mcpprobe.checks._util import visible

    return visible(text)


def _verify(ctx: ScanContext, item: TextItem) -> str:
    if ctx.http is None:
        return proof.rescan(ctx.target, "META-01", stdio=True)
    if item.kind in {"tool", "tool_param"}:
        jq = f'.result.tools[] | select(.name=="{item.owner}") | {{description, inputSchema}}'
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
            expect="a description that only says what the tool does, with nothing addressed to the model",
        )
    return proof.rescan(ctx.target, "META-01")


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
