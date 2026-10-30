"""Heuristic classification of tools into capability classes.

Used by META-03 (annotation cross-check) and to weight the severity of other
findings (an unauthenticated server exposing ``run_command`` is worse than one
exposing ``get_weather``). Annotations are *not* used as input, because the
spec says clients must treat them as untrusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Classes considered dangerous when exposed without authentication.
DANGEROUS_CLASSES: frozenset[str] = frozenset(
    {"exec", "file_write", "database_write", "network", "email", "credentials", "payments"}
)

#: Classes that imply a write/side effect (should not be ``readOnlyHint: true``).
WRITE_CLASSES: frozenset[str] = frozenset(
    {"exec", "file_write", "database_write", "email", "payments", "delete"}
)

_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "exec",
        re.compile(
            r"\b(exec(ute)?|shell|bash|sh|cmd|command|run_?(command|script|code)|"
            r"subprocess|powershell|terminal|eval|spawn|system)\b",
            re.I,
        ),
    ),
    (
        "file_write",
        re.compile(
            r"\b(write_?file|save_?file|create_?file|edit_?file|move_?file|"
            r"rename|chmod|mkdir|upload|overwrite|append_?file)\b",
            re.I,
        ),
    ),
    ("delete", re.compile(r"\b(delete|remove|rm|drop|purge|destroy|truncate|wipe)\b", re.I)),
    (
        "file_read",
        re.compile(
            r"\b(read_?file|cat|open_?file|list_?dir(ectory)?|ls|glob|"
            r"file_?(content|path)|filesystem|directory)\b",
            re.I,
        ),
    ),
    (
        "database_write",
        re.compile(
            r"\b(insert|update|upsert|alter|create_?table|migrate|"
            r"execute_?sql|run_?sql|sql_?(exec|write))\b",
            re.I,
        ),
    ),
    (
        "database_read",
        re.compile(
            r"\b(sql|query|select|database|db|postgres|mysql|sqlite|mongo|"
            r"redis|table|schema)\b",
            re.I,
        ),
    ),
    (
        "network",
        re.compile(
            r"\b(fetch|http|url|curl|wget|download|request|browse|crawl|scrape|"
            r"webhook|api_?call|proxy|ssrf)\b",
            re.I,
        ),
    ),
    (
        "email",
        re.compile(
            r"\b(e-?mail|smtp|send_?(mail|message|sms|slack|notification)|"
            r"bcc|cc|recipient|inbox|mailbox)\b",
            re.I,
        ),
    ),
    (
        "credentials",
        re.compile(
            r"\b(secret|token|credential|password|api_?key|ssh|private_?key|"
            r"keychain|vault|oauth|\.env)\b",
            re.I,
        ),
    ),
    (
        "payments",
        re.compile(
            r"\b(payment|pay|charge|refund|invoice|stripe|billing|transfer_?funds|"
            r"wallet|crypto)\b",
            re.I,
        ),
    ),
    ("search", re.compile(r"\b(search|find|lookup|get|list|read|fetch_?info|describe|show)\b", re.I)),
]


@dataclass(slots=True)
class Classification:
    name: str
    classes: list[str] = field(default_factory=list)
    matched_terms: dict[str, list[str]] = field(default_factory=dict)

    #: Arbitrary-capability kinds (see :func:`arbitrary_capabilities`), with the argument that enables each.
    arbitrary: dict[str, str] = field(default_factory=dict)

    @property
    def dangerous(self) -> bool:
        return bool(self.arbitrary) or any(c in DANGEROUS_CLASSES for c in self.classes)

    @property
    def writes(self) -> bool:
        return any(c in WRITE_CLASSES for c in self.classes)

    @property
    def primary(self) -> str:
        return self.classes[0] if self.classes else "other"


def _text_of(tool: dict[str, Any]) -> tuple[str, str]:
    """Return (name-ish text, description-ish text)."""
    name_text = (
        " ".join(str(tool.get(k, "")) for k in ("name", "title") if tool.get(k))
        .replace("_", " ")
        .replace("-", " ")
        .replace(".", " ")
    )
    desc_parts = [str(tool.get("description", "") or "")]
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            for pname, pdef in props.items():
                desc_parts.append(str(pname).replace("_", " "))
                if isinstance(pdef, dict) and pdef.get("description"):
                    desc_parts.append(str(pdef["description"]))
    return name_text, " ".join(desc_parts)


def classify_tool(tool: dict[str, Any]) -> Classification:
    """Classify one tool. Name matches weigh more than description matches."""
    name_text, desc_text = _text_of(tool)
    name = str(tool.get("name", ""))
    name_text = f"{name_text} {name}"
    scores: dict[str, int] = {}
    terms: dict[str, list[str]] = {}
    for cls, pattern in _RULES:
        name_hits = pattern.findall(name_text + " " + name.replace("_", " "))
        desc_hits = pattern.findall(desc_text)
        hits = [h if isinstance(h, str) else h[0] for h in name_hits + desc_hits]
        hits = [h for h in hits if h]
        if not hits:
            continue
        score = 3 * len([h for h in name_hits if h]) + len([h for h in desc_hits if h])
        scores[cls] = score
        terms[cls] = sorted(set(hits))[:5]
    # "search" is a weak catch-all; drop it when anything stronger matched.
    if "search" in scores and len(scores) > 1:
        scores.pop("search")
        terms.pop("search", None)
    # database_read is implied by database_write.
    if "database_write" in scores and "database_read" in scores:
        scores.pop("database_read")
        terms.pop("database_read", None)
    ordered = [c for c, _ in sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))]
    return Classification(
        name=name, classes=ordered, matched_terms=terms, arbitrary=arbitrary_capabilities(tool)
    )


# ----------------------------------------------------------------------------- arbitrary capabilities
ARBITRARY_EXEC = "arbitrary_command_execution"
ARBITRARY_FILE_READ = "arbitrary_file_read"
ARBITRARY_FILE_WRITE = "arbitrary_file_write"

_EXEC_WORDS = re.compile(
    r"\b(shell|bash|zsh|sh|cmd|command|commands|terminal|subprocess|powershell|eval|"
    r"exec(ute)?_?(command|shell|script|code|cmd)|run_?(command|script|code|shell|cmd))\b",
    re.I,
)
_EXEC_ARG = re.compile(
    r"^(cmd|command|commands|script|code|shell|expr|expression|line|args?|argv|program)$", re.I
)
_READ_WORDS = re.compile(
    r"\b(read_?file|file_?read|get_?file|open_?file|cat|file_?contents?|"
    r"read\s+(any\s+|a\s+|the\s+|arbitrary\s+)?files?|contents?\s+of\s+(any|a|the)\s+file)\b",
    re.I,
)
_WRITE_WORDS = re.compile(
    r"\b(write_?file|save_?file|create_?file|edit_?file|file_?write|"
    r"write\s+(to\s+)?(any\s+|a\s+|the\s+|arbitrary\s+)?files?)\b",
    re.I,
)
_PATH_ARG = re.compile(
    r"^(path|file|filename|file_?path|filepath|file_?name|target|dest(ination)?|location)$", re.I
)


def _unconstrained_strings(tool: dict[str, Any]) -> list[str]:
    """String arguments with no enum/const/pattern (maxLength bounds size, not content)."""
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    out: list[str] = []
    for pname, pdef in props.items():
        if not isinstance(pdef, dict):
            continue
        if pdef.get("type", "string") != "string":
            continue
        if any(k in pdef for k in ("enum", "const", "pattern")):
            continue
        out.append(str(pname))
    return out


def arbitrary_capabilities(tool: dict[str, Any]) -> dict[str, str]:
    """Advertised capabilities that are arbitrary by construction.

    A tool qualifies when its name/description advertise command execution or
    file access *and* it takes a free-form string argument (no enum, const or
    pattern) that selects the command or path. Based on what the server
    advertises; a passive scan does not call the tool.
    """
    name = str(tool.get("name", ""))
    text = f"{name} {name.replace('_', ' ')} {tool.get('title') or ''} {tool.get('description') or ''}"
    free = _unconstrained_strings(tool)
    out: dict[str, str] = {}
    if _EXEC_WORDS.search(text):
        arg = next((a for a in free if _EXEC_ARG.match(a)), None)
        if arg:
            out[ARBITRARY_EXEC] = arg
    path_arg = next((a for a in free if _PATH_ARG.match(a)), None)
    if path_arg and _READ_WORDS.search(text):
        out[ARBITRARY_FILE_READ] = path_arg
    if path_arg and _WRITE_WORDS.search(text):
        out[ARBITRARY_FILE_WRITE] = path_arg
    return out


def classify_tools(tools: list[dict[str, Any]]) -> dict[str, Classification]:
    return {str(t.get("name", "")): classify_tool(t) for t in tools}


# ----------------------------------------------------------------------------- toxic-flow roles (META-07)
ROLE_PRIVATE = "private_data"
ROLE_UNTRUSTED = "untrusted_content"
ROLE_SEND = "external_send"

#: Reading mail or messages: private data and, at the same time, content written by strangers.
_INBOX_READ = re.compile(
    r"\b(inbox|mailbox|unread|read\s*_?(e-?mails?|mail|messages?)|"
    r"(list|get|search|fetch|retrieve)\s*_?(e-?mails?|mail|messages?))\b",
    re.I,
)
#: Pulling content from the open web.
_WEB_INTAKE = re.compile(
    r"\b(fetch|browse|crawl|scrape|download|web\s*_?search|search\s*_?(the\s+)?web|"
    r"(read|get|open|load)\s*_?(a\s+|the\s+)?(url|web\s*page|page|website)|rss|feed)\b",
    re.I,
)
#: Moving data out of the server's own boundary.
_SEND_OUT = re.compile(
    r"\b(send|sends|post|posts|publish|tweet|webhook|notify|upload|transmit|forward|reply|"
    r"smtp|share|e-?mail\s+(to|a|an)\b)",
    re.I,
)
#: Verbs that make an e-mail or payment tool a write rather than a read.
_MUTATING = re.compile(
    r"\b(send|sends|post|charge|refund|pay|transfer|create|cancel|delete|update|write|forward|reply)\b",
    re.I,
)

#: Classes that change or destroy state on their own (no verb needed).
MUTATING_CLASSES: frozenset[str] = frozenset({"exec", "file_write", "database_write", "delete"})
#: Classes that are writes only when a mutating verb is present.
VERB_MUTATING_CLASSES: frozenset[str] = frozenset({"email", "payments"})
_PRIVATE_LABEL = {
    "file_read": "files",
    "database_read": "a database",
    "database_write": "a database",
    "credentials": "credentials",
}

#: Classes that only read.
READ_CLASSES: frozenset[str] = frozenset({"search", "file_read", "database_read"})


def _plain_text(tool: dict[str, Any]) -> str:
    """Name (with separators as spaces), title and description; parameter names excluded."""
    name = str(tool.get("name", ""))
    spaced = name.replace("_", " ").replace("-", " ").replace(".", " ")
    return " ".join([name, spaced, str(tool.get("title") or ""), str(tool.get("description") or "")])


def looks_mutating(tool: dict[str, Any], cls: Classification) -> bool:
    """Whether the advertised capability changes state (used for annotation contradictions)."""
    if ARBITRARY_EXEC in cls.arbitrary or ARBITRARY_FILE_WRITE in cls.arbitrary:
        return True
    if any(c in MUTATING_CLASSES for c in cls.classes):
        return True
    return any(c in VERB_MUTATING_CLASSES for c in cls.classes) and bool(_MUTATING.search(_plain_text(tool)))


def looks_destructive(cls: Classification) -> bool:
    """Execution, deletion and overwriting writes (destructiveHint:false would be wrong)."""
    return (
        ARBITRARY_EXEC in cls.arbitrary
        or ARBITRARY_FILE_WRITE in cls.arbitrary
        or any(c in MUTATING_CLASSES for c in cls.classes)
    )


def looks_read_only(tool: dict[str, Any], cls: Classification) -> bool:
    """Only read classes matched and nothing suggests a write."""
    return bool(cls.classes) and set(cls.classes) <= READ_CLASSES and not looks_mutating(tool, cls)


def toxic_roles(tool: dict[str, Any], cls: Classification) -> dict[str, str]:
    """Lethal-trifecta roles a tool can play, each with the reason (from its advertised metadata).

    Arbitrary command execution plays all three (a shell reads local data, fetches
    content and sends it anywhere); arbitrary file read is private data.
    """
    text = _plain_text(tool)
    roles: dict[str, str] = {}
    if ARBITRARY_EXEC in cls.arbitrary:
        why = "arbitrary command execution (see META-03)"
        return {ROLE_PRIVATE: why, ROLE_UNTRUSTED: why, ROLE_SEND: why}
    classes = set(cls.classes)
    if ARBITRARY_FILE_READ in cls.arbitrary:
        roles[ROLE_PRIVATE] = "arbitrary file read (see META-03)"
    elif classes & set(_PRIVATE_LABEL):
        labels = sorted({_PRIVATE_LABEL[c] for c in classes & set(_PRIVATE_LABEL)})
        roles[ROLE_PRIVATE] = "accesses " + " and ".join(labels)
    inbox = _INBOX_READ.search(text) if "email" in classes else None
    if inbox:
        roles.setdefault(ROLE_PRIVATE, f"reads mail or messages ('{inbox.group(0)}')")
        roles[ROLE_UNTRUSTED] = f"returns mail or messages written by others ('{inbox.group(0)}')"
    if "network" in classes:
        web = _WEB_INTAKE.search(text)
        if web:
            roles[ROLE_UNTRUSTED] = f"pulls content from the web ('{web.group(0)}')"
    if classes & {"email", "network"}:
        out = _SEND_OUT.search(text)
        if out:
            roles[ROLE_SEND] = f"sends data out ('{out.group(0).strip()}')"
    return roles
