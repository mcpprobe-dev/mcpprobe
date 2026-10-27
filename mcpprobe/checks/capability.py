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
            r"bcc|cc|recipient|inbox|gmail|outlook)\b",
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

    @property
    def dangerous(self) -> bool:
        return any(c in DANGEROUS_CLASSES for c in self.classes)

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
    return Classification(name=name, classes=ordered, matched_terms=terms)


def classify_tools(tools: list[dict[str, Any]]) -> dict[str, Classification]:
    return {str(t.get("name", "")): classify_tool(t) for t in tools}
