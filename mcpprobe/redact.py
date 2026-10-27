"""Secret patterns and redaction helpers.

Shared by META-05 (which reports secrets found in server metadata) and the
evidence log (which must never re-publish a credential in a JSON or SARIF
report that may end up in CI logs or GitHub code scanning).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mcpprobe.models import Severity

#: (label, pattern, severity). When a pattern has a capture group, group 1 is the secret value.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        Severity.HIGH,
    ),
    ("AWS access key id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), Severity.HIGH),
    (
        "GitHub token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        Severity.HIGH,
    ),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), Severity.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    ("generic sk- API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), Severity.HIGH),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}"),
        Severity.MEDIUM,
    ),
    ("bearer token", re.compile(r"\bbearer\s+([A-Za-z0-9\-._~+/]{20,}=*)", re.I), Severity.MEDIUM),
    (
        "connection string with password",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/]+:([^@\s]+)@", re.I
        ),
        Severity.HIGH,
    ),
    (
        "credential assignment",
        re.compile(
            r"\b(?:api[_-]?key|secret(?:[_-]?key)?|token|password|passwd|pwd|auth[_-]?key|"
            r"access[_-]?key|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+=.]{16,})",
            re.I,
        ),
        Severity.MEDIUM,
    ),
    (
        "secret after keyword",
        re.compile(r"\bsecret\s+([A-Za-z0-9/+=]{30,})", re.I),
        Severity.MEDIUM,
    ),
]

_SENSITIVE_QUERY_KEYS = frozenset({"access_token", "token", "api_key", "apikey", "key", "secret", "password"})


def redact(value: str) -> str:
    """Keep a short prefix/suffix so a human can recognise the value without it being usable."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def redact_secrets(text: str) -> str:
    """Replace every known secret pattern match in ``text`` with its redacted form."""
    out = text
    for _label, pattern, _sev in SECRET_PATTERNS:

        def _sub(m: re.Match[str]) -> str:
            if m.lastindex:
                start, end = m.span(1)
                whole_start = m.start(0)
                g = m.group(0)
                return g[: start - whole_start] + redact(m.group(1)) + g[end - whole_start :]
            return redact(m.group(0))

        out = pattern.sub(_sub, out)
    return out


def redact_url(url: str) -> str:
    """Redact credential-like query parameters in a URL."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(k.lower() in _SENSITIVE_QUERY_KEYS for k, _ in pairs):
        return url
    cleaned = [(k, "<redacted>" if k.lower() in _SENSITIVE_QUERY_KEYS else v) for k, v in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(cleaned), parts.fragment))


__all__ = ["SECRET_PATTERNS", "redact", "redact_secrets", "redact_url"]
