"""Small helpers shared by several checks."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import unicodedata
from collections import Counter
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_PARAM_RE = re.compile(r'([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')


def parse_www_authenticate(value: str | None) -> dict[str, str]:
    """Parse a ``WWW-Authenticate`` header into ``{'scheme': ..., param: value}``."""
    out: dict[str, str] = {}
    if not value:
        return out
    scheme, _, rest = value.strip().partition(" ")
    out["scheme"] = scheme
    for match in _PARAM_RE.finditer(rest):
        key = match.group(1).lower()
        out[key] = match.group(2) if match.group(2) is not None else match.group(3)
    return out


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def well_known_urls(url: str, suffix: str) -> list[str]:
    """Path-aware well-known URL first (RFC 9728 s.3.1), then the host root."""
    parts = urlsplit(url)
    root = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    urls: list[str] = []
    path = parts.path.rstrip("/")
    if path:
        urls.append(f"{root}/.well-known/{suffix}{path}")
    urls.append(f"{root}/.well-known/{suffix}")
    return urls


def host_of(url: str) -> str:
    return urlsplit(url).hostname or ""


def is_local_or_private(host: str) -> bool:
    """True for loopback, link-local, RFC 1918 and ``localhost``-style names."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    if h in {"localhost", "ip6-localhost"} or h.endswith(".localhost") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def canonical_json(data: Any) -> str:
    """Deterministic JSON used for hashing (sorted keys, compact, ASCII-escaped)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def try_json(body: bytes) -> Any | None:
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None


def visible(text: str) -> str:
    """Make invisible/format characters visible as ``<U+XXXX>`` so reviewers can see them."""
    out: list[str] = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "\n\t":
            out.append(" ")
        elif cat in {"Cf", "Cc", "Co", "Cn"} or 0xE0000 <= ord(ch) <= 0xE007F:
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)


def excerpt(text: str, limit: int = 160) -> str:
    text = visible(text)
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"
