"""DNS TXT lookups shared by ownership verification and opt-out handling."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

#: Resolver signature: name -> list of TXT strings ([] when the name has none).
TxtLookup = Callable[[str], list[str]]

#: Label under which both verification and opt-out records live: ``_mcpprobe.<host>``.
RECORD_LABEL = "_mcpprobe"


class DnsLookupError(Exception):
    """The resolver failed for a reason other than 'no such record'."""


def record_name(host: str) -> str:
    return f"{RECORD_LABEL}.{host.rstrip('.').lower()}"


def has_public_dns_name(host: str) -> bool:
    """False for IP literals and loopback-only names, which have no public TXT records."""
    h = host.strip("[]").rstrip(".").lower()
    if not h:
        return False
    try:
        ipaddress.ip_address(h)
    except ValueError:
        pass
    else:
        return False
    if h in {"localhost", "ip6-localhost"} or h.endswith((".localhost", ".local", ".internal", ".invalid")):
        return False
    return "." in h


def default_txt_lookup(name: str) -> list[str]:
    """Resolve TXT records with dnspython; ``[]`` on NXDOMAIN / no answer."""
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise DnsLookupError(f"DNS lookup failed for {name}: {exc}") from exc
    out: list[str] = []
    for rdata in answers:
        strings = getattr(rdata, "strings", None)
        if strings is None:
            out.append(str(rdata).strip('"'))
        else:
            out.append(b"".join(strings).decode("utf-8", errors="replace"))
    return out


__all__ = [
    "RECORD_LABEL",
    "DnsLookupError",
    "TxtLookup",
    "default_txt_lookup",
    "has_public_dns_name",
    "record_name",
]
