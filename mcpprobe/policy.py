"""Scanner identification and opt-out handling.

* Every request carries ``User-Agent: mcpprobe/<version> (+https://mcpprobe.tech/scanning-policy)``.
* Before **any** request is sent to an HTTP target the scanner checks two
  opt-out signals, in this order, and aborts if either is present:

  1. DNS: a TXT record ``mcpprobe-opt-out=all`` at ``_mcpprobe.<host>`` (and at
     ``_mcpprobe.<parent>`` for each parent domain with at least two labels, so
     an operator can opt out a whole zone with one record). This is checked
     before any packet reaches the target itself.
  2. HTTP: ``GET /.well-known/mcpprobe-opt-out`` on the target's origin. A
     ``200`` response means the operator does not want to be scanned.

  Neither check can be disabled from the command line.
* All traffic passes through one rate limiter (default 5 requests/second,
  hard maximum 10).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from mcpprobe import POLICY_URL, USER_AGENT
from mcpprobe.dnsutil import (
    DnsLookupError,
    TxtLookup,
    default_txt_lookup,
    has_public_dns_name,
    record_name,
)

if TYPE_CHECKING:  # avoid an import cycle: checks -> policy -> transport
    from mcpprobe.transport import HttpTransport

OPT_OUT_PATH = "/.well-known/mcpprobe-opt-out"


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def host_of(url: str) -> str:
    return urlsplit(url).hostname or ""


OPT_OUT_TXT = "mcpprobe-opt-out=all"
#: Hard ceiling on requests per second, whatever the operator asks for.
MAX_RATE = 10.0
DEFAULT_RATE = 5.0


class OptOutError(Exception):
    """The target host has published an opt-out signal."""


def opt_out_url(target: str) -> str:
    return origin_of(target) + OPT_OUT_PATH


def opt_out_dns_names(host: str) -> list[str]:
    """``_mcpprobe.<host>`` then each parent with >= 2 labels (max 3 names)."""
    labels = host.rstrip(".").lower().split(".")
    names = [record_name(".".join(labels[i:])) for i in range(len(labels) - 1)]
    return names[:3]


def _is_opt_out_record(value: str) -> bool:
    return value.strip().strip('"').lower().replace(" ", "") == OPT_OUT_TXT


async def check_dns_opt_out(host: str, lookup: TxtLookup | None = None) -> list[str]:
    """Raise :class:`OptOutError` if a DNS opt-out record exists. Returns notes for the report."""
    notes: list[str] = []
    if not has_public_dns_name(host):
        notes.append(f"opt-out: DNS check skipped for {host or 'target'} (no public DNS name)")
        return notes
    resolver = lookup or default_txt_lookup
    for name in opt_out_dns_names(host):
        try:
            records = await asyncio.to_thread(resolver, name)
        except DnsLookupError as exc:
            notes.append(f"opt-out: {exc}; continuing with the HTTP opt-out check")
            continue
        if any(_is_opt_out_record(r) for r in records):
            raise OptOutError(
                f"{name} publishes TXT {OPT_OUT_TXT!r}; the operator of {host} has opted out of "
                f"mcpprobe scans. No request was sent to the target. See {POLICY_URL}."
            )
    notes.append(f"opt-out: no DNS opt-out record for {host}")
    return notes


async def check_http_opt_out(http: HttpTransport, target: str) -> None:
    """Raise :class:`OptOutError` if the host serves the opt-out document."""
    url = opt_out_url(target)
    resp = await http.get(url, note="opt-out check", label="GET(opt-out)")
    if resp.status == 200:
        body = resp.body.decode("utf-8", errors="replace").strip()
        excerpt = body.splitlines()[0][:200] if body else ""
        raise OptOutError(
            f"{origin_of(target)} publishes {OPT_OUT_PATH}; scanning is not permitted. "
            + (f"Message from host: {excerpt!r}. " if excerpt else "")
            + f"See {POLICY_URL}."
        )


async def check_opt_out(http: HttpTransport, target: str, lookup: TxtLookup | None = None) -> list[str]:
    """Run both opt-out checks (DNS first). Raises :class:`OptOutError`; returns report notes."""
    notes = await check_dns_opt_out(host_of(target), lookup)
    await check_http_opt_out(http, target)
    return notes


def clamp_rate(rate: float) -> float:
    """Validate a requested rate against the hard maximum."""
    if rate <= 0:
        raise ValueError("rate must be positive")
    if rate > MAX_RATE:
        raise ValueError(f"rate {rate:g} req/s exceeds the maximum of {MAX_RATE:g} req/s")
    return rate


__all__ = [
    "DEFAULT_RATE",
    "MAX_RATE",
    "OPT_OUT_PATH",
    "OPT_OUT_TXT",
    "POLICY_URL",
    "USER_AGENT",
    "OptOutError",
    "check_dns_opt_out",
    "check_http_opt_out",
    "check_opt_out",
    "clamp_rate",
    "opt_out_dns_names",
    "opt_out_url",
]
