"""Split registry entries into remote and package-only, dedupe hosts, apply exclusions.

Offline: no DNS or network. Hosts that only turn out to be private when resolved are
caught later by the batch scanner, which resolves and pins every connection itself.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcpprobe.registry.common import is_ip_literal, rate_key
from mcpprobe.registry.fetch import REMOTE_TYPES

#: Names that never resolve publicly (mirrors :func:`mcpprobe.dnsutil.has_public_dns_name`).
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".invalid", ".lan", ".home.arpa", ".test")


@dataclass(slots=True)
class Exclusions:
    """Hosts we were asked not to scan, or chose not to (one per line; ``*.x`` or ``.x`` = x and subdomains)."""

    hosts: set[str] = field(default_factory=set)
    suffixes: tuple[str, ...] = ()

    @classmethod
    def parse(cls, lines: Iterable[str]) -> Exclusions:
        hosts: set[str] = set()
        suffixes: list[str] = []
        for raw in lines:
            line = raw.split("#", 1)[0].strip().lower().rstrip(".")
            if not line:
                continue
            if line.startswith("*."):
                line = line[1:]
            if line.startswith("."):
                suffixes.append(line)
                hosts.add(line[1:])
            else:
                hosts.add(line)
        return cls(hosts=hosts, suffixes=tuple(suffixes))

    @classmethod
    def load(cls, path: Path | None) -> Exclusions:
        if path is None or not path.exists():
            return cls()
        return cls.parse(path.read_text(encoding="utf-8").splitlines())

    def matches(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        return h in self.hosts or any(h.endswith(s) for s in self.suffixes)


@dataclass(slots=True)
class Selection:
    targets: list[dict[str, Any]] = field(default_factory=list)
    package_only: list[str] = field(default_factory=list)
    excluded: Counter[str] = field(default_factory=Counter)
    summary: dict[str, Any] = field(default_factory=dict)


def exclusion_reason(url: str, exclusions: Exclusions) -> str | None:
    """Why a remote URL must not be scanned, or None."""
    if "{" in url or "}" in url:
        return "templated_url"  # needs per-user variables (tenant, region, key...)
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "unsupported_scheme"
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return "no_host"
    if is_ip_literal(host):
        # Also covers public IP literals: there is no DNS name to check an opt-out on.
        return "ip_literal"
    if "." not in host or host in {"localhost", "ip6-localhost"} or host.endswith(_LOCAL_SUFFIXES):
        return "local_name"
    if exclusions.matches(host):
        return "excluded_by_list"
    return None


def select_targets(
    entries: Iterable[dict[str, Any]],
    exclusions: Exclusions | None = None,
    *,
    max_urls_per_host: int = 1,
) -> Selection:
    """One target per host (streamable-http preferred over SSE); every decision counted.

    Every remote URL ends up either selected or under exactly one reason in ``excluded``, so
    ``remote_urls - sum(excluded) == selected_urls``, and with ``max_urls_per_host=1``
    ``selected_urls == unique_hosts``.
    """
    exclusions = exclusions or Exclusions()
    sel = Selection()
    by_host: dict[str, dict[str, Any]] = {}
    kinds: Counter[str] = Counter()
    n_entries = 0
    remote_urls = 0
    for entry in entries:
        n_entries += 1
        remotes = [r for r in entry.get("remotes") or [] if r.get("type") in REMOTE_TYPES]
        if not remotes:
            if entry.get("packages"):
                kinds["package_only"] += 1
                sel.package_only.append(str(entry["name"]))
            else:
                kinds["no_remote_no_package"] += 1
            continue
        kinds["remote"] += 1
        remotes.sort(key=lambda r: REMOTE_TYPES.index(r["type"]))
        for remote in remotes:
            remote_urls += 1
            url = str(remote["url"])
            reason = exclusion_reason(url, exclusions)
            if reason:
                sel.excluded[reason] += 1
                continue
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
            target = by_host.get(host)
            if target is None:
                target = {
                    "host": host,
                    "rate_key": rate_key(host),
                    "urls": [],
                    "transports": [],
                    "entries": [],
                    "needs_headers": False,
                }
                by_host[host] = target
            if entry["name"] not in target["entries"]:
                target["entries"].append(entry["name"])
            if url in target["urls"]:
                # The same URL listed again (another entry, version or transport): count it,
                # or the funnel would not add up (remote_urls - excluded != selected URLs).
                sel.excluded["duplicate_url"] += 1
                continue
            if len(target["urls"]) >= max_urls_per_host:
                sel.excluded["duplicate_host"] += 1
                continue
            target["urls"].append(url)
            target["transports"].append(remote["type"])
            target["needs_headers"] = target["needs_headers"] or bool(remote.get("has_headers"))
    sel.targets = sorted(by_host.values(), key=lambda t: (t["rate_key"], t["host"]))
    sel.targets = [t for t in sel.targets if t["urls"]]
    sel.summary = {
        "entries": n_entries,
        "remote_entries": kinds["remote"],
        "package_only_entries": kinds["package_only"],
        "no_remote_no_package_entries": kinds["no_remote_no_package"],
        "remote_urls": remote_urls,
        "excluded": dict(sorted(sel.excluded.items())),
        "selected_urls": sum(len(t["urls"]) for t in sel.targets),
        "unique_hosts": len(sel.targets),
        "rate_keys": len({t["rate_key"] for t in sel.targets}),
        "max_urls_per_host": max_urls_per_host,
    }
    return sel
