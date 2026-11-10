"""Find published contacts for post-survey outreach. Output is PRIVATE and never committed.

For the hosts in one outreach segment of a registry survey working directory, derive the
organisation and a contact address **only from channels the operator published**:

1. ``https://<host>/.well-known/security.txt`` (RFC 9116), skipped on shared platforms
   (``*.vercel.app`` and the like), where the file belongs to the platform, not the tenant;
2. ``https://<org domain>/.well-known/security.txt``;
3. ``SECURITY.md``, ``.github/SECURITY.md`` or ``docs/SECURITY.md`` in the registry entry's
   repository (GitHub, GitLab);
4. the registry entry's ``websiteUrl`` and its ``/security`` and ``/contact`` pages.

Role addresses are preferred (security@, psirt@, hello@, contact@ …). Segment A
(disclosure) takes security roles first. A named address (jane@…) is recorded **only for
segment A**, only when the operator published it as a security contact in ``security.txt``
or ``SECURITY.md``, and only when that same file names no security role address; the row
says ``address_kind=named`` and carries its source URL. Every other non-role address is
never recorded, only counted as withheld. Segments B and C (marketing) take general role
addresses only, never security@, never a named address, and only from corporate
subscribers (PECR): a free-mail domain, a personal GitHub namespace or anything unclear is
ineligible. Addresses are never guessed: an organisation without a published contact is
listed as "no published contact".

Segments (see the web repo's emails/outreach/PLAN.md):
  A  hosts in PRIVATE-disclosure-queue.json (default priorities P1-P3)
  B  scanned, tools observable, not in the queue
  C  scanned, login required (tool checks "blocked"), not in the queue
An organisation with any host in A is never listed in B or C.

P4 (META-07, medium, heuristic) is gated: ``--priority P4`` is refused unless
``--p4-hand-check CSV`` records a manual check of at least 50 distinct P4 hosts with at
least 90% of them confirmed correct (columns ``host,correct``; correct is yes/no).

Nothing is fetched unless ``--live`` is given; ``--dry-run --fixtures DIR`` reads a fixture
map instead. Nothing is ever sent. The CSV is refused inside a git work tree unless the
path is git-ignored (the repo ignores ``PRIVATE-*``).

    python scripts/outreach_contacts.py --workdir W --segment A --dry-run --fixtures F --out /secure/PRIVATE-contacts-A.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

from mcpprobe import USER_AGENT
from mcpprobe.registry.aggregate import disclosure_queue
from mcpprobe.registry.common import HostStatus, WorkDir, read_json, read_jsonl
from mcpprobe.registry.pipeline import survey_records

MAX_BODY = 64 * 1024
TIMEOUT_S = 10.0
PER_DOMAIN_INTERVAL_S = 1.0

#: Shared hosting where the host's own security.txt belongs to the platform, not the tenant.
PLATFORM_SUFFIXES: tuple[str, ...] = (
    "vercel.app",
    "netlify.app",
    "workers.dev",
    "pages.dev",
    "onrender.com",
    "herokuapp.com",
    "fly.dev",
    "railway.app",
    "github.io",
    "gitlab.io",
    "azurewebsites.net",
    "azurecontainerapps.io",
    "amazonaws.com",
    "on.aws",
    "run.app",
    "appspot.com",
    "cloudfunctions.net",
    "deno.dev",
    "deno.net",
    "glitch.me",
    "replit.app",
    "repl.co",
    "ngrok.app",
    "ngrok-free.app",
    "ngrok.io",
    "trycloudflare.com",
    "modal.run",
    "hf.space",
    "supabase.co",
    "val.run",
    "koyeb.app",
    "web.app",
    "firebaseapp.com",
)
#: Second-level suffixes where the registrable domain has three labels.
MULTI_LABEL_TLDS = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "ltd.uk",
        "plc.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.br",
        "com.cn",
        "com.tw",
        "co.in",
        "co.kr",
        "co.za",
        "com.mx",
        "com.sg",
        "com.tr",
        "com.hk",
        "co.il",
    }
)
FREE_MAIL = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "icloud.com",
        "me.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "aol.com",
        "gmx.com",
        "gmx.de",
        "mail.com",
        "yandex.com",
        "yandex.ru",
        "qq.com",
        "163.com",
        "zoho.com",
        "fastmail.com",
        "hey.com",
        "tutanota.com",
        "users.noreply.github.com",
    }
)
SECURITY_ROLES = frozenset(
    {
        "security",
        "secure",
        "psirt",
        "cert",
        "csirt",
        "sirt",
        "vulnerability",
        "vulnerabilities",
        "vuln",
        "vulns",
        "disclosure",
        "security-reports",
        "securityreports",
        "product-security",
        "productsecurity",
        "appsec",
        "infosec",
        "secops",
        "bugbounty",
        "bug-bounty",
        "responsible-disclosure",
        "security-team",
    }
)
GENERAL_ROLES = frozenset(
    {
        "hello",
        "contact",
        "info",
        "team",
        "enquiries",
        "inquiries",
        "partnerships",
        "hi",
        # second pass (10 Nov 2026): other role mailboxes an organisation publishes for the public
        "support",
        "sales",
        "office",
        "business",
        "partners",
        "developers",
        "devrel",
        "mail",
    }
)
#: Pages read on an organisation's own site, in order. GET only, same origin only.
CONTACT_PATHS = ("/security", "/contact", "/contact-us", "/about", "/support")
_FORM_RE = re.compile(r"<form\b[^>]*>.*?<textarea\b", re.I | re.S)
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")

CSV_FIELDS = (
    "segment",
    "priority",
    "org",
    "org_domain",
    "hosts",
    "server_names",
    "contact",
    "contact_type",
    "address_kind",
    "source",
    "source_url",
    "retrieved_at",
    "subscriber_type",
    "eligible",
    "notes",
)


# ----------------------------------------------------------------------------- fetching
@dataclass(frozen=True, slots=True)
class Page:
    status: int
    text: str
    final_url: str


class Fetcher(Protocol):
    def get(self, url: str) -> Page: ...


class FixtureFetcher:
    """Dry run: answers from ``<dir>/index.json`` ({url: {"status", "body" | "file"}}); 404 otherwise."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.index: dict[str, dict[str, Any]] = json.loads((root / "index.json").read_text())
        self.requested: list[str] = []

    def get(self, url: str) -> Page:
        self.requested.append(url)
        hit = self.index.get(url)
        if not hit:
            return Page(404, "", url)
        body = hit.get("body")
        if body is None and hit.get("file"):
            body = (self.root / str(hit["file"])).read_text()
        return Page(int(hit.get("status", 200)), str(body or "")[:MAX_BODY], str(hit.get("final_url") or url))


class LiveFetcher:  # pragma: no cover - never exercised by tests: they must not touch the network
    """GET only, identifying user-agent, 1 request/s per registrable domain, 64 KiB cap."""

    def __init__(self, sleep: Callable[[float], None] = time.sleep) -> None:
        import httpx

        self._client = httpx.Client(
            headers={
                "User-Agent": f"{USER_AGENT} outreach-contacts",
                "Accept": "text/plain, text/html;q=0.9",
            },
            timeout=TIMEOUT_S,
            follow_redirects=True,
            max_redirects=3,
        )
        self._last: dict[str, float] = {}
        self._sleep = sleep

    def get(self, url: str) -> Page:
        key = registrable_domain(urlparse(url).hostname or "")
        wait = PER_DOMAIN_INTERVAL_S - (time.monotonic() - self._last.get(key, 0.0))
        if wait > 0:
            self._sleep(wait)
        self._last[key] = time.monotonic()
        try:
            with self._client.stream("GET", url) as r:
                chunks: list[bytes] = []
                size = 0
                for chunk in r.iter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY:
                        break
                text = b"".join(chunks)[:MAX_BODY].decode("utf-8", "replace")
                return Page(r.status_code, text, str(r.url))
        except Exception:  # any failure just means "no contact here"
            return Page(0, "", url)


# ----------------------------------------------------------------------------- domains and roles
def registrable_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def platform_suffix(host: str, extra: Iterable[str] = ()) -> str | None:
    h = host.lower().strip(".")
    for s in (*PLATFORM_SUFFIXES, *extra):
        if h == s or h.endswith("." + s):
            return s
    return None


def namespace_domain(server_name: str) -> str | None:
    """Registry names are reverse-DNS (``com.acme/server``); ``io.github.<user>`` is a GitHub namespace."""
    ns = server_name.split("/", 1)[0].lower()
    parts = ns.split(".")
    if len(parts) < 2 or ns.startswith(("io.github.", "com.github.")):
        return None
    return ".".join(reversed(parts))


def github_namespace(server_name: str) -> bool:
    return server_name.lower().startswith(("io.github.", "com.github."))


def role_of(address: str) -> str | None:
    local = address.split("@", 1)[0].lower().split("+", 1)[0]
    if local in SECURITY_ROLES:
        return "security"
    if local in GENERAL_ROLES:
        return "general"
    return None


def emails_in(text: str) -> list[str]:
    seen: list[str] = []
    for m in EMAIL_RE.finditer(text):
        a = m.group(1).strip(".").lower()
        if a not in seen and not a.endswith((".png", ".jpg", ".svg", ".webp", ".gif")):
            seen.append(a)
    return seen


# ----------------------------------------------------------------------------- security.txt
def parse_security_txt(text: str, now: datetime) -> tuple[list[str], list[str], str | None]:
    """(mailto addresses, other contact URIs, problem) from an RFC 9116 file."""
    mails: list[str] = []
    uris: list[str] = []
    expires: datetime | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:]  # OpenPGP dash-escaping
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "contact":
            if value.lower().startswith("mailto:"):
                mails.append(value[7:].split("?", 1)[0].lower())
            elif value.lower().startswith("https://"):
                uris.append(value)
        elif key == "expires":
            try:
                expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return [], [], "unparseable Expires"
            if expires.tzinfo is None:  # RFC 9116 requires a zone; treat a bare timestamp as UTC
                expires = expires.replace(tzinfo=UTC)
    if not mails and not uris:
        return [], [], "no Contact field"
    if expires is None:
        return [], [], "no Expires field"
    if expires < now:
        return [], [], "expired (RFC 9116: should not be used)"
    return mails, uris, None


# ----------------------------------------------------------------------------- segments
@dataclass
class Target:
    host: str
    url: str
    entries: list[str]
    priority: str = ""
    notes: list[str] = field(default_factory=list)


def _queue(wd: WorkDir, records: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if wd.disclosure_queue.exists():
        return [d for d in read_json(wd.disclosure_queue) if d.get("priority")]
    return disclosure_queue(records or survey_records(wd))


def load_segment(wd: WorkDir, segment: str, priorities: Iterable[str]) -> tuple[list[Target], set[str]]:
    """Targets of the segment, and the hosts of the disclosure queue (to keep A out of B and C)."""
    if segment == "A":
        queue = _queue(wd, None)
        wanted = set(priorities)
        targets = [
            Target(d["host"], str(d.get("url") or ""), list(d.get("entries") or []), str(d["priority"]))
            for d in queue
            if d["priority"] in wanted
        ]
        return targets, {d["host"] for d in queue}
    records = survey_records(wd)
    queued = {d["host"] for d in _queue(wd, records)}
    out = []
    for r in records:
        if r.get("status") != HostStatus.SCANNED.value or r["host"] in queued:
            continue
        locked = (r.get("outcomes") or {}).get("META-01") == "blocked"
        if (segment == "C") != locked:
            continue
        t = Target(r["host"], str(r.get("url") or ""), list(r.get("entries") or []))
        if segment == "C":
            t.notes.append(f"AUTH-02 {(r.get('outcomes') or {}).get('AUTH-02', 'unknown')}")
        out.append(t)
    return out, queued


def load_registry_meta(wd: WorkDir) -> dict[str, dict[str, str]]:
    """name -> {repository, website}. ``entries.jsonl`` keeps neither, so read the raw pages too."""
    meta: dict[str, dict[str, str]] = {}
    for e in read_jsonl(wd.entries):
        repo = e.get("repository")
        repo_url = repo.get("url") if isinstance(repo, dict) else repo
        site = e.get("website_url") or e.get("websiteUrl")
        if repo_url or site:
            meta[str(e["name"])] = {"repository": str(repo_url or ""), "website": str(site or "")}
    if wd.pages.exists():
        for page in sorted(wd.pages.glob("page-*.json")):
            for item in read_json(page).get("servers") or []:
                server = item.get("server") if isinstance(item.get("server"), dict) else item
                if not isinstance(server, dict) or not isinstance(server.get("name"), str):
                    continue
                repo = server.get("repository")
                repo_url = repo.get("url") if isinstance(repo, dict) else None
                site = server.get("websiteUrl")
                cur = meta.setdefault(server["name"], {"repository": "", "website": ""})
                cur["repository"] = cur["repository"] or str(repo_url or "")
                cur["website"] = cur["website"] or str(site or "")
    return meta


# ----------------------------------------------------------------------------- discovery
@dataclass
class Org:
    key: str
    domain: str
    github: bool
    hosts: list[Target] = field(default_factory=list)


def org_of(t: Target, extra_platforms: Iterable[str]) -> Org:
    ns = next((d for d in map(namespace_domain, t.entries) if d), None)
    gh = any(github_namespace(n) for n in t.entries)
    if ns:
        domain = registrable_domain(ns)
    elif not platform_suffix(t.host, extra_platforms):
        domain = registrable_domain(t.host)
    else:
        domain = ""
    if domain:
        return Org(domain, domain, gh)
    owner = t.entries[0].split("/", 1)[0].lower() if t.entries else t.host
    return Org(owner, "", gh)


def repo_security_urls(repo: str) -> list[str]:
    p = urlparse(repo)
    parts = [x for x in p.path.strip("/").removesuffix(".git").split("/") if x]
    if len(parts) < 2:
        return []
    owner, name = parts[0], parts[1]
    files = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
    if p.hostname == "github.com":
        return [f"https://raw.githubusercontent.com/{owner}/{name}/HEAD/{f}" for f in files]
    if p.hostname == "gitlab.com":
        return [f"https://gitlab.com/{owner}/{name}/-/raw/HEAD/{f}" for f in files]
    return []


@dataclass
class Found:
    contact: str
    contact_type: str
    source: str
    source_url: str
    retrieved_at: str
    address_kind: str = ""  # "role", "named" (segment A only) or "" for a URL contact


class Discoverer:
    def __init__(
        self,
        fetcher: Fetcher,
        *,
        segment: str,
        now: datetime,
        extra_platforms: Iterable[str] = (),
    ) -> None:
        self.fetcher = fetcher
        self.segment = segment
        self.now = now
        self.extra_platforms = tuple(extra_platforms)
        self.withheld = 0

    def _accept(self, addresses: Iterable[str], *, security_channel: bool = False) -> list[tuple[str, str]]:
        """(address, kind) pairs this segment may use; anything else is counted and dropped, never stored.

        A named address is kept only for segment A, only from a security channel the operator
        published (security.txt, SECURITY.md), and only when that file names no security role.
        """
        want = {"security", "general"} if self.segment == "A" else {"general"}
        roles: list[str] = []
        named: list[str] = []
        for a in dict.fromkeys(x.lower() for x in addresses):
            role = role_of(a)
            if role is None:
                named.append(a)
            elif role in want:
                roles.append(a)
        if self.segment == "A":  # security roles first
            roles.sort(key=lambda a: role_of(a) != "security")
        has_security_role = any(role_of(a) == "security" for a in roles)
        if self.segment == "A" and security_channel and not has_security_role and named:
            out = [(a, "named") for a in named] + [(a, "role") for a in roles]
        else:
            self.withheld += len(named)
            out = [(a, "role") for a in roles]
        return out

    def _stamp(self) -> str:
        return self.now.isoformat(timespec="seconds")

    def _security_txt(self, host: str, label: str, notes: list[str]) -> list[Found]:
        url = f"https://{host}/.well-known/security.txt"
        page = self.fetcher.get(url)
        if page.status != 200 or not page.text:
            return []
        if registrable_domain(urlparse(page.final_url).hostname or "") != registrable_domain(host):
            notes.append(f"{label}: security.txt redirected off-domain, ignored")
            return []
        mails, uris, problem = parse_security_txt(page.text, self.now)
        if problem:
            notes.append(f"{label}: security.txt {problem}")
            return []
        found = [
            Found(a, "email", f"security.txt ({label})", url, self._stamp(), kind)
            for a, kind in self._accept(mails, security_channel=True)
        ]
        if self.segment == "A" and not found:
            found = [Found(u, "url", f"security.txt ({label})", url, self._stamp()) for u in uris]
        return found

    def _repository(self, repo: str, notes: list[str]) -> list[Found]:
        for url in repo_security_urls(repo):
            page = self.fetcher.get(url)
            if page.status != 200 or not page.text:
                continue
            found = [
                Found(a, "email", "repository SECURITY.md", url, self._stamp(), kind)
                for a, kind in self._accept(emails_in(page.text), security_channel=True)
            ]
            if (
                self.segment == "A"
                and not found
                and re.search(r"security/advisories|private vulnerability report", page.text, re.I)
            ):
                p = urlparse(repo)
                found = [
                    Found(
                        f"https://github.com{p.path.removesuffix('.git').rstrip('/')}/security/advisories/new",
                        "url",
                        "repository SECURITY.md (GitHub private reporting)",
                        url,
                        self._stamp(),
                    )
                ]
            if found:
                return found
            notes.append("SECURITY.md has no usable role contact")
            return []
        return []

    def _website(self, site: str, notes: list[str], label: str = "website") -> list[Found]:
        if not site.startswith("https://"):
            return []
        origin = f"https://{urlparse(site).hostname}"
        form_url = ""
        for url in dict.fromkeys([site, *(urljoin(origin, p) for p in CONTACT_PATHS)]):
            page = self.fetcher.get(url)
            if page.status != 200 or not page.text:
                continue
            if registrable_domain(urlparse(page.final_url).hostname or "") != registrable_domain(
                urlparse(origin).hostname or ""
            ):
                continue  # redirected to another organisation's site: not theirs
            mails = [m.removeprefix("mailto:") for m in re.findall(r"mailto:([^\"'?>\s]+)", page.text, re.I)]
            found = [
                Found(a, "email", label, url, self._stamp(), kind)
                for a, kind in self._accept(mails + emails_in(page.text))
            ]
            if found:
                return found
            if not form_url and url != site and _FORM_RE.search(page.text):
                form_url = url
        if form_url and self.segment != "A":
            # Recorded for a person to use by hand; never submitted by a script, never "eligible".
            return [Found(form_url, "form", f"{label} contact form", form_url, self._stamp())]
        return []

    def discover(self, org: Org, meta: dict[str, dict[str, str]]) -> tuple[list[Found], list[str]]:
        notes: list[str] = []
        for t in org.hosts:
            if platform_suffix(t.host, self.extra_platforms):
                notes.append(f"{t.host}: shared platform, host security.txt skipped")
                continue
            if found := self._security_txt(t.host, "host", notes):
                return found, notes
        if org.domain and org.domain not in {t.host for t in org.hosts}:
            if found := self._security_txt(org.domain, "organisation domain", notes):
                return found, notes
        names = [n for t in org.hosts for n in t.entries]
        for n in names:
            if (repo := meta.get(n, {}).get("repository")) and (found := self._repository(repo, notes)):
                return found, notes
        for n in names:
            if (site := meta.get(n, {}).get("website")) and (found := self._website(site, notes)):
                return found, notes
        if org.domain and not org.github:
            # No websiteUrl in the registry: the organisation's own domain is still its site.
            if found := self._website(f"https://{org.domain}/", notes, "website (organisation domain)"):
                return found, notes
        return [], notes  # never guessed (no RFC 2142 security@<domain>): no published contact


def subscriber_type(contact: str, org: Org) -> str:
    """PECR: corporate only when the address is on the organisation's own (non-free-mail) domain."""
    if "@" not in contact:
        return "n/a"
    domain = registrable_domain(contact.rsplit("@", 1)[1])
    if org.github or domain in FREE_MAIL or not org.domain or domain != org.domain:
        return "individual_or_unknown"
    return "corporate"


# ----------------------------------------------------------------------------- suppression and output
def load_suppression(path: Path | None) -> set[str]:
    if not path:
        return set()
    out = set()
    for line in path.read_text().splitlines():
        s = line.split("#", 1)[0].strip().lower()
        if s:
            out.add(s)
    return out


def suppressed(contact: str, org: Org, suppress: set[str]) -> bool:
    c = contact.lower()
    keys = {c, hashlib.sha256(c.encode()).hexdigest(), org.domain, *(t.host for t in org.hosts)}
    if "@" in c:
        keys.add(registrable_domain(c.rsplit("@", 1)[1]))
    return bool(keys & suppress)


def ensure_private_path(out: Path) -> None:
    """Refuse to write contacts where git could pick them up."""
    parent = out.resolve().parent
    top = subprocess.run(
        ["git", "-C", str(parent), "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if top.returncode != 0:
        return  # not in a work tree
    ignored = subprocess.run(["git", "-C", str(parent), "check-ignore", "-q", str(out.resolve())])
    if ignored.returncode != 0:
        raise SystemExit(
            f"refusing to write {out}: it is inside a git work tree and not ignored (name it PRIVATE-*)"
        )


P4_SAMPLE_MIN = 50
P4_PRECISION_MIN = 0.90
_YES = {"yes", "y", "true", "1", "correct"}
_NO = {"no", "n", "false", "0", "wrong", "incorrect"}


def p4_gate(wd: WorkDir, hand_check: Path | None) -> tuple[int, int]:
    """Refuse P4 unless a hand check of >= 50 distinct P4 hosts found >= 90% correct.

    The file is a CSV with columns ``host`` and ``correct`` (yes/no). Every host must be a P4
    host in the disclosure queue, so the sample cannot be padded with P1-P3 cases. Returns
    (correct, checked).
    """
    if hand_check is None:
        raise SystemExit(
            "P4 is gated: hand-check a random sample of at least "
            f"{P4_SAMPLE_MIN} P4 hosts and pass it with --p4-hand-check (see PLAN.md section 4)"
        )
    p4_hosts = {d["host"] for d in _queue(wd, None) if d.get("priority") == "P4"}
    verdicts: dict[str, bool] = {}
    with hand_check.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            host = (row.get("host") or "").strip().lower()
            mark = (row.get("correct") or "").strip().lower()
            if not host:
                continue
            if host not in p4_hosts:
                raise SystemExit(f"P4 hand check: {host} is not a P4 host in the disclosure queue")
            if mark not in _YES | _NO:
                raise SystemExit(f"P4 hand check: {host} has no yes/no verdict")
            verdicts[host] = mark in _YES
    n = len(verdicts)
    ok = sum(verdicts.values())
    if n < P4_SAMPLE_MIN:
        raise SystemExit(f"P4 hand check covers {n} hosts; at least {P4_SAMPLE_MIN} are needed")
    if ok / n < P4_PRECISION_MIN:
        raise SystemExit(
            f"P4 hand check: {ok}/{n} correct ({ok / n:.0%}), below {P4_PRECISION_MIN:.0%}: do not send P4"
        )
    return ok, n


#: Wall-clock cap per organisation: a server that drips bytes forever must not stall the run.
ORG_DEADLINE_S = 120


class _DeadlineError(Exception):
    pass


def _raise_deadline(*_: object) -> None:
    raise _DeadlineError


def _discover_with_deadline(
    disc: Discoverer, org: Org, meta: dict[str, dict[str, str]]
) -> tuple[list[Found], list[str]]:
    if not hasattr(signal, "SIGALRM"):  # pragma: no cover - Windows
        return disc.discover(org, meta)
    previous = signal.signal(signal.SIGALRM, _raise_deadline)
    signal.alarm(ORG_DEADLINE_S)
    try:
        return disc.discover(org, meta)
    except _DeadlineError:
        return [], [f"discovery abandoned after {ORG_DEADLINE_S}s"]
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def run(
    wd: WorkDir,
    segment: str,
    fetcher: Fetcher,
    *,
    priorities: Iterable[str] = ("P1", "P2", "P3"),
    now: datetime | None = None,
    suppress: set[str] | None = None,
    extra_platforms: Iterable[str] = (),
    limit: int | None = None,
    p4_hand_check: Path | None = None,
) -> tuple[list[dict[str, str]], dict[str, int]]:
    now = now or datetime.now(UTC)
    priorities = tuple(priorities)
    p4_checked: tuple[int, int] | None = None
    if segment == "A" and "P4" in priorities:
        p4_checked = p4_gate(wd, p4_hand_check)
    targets, queued_hosts = load_segment(wd, segment, priorities)
    meta = load_registry_meta(wd)
    orgs: dict[str, Org] = {}
    for t in targets:
        o = org_of(t, extra_platforms)
        orgs.setdefault(o.key, o).hosts.append(t)
    excluded_a = 0
    if segment in ("B", "C"):
        a_keys = set()
        for d in _queue(wd, None):
            if d.get("host") in queued_hosts:
                a_keys.add(org_of(Target(d["host"], "", list(d.get("entries") or [])), extra_platforms).key)
        excluded_a = sum(1 for k in orgs if k in a_keys)
        orgs = {k: o for k, o in orgs.items() if k not in a_keys}
    disc = Discoverer(fetcher, segment=segment, now=now, extra_platforms=extra_platforms)
    suppress = suppress or set()
    rows: list[dict[str, str]] = []
    stats = {
        "targets": len(targets),
        "orgs": len(orgs),
        "orgs_excluded_in_A": excluded_a,
        "no_contact": 0,
        "suppressed": 0,
        "ineligible": 0,
    }
    for i, org in enumerate(
        sorted(orgs.values(), key=lambda o: (min((t.priority or "P9") for t in o.hosts), o.key))
    ):
        if limit is not None and i >= limit:
            break
        found, notes = _discover_with_deadline(disc, org, meta)
        host_notes = [n for t in org.hosts for n in t.notes]
        base = {
            "segment": segment,
            "priority": min((t.priority for t in org.hosts if t.priority), default=""),
            "org": org.key,
            "org_domain": org.domain,
            "hosts": ";".join(sorted(t.host for t in org.hosts)),
            "server_names": ";".join(sorted({n for t in org.hosts for n in t.entries})),
        }
        if not found:
            stats["no_contact"] += 1
            rows.append(
                {
                    **base,
                    "contact": "",
                    "contact_type": "",
                    "address_kind": "",
                    "source": "",
                    "source_url": "",
                    "retrieved_at": now.isoformat(timespec="seconds"),
                    "subscriber_type": "",
                    "eligible": "false",
                    "notes": "; ".join(["no published contact", *notes, *host_notes]),
                }
            )
            continue
        for f in found:
            sub = subscriber_type(f.contact, org)
            row_notes = [*notes, *host_notes]
            eligible = True
            if f.address_kind == "named":
                row_notes.append("named address published as the security contact (segment A only)")
            if f.contact_type == "form":
                eligible = False
                row_notes.append("contact form: by hand only, never scripted")
            elif segment in ("B", "C") and sub != "corporate":
                eligible = False
                row_notes.append("PECR: not a corporate subscriber, no marketing")
            if suppressed(f.contact, org, suppress):
                eligible = False
                stats["suppressed"] += 1
                row_notes.append("on suppression list")
            if not eligible:
                stats["ineligible"] += 1
            rows.append(
                {
                    **base,
                    "contact": f.contact,
                    "contact_type": f.contact_type,
                    "address_kind": f.address_kind,
                    "source": f.source,
                    "source_url": f.source_url,
                    "retrieved_at": f.retrieved_at,
                    "subscriber_type": sub,
                    "eligible": str(eligible).lower(),
                    "notes": "; ".join(row_notes),
                }
            )
    if p4_checked is not None:
        stats["p4_hand_check_correct"], stats["p4_hand_check_sample"] = p4_checked
    stats["withheld_non_role_addresses"] = disc.withheld
    stats["rows"] = len(rows)
    stats["eligible_rows"] = sum(1 for r in rows if r["eligible"] == "true")
    return rows, stats


def write_csv(rows: list[dict[str, str]], out: Path) -> None:
    ensure_private_path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    out.chmod(0o600)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--workdir", type=Path, required=True)
    ap.add_argument("--segment", choices=("A", "B", "C"), required=True)
    ap.add_argument(
        "--priority",
        action="append",
        choices=("P1", "P2", "P3", "P4"),
        help="Segment A priorities (repeatable). Default: P1, P2, P3.",
    )
    ap.add_argument(
        "--out", type=Path, required=True, help="PRIVATE CSV; refused inside a git tree unless ignored"
    )
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Read --fixtures only; no network")
    mode.add_argument("--live", action="store_true", help="Fetch the published channels (GET only)")
    ap.add_argument("--fixtures", type=Path, help="Fixture directory with index.json (dry run)")
    ap.add_argument(
        "--suppress", type=Path, help="Suppression list: emails, sha256 of emails, domains or hosts"
    )
    ap.add_argument(
        "--p4-hand-check",
        type=Path,
        help="CSV (host,correct) of a manual check of >= 50 P4 hosts; required for --priority P4",
    )
    ap.add_argument("--platform-suffix", action="append", default=[], help="Extra shared-hosting suffix")
    ap.add_argument("--limit", type=int, help="Stop after N organisations")
    args = ap.parse_args(argv)
    if args.dry_run and not args.fixtures:
        ap.error("--dry-run needs --fixtures")
    if args.priority and args.segment != "A":
        ap.error("--priority applies to segment A only")
    fetcher: Fetcher = FixtureFetcher(args.fixtures) if args.dry_run else LiveFetcher()
    rows, stats = run(
        WorkDir(args.workdir),
        args.segment,
        fetcher,
        priorities=args.priority or ("P1", "P2", "P3"),
        suppress=load_suppression(args.suppress),
        extra_platforms=args.platform_suffix,
        limit=args.limit,
        p4_hand_check=args.p4_hand_check,
    )
    write_csv(rows, args.out)
    print(json.dumps({"segment": args.segment, "out": str(args.out), **stats}, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
