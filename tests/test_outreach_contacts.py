"""Contact discovery for post-survey outreach (scripts/outreach_contacts.py).

Dry run only: every test runs with the network blocked, and the fetcher reads fixtures.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import socket
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from mcpprobe.checks.poisoning import RULES_VERSION as META01_RULES
from mcpprobe.registry.common import WorkDir

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "data" / "outreach"
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)

_spec = importlib.util.spec_from_file_location("outreach_contacts", ROOT / "scripts" / "outreach_contacts.py")
oc = importlib.util.module_from_spec(_spec)
sys.modules["outreach_contacts"] = oc
_spec.loader.exec_module(oc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("a test tried to use the network")

    monkeypatch.setattr(httpx.Client, "send", refuse)
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


OPEN = {
    "AUTH-01": "critical",
    "AUTH-02": "n_a",
    "META-01": "passed",
    "META-03": "medium",
    "META-05": "passed",
    "META-07": "passed",
}
LOCKED = {
    "AUTH-01": "passed",
    "AUTH-02": "medium",
    "META-01": "blocked",
    "META-03": "blocked",
    "META-05": "blocked",
    "META-07": "blocked",
}


def rec(host, entry, **outcomes):
    base = dict(LOCKED if outcomes.pop("locked", False) else OPEN)
    base.update({k.replace("_", "-"): v for k, v in outcomes.items()})
    return {
        "host": host,
        "url": f"https://{host}/mcp",
        "status": "scanned",
        "entries": [entry],
        "outcomes": base,
        "meta01_rules": META01_RULES,
        "finished_at": "2026-11-01T10:00:00+00:00",
    }


RECORDS = [
    rec("p1.acme.example", "example.acme/p1", META_05="high"),
    rec("docs.acme.example", "example.acme/docs"),  # clean, but its organisation is in A
    rec("poison.tenant.vercel.app", "io.github.dev42/poison", META_01="high"),
    rec("trifecta.example.net", "net.example/trifecta", META_07="medium"),
    rec("old.stale.example", "example.stale/old", META_03="high"),
    rec("clean.widgets.example", "example.widgets/clean"),
    rec("free.hobby.example", "io.github.hobbyist/tool"),
    rec("locked.bigco.example", "example.bigco/locked", locked=True),
]
SERVERS = {
    "io.github.dev42/poison": {"repository": {"url": "https://github.com/dev42/poison", "source": "github"}},
    "io.github.hobbyist/tool": {
        "repository": {"url": "https://github.com/hobbyist/tool", "source": "github"}
    },
    "example.widgets/clean": {"websiteUrl": "https://widgets.example"},
    "example.bigco/locked": {"websiteUrl": "https://bigco.example"},
}


@pytest.fixture
def wd(tmp_path):
    w = WorkDir(tmp_path / "work").ensure()
    w.scan.write_text("".join(json.dumps(r) + "\n" for r in RECORDS))
    w.pages.mkdir()
    servers = [{"server": {"name": name, **extra}} for name, extra in SERVERS.items()]
    (w.pages / "page-1.json").write_text(json.dumps({"servers": servers, "metadata": {}}))
    return w


def run(wd, segment, **kw):
    fetcher = oc.FixtureFetcher(FIXTURES)
    rows, stats = oc.run(wd, segment, fetcher, now=NOW, **kw)
    return rows, stats, fetcher


def by_org(rows):
    return {r["org"]: r for r in rows}


def test_segment_a_uses_published_security_contacts_with_source_and_date(wd):
    rows, stats, fetcher = run(wd, "A")
    orgs = by_org(rows)
    assert set(orgs) == {"acme.example", "io.github.dev42", "stale.example"}  # P4 not included by default
    acme = orgs["acme.example"]
    assert acme["contact"] == "security@acme.example"
    assert acme["source"] == "security.txt (organisation domain)"
    assert acme["source_url"] == "https://acme.example/.well-known/security.txt"
    assert acme["retrieved_at"] == "2026-11-03T12:00:00+00:00"
    assert acme["priority"] == "P1" and acme["eligible"] == "true" and acme["subscriber_type"] == "corporate"
    dev = orgs["io.github.dev42"]
    assert dev["contact"] == "security@dev42.example"
    assert dev["source_url"].endswith("/dev42/poison/HEAD/.github/SECURITY.md")
    assert (
        dev["subscriber_type"] == "individual_or_unknown" and dev["eligible"] == "true"
    )  # disclosure is not marketing
    stale = orgs["stale.example"]
    assert stale["contact"] == "" and stale["eligible"] == "false"
    assert "expired" in stale["notes"]
    # A shared platform's security.txt belongs to the platform, never to the tenant.
    assert "https://poison.tenant.vercel.app/.well-known/security.txt" not in fetcher.requested
    assert stats["withheld_non_role_addresses"] == 2


def test_personal_addresses_are_never_recorded(wd, tmp_path):
    out = tmp_path / "PRIVATE-contacts.csv"
    for segment in ("A", "B", "C"):
        rows, _, _ = run(wd, segment)
        oc.write_csv(rows, out)
        text = out.read_text()
        # Withheld everywhere: each sits next to a security role address, or is on a website.
        for personal in ("jane.doe@acme.example", "dev42.personal@gmail.com", "jane@widgets.example"):
            assert personal not in text


def _p4_queue(wd, n):
    queue = [
        {
            "host": f"t{i}.p4.example",
            "url": f"https://t{i}.p4.example/mcp",
            "entries": [f"example.p4/t{i}"],
            "priority": "P4",
        }
        for i in range(n)
    ]
    queue.append(
        {
            "host": "p1.acme.example",
            "url": "https://p1.acme.example/mcp",
            "entries": ["example.acme/p1"],
            "priority": "P1",
        }
    )
    wd.disclosure_queue.write_text(json.dumps(queue))
    return [q["host"] for q in queue if q["priority"] == "P4"]


def _hand_check(tmp_path, rows):
    f = tmp_path / "PRIVATE-p4-hand-check.csv"
    f.write_text("host,correct\n" + "".join(f"{h},{c}\n" for h, c in rows))
    return f


def test_p4_is_refused_without_a_hand_check(wd):
    with pytest.raises(SystemExit, match="P4 is gated"):
        run(wd, "A", priorities=("P4",))


def test_p4_needs_fifty_hosts_and_ninety_percent(wd, tmp_path):
    hosts = _p4_queue(wd, 60)
    few = _hand_check(tmp_path, [(h, "yes") for h in hosts[:49]])
    with pytest.raises(SystemExit, match="49 hosts"):
        run(wd, "A", priorities=("P4",), p4_hand_check=few)
    poor = _hand_check(tmp_path, [(h, "yes") for h in hosts[:44]] + [(h, "no") for h in hosts[44:50]])
    with pytest.raises(SystemExit, match="44/50"):
        run(wd, "A", priorities=("P4",), p4_hand_check=poor)
    padded = _hand_check(tmp_path, [(h, "yes") for h in hosts[:49]] + [("p1.acme.example", "yes")])
    with pytest.raises(SystemExit, match="not a P4 host"):
        run(wd, "A", priorities=("P4",), p4_hand_check=padded)
    good = _hand_check(tmp_path, [(h, "yes") for h in hosts[:45]] + [(h, "no") for h in hosts[45:50]])
    rows, stats, _ = run(wd, "A", priorities=("P4",), p4_hand_check=good)
    [row] = rows  # one organisation, p4.example
    assert row["priority"] == "P4" and len(row["hosts"].split(";")) == 60
    assert (stats["p4_hand_check_correct"], stats["p4_hand_check_sample"]) == (45, 50)


def test_addresses_are_never_guessed(wd):
    rows, _, _ = run(wd, "A")
    stale = by_org(rows)["stale.example"]  # its only security.txt has expired
    assert stale["contact"] == "" and stale["notes"].startswith("no published contact")
    assert all("rfc2142" not in r["source"] for r in rows)
    with pytest.raises(SystemExit):
        oc.main(
            [
                "--workdir",
                str(wd.root),
                "--segment",
                "A",
                "--dry-run",
                "--fixtures",
                str(FIXTURES),
                "--allow-rfc2142",
                "--out",
                "x.csv",
            ]
        )


def _solo(tmp_path, **outcomes):
    w = WorkDir(tmp_path / "solo").ensure()
    w.scan.write_text(json.dumps(rec("mcp.solo.example", "example.solo/tool", **outcomes)) + "\n")
    return w


def test_named_security_contact_is_used_for_segment_a_only_with_its_source(tmp_path):
    rows, stats, _ = run(_solo(tmp_path, META_05="high"), "A")
    [row] = rows
    assert row["contact"] == "alex.smith@solo.example"
    assert row["address_kind"] == "named" and row["eligible"] == "true"
    assert row["source"] == "security.txt (organisation domain)"
    assert row["source_url"] == "https://solo.example/.well-known/security.txt"
    assert "segment A only" in row["notes"] and stats["withheld_non_role_addresses"] == 0
    # Marketing never takes a named address, even one published in security.txt.
    rows_b, stats_b, _ = run(_solo(tmp_path / "b"), "B")
    assert [r["contact"] for r in rows_b] == [""] and stats_b["withheld_non_role_addresses"] == 1


def test_named_address_is_not_kept_when_a_security_role_is_published(wd):
    rows, _, _ = run(wd, "A")
    acme = [r for r in rows if r["org"] == "acme.example"]
    assert [(r["contact"], r["address_kind"]) for r in acme] == [("security@acme.example", "role")]


def test_segment_b_marketing_is_corporate_role_addresses_only_and_excludes_a(wd):
    rows, stats, _ = run(wd, "B")
    orgs = by_org(rows)
    assert "acme.example" not in orgs and stats["orgs_excluded_in_A"] == 1
    w = orgs["widgets.example"]
    assert w["contact"] == "hello@widgets.example" and w["source"] == "website"
    assert w["subscriber_type"] == "corporate" and w["eligible"] == "true"
    hob = orgs["hobby.example"]  # personal GitHub namespace on its own domain
    assert hob["contact"] == "hello@gmail.com" and hob["eligible"] == "false"
    assert "PECR" in hob["notes"]


def test_segment_c_never_uses_security_addresses_for_marketing(wd):
    rows, _, _ = run(wd, "C")
    [row] = rows
    assert row["org"] == "bigco.example"
    assert row["contact"] == "info@bigco.example"
    assert row["source_url"] == "https://bigco.example/contact"
    assert "AUTH-02 medium" in row["notes"]
    assert all(not r["contact"].startswith("security@") for r in rows)


def test_suppression_by_address_hash_or_domain(wd):
    import hashlib

    h = hashlib.sha256(b"hello@widgets.example").hexdigest()
    for key in ("hello@widgets.example", h, "widgets.example"):
        rows, stats, _ = run(wd, "B", suppress={key})
        assert by_org(rows)["widgets.example"]["eligible"] == "false"
        assert stats["suppressed"] == 1


def test_cli_dry_run_writes_private_csv(wd, tmp_path, capsys):
    out = tmp_path / "out" / "PRIVATE-contacts-A.csv"
    assert (
        oc.main(
            [
                "--workdir",
                str(wd.root),
                "--segment",
                "A",
                "--dry-run",
                "--fixtures",
                str(FIXTURES),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    rows = list(csv.DictReader(out.open()))
    assert tuple(rows[0]) == oc.CSV_FIELDS
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    assert json.loads(capsys.readouterr().err)["orgs"] == 3


def test_cli_needs_an_explicit_mode(wd, tmp_path):
    with pytest.raises(SystemExit):
        oc.main(["--workdir", str(wd.root), "--segment", "A", "--out", str(tmp_path / "x.csv")])
    with pytest.raises(SystemExit):
        oc.main(
            [
                "--workdir",
                str(wd.root),
                "--segment",
                "B",
                "--dry-run",
                "--fixtures",
                str(FIXTURES),
                "--priority",
                "P1",
                "--out",
                str(tmp_path / "x.csv"),
            ]
        )


def test_refuses_to_write_into_a_git_tree_unless_ignored(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / ".gitignore").write_text("PRIVATE-*\n")
    with pytest.raises(SystemExit, match="refusing"):
        oc.write_csv([], repo / "contacts.csv")
    oc.write_csv([], repo / "PRIVATE-contacts.csv")
    assert (repo / "PRIVATE-contacts.csv").exists()


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("mcp.example.co.uk", "example.co.uk"),
        ("a.b.example.com", "example.com"),
        ("example.org", "example.org"),
    ],
)
def test_registrable_domain(host, expected):
    assert oc.registrable_domain(host) == expected


def test_security_txt_rules():
    good = "Contact: mailto:security@x.example\nExpires: 2027-01-01T00:00:00Z\n"
    assert oc.parse_security_txt(good, NOW) == (["security@x.example"], [], None)
    assert oc.parse_security_txt("Contact: mailto:a@x.example\n", NOW)[2] == "no Expires field"
    assert oc.parse_security_txt("Expires: 2027-01-01T00:00:00Z\n", NOW)[2] == "no Contact field"
    # A bare timestamp (no zone) is read as UTC instead of crashing the run (seen live, 8 Nov 2026).
    naive = "Contact: mailto:security@x.example\nExpires: 2027-01-01T00:00:00\n"
    assert oc.parse_security_txt(naive, NOW) == (["security@x.example"], [], None)
    stale = "Contact: mailto:security@x.example\nExpires: 2020-01-01T00:00:00\n"
    assert oc.parse_security_txt(stale, NOW)[2].startswith("expired")


def test_discover_deadline_abandons_a_hanging_org(monkeypatch):
    class Hang:
        def discover(self, org, meta):
            raise oc._DeadlineError

    found, notes = oc._discover_with_deadline(Hang(), None, {})
    assert found == [] and notes and "abandoned" in notes[0]


class _Pages:
    """A fetcher over an in-memory {url: html} map; everything else is a 404."""

    def __init__(self, pages):
        self.pages, self.seen = pages, []

    def get(self, url):
        self.seen.append(url)
        if url in self.pages:
            return oc.Page(200, self.pages[url], url)
        return oc.Page(404, "", url)


def _disc(pages, segment="B"):
    return oc.Discoverer(_Pages(pages), segment=segment, now=NOW)


def test_second_pass_reads_the_organisation_domain_when_the_registry_has_no_website():
    org = oc.Org(
        "nosite.example", "nosite.example", False, [oc.Target("mcp.nosite.example", "", ["example.nosite/x"])]
    )
    d = _disc(
        {"https://nosite.example/about": "<p>Write to <a href='mailto:support@nosite.example'>us</a></p>"}
    )
    found, _ = d.discover(org, {})
    assert [(f.contact, f.source) for f in found] == [
        ("support@nosite.example", "website (organisation domain)")
    ]
    # a personal GitHub namespace has no organisation site to read
    gh = oc.Org("someone", "", True, [oc.Target("x.vercel.app", "", ["io.github.someone/x"])])
    assert _disc({}).discover(gh, {}) == ([], ["x.vercel.app: shared platform, host security.txt skipped"])


def test_contact_form_is_recorded_for_hand_use_and_never_eligible(wd):
    form = "<form action='/send'><input name='email'><textarea name='msg'></textarea></form>"
    d = _disc({"https://formonly.example/contact": form})
    org = oc.Org(
        "formonly.example",
        "formonly.example",
        False,
        [oc.Target("mcp.formonly.example", "", ["example.formonly/x"])],
    )
    found, _ = d.discover(org, {})
    assert [(f.contact, f.contact_type) for f in found] == [("https://formonly.example/contact", "form")]
    # segment A never falls back to a form
    assert _disc({"https://formonly.example/contact": form}, "A").discover(org, {})[0] == []


def test_website_page_redirected_off_domain_is_ignored():
    class Redirect(_Pages):
        def get(self, url):
            if url.endswith("/contact"):
                return oc.Page(200, "mailto:hello@parked.example", "https://parked.example/")
            return super().get(url)

    org = oc.Org(
        "moved.example", "moved.example", False, [oc.Target("mcp.moved.example", "", ["example.moved/x"])]
    )
    assert oc.Discoverer(Redirect({}), segment="B", now=NOW).discover(org, {})[0] == []


def test_shard_and_only_orgs_split_a_run_without_overlap(wd):
    whole, _, _ = run(wd, "B")
    parts = [run(wd, "B", shard=(k, 2))[0] for k in (0, 1)]
    assert sorted(r["org"] for p in parts for r in p) == sorted(r["org"] for r in whole)
    assert not {r["org"] for r in parts[0]} & {r["org"] for r in parts[1]}
    only, _, _ = run(wd, "B", only_orgs={"widgets.example"})
    assert [r["org"] for r in only] == ["widgets.example"]
