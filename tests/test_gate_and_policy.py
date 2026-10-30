"""The active-mode authorisation gate, opt-out handling, scanner identification and rate caps."""

from __future__ import annotations

import json

import httpx
import pytest

from mcpprobe import USER_AGENT, __version__
from mcpprobe.authz import (
    AuthorisationError,
    authorise,
    expected_txt_record,
    record_path_for,
    require_active_authorisation,
    save_token,
    write_record,
)
from mcpprobe.checks import ScanContext, ScanOptions
from mcpprobe.checks.active_stubs import ACTIVE_STUBS, Inj01CommandInjection
from mcpprobe.models import CheckMode, Fingerprint, Inventory
from mcpprobe.policy import (
    MAX_RATE,
    OPT_OUT_TXT,
    OptOutError,
    check_dns_opt_out,
    clamp_rate,
    opt_out_dns_names,
)
from mcpprobe.scanner import ScanConfig, run_scan
from mcpprobe.transport import EvidenceLog, StdioTransport, TransportError
from tests.conftest import run, status_of, stdio_command

TOKEN = "testtoken" * 4
HOST = "mcp.example.com"
ACTIVE_IDS = [c.id for c in ACTIVE_STUBS]


def txt(records: dict[str, list[str]], calls: list[str] | None = None):
    def lookup(name: str) -> list[str]:
        if calls is not None:
            calls.append(name)
        return records.get(name, [])

    return lookup


def _auth(**kw):
    base = dict(
        target=f"https://{HOST}/mcp",
        transport="http",
        host=HOST,
        active=True,
        authorised_by="security lead, ticket SEC-1",
        scope=f"https://{HOST}/mcp read-only",
        verify_method="dns-txt",
        token=TOKEN,
        rate_cap_rps=5.0,
    )
    base.update(kw)
    return authorise(**base)


# ----------------------------------------------------------------------------- gate unit
@pytest.mark.parametrize("missing", ["authorised_by", "scope"])
def test_gate_requires_authorised_by_and_scope(missing):
    with pytest.raises(AuthorisationError, match="requires --"):
        _auth(**{missing: None}, lookup=txt({}))


def test_gate_requires_verify_method():
    with pytest.raises(AuthorisationError, match="--verify"):
        _auth(verify_method=None, lookup=txt({}))


def test_gate_dns_txt_verified_at_mcpprobe_label():
    calls: list[str] = []
    rec = _auth(lookup=txt({f"_mcpprobe.{HOST}": [expected_txt_record(TOKEN), "v=spf1 -all"]}, calls))
    assert rec.verified and rec.mode == CheckMode.ACTIVE
    assert calls == [f"_mcpprobe.{HOST}"]
    assert rec.verification.evidence["records"] == [expected_txt_record(TOKEN)]  # foreign TXT not stored
    # The token itself is public (it is in DNS); the record keeps the DNS answer as proof plus a fingerprint.
    assert rec.token_fingerprint and len(rec.token_fingerprint) == 16


def test_gate_rejects_wrong_token_and_apex_record():
    with pytest.raises(AuthorisationError, match="verification failed"):
        _auth(lookup=txt({f"_mcpprobe.{HOST}": [expected_txt_record("other")]}))
    with pytest.raises(AuthorisationError, match="verification failed"):
        _auth(lookup=txt({HOST: [expected_txt_record(TOKEN)]}))


def test_gate_rejects_ip_literal():
    with pytest.raises(AuthorisationError, match="IP address"):
        _auth(host="127.0.0.1", target="http://127.0.0.1/mcp", lookup=txt({}))


def test_gate_uses_saved_token(tmp_path):
    store = tmp_path / "t.json"
    save_token(HOST, TOKEN, store)
    rec = _auth(
        token=None, token_store=store, lookup=txt({f"_mcpprobe.{HOST}": [expected_txt_record(TOKEN)]})
    )
    assert rec.verified
    with pytest.raises(AuthorisationError, match="no verification token"):
        _auth(token=None, token_store=tmp_path / "empty.json", lookup=txt({}))


def test_gate_local_only_for_stdio():
    with pytest.raises(AuthorisationError, match="only valid for stdio"):
        _auth(verify_method="local")
    rec = _auth(verify_method="local", transport="stdio", host="", target="python server.py")
    assert rec.verified and rec.verification.method == "local"


def test_gate_passive_never_raises():
    rec = authorise(
        target="https://x.example/mcp",
        transport="http",
        host="x.example",
        active=False,
        authorised_by=None,
        scope=None,
        verify_method=None,
        rate_cap_rps=5,
    )
    assert rec.mode == CheckMode.PASSIVE and not rec.verified
    with pytest.raises(AuthorisationError):
        require_active_authorisation(rec)
    with pytest.raises(AuthorisationError):
        require_active_authorisation(None)


def test_authorisation_record_written_next_to_report(tmp_path):
    rec = _auth(lookup=txt({f"_mcpprobe.{HOST}": [expected_txt_record(TOKEN)]}))
    path = write_record(rec, tmp_path / "out" / "report.json")
    assert path == tmp_path / "out" / "report.authorisation.json"
    data = json.loads(path.read_text())
    assert data["authorised_by"] == "security lead, ticket SEC-1"
    assert data["verification"]["verified"] is True
    assert record_path_for(None).name.startswith("mcpprobe-authorisation-")


# ----------------------------------------------------------------------------- gate e2e
async def test_active_checks_skipped_in_passive_mode(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=ACTIVE_IDS)
        assert srv.tool_calls == []
    for cid in ("INJ-01", "INJ-05"):
        st = status_of(report, cid)
        assert st.status.value == "skipped" and "verified ownership" in (st.reason or "")


async def test_active_stubs_run_only_with_verified_record(make_server):
    rec = authorise(
        target="python server.py",
        transport="stdio",
        host="",
        active=True,
        authorised_by="owner",
        scope="local package",
        verify_method="local",
        rate_cap_rps=5,
    )
    report = await run(stdio_command(), stdio=True, only=ACTIVE_IDS, authorisation=rec, mode=CheckMode.ACTIVE)
    statuses = {c.check_id: c.status.value for c in report.checks}
    assert statuses["SUPPLY-01"] == "not_implemented"
    assert statuses["SANDBOX-01"] == "not_implemented"
    assert statuses["INJ-01"] == "not_implemented"
    assert report.findings == []


async def test_forged_unverified_record_is_refused(make_server):
    rec = authorise(
        target="x",
        transport="stdio",
        host="",
        active=True,
        authorised_by="a",
        scope="b",
        verify_method="local",
        rate_cap_rps=5,
    )
    rec.verification.verified = False  # tampered
    report = await run(stdio_command(), stdio=True, only=["INJ-01"], authorisation=rec, mode=CheckMode.ACTIVE)
    assert status_of(report, "INJ-01").status.value == "skipped"


async def test_active_check_defends_itself():
    ctx = ScanContext(
        target="x",
        transport=StdioTransport(stdio_command()),
        fingerprint=Fingerprint(transport="stdio"),
        inventory=Inventory(),
        evidence=EvidenceLog(),
        options=ScanOptions(mode=CheckMode.ACTIVE),
        authorisation=None,
    )
    with pytest.raises(PermissionError):
        await Inj01CommandInjection().run(ctx)


def test_active_stubs_have_todo_docstrings():
    for cls in ACTIVE_STUBS:
        assert cls.mode == CheckMode.ACTIVE
        assert cls.__doc__ and "TODO" in cls.__doc__, cls.id
        assert "NOT IMPLEMENTED" in cls.description


# ----------------------------------------------------------------------------- opt-out
def test_opt_out_dns_names():
    assert opt_out_dns_names("api.mcp.example.com") == [
        "_mcpprobe.api.mcp.example.com",
        "_mcpprobe.mcp.example.com",
        "_mcpprobe.example.com",
    ]
    assert opt_out_dns_names("example.com") == ["_mcpprobe.example.com"]


async def test_dns_opt_out_raises_and_parent_zone_counts():
    with pytest.raises(OptOutError, match="opted out"):
        await check_dns_opt_out(HOST, txt({f"_mcpprobe.{HOST}": [OPT_OUT_TXT]}))
    with pytest.raises(OptOutError):
        await check_dns_opt_out("api." + HOST, txt({"_mcpprobe.example.com": ['"mcpprobe-opt-out=all"']}))
    notes = await check_dns_opt_out(HOST, txt({f"_mcpprobe.{HOST}": ["mcpprobe-verification=abc"]}))
    assert any("no DNS opt-out" in n for n in notes)


async def test_dns_opt_out_aborts_before_any_http_request(monkeypatch):
    sent: list[str] = []

    async def no_network(self, request, **kw):  # pragma: no cover - must not be reached
        sent.append(str(request.url))
        raise AssertionError("an HTTP request was sent despite the DNS opt-out")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_network)
    cfg = ScanConfig(target=f"https://{HOST}/mcp", txt_lookup=txt({f"_mcpprobe.{HOST}": [OPT_OUT_TXT]}))
    with pytest.raises(OptOutError):
        await run_scan(cfg)
    assert sent == []


async def test_http_opt_out_aborts_after_single_request(make_server):
    async with make_server(opt_out=True) as srv:
        with pytest.raises(OptOutError, match="mcpprobe-opt-out"):
            await run(srv.url)
        assert [r["path"] for r in srv.requests] == ["/.well-known/mcpprobe-opt-out"]


async def test_no_opt_out_proceeds_and_is_noted(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["AUTH-01"])
        assert srv.requests[0]["path"] == "/.well-known/mcpprobe-opt-out"
    assert any(n.startswith("opt-out: DNS check skipped") for n in report.notes)


# ----------------------------------------------------------------------------- identification, rate
async def test_every_request_carries_user_agent(make_server):
    async with make_server(preset="vulnerable") as srv:
        await run(srv.url)
        agents = {r["headers"].get("user-agent") for r in srv.requests}
    assert agents == {USER_AGENT}
    assert USER_AGENT.startswith(f"mcpprobe/{__version__} (+https://mcpprobe.tech/scanning-policy)")


def test_rate_ceiling():
    assert clamp_rate(5) == 5 and clamp_rate(MAX_RATE) == MAX_RATE == 10
    with pytest.raises(ValueError, match="maximum"):
        clamp_rate(10.5)
    with pytest.raises(ValueError):
        clamp_rate(0)
    assert ScanConfig(target="https://x.example/mcp").rate == 5.0


async def test_scan_refuses_rate_above_ceiling():
    with pytest.raises(TransportError, match="maximum"):
        await run_scan(ScanConfig(target="https://x.example/mcp", rate=50))


async def test_default_rate_is_enforced_by_limiter(make_server):
    import time

    async with make_server() as srv:
        cfg = ScanConfig(target=srv.url, rate=10, only=["TRANS-02"], txt_lookup=txt({}))
        start = time.monotonic()
        await run_scan(cfg)
        elapsed = time.monotonic() - start
        n = len(srv.requests)
    # burst of one token, then 10/s: n requests need at least (n - 1) / 10 seconds
    assert n > 5 and elapsed >= (n - 1) / 10 - 0.05
