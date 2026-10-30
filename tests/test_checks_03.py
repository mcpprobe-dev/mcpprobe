"""0.3 checks: META-06, META-07, the 2026-07-28 rules (TRANS-06..09, AUTH-05/06),
rate-limit handling and directory readiness, each against the configurable fake server."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from mcpprobe.models import Confidence, Severity
from mcpprobe.report.json_report import report_to_dict
from mcpprobe.transport import HttpTransport, RateLimiter
from mcpprobe.transport.http import retry_after_seconds
from tests.conftest import by_id, run, status_of, stdio_command
from tests.fake_server import POISONED_TOOLS, TRIFECTA_TOOLS, VALID_TOKEN

MODERN = {"stateless_2026": True, "session_mode": "none"}
AUTH = {"Authorization": f"Bearer {VALID_TOKEN}"}


def _tool(name: str, description: str, annotations: dict | None = None, **extra) -> dict:
    tool = {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        **extra,
    }
    if annotations is not None:
        tool["annotations"] = annotations
    return tool


FULL_RO = {"readOnlyHint": True, "openWorldHint": False}


# ----------------------------------------------------------------------------- META-06
async def test_meta06_missing_annotations_is_low_and_certain(make_server):
    async with make_server() as srv:  # BENIGN_TOOLS: get_weather partly annotated, add_numbers bare
        report = await run(srv.url, only=["META-06"])
    [f] = by_id(report, "META-06")
    assert f.severity == Severity.LOW and f.confidence == Confidence.HIGH
    assert f.details["missing"] == {
        "get_weather": ["title"],
        "add_numbers": ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint", "title"],
    }
    assert f.details["inconsistent"] == {}
    assert f.verify and "tools/list" in f.verify


async def test_meta06_read_only_tool_needs_no_destructive_hint(make_server):
    tools = [_tool("get_weather", "Return the current weather for a city.", FULL_RO, title="Weather")]
    async with make_server(tools=tools) as srv:
        report = await run(srv.url, only=["META-06"])
    assert by_id(report, "META-06") == []
    assert status_of(report, "META-06").passed


async def test_meta06_title_inside_annotations_counts(make_server):
    tools = [_tool("get_weather", "Return the weather.", {**FULL_RO, "title": "Weather"})]
    async with make_server(tools=tools) as srv:
        report = await run(srv.url, only=["META-06"])
    assert by_id(report, "META-06") == []


async def test_meta06_contradictions_are_medium(make_server):
    async with make_server(tools=POISONED_TOOLS) as srv:
        report = await run(srv.url, only=["META-06"])
    [f] = by_id(report, "META-06")
    assert f.severity == Severity.MEDIUM and f.confidence == Confidence.MEDIUM and f.confidence_reason
    bad = f.details["inconsistent"]
    assert any("readOnlyHint=true" in p for p in bad["run_command"])
    assert any("destructiveHint=false" in p for p in bad["run_command"])
    assert any("readOnlyHint=true" in p for p in bad["send_email"])
    assert "inconsistent: readOnlyHint=true" in f.proof


async def test_meta06_reading_mail_marked_read_only_is_not_a_contradiction(make_server):
    tools = [_tool("list_emails", "List the messages in the user's inbox.", {**FULL_RO}, title="Inbox")]
    async with make_server(tools=tools) as srv:
        report = await run(srv.url, only=["META-06"])
    assert by_id(report, "META-06") == []


async def test_meta06_read_only_tool_marked_destructive_is_low_noise(make_server):
    ann = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False}
    tools = [_tool("search_docs", "Search the documentation and list matching pages.", ann, title="Search")]
    async with make_server(tools=tools) as srv:
        report = await run(srv.url, only=["META-06"])
    [f] = by_id(report, "META-06")
    assert f.severity == Severity.LOW and f.confidence == Confidence.MEDIUM
    assert "search_docs" in f.details["noise"] and f.details["inconsistent"] == {}


async def test_meta06_non_boolean_hint(make_server):
    ann = {**FULL_RO, "readOnlyHint": "yes"}
    tools = [_tool("get_weather", "Return the weather.", ann, title="Weather")]
    async with make_server(tools=tools) as srv:
        report = await run(srv.url, only=["META-06"])
    [f] = by_id(report, "META-06")
    assert f.details["inconsistent"]["get_weather"] == ['readOnlyHint is "yes", not a boolean']


async def test_meta06_not_applicable_without_tools(make_server):
    async with make_server(tools=[]) as srv:
        report = await run(srv.url, only=["META-06", "META-07"])
    for cid in ("META-06", "META-07"):
        assert status_of(report, cid).status.value == "not_applicable"


# ----------------------------------------------------------------------------- META-07
async def test_meta07_benign_server_passes(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["META-07"])
    assert status_of(report, "META-07").passed


async def test_meta07_two_roles_are_not_a_trifecta(make_server):
    async with make_server(tools=TRIFECTA_TOOLS[:2]) as srv:
        report = await run(srv.url, only=["META-07"])
    assert by_id(report, "META-07") == []


async def test_meta07_medium_when_authenticated(make_server):
    async with make_server(tools=TRIFECTA_TOOLS, require_auth=True) as srv:
        report = await run(srv.url, only=["META-07"], headers=AUTH)
    [f] = by_id(report, "META-07")
    assert f.severity == Severity.MEDIUM and f.details["unauthenticated"] is False
    assert "Authentication: required" in f.proof


async def test_meta07_inbox_is_private_and_untrusted(make_server):
    tools = [
        _tool("list_emails", "List the messages in the user's inbox.", FULL_RO, title="Inbox"),
        TRIFECTA_TOOLS[2],
    ]
    async with make_server(tools=tools) as srv:
        report = await run(srv.url, only=["META-07"])
    [f] = by_id(report, "META-07")
    assert set(f.details["roles"]["private_data"]) == {"list_emails"}
    assert set(f.details["roles"]["untrusted_content"]) == {"list_emails"}


async def test_meta07_stdio_is_medium():
    # The poisoned stdio echo tool has no network role: not a trifecta, but the check runs on stdio.
    report = await run(stdio_command(), stdio=True, only=["META-07"])
    assert status_of(report, "META-07").passed


# ----------------------------------------------------------------------------- 2026-07-28: gating
async def test_2026_checks_not_applicable_on_handshake_server(make_server):
    ids = ["TRANS-06", "TRANS-07", "TRANS-08", "TRANS-09", "AUTH-05", "AUTH-06"]
    async with make_server() as srv:
        report = await run(srv.url, only=ids)
    for cid in ids:
        st = status_of(report, cid)
        assert st.status.value == "not_applicable" and "2026-07-28" in (st.reason or ""), cid
        assert st.blocked is False


async def test_2026_conformant_server_passes(make_server):
    ids = ["TRANS-06", "TRANS-07", "TRANS-08", "TRANS-09"]
    async with make_server(**MODERN) as srv:
        report = await run(srv.url, only=ids)
    assert [status_of(report, c).passed for c in ids] == [True] * 4
    assert report.fingerprint.supported_versions == ["2026-07-28"]
    sent = json.loads(_first_body())
    meta = sent["params"]["_meta"]
    assert meta["io.modelcontextprotocol/clientCapabilities"] == {}
    assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "mcpprobe"


def _first_body() -> str:
    from tests.conftest import LAST_EVIDENCE

    return next(r.request_body for r in LAST_EVIDENCE if r.method == "server/discover")


# ----------------------------------------------------------------------------- TRANS-06
async def test_trans06_pre_release_discover_shape(make_server):
    async with make_server(**MODERN, discover_legacy_shape=True) as srv:
        report = await run(srv.url, only=["TRANS-06", "TRANS-07"])
    [f] = by_id(report, "TRANS-06")
    assert f.severity == Severity.LOW
    assert any("protocolVersions" in p for p in f.details["problems"])
    assert any("resultType" in p for p in f.details["problems"])
    assert '"protocolVersions"' in f.proof
    st = status_of(report, "TRANS-07")
    assert st.status.value == "not_applicable" and st.related_to == "TRANS-06"


async def test_trans06_stdio_stateless():
    report = await run(stdio_command("--stateless"), stdio=True, only=["TRANS-06", "TRANS-09"])
    assert status_of(report, "TRANS-06").passed and status_of(report, "TRANS-09").passed


# ----------------------------------------------------------------------------- TRANS-07
async def test_trans07_unadvertised_version_accepted(make_server):
    async with make_server(**MODERN, accept_unadvertised=True) as srv:
        report = await run(srv.url, only=["TRANS-07"])
    [f] = by_id(report, "TRANS-07")
    assert f.severity == Severity.LOW and f.details["declared"] == "2025-11-25"
    assert "mcp-protocol-version: 2025-11-25" in f.proof
    assert "expect HTTP 400 with error code -32022" in f.verify


async def test_trans07_not_applicable_when_everything_is_advertised(make_server):
    versions = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]
    async with make_server(**MODERN, supported_2026=versions) as srv:
        report = await run(srv.url, only=["TRANS-07"])
    st = status_of(report, "TRANS-07")
    assert st.status.value == "not_applicable" and "every earlier revision" in (st.reason or "")


# ----------------------------------------------------------------------------- TRANS-08
async def test_trans08_header_mismatch_processed(make_server):
    async with make_server(**MODERN, validate_mcp_headers=False) as srv:
        report = await run(srv.url, only=["TRANS-08"])
    [f] = by_id(report, "TRANS-08")
    assert f.severity == Severity.MEDIUM and len(f.affected) == 2
    assert "mcp-method: tools/list" in f.proof and "mcp-method: (not sent)" in f.proof
    assert "-32020" in f.verify


async def test_trans08_blocked_by_auth(make_server):
    async with make_server(**MODERN, require_auth=True) as srv:
        report = await run(srv.url, only=["TRANS-08"])
    st = status_of(report, "TRANS-08")
    assert st.status.value == "not_applicable" and st.blocked is True


# ----------------------------------------------------------------------------- TRANS-09
async def test_trans09_missing_caching_hints(make_server):
    async with make_server(**MODERN, cache_hints=False) as srv:
        report = await run(srv.url, only=["TRANS-09"])
    [f] = by_id(report, "TRANS-09")
    assert set(f.affected) >= {"server/discover", "tools/list"}
    assert f.details["problems"]["tools/list"] == ["ttlMs missing", "cacheScope missing"]
    assert "ttlMs: (absent)" in f.proof


# ----------------------------------------------------------------------------- AUTH-05 / AUTH-06
AUTHED = {**MODERN, "require_auth": True}


async def test_auth05_06_pass_on_conformant_authorization_server(make_server):
    async with make_server(**AUTHED) as srv:
        report = await run(srv.url, only=["AUTH-02", "AUTH-03", "AUTH-05", "AUTH-06"], headers=AUTH)
    assert all(status_of(report, c).passed for c in ("AUTH-02", "AUTH-03", "AUTH-05", "AUTH-06"))


async def test_auth05_iss_not_advertised(make_server):
    async with make_server(**AUTHED, as_iss_supported=False) as srv:
        report = await run(srv.url, only=["AUTH-02", "AUTH-03", "AUTH-05"], headers=AUTH)
    [f] = by_id(report, "AUTH-05")
    assert (
        f.severity == Severity.LOW and "authorization_response_iss_parameter_supported: (absent)" in f.proof
    )
    assert f.verify.endswith("# expect true")


async def test_auth06_dcr_without_cimd_is_low(make_server):
    async with make_server(**AUTHED, as_registration_endpoint=True, as_cimd=False) as srv:
        report = await run(srv.url, only=["AUTH-02", "AUTH-03", "AUTH-06"], headers=AUTH)
    [f] = by_id(report, "AUTH-06")
    assert f.severity == Severity.LOW and "registration_endpoint:" in f.proof


async def test_auth06_dcr_alongside_cimd_is_info(make_server):
    async with make_server(**AUTHED, as_registration_endpoint=True) as srv:
        report = await run(srv.url, only=["AUTH-02", "AUTH-03", "AUTH-06"], headers=AUTH)
    [f] = by_id(report, "AUTH-06")
    assert f.severity == Severity.INFO


async def test_auth05_needs_auth03(make_server):
    async with make_server(**AUTHED) as srv:
        report = await run(srv.url, only=["AUTH-05"], headers=AUTH)
    st = status_of(report, "AUTH-05")
    assert st.status.value == "not_applicable" and st.related_to == "AUTH-03"


# ----------------------------------------------------------------------------- rate limiting
def test_retry_after_parsing():
    assert retry_after_seconds(None) == 1.0
    assert retry_after_seconds("7") == 7.0
    assert retry_after_seconds("soon") == 1.0
    now = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)
    assert retry_after_seconds("Fri, 30 Oct 2026 12:00:05 GMT", now=now) == 5.0
    assert retry_after_seconds("Fri, 30 Oct 2026 11:00:00 GMT", now=now) == 0.0


async def test_429_is_waited_out_within_the_budget(make_server):
    async with make_server(rate_limit=True, rate_limit_per_sec=2, session_mode="none") as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            statuses = [(await t.rpc("ping", {})).status for _ in range(4)]
    assert statuses == [200, 200, 200, 200]
    assert 0 < t.throttle_waited <= t.throttle_budget and t.throttle_exhausted == 0
    assert any("retry 1 after HTTP 429" in (r.note or "") for r in t.evidence.records)


async def test_429_budget_exhausted_returns_the_429(make_server):
    async with make_server(rate_limit=True, rate_limit_per_sec=1, session_mode="none") as srv:
        async with HttpTransport(srv.url, limiter=RateLimiter(1000)) as t:
            t.throttle_budget = 0.0
            statuses = [(await t.rpc("ping", {})).status for _ in range(3)]
    assert 429 in statuses and t.throttle_exhausted >= 1 and t.throttle_waited == 0
    assert any("not retried" in (r.note or "") for r in t.evidence.records)


async def test_throttled_check_is_not_applicable_not_a_finding(make_server):
    # verbose_errors would give ERR-01 a finding; the 429s must stop it from reporting anything.
    async with make_server(
        rate_limit=True, rate_limit_per_sec=2, session_mode="none", verbose_errors=True
    ) as srv:
        report = await run(srv.url, only=["ERR-01"], max_rate_limit_wait=0)
    st = status_of(report, "ERR-01")
    assert st.status.value == "not_applicable" and st.blocked is True
    assert "HTTP 429" in (st.reason or "") and "Retry-After" in (st.reason or "")
    assert by_id(report, "ERR-01") == []


async def test_throttled_check_recovers_with_budget(make_server):
    async with make_server(
        rate_limit=True, rate_limit_per_sec=2, session_mode="none", verbose_errors=True
    ) as srv:
        report = await run(srv.url, only=["ERR-01"], max_rate_limit_wait=30)
    assert status_of(report, "ERR-01").status.value == "ran"
    assert by_id(report, "ERR-01")


async def test_dos01_still_sees_429_with_retry_enabled(make_server):
    async with make_server(rate_limit=True, rate_limit_per_sec=3) as srv:
        report = await run(srv.url, only=["DOS-01"], max_rate_limit_wait=30)
    assert by_id(report, "DOS-01") == []
    assert any("rate limiting observed" in n for n in report.notes)


# ----------------------------------------------------------------------------- readiness / schema
async def test_readiness_only_from_checks_that_ran(make_server):
    async with make_server(tools=TRIFECTA_TOOLS) as srv:
        report = await run(srv.url, only=["META-06"])
    items = {r.requirement.split(":")[0]: r for r in report.readiness}
    assert items["5E"].status.value == "met"
    assert items["2G"].status.value == "not_assessable" and "META-01 was not run" in items["2G"].note
    assert items["5D"].status.value == "not_assessable"


async def test_report_schema_03_fields(make_server):
    async with make_server(**MODERN) as srv:
        report = await run(srv.url, only=["META-06"])
    data = report_to_dict(report)
    assert data["schema_version"] == "0.3"
    assert data["fingerprint"]["supported_versions"] == ["2026-07-28"]
    assert "discover_result" not in data["fingerprint"]
    assert {"directory", "requirement", "source_url", "status", "check_ids", "note"} == set(
        data["readiness"][0]
    )
    assert all("blocked" in c for c in data["checks"])


@pytest.mark.parametrize(
    "cid", ["META-06", "META-07", "TRANS-06", "TRANS-07", "TRANS-08", "TRANS-09", "AUTH-05", "AUTH-06"]
)
def test_new_checks_are_registered_passive(cid):
    from mcpprobe.checks import get_check
    from mcpprobe.models import CheckMode

    assert get_check(cid).mode == CheckMode.PASSIVE
