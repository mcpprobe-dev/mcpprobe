from __future__ import annotations

from mcpprobe.models import Confidence, Severity
from tests.conftest import by_id, run, status_of
from tests.fake_server import POISONED_TOOLS


async def test_auth01_no_auth_flags(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["AUTH-01"])
    f = by_id(report, "AUTH-01")
    assert len(f) == 1
    # loopback + benign tools -> medium
    assert f[0].severity == Severity.MEDIUM
    assert f[0].confidence == Confidence.HIGH
    assert f[0].evidence and f[0].evidence[0].method == "tools/list"
    assert f[0].details["local"] is True


async def test_auth01_dangerous_tools_raise_severity(make_server):
    async with make_server(tools=POISONED_TOOLS) as srv:
        report = await run(srv.url, only=["AUTH-01"])
    f = by_id(report, "AUTH-01")[0]
    assert f.severity == Severity.HIGH
    assert "run_command" in f.details["dangerous_tools"]


async def test_auth01_silent_when_auth_required(make_server):
    async with make_server(require_auth=True) as srv:
        report = await run(srv.url, only=["AUTH-01"])
    assert by_id(report, "AUTH-01") == []
    assert report.fingerprint.auth_required


async def test_auth02_missing_prm(make_server):
    async with make_server(require_auth=True, serve_prm=False, advertise_prm_in_401=False) as srv:
        report = await run(srv.url, only=["AUTH-02"])
    f = by_id(report, "AUTH-02")
    assert len(f) == 1
    assert f[0].severity == Severity.HIGH
    assert len(f[0].evidence) >= 2  # path-aware and root well-known attempts


async def test_auth02_invalid_prm(make_server):
    async with make_server(require_auth=True, prm_invalid=True) as srv:
        report = await run(srv.url, only=["AUTH-02"])
    f = by_id(report, "AUTH-02")
    assert any("authorization_servers" in x.description for x in f)


async def test_auth02_no_hint_in_401_is_low(make_server):
    async with make_server(require_auth=True, advertise_prm_in_401=False) as srv:
        report = await run(srv.url, only=["AUTH-02"])
    f = by_id(report, "AUTH-02")
    assert len(f) == 1
    assert f[0].severity == Severity.LOW


async def test_auth02_conformant_is_clean(make_server):
    async with make_server(require_auth=True) as srv:
        report = await run(srv.url, only=["AUTH-02", "AUTH-03"])
    assert by_id(report, "AUTH-02") == []
    assert by_id(report, "AUTH-03") == []


async def test_auth03_pkce_missing_and_http_endpoints(make_server):
    async with make_server(require_auth=True, pkce_s256=False, as_https_only=False) as srv:
        report = await run(srv.url, only=["AUTH-02", "AUTH-03"])
    f = by_id(report, "AUTH-03")
    titles = {x.title for x in f}
    assert "PKCE S256 not advertised by authorization server" in titles
    assert "Authorization server advertises plain-HTTP endpoints" in titles
    assert all(x.severity == Severity.HIGH for x in f)


async def test_auth03_metadata_missing(make_server):
    async with make_server(require_auth=True, serve_as_metadata=False) as srv:
        report = await run(srv.url, only=["AUTH-02", "AUTH-03"])
    f = by_id(report, "AUTH-03")
    assert len(f) == 1 and f[0].severity == Severity.MEDIUM


async def test_auth03_respects_no_follow(make_server):
    async with make_server(require_auth=True, pkce_s256=False) as srv:
        # AS is on the same host here, so --no-follow-as still fetches it.
        report = await run(srv.url, only=["AUTH-02", "AUTH-03"], follow_authorization_server=False)
    assert by_id(report, "AUTH-03")


async def test_auth04_accepts_forged_jwt(make_server):
    async with make_server(require_auth=True, accept_any_bearer=True) as srv:
        report = await run(srv.url, only=["AUTH-04"])
    f = by_id(report, "AUTH-04")
    assert len(f) == 2  # HS256 and alg=none
    assert all(x.severity == Severity.CRITICAL for x in f)
    assert f[0].evidence[0].request_headers["authorization"] == "Bearer <redacted>"
    # Never a real token: claims point at scanner-controlled values.
    assert f[0].details["claims"]["aud"] == "https://not-the-target.invalid"


async def test_auth04_query_string_token(make_server):
    async with make_server(require_auth=True, accept_query_token=True) as srv:
        report = await run(srv.url, only=["AUTH-04"])
    f = by_id(report, "AUTH-04")
    assert len(f) == 1
    assert f[0].title == "Bearer token accepted via URI query string"
    assert f[0].severity == Severity.HIGH


async def test_auth04_secure_server_clean(make_server):
    async with make_server(require_auth=True) as srv:
        report = await run(srv.url, only=["AUTH-04"])
    assert by_id(report, "AUTH-04") == []
    assert status_of(report, "AUTH-04").status.value == "ran"


async def test_auth_checks_skipped_for_stdio():
    from tests.conftest import stdio_command

    report = await run(stdio_command(), stdio=True, only=["AUTH-01", "AUTH-02", "AUTH-04"])
    for cid in ("AUTH-01", "AUTH-02", "AUTH-04"):
        assert status_of(report, cid).status.value == "skipped"
