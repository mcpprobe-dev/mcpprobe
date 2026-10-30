"""Edge detection, header redaction in evidence and the not-applicable plumbing."""

from __future__ import annotations

import datetime as dt

import pytest

from mcpprobe.checks import Check, NotApplicable, ScanContext
from mcpprobe.environment import detect_environment
from mcpprobe.models import CheckStatus, Confidence, EvidenceRecord, Finding, Fingerprint, Inventory
from mcpprobe.scanner import run_check
from mcpprobe.transport import EvidenceLog
from mcpprobe.transport.evidence import redact_headers


def _rec(headers: dict[str, str]) -> EvidenceRecord:
    return EvidenceRecord(
        id="ev-0001",
        timestamp=dt.datetime.now(dt.UTC),
        transport="http",
        method="tools/list",
        response_headers=headers,
    )


@pytest.mark.parametrize(
    ("headers", "edge"),
    [
        ({"apigw-requestid": "abc="}, "aws-api-gateway"),
        ({"x-amz-apigw-id": "abc="}, "aws-api-gateway"),
        ({"x-amz-cf-id": "x"}, "aws-cloudfront"),
        ({"via": "1.1 abc.cloudfront.net (CloudFront)"}, "aws-cloudfront"),
        ({"cf-ray": "8a1b2c3d4e5f-LHR"}, "cloudflare"),
        ({"x-vercel-id": "lhr1::abc"}, "vercel"),
        ({"server": "nginx"}, None),
    ],
)
def test_edge_detection(headers, edge):
    env = detect_environment("https://mcp.example.com/mcp", [_rec(headers)], transport="http")
    assert env.edge == edge and env.public is True


def test_local_and_stdio_are_not_public():
    assert detect_environment("http://127.0.0.1:8000/mcp", [], transport="http").public is False
    assert detect_environment("python server.py", [], transport="stdio").public is False


def test_evidence_keeps_all_headers_and_redacts_credentials():
    out = redact_headers(
        {
            "Authorization": "Bearer abc.def.ghi",
            "Cookie": "sid=1",
            "Set-Cookie": "sid=2",
            "X-Api-Key": "k",
            "X-Refresh-Token": "t",
            "apigw-requestid": "abc=",
            "Content-Type": "application/json",
        }
    )
    assert out["authorization"] == "Bearer <redacted>"
    assert out["cookie"] == out["set-cookie"] == out["x-api-key"] == out["x-refresh-token"] == "<redacted>"
    assert out["apigw-requestid"] == "abc=" and out["content-type"] == "application/json"


class _NA(Check):
    id = "TEST-NA"
    title = "test"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        raise NotApplicable("nothing to test here.", related_to="AUTH-01")


class _Unexplained(Check):
    id = "TEST-CONF"
    title = "test"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [self.finding(description="x", confidence=Confidence.LOW)]


def _ctx() -> ScanContext:
    from mcpprobe.transport import StdioTransport

    return ScanContext(
        target="x",
        transport=StdioTransport("true"),
        fingerprint=Fingerprint(transport="stdio"),
        inventory=Inventory(),
        evidence=EvidenceLog(),
    )


async def test_not_applicable_is_recorded_and_never_passes():
    result = await run_check(_NA(), _ctx())
    assert result.status == CheckStatus.NOT_APPLICABLE
    assert result.reason == "nothing to test here." and result.related_to == "AUTH-01"
    assert result.passed is False


async def test_low_confidence_without_reason_is_refused():
    result = await run_check(_Unexplained(), _ctx())
    assert result.status == CheckStatus.ERROR and "confidence_reason" in (result.reason or "")
