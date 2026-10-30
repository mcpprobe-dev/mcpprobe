"""Where does the target run? Edge/platform detection from response headers.

Used only to tailor fix text (for example: behind AWS API Gateway, TLS policy
and throttling are configured on the gateway, not in application code). The
detection is a hint, never a finding.
"""

from __future__ import annotations

from collections.abc import Iterable

from mcpprobe.models import Environment, EvidenceRecord

#: (edge, header name, optional value substring) in priority order.
_SIGNATURES: tuple[tuple[str, str, str | None], ...] = (
    ("aws-api-gateway", "apigw-requestid", None),
    ("aws-api-gateway", "x-amz-apigw-id", None),
    ("aws-cloudfront", "x-amz-cf-id", None),
    ("aws-cloudfront", "via", "cloudfront"),
    ("cloudflare", "cf-ray", None),
    ("vercel", "x-vercel-id", None),
)

EDGE_LABELS: dict[str, str] = {
    "aws-api-gateway": "AWS API Gateway",
    "aws-cloudfront": "Amazon CloudFront",
    "cloudflare": "Cloudflare",
    "vercel": "Vercel",
}


def detect_environment(target: str, records: Iterable[EvidenceRecord], *, transport: str) -> Environment:
    """Classify the target as public/local and identify a known edge from response headers."""
    from mcpprobe.checks._util import host_of, is_local_or_private  # avoid an import cycle

    if transport != "http":
        return Environment(edge=None, public=False)
    public = not is_local_or_private(host_of(target))
    headers: dict[str, str] = {}
    for rec in records:
        if rec.transport == "http":
            for k, v in rec.response_headers.items():
                headers.setdefault(k.lower(), v)
    for edge, name, needle in _SIGNATURES:
        value = headers.get(name)
        if value is None:
            continue
        if needle is not None and needle not in value.lower():
            continue
        return Environment(edge=edge, public=public, signals=[f"{name}: {value}"])
    return Environment(edge=None, public=public)
