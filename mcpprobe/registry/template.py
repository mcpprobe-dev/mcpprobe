"""Default Markdown template for the registry report (``{{placeholder}}`` syntax).

Pass ``--template FILE`` to ``registry-report render`` to use your own; unknown
placeholders are an error so a typo cannot silently drop a section.
"""

from __future__ import annotations

DEFAULT_TEMPLATE = """\
# State of MCP server security: remote endpoints in the official MCP Registry

Generated {{generated_at}} with mcpprobe {{scanner_version}}. Every figure below is an
aggregate. No server, host or publisher is named, except servers that are ours.

## Summary

{{chart_headline}}

{{headline_table}}

The 95% intervals are Wilson score intervals. They treat the scanned hosts as a sample
of remote MCP endpoints in general. The registry is not a random sample of all MCP
servers (see Limitations), so read the intervals as a measure of sampling noise only,
not of selection bias.

## What we measured and how

**Population.** Every entry in the official MCP Registry list API (latest version of
each server, deleted entries dropped), fetched once at one request per second. Entries
are split into those with a remote endpoint (`remotes[]` of type `streamable-http` or
`sse`) and package-only entries. Remote URLs are deduplicated to one URL per host, with
streamable HTTP preferred over SSE.

{{funnel_table}}

**Survey profile.** Each remote host received only the requests an ordinary MCP client
sends:

- the opt-out checks;
- protocol negotiation (`server/discover`, then `initialize`);
- the `tools/list`, `prompts/list` and `resources/list` methods;
- the RFC 9728 well-known metadata document on the same origin.

The checks that ran are {{survey_checks}}. These checks read only what those requests
returned. The scanner's other passive checks send deliberately malformed or forged
requests: a foreign `Origin`, a bogus protocol version, a forged session ID, a
self-signed token, oversized or deeply nested payloads, and a request burst. Those
checks are meant for owners scanning their own servers, and they were **not** run. No
tool was called.

**Safeguards.**

- Opt-outs were honoured before anything else: the DNS TXT record
  `mcpprobe-opt-out=all` at `_mcpprobe.<host>` (or a parent domain), then
  `/.well-known/mcpprobe-opt-out`.
- Each request carried an identifying User-Agent with a link to the scanning policy.
- Traffic was capped at one request per {{per_host_interval}} s per provider domain,
  with at most {{max_concurrency}} hosts in parallel.
- The scanner sent nothing to hosts that resolve to loopback, private or reserved
  addresses. Every connection was pinned to the public address that had been checked.
- The first HTTP 429 or 403 from a provider stopped all traffic to that provider.
- Response bodies were never stored. The working data holds only each check's outcome,
  counts, the negotiated protocol revision and the detected edge provider.

**Static checks on registry metadata.** For every entry, including package-only ones,
META-01, META-06 and META-07 ran on any full tool definitions the publisher included in
the registry entry. Entries without them are counted as not assessable.

{{static_table}}

## Protocol revisions, negotiation style and edge providers

Categories seen on fewer than {{min_cell}} hosts are merged into "other".

{{chart_protocols}}

{{protocol_table}}

{{flavour_table}}

{{chart_edges}}

{{edge_table}}

## How often each check could reach a result

A check that could not observe the behaviour it tests is never counted as passed.
Examples are tool metadata behind authentication, or a 2026-07-28 rule on a server that
speaks an earlier revision. Such checks are reported here as not applicable or blocked
and left out of the rates above.

{{na_table}}

## Accuracy of the detectors

The META-01 heuristics were measured on the project's labelled corpus and a held-out
set (docs/benchmark.md). The survey profile was also run against the project's known-good
and known-bad reference fixtures:

{{accuracy_section}}

## Limitations

- **Selection.** The registry lists servers whose publishers chose to register. Most
  MCP servers run locally over stdio or privately and never appear. Remote entries
  probably over-represent public, vendor-run endpoints.
- **One URL per host.** Hosting platforms that serve many servers from one host
  contribute one observation.
- **Provider-level stopping.** Hosts are grouped into provider domains by their last two
  DNS labels. A 429 or 403 stops a whole provider, and some servers answer 403 rather than
  401 when credentials are missing. Both reduce coverage, and the excluded hosts are not
  a random subset.
- **Authentication.** For servers that require authentication, tool metadata was not
  visible. The META checks are blocked there, so the tool-level rates describe
  unauthenticated servers only.
- **Point in time.** Each host was scanned once. Servers change, and this report does not
  track them over time.
- **Heuristics.** META-01, META-06 and META-07 are keyword and pattern heuristics with the
  measured error rates above. They indicate risk; they do not prove intent.

## What passive scanning cannot see

A passive scan observes only what an anonymous client is shown. It cannot see:

- what a tool does when called;
- source code, dependencies or package malware;
- how tokens are validated beyond the absence of authentication (the forged-token probes
  were not run);
- per-user authorisation and tenant isolation;
- server-side logging, rate limits beyond what was observed, or data retention;
- the security of the client that connects.

A server that passes every check here can still be unsafe. Absence of findings is not
evidence of security.

## Disclosure policy

Findings at high or critical severity were reported privately to the operator before
publication. The order of contact was: the operator's `security.txt` or `security@`
address, then the contact listed in the registry entry or its repository, then the
registry maintainers when no operator contact could be found. Operators had 90 days to
respond and fix. This report never names a server whose finding is unfixed. Specifics
of fixed issues are named only with the operator's agreement.

{{fixed_section}}
"""
