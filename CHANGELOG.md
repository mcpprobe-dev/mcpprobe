# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0]

Directory readiness, the 2026-07-28 protocol rules, tool annotations and toxic flows.
Report schema 0.3 (additions only). 24 passive checks, up from 16.

### Added

- **META-06 Tool annotation lint.** Missing `readOnlyHint`, `openWorldHint` and title on
  every tool, `destructiveHint`/`idempotentHint` on every tool not marked read-only (the
  spec says they only mean something then), non-boolean hints, and annotations that
  contradict the tool's apparent capability (read-only or non-destructive on something
  that executes, writes, deletes, sends or pays; closed-world on a network tool). Medium
  when a dangerous-class tool is mislabelled, low when annotations are only missing;
  one finding lists every tool. Fix text cites Anthropic's directory policy (5E) and
  OpenAI's app review.
- **META-07 Toxic flow (lethal trifecta).** Warns when one server offers access to
  private data, intake of untrusted content and a way to send data out, listing the
  tools in each role. Medium; high when the endpoint needs no authentication. A tool
  advertising arbitrary command execution counts for all three roles.
- **2026-07-28 checks**, each verified against the specification text on
  modelcontextprotocol.io and not applicable (with the negotiated revision as the
  reason) on servers that speak an earlier revision:
  - TRANS-06 `server/discover` result: `supportedVersions` including 2026-07-28,
    `capabilities`, `resultType: "complete"`; missing `serverInfo` is informational.
  - TRANS-07 a protocol version the server does not list in `supportedVersions` is
    served instead of rejected with HTTP 400 / `UnsupportedProtocolVersionError`
    (-32022): downgrade acceptance. One request.
  - TRANS-08 `Mcp-Method` header that differs from the body, or is missing, is not
    rejected with HTTP 400 / `HeaderMismatch` (-32020). Two requests. `Mcp-Name` is
    not tested passively (it exists only for `tools/call`, `resources/read`,
    `prompts/get`).
  - TRANS-09 `ttlMs` (number >= 0) and `cacheScope` (`public`/`private`) missing or
    invalid on `server/discover` and list results. Sends nothing.
  - AUTH-05 authorization server metadata does not advertise
    `authorization_response_iss_parameter_supported: true` (RFC 9207). Sends nothing.
  - AUTH-06 deprecated Dynamic Client Registration offered without Client ID Metadata
    Documents (low), or alongside them (informational). Sends nothing.
  - "Deprecated HTTP+SSE still reachable" stays TRANS-04 (no new ID).
- **Directory readiness** (`readiness` in the JSON report): Anthropic 5D/5E/2G/3F,
  OpenAI annotations, HubSpot no-critical/high, exfiltration/poisoning risk and HTTPS,
  each `met` / `not_met` / `not_assessable` with source URL, check IDs and a note.
  Derived only from checks that ran; ownership (3F) is always not assessable from the CLI.
- **Rate-limit handling.** HTTP 429 is honoured with `Retry-After` (1 s when absent), at
  most 3 retries per request, within a scan-wide waiting budget (`--rate-limit-wait`,
  default 30 s). When the budget is used up, the checks that met the throttled
  responses are reported `not_applicable` (blocked) and their findings withheld,
  instead of drawing conclusions from throttled responses. DOS-01's burst still
  observes 429 directly. A target that rate-limits negotiation is reported
  `unreachable`, not "not an MCP server".
- **Optional Hugging Face judge for META-01** (`--judge hf:<model-id-or-path>`,
  `--judge-download`, `--judge-threshold`; extra `mcpprobe-scanner[hf]`). Off by
  default, safetensors only, no remote code, no download unless asked. Licence notes in
  docs/judges.md.
- `scripts/benchmark_judge.py` and docs/benchmark.md: precision, recall and false-positive
  rate of META-01 on the in-sample corpus and on a new held-out set (65% recall at medium
  or above, 0 false positives on 40 benign descriptions). The Hugging Face Hub was not
  reachable when the numbers were produced, so no public dataset or classifier was scored.
- Report schema 0.3: `checks[].blocked`, `fingerprint.supported_versions`, `readiness`.
- Fixture `trifecta` (a conformant 2026-07-28 server whose tools form the trifecta); all
  its check outcomes are pinned in CI.

### Changed

- Annotation contradictions moved from META-03 to META-06 (reported once). META-03 is
  now titled "Dangerous tool capability exposed". E-mail and payment tools count as
  writes only when a mutating verb (send, charge, refund, ...) is present, so a
  read-only `list_emails` marked `readOnlyHint: true` is no longer a contradiction.
- 2026-07-28 requests now carry the required `io.modelcontextprotocol/clientCapabilities`
  and the recommended `clientInfo` in `_meta`.
- The fingerprint reads `supportedVersions` and `_meta["io.modelcontextprotocol/serverInfo"]`
  from `server/discover` as the 2026-07-28 schema defines them (the pre-release keys are
  no longer merged into `server_info`).
- The `hardened` fixture is now dual-era (2026-07-28 and 2025-11-25) with
  spec-conformant `server/discover`, header validation, caching hints, RFC 9207 and
  CIMD metadata; it still produces zero findings.

## [0.2.0]

Accuracy release, driven by an independent review of a 0.1.0 scan of the project's own
deliberately weak demo server. 0.1.0 missed the demo's textbook tool poisoning,
reported four checks as passed that had tested nothing, and rated an unauthenticated
remote shell low. All of that is fixed and pinned by fixtures in CI.

- Licence changes from MIT to Apache-2.0 for future releases. Version 0.1.0 remains available under MIT.

### Fixed

- **META-01 missed obvious poisoning.** It now detects instructions aimed at the model
  ("always call this first", "call this tool before any other", "you must", "do not
  tell the user", "ignore previous instructions"), requests to send the model's context
  out (conversation, chat history, system prompt, previous messages), requests to
  harvest the user's secrets, and HTML comments, in tool, argument, prompt and resource
  descriptions. A directive combined with a context-exfiltration request is high. The
  demo's `run_command` description is now reported high. Several 0.1 patterns that
  fired on benign text ("Read the file at the given path", "Forward an email",
  "Silently ignores unknown fields", "Operating system: Linux", "rather than the user's
  timezone") were tightened; a corpus of 33 benign real-world descriptions must stay
  below medium in the test-suite.
- **Checks no longer report "passed" for things they did not test.** New check status
  `not_applicable` (with a one-sentence reason and an optional `related_to`), raised
  through `NotApplicable`. Every early exit was audited: AUTH-03/AUTH-04 are not
  applicable when the server needs no authentication (related to AUTH-01), TRANS-03
  when no `Mcp-Session-Id` is issued, META-* when no tool metadata could be read,
  ERR-01/DOS-01 when every probe was stopped at authentication, META-02 without a
  previous baseline, TRANS-01/TRANS-02 when a 401/429 hides the behaviour. Transport
  failures are now `error`, not a pass. Reporters count only `ran` with no findings
  as passed; SARIF lists not-applicable checks as notifications, never as passes.
- **AUTH-02 passed when the metadata was missing.** Missing RFC 9728 metadata is now a
  finding on unauthenticated servers too (medium on public hosts, low on loopback).
- **AUTH-01 misreported servers scanned with credentials.** When `--header` supplies
  credentials, one extra request is sent with them removed; a 401/403 marks the server
  protected. AUTH-04's query-string probe no longer carries the operator's own token.
- **Not an MCP server.** A target that answers but does not speak MCP (for example an
  ordinary web site) no longer aborts with a generic error or produces results: the
  report has `target_kind: "not_mcp"`, every check is not applicable with the
  observation ("Not an MCP server: initialize -> HTTP 200 text/html"), and the CLI
  exits with the new code 3. Unreachable targets get `target_kind: "unreachable"`
  (exit 2, as before).

### Changed

- **META-03 rates by capability.** Tools that advertise arbitrary command execution or
  arbitrary file read/write (a shell or file capability selected by a free-form string
  argument) are high on their own and critical on an unauthenticated public endpoint.
  The fix text says to remove or sandbox the tool with an allow-list; annotations come
  after. The description states that a passive scan sees the advertised capability, not
  whether the implementation really executes. Annotation contradictions are one finding
  listing every affected tool. Check title updated accordingly.
- **One finding per check per root cause.** META-04 emits one finding listing every
  affected tool, with each tool's complete `inputSchema` and its specific problems
  (including arguments missing from `required` and `additionalProperties` not false).
- **Evidence and proof.** Every finding has `proof` (the complete object judged, built
  from parsed data), `verify` (one runnable line, a `curl` against the real target for
  HTTP), `affected`, `evidence_ids`, and `confidence_reason` whenever confidence is not
  high (enforced). Evidence keeps every request and response header, with credential
  headers redacted, and bodies up to 64 KiB (was 4 KiB).
- **Environment-aware fix text.** The edge is detected from response headers
  (`apigw-requestid`/`x-amz-apigw-id` -> AWS API Gateway, CloudFront, Cloudflare
  `cf-ray`, Vercel `x-vercel-id`) and public vs local hosts are told apart. TRANS-05 and
  DOS-01 say where to configure TLS, headers and throttling; AUTH-01 and TRANS-01 drop
  "bind to 127.0.0.1" on public hosts. AUTH-01 shows the exact `WWW-Authenticate` header
  with the target's metadata URL and notes that authentication does not make a shell
  tool safe. TRANS-01 also probes and advises on `Origin: null` and allows requests with
  no Origin. TRANS-02 mentions version negotiation on `initialize`.
- **Attack chains.** New top-level `chains`: CHAIN-01 (unauthenticated + arbitrary
  capability, + poisoned description when META-01 fired on that tool, critical) and
  CHAIN-02 (the same on a local server that accepts foreign Origins). A chain is only
  emitted when every constituent finding is present.
- Report schema 0.2 (`schema_version`, `target_kind`, `environment`, `chains`, the new
  finding fields, `checks[].related_to`, `summary.checks_passed` /
  `checks_not_applicable`), documented in `docs/report-schema.md`.

### Tests

- Fixtures pinned in CI: an exact replica of the public demo server (`--preset demo`),
  the observable passive behaviour of a hardened reference server (`--preset
  hardened`), and an ordinary HTML site (`--preset html`). The exact outcome of every
  check against each is asserted; any change fails the suite.

## [0.1.0]

- Published on PyPI as `mcpprobe-scanner` (PyPI blocks `mcpprobe` and `mcpprobe-cli` as too similar to existing projects). The command and the Python package are both `mcpprobe`.
 - 2026-10-27

First public release of the open-source scanner core.

### Added

- MCP client for Streamable HTTP (JSON-RPC over POST, JSON or SSE responses)
  and stdio, written to send deliberately non-conformant requests.
- Protocol fingerprinting: `server/discover` (2026-07-28) first, then
  `initialize` with 2025-11-25 and 2025-06-18, then the deprecated
  2024-11-05 HTTP+SSE transport.
- Evidence log: every request/response with timestamp, method, status, a
  header subset, bodies truncated to 4 KB, `Authorization` values and known
  secret patterns redacted.
- Passive checks: AUTH-01..04, TRANS-01..05, META-01..05, ERR-01, DOS-01.
- Active checks INJ-01..05, SUPPLY-01/02 and SANDBOX-01 registered as gated
  stubs (report `not_implemented`; no payloads are sent).
- Governance items GOV-01..05 listed as attestation-only in every report.
- Authorisation gate for active mode: `--authorised-by`, `--scope` and
  ownership verification (`--verify dns-txt` via `_mcpprobe.<host>` TXT, or
  `--verify local` for stdio); an authorisation record JSON is written next to
  the report.
- Opt-out: DNS TXT `mcpprobe-opt-out=all` at `_mcpprobe.<host>` and
  `/.well-known/mcpprobe-opt-out`, both checked before any MCP request.
- Rate limiting: 5 requests/second by default, hard ceiling 10.
- Reports: JSON (with evidence), SARIF 2.1.0 (validated against the official
  schema in tests) and a rich terminal summary. Exit codes 0 / 1 / 2.
- META-02 baselines: canonical SHA-256 of tools, prompts, resources and
  instructions with diffing against a stored baseline (rug-pull detection).
- Optional LLM-judge hook for META-01 (`ScanOptions.judge`); mcpprobe makes no
  LLM or third-party network calls itself.
- Docker container GitHub Action, CI (ruff, strict mypy, pytest on Python
  3.11 to 3.13) and PyPI Trusted Publishing release workflow.

[0.1.0]: https://github.com/mcpprobe-dev/mcpprobe/releases/tag/v0.1.0
