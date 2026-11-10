# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- After an interactive scan of a public server, the CLI prints two dim lines pointing to the
  hosted service. Text only, nothing is sent; never shown in CI, when output is piped, with
  `-q`, for local or stdio targets, or when `MCPPROBE_NO_HINT=1` is set.

## [0.3.5] - 2026-11-08

### Changed

- META-03 wording: the finding now says the handshake and tool list answer without
  authentication and that a passive scan cannot see whether `tools/call` needs a key.
  Prompted by an operator whose listing is open on purpose while every `tools/call`
  requires an API key.
- Registry survey: a host whose registry entry declares a required header (an API key)
  no longer counts as "open" for the P2 and P4 disclosure priorities.

## [0.3.4] - 2026-11-04

Two false positives reported by server owners are fixed.

### Fixed

- META-05 no longer reports published sample credentials (the AWS documentation keys
  ending in `EXAMPLE`, the Stripe and jwt.io documentation samples) or obvious
  placeholders such as `xxxxxx`, `your_api_key` or `${TOKEN}` as live secrets. A
  security tool that quotes `AKIAIOSFODNN7EXAMPLE` to explain what it detects is no
  longer flagged.
- META-03 no longer rates lookup tools as command execution or file read on wording
  alone. `get_cli_command(command)`, which returns documentation for a command, and
  `get_document(path)`, which returns a published page, are only rated when the
  description says the tool executes something or reads files. `run_command`,
  `read_file` and lookup-named tools that say they run shell commands are still
  reported.

## [0.3.3] - 2026-11-03

Findings in one report no longer share an identity. Nothing about what the checks
detect has changed.

### Fixed

- A report could contain the same finding identity more than once. A finding was
  identified by its check ID and location only, but several checks report more than one
  thing at the same location (TRANS-03 weak and forged session IDs, TRANS-05 plain HTTP
  and missing security headers, ERR-01 verbose errors and the `Server` header, META-03
  arbitrary and high-impact capabilities; also AUTH-03, AUTH-04, DOS-01, META-02, META-04
  and TRANS-04), so their SARIF results shared a `partialFingerprints` value and
  code-scanning tools could merge them. A server that
  listed the same tool twice also made META-01 and META-05 report the same finding twice,
  which counted it twice in `counts`.
- Each finding now has a `uid` (`<check id>:<location>`, plus `:<variant>` where a check
  reports more than one thing at one location) that is unique within the report and is
  used as the SARIF fingerprint. Findings reported twice with identical content are
  merged into one, keeping the evidence of both, so `counts`, `max_severity`,
  `findings_max_severity`, attack chains and SARIF results all come from the same
  de-duplicated list. `id` and SARIF `ruleId` are unchanged (still the check ID).
- AUTH-03 assesses an authorization server listed twice in the protected resource
  metadata once.

### Changed

- JSON report: findings have new `uid` and `variant` fields (schema stays 0.3; fields
  were only added). A finding without a variant keeps the SARIF fingerprint it had in
  0.3.2; findings that now have a variant get a new one, so code scanning may close the
  old alert and open a new one for them once.

## [0.3.2] - 2026-11-02

Two counting fixes. Nothing about what the checks detect has changed.

### Fixed

- Attack chains were left out of the summary counts and the pass/fail decision. A scan
  could list a CRITICAL `CHAIN-01` while the summary line said "critical 0", and
  `--fail-on critical` passed (exit 0) because no single finding was critical. The
  terminal now prints a second count line for attack chains under the findings line, for
  example `Attack chains  critical 1  high 1 ... (2 chains, built from the findings counted
  above)`. Chains are counted on their own line, not added to the findings counts, because
  each chain is made of findings that are already counted. The exit code and the
  `Result:` line now take chains into account, and the `Result:` line says whether
  findings, attack chains or both reached the threshold.
- The JSON summary has a new `chain_counts` field and a `findings_max_severity` field;
  `max_severity` is now the worst of findings and attack chains (the value the exit code
  uses). SARIF run properties have a new `chainCounts`. `counts` is unchanged: findings
  only, one per SARIF result.
- The GitHub Action's annotation and job summary mention attack chains and show them in
  their own column.
- Registry survey funnel: a remote URL listed more than once (by a second entry, or as
  both streamable-http and SSE) was dropped without being counted, so `remote_urls` minus
  the exclusions did not equal `unique_hosts` (36,687 - 9,976 = 26,711, not 26,617). These
  are now counted as `duplicate_url`, the summary has `selected_urls`, and the funnel adds
  up exactly. Re-run `reaggregate` to correct an existing `aggregates.json`.

## [0.3.1] - 2026-11-01

Fewer false tool-poisoning alarms. META-01 (tool poisoning) was flagging ordinary
documentation in real MCP servers: tool descriptions that say "call this tool first",
name a sibling tool, link to docs, or mention `~/.ssh` only to say such paths are
rejected. 0.3.1 retunes those rules. On real tool descriptions from published MCP
servers that were held out from the tuning, precision at medium or above rose from
48.0% to 96.0% (false-positive rate 2.7% to 0.1%), and the share of server packages with at
least one medium-or-above META-01 finding fell from 22.5% to 2.2% on the tuning set
and from 25.6% to 2.6% on the held-out set. Recall on the project's poisoned texts is
unchanged (77.4% at medium or above). Known-bad cases such as the demo's `run_command`
and the 0.2.0 planted-instruction example are still High. Numbers and method:
[docs/benchmark.md](docs/benchmark.md).

### Changed

- META-01 rules 0.3.1 (`RULES_VERSION`): usage guidance ("always use this tool to", "you
  must call X first", "call this first when") is no longer an indicator on its own;
  shadowing needs wording that changes what another tool does; dictionary-word tool names
  count only when quoted; plain URLs and example.com addresses are not indicators; a
  credential path is medium only after a read/send verb that is not negated; shadowing in
  server instructions is low. On 3,762 real descriptions from 128 published MCP server
  packages (`tests/data/meta01_real_benign.json`) the medium-or-above false-positive rate
  fell from 2.8% to 0.1% (22.5% to 2.2% of packages); recall on the project's poisoned set
  is unchanged at medium or above. See docs/benchmark.md.
- Registry survey disclosure queue: an open server is descriptive. A host qualifies only
  for META-05 secrets (P1), META-03 high/critical without authentication or AUTH-04 (P2),
  META-01 high from current rules (P3) or META-07 without authentication (P4).

### Added

- `registry-report recheck` (re-run survey-profile checks on hosts with visible tools, or
  `--from-queue`, under the same polite rules) and `registry-report reaggregate` (offline;
  merges scan and recheck passes, re-runs static checks, prints before/after counts).
- `disclosure-summary.json` (counts only), survey cross-tabs (capability and trifecta by
  authentication, tool-count distribution, open servers with write/exec-capable tools) in
  `aggregates.json` and the report; derived labels (`meta01_rules`, `meta01_indicators`,
  `capabilities`) in `scan.jsonl`.

- `mcpprobe registry-report fetch|scan|calibrate|aggregate|render` (also
  `python -m mcpprobe.registry`): a resumable pipeline for an anonymised "State of MCP
  server security" report over the official MCP Registry. It covers:
  - paging the list API;
  - remote and package-only selection;
  - static META-01/06/07 on the tool definitions in registry entries;
  - a passive survey-profile batch scan (opt-out first, 1 request/s per provider,
    at most 8 hosts in parallel, public addresses only with pinned connections,
    same origin only, stop on 429/403, no response bodies stored);
  - aggregates with 95% Wilson intervals;
  - a Markdown/SVG report that refuses to name third-party hosts.

  See [docs/registry-report.md](docs/registry-report.md).

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

### GitHub Action

- The Action now names its outcome: one annotation per run (`mcpprobe: findings`,
  `mcpprobe: not an MCP server`, `mcpprobe: scan error`, or a `mcpprobe: passed`
  notice), a job summary with a severity table, and a new `result` output (`clean`,
  `findings`, `error`, `not-mcp`). Exit code 3 (not an MCP server) is documented in
  the `exit-code` output. `sarif-file` is empty when no SARIF was written.
- `action.yml` description shortened to 115 characters for GitHub Marketplace.
- README and new `docs/github-action.md` pin `@v0.3.0` and upload SARIF only for exit
  codes 0 and 1: SARIF from an error or a non-MCP target has no results and would
  close every open alert. New manual-only example workflow
  `.github/workflows/example-scan.yml`.


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

[0.3.1]: https://github.com/mcpprobe-dev/mcpprobe/releases/tag/v0.3.1
[0.1.0]: https://github.com/mcpprobe-dev/mcpprobe/releases/tag/v0.1.0
