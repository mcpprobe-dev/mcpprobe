# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-27

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
