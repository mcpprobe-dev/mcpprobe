# mcpprobe

Security scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers.
It checks authentication, OAuth metadata, transport conformance, tool-description
poisoning, rug pulls, secrets in metadata, verbose errors and basic resource limits,
maps every finding to the OWASP MCP, Agentic and LLM Top 10 lists, and writes JSON,
SARIF 2.1.0 and a readable terminal summary.

It runs locally, sends no telemetry, and never calls a tool in its default mode.

> **Only scan servers you own or are explicitly authorised to test.**
> See [Ownership rule](#ownership-rule).

## 60-second quickstart

```console
$ pipx run --spec mcpprobe-scanner mcpprobe https://your-server.example/mcp
```

or install it:

```console
$ pipx install mcpprobe-scanner    # or: pip install mcpprobe-scanner; the command is `mcpprobe`
$ mcpprobe https://your-server.example/mcp --sarif mcpprobe.sarif --json mcpprobe.json
```

A local stdio server you run yourself:

```console
$ mcpprobe --stdio "npx -y @your-scope/your-mcp-server@1.2.3"
```

Passing a bearer token you own (for checks behind your auth):

```console
$ mcpprobe https://your-server.example/mcp --header "Authorization: Bearer $MCP_TEST_TOKEN"
```

The summary lists each finding with severity, check ID, confidence, OWASP mapping,
an evidence excerpt and a plain-English fix, followed by a coverage table showing
which checks ran, which were skipped and why. `mcpprobe checks` lists every check;
[CHECKS.md](CHECKS.md) documents them in full.

## What it checks

| Area | Checks | Examples |
|---|---|---|
| Authentication | AUTH-01..06 | endpoint answers without credentials; missing RFC 9728 protected-resource metadata; no PKCE S256; accepts a self-minted JWT with the wrong audience; token accepted in the query string; 2026-07-28: authorization server does not advertise RFC 9207 `iss`, deprecated Dynamic Client Registration without Client ID Metadata Documents |
| Transport | TRANS-01..09 | `Origin` not validated (DNS rebinding); bogus `MCP-Protocol-Version` accepted; weak or forgeable `Mcp-Session-Id`; deprecated HTTP+SSE still served; plain HTTP, weak TLS, missing headers; 2026-07-28: incomplete `server/discover` result, a version the server does not advertise accepted (downgrade), `Mcp-Method` header/body mismatch not rejected with -32020, missing or invalid `ttlMs`/`cacheScope` |
| Tool metadata | META-01..07 | instructions aimed at the model ("always call this first", "do not tell the user"), requests to send conversation, system prompt or secrets out, cross-tool shadowing, credential paths, URLs, base64, HTML comments, zero-width/bidi/homoglyph Unicode; rug-pull diff against a stored SHA-256 baseline; advertised arbitrary command execution or file access (high, critical when unauthenticated); schema hygiene; secrets in descriptions or stdio env; tool annotations missing or contradicting the tool (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, title); the "lethal trifecta" of private data, untrusted content and an outbound channel on one server |
| Robustness | ERR-01, DOS-01 | stack traces and versions in errors; one oversized argument, one 64-deep nesting probe and 20 paced `tools/list` calls, never more |
| Active (gated stubs) | INJ-01..05, SUPPLY-01/02, SANDBOX-01 | registered and reported as `not_implemented` in this release |
| Governance | GOV-01..05 | listed as attestation-only: not assessable by a scan, never marked passed |

24 passive checks (plus 8 gated active stubs and 5 attestation-only governance items);
`mcpprobe checks` lists them.

Protocol revisions: the scanner tries `server/discover` (2026-07-28) first, then
`initialize` with 2025-11-25 and 2025-06-18, then the deprecated 2024-11-05 HTTP+SSE
transport, and records which one answered. Checks for rules that only exist in
2026-07-28 are reported not applicable, with the negotiated revision as the reason,
on servers that speak an earlier one.

## Directory readiness

Every JSON report carries a `readiness` list that maps the scan onto the listing
requirements of the Anthropic, OpenAI and HubSpot MCP directories (OAuth 2.0, complete
and accurate tool annotations, no hidden instructions, no unresolved critical/high
findings, low exfiltration and poisoning risk, HTTPS). Each item is `met`, `not_met` or
`not_assessable`, cites its source and names the checks it rests on; it is derived only
from checks that actually ran, and anything a scan cannot decide (such as proof of
endpoint ownership) is `not_assessable` with the reason. See
[docs/report-schema.md](docs/report-schema.md).

## Rate limits on the target

An HTTP 429 is honoured: the request is repeated after `Retry-After` (1 s if absent),
within a total waiting budget for the whole scan (`--rate-limit-wait`, 30 s by default).
When the budget is used up, the checks whose requests were throttled are reported
not applicable instead of drawing conclusions from throttled responses. DOS-01's burst
is the exception: a 429 there is the evidence it looks for.

## Passive vs active

**Passive (default)** sends only what a normal MCP client sends (negotiation, the
`*/list` methods, well-known metadata documents) plus a handful of benign malformed
requests (bad `Origin`, bogus version header, forged session ID, self-minted
wrong-audience JWT, truncated JSON, one oversized and one deeply nested request). It
never calls a tool.

**Active** (`--active`) is for checks that call tools with non-destructive canaries.
In 0.1.0 these are stubs, but the gate is real and enforced in code. Active mode is
refused unless you pass all of:

- `--authorised-by "<who approved this, e.g. name/role/ticket>"`
- `--scope "<what is in scope>"`
- `--verify dns-txt` (HTTP targets) or `--verify local` (stdio servers you run yourself)

For `dns-txt`, generate a token and publish it:

```console
$ mcpprobe token your-server.example
Publish this DNS TXT record, then run with --active --verify dns-txt:
  _mcpprobe.your-server.example.  TXT  "mcpprobe-verification=<token>"
$ mcpprobe https://your-server.example/mcp --active --verify dns-txt \
    --authorised-by "platform security, CHG-1234" --scope "https://your-server.example/mcp" \
    --json scan.json
```

Every active run writes an authorisation record (`scan.authorisation.json` next to the
report): who authorised it, the scope, the verification proof, rate cap and excluded
tools. Use `--exclude-tool NAME` for tools that must never be called.

## Ownership rule

Scan only MCP servers you own, operate, or have explicit written permission to test.
This applies to passive mode too: even benign requests are unauthorised access if
the system is not yours. mcpprobe identifies itself on every request and honours
opt-outs (below), but those are courtesy mechanisms, not permission.

## Scanner identification, opt-out and rate limits

- User-Agent: `mcpprobe/<version> (+https://mcpprobe.tech/scanning-policy)`.
- Opt-out, checked before any MCP request and impossible to override:
  - DNS TXT `mcpprobe-opt-out=all` at `_mcpprobe.<host>` (or a parent domain), checked
    before any packet reaches the host;
  - an HTTP `200` at `/.well-known/mcpprobe-opt-out`.
- Rate: 5 requests/second by default (`--rate`), hard ceiling 10.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above `--fail-on` (default `high`) |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Error: target unreachable, bad arguments, ownership verification failed, authorisation refused, or the target opted out |
| `3` | The target answered but is not an MCP server (for example an ordinary web site); every check is reported not applicable and nothing passes |

## SARIF and GitHub code scanning

As a GitHub Action (Docker container action, no Python setup needed):

```yaml
name: MCP security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  mcpprobe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mcpprobe-dev/mcpprobe@v0.1.0
        with:
          target: https://staging.your-server.example/mcp
          fail-on: high
          sarif-output: mcpprobe.sarif
          sarif-location: src/server.py   # optional: anchor alerts to a repo file
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcpprobe.sarif
          category: mcpprobe
```

Or from any CI with the CLI:

```console
$ pipx run --spec mcpprobe-scanner mcpprobe https://staging.your-server.example/mcp --sarif mcpprobe.sarif --fail-on high
```

Results use `error` for critical/high, `warning` for medium and `note` for low/info,
with GitHub's `security-severity` on each rule and the OWASP IDs as tags. Because a
scanned endpoint is not a file, results point at the target URL unless you pass
`--sarif-location`.

## Rug-pull detection

```console
$ mcpprobe https://your-server.example/mcp --baseline .mcpprobe/baseline.json
```

The first run stores canonical SHA-256 hashes of every tool, prompt, resource and the
server instructions. Later runs report anything added, removed or changed (a changed
description after approval is the classic rug pull) and update the file; use
`--no-write-baseline` to compare without updating.

## Reports and evidence

- `--json FILE`: the full report, including every request/response pair (timestamp,
  method, status, every header, bodies up to 64 KiB). Credential headers and
  recognised secret patterns are redacted. Each finding carries a `proof` excerpt
  built from parsed data, a runnable `verify` line and, when confidence is not high,
  a `confidence_reason`. Checks whose preconditions are absent are reported
  `not_applicable` with a reason and never count as passed. The schema is documented
  in [docs/report-schema.md](docs/report-schema.md).
- `--sarif FILE`: SARIF 2.1.0.
- `-v`: descriptions and scan notes in the terminal; `-q`: no terminal output.

Server-supplied text is shown with control characters made visible and is never
interpreted as terminal markup.

## Optional classifier for META-01

```console
$ pip install 'mcpprobe-scanner[hf]'     # transformers, torch, safetensors
$ mcpprobe https://your-server.example/mcp --judge hf:/path/to/local/model
$ mcpprobe https://your-server.example/mcp --judge hf:<hub-model-id> --judge-download
```

Off by default. A local prompt-injection classifier gives META-01 a second opinion; it
adds a medium-severity indicator when it flags a description. Only `.safetensors`
weights are loaded, model code is never executed, and nothing is downloaded unless you
pass `--judge-download`. Model licences differ; read [docs/judges.md](docs/judges.md)
first. Detection numbers for the heuristics are in [docs/benchmark.md](docs/benchmark.md).

## Python API and LLM-judge hook

```python
import asyncio
from mcpprobe.checks import JudgeVerdict, ScanOptions
from mcpprobe.scanner import ScanConfig, run_scan


def judge(text: str, task: str) -> JudgeVerdict | None:
    return None  # plug in your own model here; mcpprobe makes no LLM calls


report, evidence = asyncio.run(
    run_scan(ScanConfig(target="https://your-server.example/mcp", options=ScanOptions(judge=judge)))
)
print(report.counts())
```

## Development

```console
$ pip install -e ".[dev]"
$ ruff check . && ruff format --check . && mypy && pytest
$ python -m tests.fake_server --preset vulnerable --port 8765   # deliberately vulnerable local server
$ mcpprobe http://127.0.0.1:8765/mcp
```

Security issues: see [SECURITY.md](SECURITY.md). Licence: [Apache-2.0](LICENSE) from 0.2.0 (see [NOTICE](NOTICE)); 0.1.0 was released under MIT.
