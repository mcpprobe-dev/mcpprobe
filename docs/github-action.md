# GitHub Action

`mcpprobe-dev/mcpprobe` is a Docker container action. On each run GitHub builds the
image from the repository's `Dockerfile` at the ref you pin (Python 3.13 slim plus
mcpprobe from source; allow about a minute for the build) and runs `mcpprobe scan`
in passive mode. It writes SARIF 2.1.0 for GitHub code scanning, an optional JSON
report with evidence, step outputs, a job summary and one annotation that names the
outcome.

> Only scan MCP servers you own or are explicitly authorised to test.

## Copy-paste workflow

```yaml
name: MCP security
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # upload-sarif
  actions: read            # upload-sarif in private repositories

jobs:
  mcpprobe:
    runs-on: ubuntu-latest   # Docker container actions run on Linux runners only
    steps:
      - uses: actions/checkout@v4

      - name: Scan the MCP server
        id: scan
        uses: mcpprobe-dev/mcpprobe@v0.2.0
        with:
          target: https://staging.your-server.example/mcp
          fail-on: high
          sarif-output: mcpprobe.sarif
          sarif-location: src/server.py   # optional: a repo file to attach alerts to

      # Upload only when the scan ran (exit 0 or 1). Exit 2 (error) and exit 3
      # (not an MCP server) write SARIF with no results; uploading that would
      # mark every open mcpprobe alert as fixed.
      - name: Upload SARIF
        if: ${{ !cancelled() && (steps.scan.outputs.exit-code == '0' || steps.scan.outputs.exit-code == '1') }}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcpprobe.sarif
          category: mcpprobe
```

The scan step fails the job when the exit code is not 0, so the step itself is the CI
gate. The upload step still runs after a failing scan because of `!cancelled()`.

A manually triggered version with a URL input lives in
[`.github/workflows/example-scan.yml`](../.github/workflows/example-scan.yml).

## Inputs

| Input | Required | Default | Meaning |
|---|---|---|---|
| `target` | yes | | MCP endpoint URL (Streamable HTTP), for example `https://staging.example.com/mcp`. |
| `fail-on` | no | `high` | Fail the step when any finding is at or above this severity: `info`, `low`, `medium`, `high`, `critical`. |
| `rate` | no | `5` | Maximum requests per second, 0.1 to 10 (10 is a hard ceiling). |
| `sarif-output` | no | `mcpprobe.sarif` | Where to write SARIF 2.1.0, relative to the workspace. |
| `sarif-location` | no | target URL | Repository file to anchor results to. Without it, results point at the endpoint URL, which code scanning shows without a file link. |
| `json-output` | no | | Path for the full JSON report, including every request/response pair (credential headers redacted). Schema: [report-schema.md](report-schema.md). |
| `baseline` | no | | META-02 baseline file for rug-pull detection. Commit it, or cache it between runs, so later runs can compare. |
| `headers` | no | | Extra HTTP headers, one `Name: value` per line. Pass tokens from secrets: `headers: "Authorization: Bearer ${{ secrets.MCP_TEST_TOKEN }}"`. |
| `extra-args` | no | | More `mcpprobe scan` arguments, shell-split, for example `--skip DOS-01 -v`. |

## Outputs

| Output | Meaning |
|---|---|
| `exit-code` | `0`, `1`, `2` or `3` (table below). Available in v0.2.0. |
| `sarif-file` | Path of the SARIF file. Available in v0.2.0. |
| `result` | `clean`, `findings`, `error` or `not-mcp`. Added after v0.2.0 (`launch-prep`); use `exit-code` when pinning v0.2.0. |

## Exit codes

| Code | `result` | Meaning | What to do |
|---|---|---|---|
| `0` | `clean` | No finding at or above `fail-on`. Lower findings are still in the SARIF. | Upload SARIF. |
| `1` | `findings` | At least one finding at or above `fail-on`. | Upload SARIF; fix or triage the alerts. |
| `2` | `error` | Target unreachable, bad input, the target opted out, or authorisation refused. | Read the step log. Do not upload. |
| `3` | `not-mcp` | The URL answered, but not as an MCP server (for example an HTML page or the wrong path). Nothing was checked and nothing passed. | Fix the URL or the deployment. Do not upload. |

After v0.2.0 the Action also writes one annotation per run (`mcpprobe: findings`,
`mcpprobe: not an MCP server`, `mcpprobe: scan error`, or a `mcpprobe: passed` notice)
and a job summary with the outcome and a severity table. With v0.2.0, exit 3 shows in
the log as `Not an MCP server: ...`, followed by the Docker step failing with exit
code 3; the example workflow's last step turns that into an explicit error.

## What code scanning shows

Every check is a SARIF rule with a short and full description, help text (fix and
known false positives, in text and Markdown), a `helpUri`, `security-severity`
(critical 9.5, high 7.5, medium 5.0, low 2.5, info 0.5), and tags: `security`, `mcp`,
the mode, and the OWASP MCP Top 10, Agentic (ASI) and LLM Top 10 IDs. Levels are
`error` for critical and high, `warning` for medium, `note` for low and info. Each
result carries a stable `partialFingerprints` key (check ID + target), so alerts stay
the same across runs. Checks that were not applicable or skipped appear as tool
notifications on the analysis, never as passes.

## Limits and gotchas

- **Reachability.** The container runs on the runner's Docker network, so
  `127.0.0.1` inside it is not the runner. To scan a server started earlier in the
  same job, use the CLI instead of the Action:
  `pipx run --spec mcpprobe-scanner==0.2.0 mcpprobe http://127.0.0.1:8000/mcp --sarif mcpprobe.sarif`.
  For a remote target, it must be reachable from GitHub-hosted runners.
- **Private repositories** need GitHub Code Security (Advanced Security) for code
  scanning uploads. Without it, keep the scan step as the gate and save
  `json-output` with `actions/upload-artifact`.
- **Pull requests from forks** get a read-only token, so `upload-sarif` cannot write
  alerts there. Scanning a staging server from fork PRs is rarely wanted anyway; use
  `push` or `workflow_dispatch`.
- **`codeql-action` v3 vs v4.** GitHub has released `github/codeql-action` v4 and
  plans to deprecate v3; `upload-sarif@v4` takes the same inputs. Switch when your
  organisation does.
- **Active mode** (`extra-args: --active ...`) also needs `--authorised-by`,
  `--scope` and `--verify dns-txt`; see the README. In 0.2.0 the active checks are
  stubs.
- **Pin a version.** Use `@v0.2.0` (or a full commit SHA), not `@main`.
