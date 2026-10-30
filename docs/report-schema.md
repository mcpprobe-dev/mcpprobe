# mcpprobe JSON report, schema 0.2

`mcpprobe <target> --json FILE` writes one JSON document. Fields marked *(0.2)* are new
in schema 0.2; readers should treat them as optional so 0.1 reports still load.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` *(0.2)* | `"0.2"` | Version of this schema. |
| `scanner`, `version` | string | `mcpprobe` and the scanner version. |
| `target` | string | URL or stdio command that was scanned. |
| `target_kind` *(0.2)* | `"mcp"` \| `"not_mcp"` \| `"unreachable"` | Checks only run against `mcp`. For the other two, every check is `not_applicable` with the observation as its reason, nothing counts as passed, and the CLI exits 3 (`not_mcp`) or 2 (`unreachable`). |
| `mode` | `"passive"` \| `"active"` | |
| `started_at`, `finished_at` | ISO 8601 | |
| `fingerprint` | object | Negotiated revision, `flavour`, `auth_required`, `www_authenticate`, `session_id_seen`, `credentials_supplied` *(0.2)*, `attempts`, `error` (for `not_mcp`: `Not an MCP server: <what was observed>`). |
| `environment` *(0.2)* | `{edge, public, signals}` | `edge` is `aws-api-gateway`, `aws-cloudfront`, `cloudflare`, `vercel` or `null`, detected from response headers (`signals`). `public` is false for loopback/private hosts and stdio. Used to tailor fix text only. |
| `inventory_summary` | `{tools, prompts, resources}` | |
| `checks` | array | One entry per check, see below. |
| `findings` | array | Sorted by severity. |
| `chains` *(0.2)* | array | Attack chains, see below. |
| `attestations` | array | Governance items a scan cannot assess. |
| `notes` | array of string | |
| `summary` | object | `counts` per severity, `max_severity`, `target_kind`, `checks_passed`, `checks_with_findings`, `checks_not_applicable`, `checks_applicable`, `checks_ran`, `checks_skipped`, `checks_not_implemented`, `checks_error`. |
| `evidence` | array | Every request/response pair. |

## `checks[]`

`check_id`, `title`, `mode`, `status`, `reason`, `related_to` *(0.2)*, `findings`, `duration_ms`.

`status` is `ran`, `skipped`, `not_implemented`, `error` or `not_applicable` *(0.2)*.
A check **passed** only when `status` is `ran` and it has no findings.
`not_applicable` means the check's preconditions are absent (for example no token
validation exists to test because the server needs no authentication); `reason` is
one sentence and `related_to` names the check whose finding causes it (e.g.
`AUTH-01`). `not_applicable` never counts as a pass.

## `findings[]`

| Field | Meaning |
|---|---|
| `id`, `title`, `severity`, `confidence`, `standards`, `description`, `fix`, `location`, `details`, `false_positive_notes` | As in 0.1. |
| `confidence_reason` *(0.2)* | One sentence; always present when `confidence` is not `high`. |
| `verify` *(0.2)* | One runnable line that confirms the fix (a `curl` for HTTP targets, using the real target URL; `$TOKEN` where credentials are needed). |
| `affected` *(0.2)* | Tools, headers or paths affected. A check emits one finding per root cause, listing every affected item. |
| `proof` *(0.2)* | Multi-line, human-readable excerpt that proves the finding: the complete object judged (a tool's full `inputSchema`, a description in full with the matched phrases, the complete response header set with missing headers marked `MISSING`, or the request/status/headers of the probe). Built from parsed data, never cut off mid-object. Render monospace. |
| `evidence_ids` *(0.2)* | IDs of the evidence records supporting the finding. |
| `evidence`, `evidence_excerpt` | As in 0.1. |

## `chains[]` *(0.2)*

`{id, title, severity, finding_ids, narrative}`. A chain is emitted only when every
constituent finding is present. `CHAIN-01`: no authentication (AUTH-01) + a tool that
advertises arbitrary command execution or file access (META-03), plus META-01 when that
tool's description is poisoned. `CHAIN-02`: the same on a local server that also accepts
foreign Origins (TRANS-01), reachable through DNS rebinding.

## `evidence[]`

`id`, `timestamp`, `transport`, `method`, `url`, `status`, `request_headers`,
`response_headers`, `request_body`, `response_body`, `request_truncated`,
`response_truncated`, `elapsed_ms`, `note`, `error`.

Since 0.2 every header is kept. Values of credential-bearing headers are redacted:
`Authorization` keeps its scheme (`Bearer <redacted>`); `Cookie`, `Set-Cookie`,
`X-Api-Key` and any header whose name contains `token`, `secret`, `password`,
`api-key` or `credential` become `<redacted>`. Bodies are kept up to 64 KiB, with
recognised secret patterns redacted.
