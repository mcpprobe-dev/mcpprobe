# mcpprobe JSON report, schema 0.3

`mcpprobe <target> --json FILE` writes one JSON document. Fields marked *(0.2)* or
*(0.3)* are new in that schema version; readers should treat them as optional so older
reports still load. Schema 0.3 (mcpprobe 0.3.0) only adds fields; nothing was renamed
or removed.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` *(0.2)* | `"0.3"` | Version of this schema (`"0.2"` in 0.2.x reports). |
| `scanner`, `version` | string | `mcpprobe` and the scanner version. |
| `target` | string | URL or stdio command that was scanned. |
| `target_kind` *(0.2)* | `"mcp"` \| `"not_mcp"` \| `"unreachable"` | Checks only run against `mcp`. For the other two, every check is `not_applicable` with the observation as its reason, nothing counts as passed, and the CLI exits 3 (`not_mcp`) or 2 (`unreachable`). |
| `mode` | `"passive"` \| `"active"` | |
| `started_at`, `finished_at` | ISO 8601 | |
| `fingerprint` | object | Negotiated revision, `flavour`, `auth_required`, `www_authenticate`, `session_id_seen`, `credentials_supplied` *(0.2)*, `supported_versions` *(0.3, the `supportedVersions` list of a 2026-07-28 `server/discover` result, otherwise empty)*, `attempts`, `error` (for `not_mcp`: `Not an MCP server: <what was observed>`; for a target that rate-limited negotiation, `target_kind` is `unreachable` and the error starts `Target unreachable: rate limited (HTTP 429)`). |
| `environment` *(0.2)* | `{edge, public, signals}` | `edge` is `aws-api-gateway`, `aws-cloudfront`, `cloudflare`, `vercel` or `null`, detected from response headers (`signals`). `public` is false for loopback/private hosts and stdio. Used to tailor fix text only. |
| `inventory_summary` | `{tools, prompts, resources}` | |
| `checks` | array | One entry per check, see below. |
| `findings` | array | Sorted by severity. |
| `chains` *(0.2)* | array | Attack chains, see below. |
| `readiness` *(0.3)* | array | Directory listing readiness, see below. Always present (for `not_mcp`/`unreachable` every item is `not_assessable`). |
| `attestations` | array | Governance items a scan cannot assess. |
| `notes` | array of string | |
| `summary` | object | `counts` per severity, `max_severity`, `target_kind`, `checks_passed`, `checks_with_findings`, `checks_not_applicable`, `checks_applicable`, `checks_ran`, `checks_skipped`, `checks_not_implemented`, `checks_error`. |
| `evidence` | array | Every request/response pair. |

## `checks[]`

`check_id`, `title`, `mode`, `status`, `reason`, `related_to` *(0.2)*, `blocked` *(0.3)*, `findings`, `duration_ms`.

`status` is `ran`, `skipped`, `not_implemented`, `error` or `not_applicable` *(0.2)*.
A check **passed** only when `status` is `ran` and it has no findings.
`not_applicable` means the check's preconditions are absent (for example no token
validation exists to test because the server needs no authentication); `reason` is
one sentence and `related_to` names the check whose finding causes it (e.g.
`AUTH-01`). `not_applicable` never counts as a pass.

`blocked` *(0.3)* is meaningful only for `not_applicable`: `true` when the behaviour
exists but could not be observed (authentication without supplied credentials, HTTP 429
after the waiting budget was used up, an authorization server the operator chose not to
contact), `false` when the precondition is genuinely absent (no sessions on a stateless
server, a rule from a protocol revision the server does not speak, no baseline yet).
A check whose requests were rate limited beyond the budget is reported
`not_applicable` with `blocked: true` and a reason starting "The server answered HTTP
429", and its findings are withheld (a scan note says how many).

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

## `readiness[]` *(0.3)*

`{directory, requirement, source_url, status, check_ids, note}`

| Field | Meaning |
|---|---|
| `directory` | `"anthropic"`, `"openai"` or `"hubspot"`. |
| `requirement` | The listing requirement, prefixed with the policy's section where it has one (e.g. `5E: ...`). |
| `source_url` | The public page the requirement comes from. |
| `status` | `"met"`, `"not_met"` or `"not_assessable"`. |
| `check_ids` | Checks the status is derived from (for the HubSpot critical/high item: the checks with such findings, the checks that ran, or the checks that could not observe the server). |
| `note` | One or two sentences: why, and what is affected. |

Derived only from checks that ran in this scan; no extra request is made. A check that
was not run, not applicable, rate limited or errored makes the item `not_assessable`,
never `met`. Items in 0.3.0:

| Directory | Requirement | Derived from |
|---|---|---|
| anthropic | 5D OAuth 2.0 for remote servers that require authentication | AUTH-01 finding: not met (with a note that 5D covers servers that need authentication); AUTH-02 or AUTH-03 finding: not met; all three passed: met; stdio: not assessable |
| anthropic | 5E all applicable tool annotations (readOnlyHint, destructiveHint, title) | META-06 |
| anthropic | 2G no hidden, obfuscated or encoded instructions | META-01: a finding at medium or above is not met; only low indicators is not assessable (review them) |
| anthropic | 3F ownership of every endpoint and domain | always not assessable from the CLI (the hosted service records DNS-TXT / .well-known verification) |
| openai | accurate readOnlyHint, destructiveHint, openWorldHint | META-06 |
| hubspot | no unresolved critical or high vulnerabilities | any critical/high finding: not met; none, and no passive check blocked or errored: met; otherwise not assessable |
| hubspot | low risk of data exfiltration and tool poisoning | META-01 (as for 2G) and META-07 |
| hubspot | mcpUrl uses HTTPS | TRANS-05 plain-HTTP finding |

## `evidence[]`

`id`, `timestamp`, `transport`, `method`, `url`, `status`, `request_headers`,
`response_headers`, `request_body`, `response_body`, `request_truncated`,
`response_truncated`, `elapsed_ms`, `note`, `error`. Since 0.3 a request repeated after
HTTP 429 is a separate record whose `note` ends `(retry N after HTTP 429, waited Ns)`;
a 429 that was not retried because the waiting budget was used up has a `note` saying so.

Since 0.2 every header is kept. Values of credential-bearing headers are redacted:
`Authorization` keeps its scheme (`Bearer <redacted>`); `Cookie`, `Set-Cookie`,
`X-Api-Key` and any header whose name contains `token`, `secret`, `password`,
`api-key` or `credential` become `<redacted>`. Bodies are kept up to 64 KiB, with
recognised secret patterns redacted.
