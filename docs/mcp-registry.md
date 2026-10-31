# Official MCP Registry: plan and draft

Status: **ready to publish once `https://mcpprobe.tech/mcp` is live on production.** The endpoint
is built in the web app (branch `own-mcp`, already on `staging`, not yet on `main`). The official
registry (`registry.modelcontextprotocol.io`) lists MCP *servers*; the registry does not probe the
URL, but its docs say "A remote server **MUST** be publicly accessible at its specified URL", and each
remote URL can belong to only one server name (`remote URL ... is already used by server ...`).

**One-paste publish:** [`registry-publish-paste.sh`](registry-publish-paste.sh), for AWS CloudShell.
It pins `mcp-publisher` v1.8.7 (sha256-checked), creates or reuses an Ed25519 key in
`~/mcp-registry/key.pem` (0600), upserts the apex TXT record in the `mcpprobe.tech` Route 53 zone
(keeping SPF and other TXT values, replacing a stale `v=MCPv1` value), waits until 1.1.1.1 and
8.8.8.8 resolve it, logs in with `mcp-publisher login dns --domain ... --private-key ...`, writes
`server.json`, validates, publishes (skipped when that version already exists) and prints the
registry lookup. It refuses to run unless an unauthenticated `POST /mcp` answers 401 (override with
`FORCE=1`). Paste it again after bumping `VERSION` to publish a new version.

Sources (checked 2026-10-31 against the registry repository at commit `01e5c93`, release v1.8.7):
`docs/modelcontextprotocol-io/{quickstart,authentication,remote-servers,versioning}.mdx`,
`docs/reference/server-json/official-registry-requirements.md`, and
`internal/validators/schemas/2025-12-11.json` (the schema the registry embeds; `CurrentSchemaVersion`
in `pkg/model/constants.go` is `2025-12-11`). The registry is still labelled *preview*.

## What we publish

One remote-only server entry:

| Field | Value |
|---|---|
| `name` | `tech.mcpprobe/scanner` (reverse-DNS of `mcpprobe.tech`, proven by DNS auth) |
| transport | `streamable-http` at `https://mcpprobe.tech/mcp` |
| auth | OAuth 2.1 (Client ID Metadata Documents, no DCR); see the web app's `docs/mcp-endpoint.md` |
| `version` | `1.0.0` = `MCP_SERVER_VERSION` in the web app's `lib/oauth/config.ts` |
| `repository` | this public scanner repo: `mcpprobe-dev/mcpprobe-web` is private, so it is not linked |
| `packages` | none (remote-only entries skip package ownership checks) |

Tools served (all read-only, `readOnlyHint: true`; clients read them from the server, the list in
`_meta` is only a hint): `list_checks`, `explain_check`, `lookup_public_status`, `list_my_targets`,
`get_latest_report`. No tool starts a scan.

## `server.json`

Validated with Python `jsonschema` (Draft 7) against the embedded 2025-12-11 schema: no errors;
description 91 characters (schema `maxLength` 100); `_meta` publisher-provided block 154 bytes
(limit 4096). Semantic rules read from `internal/validators/` (https-only, non-localhost remote URL;
https `websiteUrl`; `repository.source` required; no version ranges) are all met. The same JSON is
written by the paste script, which also runs `mcp-publisher validate` (server-side) before publishing.

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "tech.mcpprobe/scanner",
  "title": "mcpprobe",
  "description": "Read-only MCP security data: check catalogue, public scan status and your own scan reports.",
  "websiteUrl": "https://mcpprobe.tech",
  "repository": {
    "url": "https://github.com/mcpprobe-dev/mcpprobe",
    "source": "github"
  },
  "version": "1.0.0",
  "remotes": [
    {
      "type": "streamable-http",
      "url": "https://mcpprobe.tech/mcp"
    }
  ],
  "_meta": {
    "io.modelcontextprotocol.registry/publisher-provided": {
      "tech.mcpprobe": {
        "readOnly": true,
        "auth": "oauth2.1",
        "tools": ["list_checks", "explain_check", "lookup_public_status", "list_my_targets", "get_latest_report"]
      }
    }
  }
}
```

Notes on the fields:

- `version` is the version of the remote server, not the scanner. Bump it (here and in the web app)
  on every publish; "Once published, the version string (and other metadata) cannot be changed."
- Only the `io.modelcontextprotocol.registry/publisher-provided` key under `_meta` is kept (max 4 KB).
- The scanner CLI / `mcpprobe-scanner` PyPI package gets **no** entry: it is an MCP *client* (it
  connects to servers over HTTP or spawns them over stdio) and exposes no MCP server, so there is
  nothing to list. It would only qualify if a `mcpprobe mcp-server` stdio mode were added, with
  `mcp-name: tech.mcpprobe/<name>` in the PyPI README as the ownership marker.

## Namespace verification for `mcpprobe.tech`

Domain auth proves control of `mcpprobe.tech` and grants `tech.mcpprobe/*` (and
subdomain namespaces such as `tech.mcpprobe.api/*`). The registry does **not** check
that the remote URL is on the same domain, but using the domain namespace shows users
that the name and URL belong to the same publisher. Pick one method.

### Option A: DNS TXT (recommended)

Needs OpenSSL 3 (on macOS: `brew install openssl@3` and use that binary).

```bash
openssl genpkey -algorithm Ed25519 -out key.pem      # keep key.pem secret, outside the repo
PUBLIC_KEY="$(openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64)"
echo "mcpprobe.tech. IN TXT \"v=MCPv1; k=ed25519; p=${PUBLIC_KEY}\""
```

Add that TXT record at the **apex** `mcpprobe.tech` (not under `_mcp...`; a record
under a selector fails with a generic signature error). It can sit next to existing
apex TXT records such as SPF. Then:

```bash
PRIVATE_KEY="$(openssl pkey -in key.pem -noout -text | grep -A3 'priv:' | tail -n +2 | tr -d ' :\n')"
mcp-publisher login dns --domain mcpprobe.tech --private-key "${PRIVATE_KEY}"
```

When rotating keys, delete the old apex TXT record; a stale one is tried first and
makes verification fail.

### Option B: HTTP well-known file

Serve the proof at `https://mcpprobe.tech/.well-known/mcp-registry-auth` (for the
Next.js site, `public/.well-known/mcp-registry-auth`):

```bash
openssl genpkey -algorithm Ed25519 -out key.pem
PUBLIC_KEY="$(openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64)"
echo "v=MCPv1; k=ed25519; p=${PUBLIC_KEY}" > mcp-registry-auth
# deploy it, then:
PRIVATE_KEY="$(openssl pkey -in key.pem -noout -text | grep -A3 'priv:' | tail -n +2 | tr -d ' :\n')"
mcp-publisher login http --domain mcpprobe.tech --private-key "${PRIVATE_KEY}"
```

The registry fetches the file itself (from Google Cloud addresses, `User-Agent:
mcp-registry/1.0`, `Accept: text/plain`, 10 s timeout). It must answer `200` with the
proof as the body: redirects are not followed (an apex-to-www redirect breaks it),
and a WAF/bot rule, a geo-block or an unreachable `AAAA` record makes login fail with
`token exchange failed with status 401`. Test with:

```bash
curl -sS -H 'Accept: text/plain' -A 'mcp-registry/1.0' https://mcpprobe.tech/.well-known/mcp-registry-auth
```

DNS avoids all of those edge cases, which is why it is recommended.

### Alternative: GitHub namespace

`io.github.mcpprobe-dev/scanner` via GitHub auth. For an **organisation** namespace
the interactive `mcp-publisher login github` currently grants only the personal
namespace; it needs the GitHub Actions OIDC flow or a PAT with `read:org` (classic) /
Members read-only (fine-grained) from an **org owner**. The domain namespace is
simpler and matches the remote URL.

## Publishing steps

1. Merge `own-mcp` to `main`, let Amplify deploy, and confirm `POST https://mcpprobe.tech/mcp` answers 401.
2. Scan it: `mcpprobe scan https://mcpprobe.tech/mcp --fail-on low` (expect no findings).
3. Open AWS CloudShell with an identity that can change the `mcpprobe.tech` Route 53 zone and paste
   [`registry-publish-paste.sh`](registry-publish-paste.sh).
4. Copy `~/mcp-registry/key.pem` into the password manager. CloudShell home persists, but only
   while the environment is used at least every 120 days.

## What remains for the owner

- [ ] Deploy `own-mcp` to production (it is on `staging` only).
- [ ] Run the paste block; store the key; keep the apex TXT record (needed for every future login).
- [ ] Registry tokens last 5 minutes (`internal/auth/jwt.go`), so every later publish reruns the whole block.

## Not verified

- `registry.modelcontextprotocol.io` and `static.modelcontextprotocol.io` are not reachable from the
  build environment, so `mcp-publisher validate` (a server-side call) and the published copy of the
  schema were not used; validation used the schema file embedded in the registry source, whose `$id`
  is the 2025-12-11 URL above. The paste block runs `mcp-publisher validate` before publishing.
- The paste block was syntax-checked and its TXT-merge and `server.json` steps were exercised
  offline; it has not been run against Route 53 or the live registry.
- `--private-key` puts the hex key on the command line (that is the documented form); CloudShell is
  single-user, but avoid running it on shared hosts.
