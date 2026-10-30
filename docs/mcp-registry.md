# Official MCP Registry: plan and draft

Status: **not published, and must not be published yet.** The official registry
(`registry.modelcontextprotocol.io`) lists MCP *servers*. The `mcpprobe` CLI and the
`mcpprobe-scanner` PyPI package are a scanner, not an MCP server, so there is
nothing to list today. A listing becomes possible once `https://mcpprobe.tech/mcp`
exists as a public, read-only remote MCP server. The registry requires a remote URL
to be publicly reachable, and each remote URL can belong to only one server name.

Sources (checked 2026-10-30): the registry repository's docs,
`docs/modelcontextprotocol-io/{quickstart,authentication,remote-servers}.mdx` and
`docs/reference/server-json/{generic-server-json,official-registry-requirements}.md`.
The registry is still labelled *preview*: breaking changes or data resets may occur.

## What we would publish

One remote-only server entry:

| Field | Value |
|---|---|
| `name` | `tech.mcpprobe/scanner` (reverse-DNS of `mcpprobe.tech`, proven by domain auth) |
| transport | `streamable-http` at `https://mcpprobe.tech/mcp` |
| auth | none for the three read-only tools below |
| `packages` | none (remote-only entries skip package ownership checks) |

Planned tools (all read-only, no scanning triggered from the MCP endpoint):

| Tool | Input | Returns |
|---|---|---|
| `lookup_public_status` | `host` (string, hostname only) | The public status page data mcpprobe.tech already shows for that host, if the owner made it public; otherwise "no public status". Never starts a scan. |
| `list_checks` | none | Check IDs, titles, mode, default severity and OWASP mapping (the data behind `mcpprobe checks` / CHECKS.md). |
| `explain_check` | `id` (string, e.g. `AUTH-01`) | Description, evidence type, fix and known false positives for one check. |

Each tool should carry `annotations: {"readOnlyHint": true, "openWorldHint": false}`,
`inputSchema` with `additionalProperties: false`, and the endpoint should pass
`mcpprobe` itself at `--fail-on medium` before it is listed. The tool list is not
part of `server.json`; clients read it from the server. The draft below repeats the
names in publisher metadata only as a hint.

## Draft `server.json` (DRAFT: do not publish until the endpoint exists)

Kept here rather than as a `server.json` file so that `mcp-publisher publish` cannot
pick it up by accident. It validates against the registry's current draft schema;
the description is 92 characters (limit 100).

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "tech.mcpprobe/scanner",
  "title": "mcpprobe",
  "description": "Read-only MCP security info: public scan status for a host and the mcpprobe check catalogue.",
  "websiteUrl": "https://mcpprobe.tech",
  "repository": {
    "url": "https://github.com/mcpprobe-dev/mcpprobe",
    "source": "github"
  },
  "version": "0.1.0",
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
        "tools": ["lookup_public_status", "list_checks", "explain_check"],
        "scannerVersion": "0.2.0"
      }
    }
  }
}
```

Notes on the fields:

- `version` is the version of the remote server, not the scanner. Bump it on every
  publish; a published version cannot be overwritten.
- Only the `io.modelcontextprotocol.registry/publisher-provided` key under `_meta` is
  kept by the registry (max 4 KB); anything else is dropped silently.
- `repository` points at the scanner repository. If the endpoint lives in another
  repository (for example the web app's), point it there instead.

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

## Publishing steps (when the endpoint exists)

1. Install the publisher: `brew install mcp-publisher`, or the release binary from
   `github.com/modelcontextprotocol/registry/releases/latest`. Check with
   `mcp-publisher --help`.
2. Deploy `https://mcpprobe.tech/mcp` with the three tools; scan it with mcpprobe and
   fix anything at medium or above.
3. Copy the draft above into a `server.json` in an empty working directory, set
   `version`, and run `mcp-publisher validate`.
4. Verify the namespace (Option A or B) and log in.
5. `mcp-publisher publish`.
6. Confirm the entry:
   `curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=tech.mcpprobe/scanner"`.

## What remains for the owner

- [ ] Build and deploy the read-only `https://mcpprobe.tech/mcp` endpoint (does not exist).
- [ ] Decide whether `lookup_public_status` may reveal anything for hosts whose owners
      have not opted in to a public status page (recommendation: no).
- [ ] Generate the Ed25519 key and store it in a password manager or KMS (never commit it).
- [ ] Add the apex TXT record (or the well-known file).
- [ ] Validate, log in and publish as above.
- [ ] Optional later: a stdio package entry needs an MCP server package on PyPI or npm
      with an ownership marker (`mcp-name: tech.mcpprobe/...` in the PyPI README).
      The scanner package is not an MCP server, so this does not apply to it.

## Not verified

- `registry.modelcontextprotocol.io` and `static.modelcontextprotocol.io` were not
  reachable from the build environment, so the draft was validated against the
  schema in the registry repository (`docs/reference/server-json/draft/server.schema.json`),
  not the published 2025-12-11 file, and no `mcp-publisher validate` run was possible.
