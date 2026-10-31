# mcpprobe -> official MCP registry: one-paste publish for AWS CloudShell (eu-west-2 or any region).
#
# Paste the whole block. Safe to re-run: the key is reused, the apex TXT record is only changed
# when it is missing or stale, and an already-published version is not published again.
# Prints short status lines only; the private key is never printed.
#
# Pinned: mcp-publisher v1.8.7 (sha256 from registry_1.8.7_checksums.txt), schema 2025-12-11.
# To publish a new version later: bump VERSION below (a published version can never be changed).
# Sources: https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/authentication.mdx
#          https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/quickstart.mdx
{ (
set -euo pipefail
DOMAIN="mcpprobe.tech"
NAME="tech.mcpprobe/scanner"
VERSION="1.0.0"
REMOTE="https://mcpprobe.tech/mcp"
PUB_VER="1.8.7"
PUB_SHA="00b21004149a4ce66f0782508ae4a2bce67d1bea395a8da0bd8028159fb59579"
REG="https://registry.modelcontextprotocol.io"
DIR="$HOME/mcp-registry"
BIN="$HOME/.local/bin/mcp-publisher"
LOG="$DIR/last-run.log"
say() { printf '[mcp-registry] %s\n' "$*"; }
die() { say "FAILED: $*"; [ -f "$LOG" ] && tail -n 5 "$LOG" | sed 's/^/    /'; exit 1; }

umask 077
mkdir -p "$DIR" "$(dirname "$BIN")"; chmod 700 "$DIR"; : > "$LOG"
cd "$DIR"

# 0. Preconditions: tools, AWS identity, and the endpoint must already be live (registry rule:
#    "A remote server MUST be publicly accessible"). Unauthenticated POST must give 401 (OAuth).
for t in aws curl jq openssl python3; do command -v "$t" >/dev/null || die "missing $t"; done
command -v dig >/dev/null || sudo dnf -y -q install bind-utils >>"$LOG" 2>&1 || die "dig not available"
aws sts get-caller-identity --query Account --output text >/dev/null 2>>"$LOG" || die "no AWS credentials"
code="$(curl -s -o /dev/null -w '%{http_code}' -m 15 -X POST -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"registry-preflight","version":"0"}}}' \
  "$REMOTE" || true)"
[ "$code" = "401" ] || [ "${FORCE:-0}" = "1" ] || die "$REMOTE answered $code, expected 401 (is own-mcp deployed on main?). Re-run with FORCE=1 to skip."
say "endpoint $REMOTE live (HTTP $code)"

# 1. mcp-publisher, pinned and checksum-verified.
if [ ! -x "$BIN" ] || ! "$BIN" --version 2>&1 | grep -q "mcp-publisher $PUB_VER"; then
  tmp="$(mktemp -d)"
  curl -fsSL -m 120 -o "$tmp/p.tgz" \
    "https://github.com/modelcontextprotocol/registry/releases/download/v${PUB_VER}/mcp-publisher_linux_amd64.tar.gz" || die "download"
  echo "$PUB_SHA  $tmp/p.tgz" | sha256sum -c --status || die "checksum mismatch for mcp-publisher"
  tar xzf "$tmp/p.tgz" -C "$tmp" mcp-publisher && install -m 755 "$tmp/mcp-publisher" "$BIN"; rm -rf "$tmp"
fi
say "mcp-publisher $PUB_VER ready"

# 2. Ed25519 key (reused when present). Needs OpenSSL 3 (CloudShell has it).
if [ ! -s key.pem ]; then openssl genpkey -algorithm Ed25519 -out key.pem 2>>"$LOG" || die "keygen"; say "new Ed25519 key in $DIR/key.pem"; else say "reusing $DIR/key.pem"; fi
chmod 600 key.pem
PUBLIC_KEY="$(openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64)"
PROOF="v=MCPv1; k=ed25519; p=${PUBLIC_KEY}"

# 3. Apex TXT on the public Route 53 zone. Keeps other TXT values (SPF etc.), drops stale MCPv1 ones
#    (a stale record "will be tried first and cause verification to fail").
ZONE="$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN" \
  --query "HostedZones[?Name=='${DOMAIN}.' && Config.PrivateZone==\`false\`].Id | [0]" --output text)"
ZONE="${ZONE##*/}"; [ -n "$ZONE" ] && [ "$ZONE" != "None" ] || die "no public hosted zone for $DOMAIN"
cur="$(aws route53 list-resource-record-sets --hosted-zone-id "$ZONE" \
  --query "ResourceRecordSets[?Name=='${DOMAIN}.' && Type=='TXT'] | [0]" --output json)"
want="\"${PROOF}\""
if [ "$cur" != "null" ] && jq -e --arg w "$want" '[.ResourceRecords[].Value | select(test("v=MCPv1"))] == [$w]' <<<"$cur" >/dev/null; then
  say "TXT already present on $DOMAIN (zone $ZONE)"
else
  change="$(jq -n --argjson cur "$cur" --arg w "$want" --arg n "${DOMAIN}." '
    {Comment:"mcp registry domain proof", Changes:[{Action:"UPSERT", ResourceRecordSet:{
      Name:$n, Type:"TXT", TTL:(if $cur == null then 300 else ($cur.TTL // 300) end),
      ResourceRecords:((if $cur == null then [] else [$cur.ResourceRecords[] | select(.Value | test("v=MCPv1") | not)] end) + [{Value:$w}])}}]}')"
  cid="$(aws route53 change-resource-record-sets --hosted-zone-id "$ZONE" --change-batch "$change" --query ChangeInfo.Id --output text 2>>"$LOG")" || die "Route 53 upsert"
  aws route53 wait resource-record-sets-changed --id "$cid" 2>>"$LOG" || die "Route 53 change not INSYNC"
  say "TXT upserted on $DOMAIN (zone $ZONE), INSYNC"
fi

# 4. Wait until public resolvers see it (max 10 min).
deadline=$(( $(date +%s) + 600 ))
until dig +short TXT "$DOMAIN" @1.1.1.1 | grep -qF "p=${PUBLIC_KEY}" && dig +short TXT "$DOMAIN" @8.8.8.8 | grep -qF "p=${PUBLIC_KEY}"; do
  [ "$(date +%s)" -lt "$deadline" ] || die "TXT not visible on 1.1.1.1 and 8.8.8.8 after 10 min"
  sleep 15
done
say "TXT resolves publicly"

# 5. Log in (exact form from the registry docs; Ed25519 is the default --algorithm).
PRIVATE_KEY="$(openssl pkey -in key.pem -noout -text | grep -A3 "priv:" | tail -n +2 | tr -d ' :\n')"
"$BIN" login dns --domain "$DOMAIN" --private-key "$PRIVATE_KEY" >>"$LOG" 2>&1 || { unset PRIVATE_KEY; die "login dns"; }
unset PRIVATE_KEY
say "logged in for namespace tech.mcpprobe/*"

# 6. server.json (validated against the 2025-12-11 schema; description 91/100 chars).
cat > server.json <<JSON
{
  "\$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "${NAME}",
  "title": "mcpprobe",
  "description": "Read-only MCP security data: check catalogue, public scan status and your own scan reports.",
  "websiteUrl": "https://mcpprobe.tech",
  "repository": {
    "url": "https://github.com/mcpprobe-dev/mcpprobe",
    "source": "github"
  },
  "version": "${VERSION}",
  "remotes": [
    {
      "type": "streamable-http",
      "url": "${REMOTE}"
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
JSON
"$BIN" validate server.json >>"$LOG" 2>&1 || die "mcp-publisher validate"
say "server.json valid"

# 7. Publish unless this exact version is already listed.
ENC="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$NAME")"
if [ "$(curl -s -o /dev/null -w '%{http_code}' "$REG/v0.1/servers/$ENC/versions/$VERSION")" = "200" ]; then
  say "$NAME $VERSION already published, skipping"
else
  "$BIN" publish server.json >>"$LOG" 2>&1 || die "publish"
  say "published $NAME $VERSION"
fi

# 8. Registry lookup.
curl -fsS "$REG/v0.1/servers/$ENC/versions/latest" | jq -c '{name:.server.name, version:.server.version, remote:.server.remotes[0].url, status:._meta["io.modelcontextprotocol.registry/official"].status, publishedAt:._meta["io.modelcontextprotocol.registry/official"].publishedAt}' \
  || die "lookup"
say "done. Search: $REG/v0.1/servers?search=$NAME"
) ; }
