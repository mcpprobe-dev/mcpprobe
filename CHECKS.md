# mcpprobe checks catalogue

Generated from the check metadata of mcpprobe 0.3.0 (`mcpprobe checks --format markdown`). Do not edit by hand.

Standards: OWASP MCP Top 10 (IDs `MCP0x:2025`, still a beta list, so shown with `(beta)`), OWASP Top 10 for Agentic Applications (`ASI0x`), OWASP Top 10 for LLM Applications 2026 (`LLM0x:2026`, primary) and 2025 (`LLM0x:2025`, kept for one release cycle). Severities are defaults; a check can raise or lower the severity of an individual finding (for example loopback-only servers are reported one level lower), and heuristic checks never rate a finding Critical on their own.

Passive checks send only what a normal MCP client would send plus a few benign malformed requests. They never call a tool. Active checks are listed so coverage is reported honestly; in this release they are stubs that run only behind the authorisation gate and report `not_implemented`.

## Summary

| ID | Mode | Default severity | Title | Standards |
|---|---|---|---|---|
| [AUTH-01](#auth-01---remote-mcp-endpoint-accepts-requests-without-authentication) | passive | high | Remote MCP endpoint accepts requests without authentication | MCP07:2025 (beta), ASI03, LLM04:2026, LLM03:2026, LLM03:2025, LLM06:2025 |
| [AUTH-02](#auth-02---protected-resource-metadata-rfc-9728-missing-or-invalid) | passive | high | Protected resource metadata (RFC 9728) missing or invalid | MCP07:2025 (beta) |
| [AUTH-03](#auth-03---authorization-server-metadata-weak-or-missing-pkce-s256--https) | passive | high | Authorization server metadata weak or missing (PKCE S256 / HTTPS) | MCP07:2025 (beta), MCP01:2025 (beta) |
| [AUTH-04](#auth-04---server-accepts-a-self-minted-token-with-the-wrong-audienceissuer) | passive | critical | Server accepts a self-minted token with the wrong audience/issuer | MCP07:2025 (beta), MCP01:2025 (beta), ASI03 |
| [AUTH-05](#auth-05---authorization-server-does-not-advertise-rfc-9207-iss-support-2026-07-28) | passive | low | Authorization server does not advertise RFC 9207 iss support (2026-07-28) | MCP07:2025 (beta) |
| [AUTH-06](#auth-06---deprecated-dynamic-client-registration-offered-2026-07-28) | passive | low | Deprecated Dynamic Client Registration offered (2026-07-28) | MCP07:2025 (beta) |
| [TRANS-01](#trans-01---origin-header-not-validated-dns-rebinding-exposure) | passive | medium | Origin header not validated (DNS-rebinding exposure) | MCP07:2025 (beta) |
| [TRANS-02](#trans-02---unsupported-mcp-protocol-version-header-not-rejected) | passive | low | Unsupported MCP-Protocol-Version header not rejected | MCP spec conformance / hygiene (no OWASP item) |
| [TRANS-03](#trans-03---weak-predictable-or-unvalidated-mcp-session-id) | passive | high | Weak, predictable or unvalidated Mcp-Session-Id | MCP07:2025 (beta) |
| [TRANS-04](#trans-04---deprecated-httpsse-2024-11-05-transport-in-use) | passive | info | Deprecated HTTP+SSE (2024-11-05) transport in use | MCP spec conformance / hygiene (no OWASP item) |
| [TRANS-05](#trans-05---plain-http-weak-tls-or-missing-security-headers) | passive | high | Plain HTTP, weak TLS or missing security headers | MCP01:2025 (beta) |
| [TRANS-06](#trans-06---serverdiscover-result-incomplete-2026-07-28) | passive | low | server/discover result incomplete (2026-07-28) | MCP spec conformance / hygiene (no OWASP item) |
| [TRANS-07](#trans-07---protocol-version-the-server-does-not-advertise-is-accepted-downgrade) | passive | low | Protocol version the server does not advertise is accepted (downgrade) | MCP spec conformance / hygiene (no OWASP item) |
| [TRANS-08](#trans-08---mcp-method-header-not-validated-against-the-request-body-2026-07-28) | passive | medium | Mcp-Method header not validated against the request body (2026-07-28) | MCP spec conformance / hygiene (no OWASP item) |
| [TRANS-09](#trans-09---ttlms--cachescope-caching-hints-missing-or-invalid-2026-07-28) | passive | low | ttlMs / cacheScope caching hints missing or invalid (2026-07-28) | MCP spec conformance / hygiene (no OWASP item) |
| [META-01](#meta-01---possible-tool-description-poisoning) | passive | high | Possible tool-description poisoning | MCP03:2025 (beta), ASI01, ASI04, LLM01:2026, LLM01:2025 |
| [META-02](#meta-02---tool-surface-changed-since-the-stored-baseline-rug-pull-indicator) | passive | medium | Tool surface changed since the stored baseline (rug-pull indicator) | MCP03:2025 (beta), ASI04 |
| [META-03](#meta-03---dangerous-tool-capability-exposed) | passive | high | Dangerous tool capability exposed | MCP02:2025 (beta), MCP05:2025 (beta), ASI02, ASI05, LLM03:2026, LLM06:2025 |
| [META-04](#meta-04---tool-schema-hygiene-problems) | passive | low | Tool schema hygiene problems | MCP05:2025 (beta) |
| [META-05](#meta-05---secret-material-in-server-metadata-or-configuration) | passive | high | Secret material in server metadata or configuration | MCP01:2025 (beta), LLM02:2026, LLM02:2025 |
| [META-06](#meta-06---tool-annotations-missing-or-inconsistent-with-the-tool) | passive | medium | Tool annotations missing or inconsistent with the tool | MCP spec conformance / hygiene (no OWASP item) |
| [META-07](#meta-07---toxic-flow-private-data-untrusted-content-and-external-send-on-one-server) | passive | medium | Toxic flow: private data, untrusted content and external send on one server | ASI01, LLM01:2026, LLM01:2025 |
| [ERR-01](#err-01---verbose-error-responses-leak-stack-traces-paths-or-versions) | passive | medium | Verbose error responses leak stack traces, paths or versions | MCP08:2025 (beta), LLM02:2026, LLM02:2025 |
| [DOS-01](#dos-01---no-visible-limits-on-request-size-nesting-or-rate) | passive | low | No visible limits on request size, nesting or rate | ASI08, LLM06:2026, LLM10:2025 |
| [INJ-01](#inj-01---commandcode-injection-safe-canaries) | active | critical | Command/code injection (safe canaries) | MCP05:2025 (beta), ASI05, LLM10:2026 |
| [INJ-02](#inj-02---path-traversal--arbitrary-file-read) | active | high | Path traversal / arbitrary file read | MCP05:2025 (beta), ASI02 |
| [INJ-03](#inj-03---server-side-request-forgery) | active | high | Server-side request forgery | MCP05:2025 (beta), ASI02 |
| [INJ-04](#inj-04---sql-injection-safe-markers) | active | high | SQL injection (safe markers) | MCP05:2025 (beta) |
| [INJ-05](#inj-05---tool-output-returned-without-sanitisation-contextual-payload-path) | active | medium | Tool output returned without sanitisation (contextual payload path) | MCP06:2025 (beta), MCP10:2025 (beta), ASI06, LLM01:2026, LLM01:2025 |
| [SUPPLY-01](#supply-01---package-provenance-and-known-vulnerabilities-stdio) | active | medium | Package provenance and known vulnerabilities (stdio) | MCP04:2025 (beta), ASI04, LLM04:2026, LLM03:2025 |
| [SUPPLY-02](#supply-02---stdio-configuration-launches-risky-commands) | active | high | stdio configuration launches risky commands | MCP05:2025 (beta), MCP04:2025 (beta), ASI05 |
| [SANDBOX-01](#sandbox-01---unexpected-runtime-behaviour-during-listing-stdio) | active | high | Unexpected runtime behaviour during listing (stdio) | MCP04:2025 (beta), ASI10, ASI04 |
| GOV-01 | attestation | - | Audit logging and telemetry for tool invocations | MCP08:2025 (beta) |
| GOV-02 | attestation | - | Shadow MCP servers (inventory of servers in use) | MCP09:2025 (beta) |
| GOV-03 | attestation | - | Data and model poisoning in training or fine-tuning pipelines | LLM05:2026, LLM04:2025 |
| GOV-04 | attestation | - | Inter-agent communication, cascading failures, human trust, rogue agents | ASI07, ASI08, ASI09, ASI10 |
| GOV-05 | attestation | - | Memory and context poisoning persistence | ASI06 |

## Passive checks

### AUTH-01 - Remote MCP endpoint accepts requests without authentication

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http |
| Standards | MCP07:2025 (beta), ASI03, LLM04:2026, LLM03:2026, LLM03:2025, LLM06:2025 |
| Evidence | The unauthenticated request (Authorization shown as not sent) and the response. |

POSTs initialize (or server/discover) and tools/list with no Authorization header. If the server answers with a tool list, anyone who can reach the endpoint can drive its tools. When the operator supplies credentials with --header, one extra request is sent with those credentials removed, so a protected server is not misreported. Passes only when the endpoint answers 401/403 without credentials.

**False positives.** Servers protected by a network boundary (VPN, mTLS at a proxy, IP allow-list) will still be flagged because the scanner only sees what the endpoint returns. Local development servers bound to loopback are reported at reduced severity but are still exposed to DNS-rebinding and browser-based attacks (see CVE-2025-49596 class).

**Fix.** Put the endpoint behind OAuth 2.1 as described in the MCP authorization spec: return 401 with WWW-Authenticate: Bearer resource_metadata="<RFC 9728 metadata URL>", validate each token's signature, issuer, expiry and audience, and reject requests without a valid bearer token. Authentication does not make a dangerous tool safe.

### AUTH-02 - Protected resource metadata (RFC 9728) missing or invalid

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http |
| Standards | MCP07:2025 (beta) |
| Evidence | The 401 response headers and each metadata GET with its status. |

Parses WWW-Authenticate for resource_metadata (when the server answers 401), then tries /.well-known/oauth-protected-resource[/path] and the host root. The document must be JSON with a non-empty authorization_servers list. Without it, conformant clients cannot start the OAuth flow and users are pushed toward pasting long-lived static tokens. A server that requires no authentication and serves no metadata is reported too (medium, the discovery half of AUTH-01).

**False positives.** Servers that use a non-OAuth scheme (API keys at a gateway) will be flagged; the MCP spec still expects RFC 9728 metadata for HTTP transports. A deliberately public, read-only server with no authentication will also be flagged; AUTH-01 is the root cause.

**Fix.** Serve /.well-known/oauth-protected-resource (path-aware variant preferred) with 'resource' and 'authorization_servers', and include WWW-Authenticate: Bearer resource_metadata="<url>" on every 401.

### AUTH-03 - Authorization server metadata weak or missing (PKCE S256 / HTTPS)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http |
| Standards | MCP07:2025 (beta), MCP01:2025 (beta) |
| Evidence | Each metadata GET with status and body. |

For each authorization server listed in the protected resource metadata, fetches /.well-known/oauth-authorization-server (RFC 8414, path-aware) then /.well-known/openid-configuration. Flags a missing document, a code_challenge_methods_supported list without S256 (MCP clients MUST refuse to proceed), and non-HTTPS endpoints. This may make one GET to a third-party host; disable with --no-follow-as.

**False positives.** Some authorization servers support PKCE but omit code_challenge_methods_supported; per the MCP spec that is still a conformance failure for clients.

**Fix.** Publish RFC 8414 metadata with code_challenge_methods_supported including S256 and HTTPS-only endpoints. If you use a third-party identity provider, confirm it exposes the metadata document at the issuer URL you advertise.

### AUTH-04 - Server accepts a self-minted token with the wrong audience/issuer

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | critical |
| Transports | http |
| Standards | MCP07:2025 (beta), MCP01:2025 (beta), ASI03 |
| Evidence | Each probe request (token redacted) and the response status/body. |

Mints two syntactically valid JWTs the server cannot have issued (HS256 with a random scanner key, and alg=none) with a foreign issuer and audience, and presents them as Bearer tokens. Any non-401/403 answer means the server is not validating signature or audience (RFC 8707). Also presents the token in the access_token query parameter, which the spec forbids. Only self-minted tokens are used; no real credentials.

**False positives.** A proxy that strips Authorization and answers 200 for health reasons could be flagged; check the response body in the evidence actually contains an MCP result.

**Fix.** Validate the token signature against the authorization server's keys, require 'aud' to equal this server's canonical URI (RFC 8707), reject alg=none, and never read tokens from query strings.

### AUTH-05 - Authorization server does not advertise RFC 9207 iss support (2026-07-28)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http |
| Standards | MCP07:2025 (beta) |
| Evidence | The authorization server metadata document AUTH-03 fetched. |

2026-07-28 says MCP authorization servers SHOULD include the RFC 9207 'iss' parameter in authorization responses and, when they do, MUST advertise authorization_response_iss_parameter_supported: true in their metadata; clients reject a response without iss only when that flag is true. Reads the authorization server metadata AUTH-03 already fetched and reports a flag that is absent or not true. Sends nothing. The revision says this SHOULD is expected to become a MUST.

**False positives.** The spec allows a server to emit iss before it updates its metadata; such a server is reported until the flag is published, because clients key their rejection on the flag.

**Fix.** Include iss in every authorization response, error responses too (RFC 9207 section 2), and publish "authorization_response_iss_parameter_supported": true in the authorization server metadata (https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation). With a hosted identity provider, enable its issuer-identification option.

### AUTH-06 - Deprecated Dynamic Client Registration offered (2026-07-28)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http |
| Standards | MCP07:2025 (beta) |
| Evidence | The authorization server metadata document AUTH-03 fetched. |

2026-07-28 deprecates OAuth Dynamic Client Registration (RFC 7591) in favour of Client ID Metadata Documents, which authorization servers SHOULD support. Reads the authorization server metadata AUTH-03 already fetched: a registration_endpoint without client_id_metadata_document_supported: true is low (clients have only the deprecated path); a registration_endpoint next to CIMD support is informational (kept for backwards compatibility). No registration request is sent.

**False positives.** Keeping DCR for older clients is allowed; the informational finding is a reminder to plan its removal, not a defect. An authorization server that supports neither DCR nor CIMD (pre-registration only) is not reported here.

**Fix.** Support Client ID Metadata Documents and advertise "client_id_metadata_document_supported": true; keep registration_endpoint only while older clients still need it, and plan its removal (https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration). Open registration endpoints also deserve rate limits and redirect-URI validation.

### TRANS-01 - Origin header not validated (DNS-rebinding exposure)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | medium |
| Transports | http |
| Standards | MCP07:2025 (beta) |
| Evidence | Each POST with a foreign Origin header and the non-403 response. |

Sends a normal negotiation request with 'Origin: https://evil.example' and one with 'Origin: null'. The transport spec says servers MUST validate Origin and return 403 on an invalid one; otherwise a web page can drive the server through the victim's browser (DNS rebinding). Requests without an Origin header are not tested: non-browser clients do not send one.

**False positives.** If the server answers 401 (or 429) before looking at Origin the check is not applicable and says so. Reverse proxies that strip Origin will cause a finding against the proxied endpoint even if the application validates it.

**Fix.** Reject any request whose Origin header is present and not on an allow-list with HTTP 403, before processing the body, including 'Origin: null'. Allow requests with no Origin header.

### TRANS-02 - Unsupported MCP-Protocol-Version header not rejected

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http |
| Standards | MCP spec conformance / hygiene (no OWASP item) |
| Evidence | The request with the bogus version header and the response. |

Sends a request with 'MCP-Protocol-Version: 1999-01-01'. The spec requires HTTP 400 (or, on 2026-07-28, an UnsupportedProtocolVersionError). Accepting any version string suggests the server ignores version negotiation entirely.

**False positives.** Pre-2025-06-18 servers never defined the header, so an older server that ignores it is noted at low severity only. A 401/429 before the header is read makes the check not applicable.

**Fix.** Validate the MCP-Protocol-Version header against the versions you support and reply 400 when it is unknown. Separately, when initialize asks for a protocolVersion you do not support, answer with the latest version you do support and let the client decide; never echo back whatever the client asked for.

### TRANS-03 - Weak, predictable or unvalidated Mcp-Session-Id

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http |
| Standards | MCP07:2025 (beta) |
| Evidence | The initialize responses (session header) and the forged-session request. |

Collects three session IDs from repeated initialize requests and checks length, character set, Shannon entropy and sequentiality. Then sends tools/list with a random forged session ID, expecting 400 or 404. Only runs on handshake revisions that issue Mcp-Session-Id (sessions were removed in 2026-07-28).

**False positives.** Entropy is estimated from three samples, so the test is conservative: only IDs shorter than 16 characters, obviously sequential, or with very low per-character entropy are flagged.

**Fix.** Generate session IDs with a CSPRNG (at least 128 bits, e.g. UUIDv4 or 32 random bytes base64url), store them server-side, and answer 404 for unknown IDs.

### TRANS-04 - Deprecated HTTP+SSE (2024-11-05) transport in use

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | info |
| Transports | http |
| Standards | MCP spec conformance / hygiene (no OWASP item) |
| Evidence | The GET request and the first SSE event. |

Reports when the endpoint answers a GET with an SSE 'endpoint' event, i.e. the 2024-11-05 HTTP+SSE transport that was deprecated in 2025-03-26 and formally classified Deprecated in 2026-07-28. Also noted when the negotiated revision predates 2025-06-18.

**False positives.** Informational only.

**Fix.** Migrate to Streamable HTTP (single endpoint, POST per message) and current protocol revision.

### TRANS-05 - Plain HTTP, weak TLS or missing security headers

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http |
| Standards | MCP01:2025 (beta) |
| Evidence | Response headers of the negotiation/tools/list exchange and the observed TLS version. |

Flags non-loopback endpoints served over plain HTTP (bearer tokens in clear), TLS versions below 1.2 observed on the connection, and missing Strict-Transport-Security / X-Content-Type-Options headers on the MCP endpoint responses.

**False positives.** Loopback plain-HTTP is reported as informational. Header checks look at the MCP endpoint only; a CDN may add headers on other paths.

**Fix.** Serve the endpoint over HTTPS with TLS 1.2+ only, add Strict-Transport-Security and X-Content-Type-Options: nosniff. Where an edge (API Gateway, CloudFront, Cloudflare, Vercel) is detected the fix text says where to configure it.

### TRANS-06 - server/discover result incomplete (2026-07-28)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http, stdio |
| Standards | MCP spec conformance / hygiene (no OWASP item) |
| Evidence | The fingerprinting server/discover request and its complete result. |

A 2026-07-28 server MUST implement server/discover. The scanner's first request is server/discover; when it is answered, its result is checked for what the revision requires: supportedVersions (a list of version strings that includes the 2026-07-28 revision the request was served under), a capabilities object and resultType 'complete'. A missing _meta['io.modelcontextprotocol/serverInfo'] (SHOULD) is reported as informational. Caching hints on the same result are checked by TRANS-09. Not applicable to servers that speak an earlier revision through initialize.

**False positives.** A server that answers server/discover under an earlier result shape (for example a 'protocolVersions' key from a pre-release draft) is reported, because 2026-07-28 clients read 'supportedVersions'.

**Fix.** Return the DiscoverResult defined in the 2026-07-28 schema: {"resultType":"complete","supportedVersions":["2026-07-28", ...],"capabilities":{...},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":...,"version":...}},"ttlMs":...,"cacheScope":"public"} (https://modelcontextprotocol.io/specification/2026-07-28/server/discover).

### TRANS-07 - Protocol version the server does not advertise is accepted (downgrade)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http |
| Standards | MCP spec conformance / hygiene (no OWASP item) |
| Evidence | The server/discover result (supportedVersions) and the downgraded request with its response. |

Takes supportedVersions from the server/discover result and sends one more server/discover declared (in _meta and in the MCP-Protocol-Version header) as the newest earlier revision the server does not list (2025-11-25, 2025-06-18 or 2025-03-26). The spec says a server that does not implement the requested version MUST answer HTTP 400 with UnsupportedProtocolVersionError (-32022). Serving the request anyway means a client or intermediary can push the server onto a revision it claims not to support, without the header validation and other protections of 2026-07-28. One request, no tool is called.

**False positives.** A dual-era server that does serve the older revision but forgot to list it is reported too; listing it in supportedVersions is then the fix. Not applicable when every earlier revision is advertised.

**Fix.** Reject any request whose declared protocol version is not in your supportedVersions with HTTP 400 and {"code":-32022,"message":"Unsupported protocol version","data":{"supported":[...],"requested":"..."}}, before doing any work (https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning). If you do serve the older revision, list it in supportedVersions.

### TRANS-08 - Mcp-Method header not validated against the request body (2026-07-28)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | medium |
| Transports | http |
| Standards | MCP spec conformance / hygiene (no OWASP item) |
| Evidence | Both probe requests (headers shown) and their responses. |

2026-07-28 requires clients to mirror the JSON-RPC method into an Mcp-Method header, and servers that process the body MUST reject a request whose headers are missing or do not match the body with HTTP 400 and HeaderMismatch (-32020); otherwise a gateway that routes, rate-limits or authorises on the header can be bypassed by a body that says something else. Sends two server/discover requests: one with 'Mcp-Method: tools/list' and one with no Mcp-Method header. Mcp-Name is not tested, because it is only defined for tools/call, resources/read and prompts/get, which a passive scan does not send.

**False positives.** A server that rejects the probes with another 4xx is reported as informational only. When a gateway in front rejects mismatches itself, the finding concerns the server behind it only if the gateway can be bypassed.

**Fix.** Before dispatching, compare Mcp-Method (and, for tools/call, resources/read and prompts/get, the decoded Mcp-Name) with the body; when a required header is missing or differs, answer HTTP 400 with {"code":-32020,"message":"Header mismatch: ..."} (https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#server-validation).

### TRANS-09 - ttlMs / cacheScope caching hints missing or invalid (2026-07-28)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http, stdio |
| Standards | MCP spec conformance / hygiene (no OWASP item) |
| Evidence | The server/discover and list results the scan already received. |

2026-07-28 servers MUST include caching hints on complete results of server/discover, tools/list, prompts/list and resources/list (among others): ttlMs, a number of milliseconds that MUST be >= 0, and cacheScope, either 'public' or 'private'. Checks the results the scan already received; sends nothing. A missing cacheScope leaves shared gateways to guess whether a list may be served to other users.

**False positives.** Only the first page of each list is checked. A public cacheScope on an authenticated server is allowed by the spec when the list is the same for every user, so it is not reported.

**Fix.** Add "ttlMs": <milliseconds, >= 0> and "cacheScope": "public" (identical for every user) or "private" (depends on the caller's authorization) to every cacheable result (https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching).

### META-01 - Possible tool-description poisoning

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http, stdio |
| Standards | MCP03:2025 (beta), ASI01, ASI04, LLM01:2026, LLM01:2025 |
| Evidence | The tools/list (or prompts/resources/initialize) response and the matched excerpts. |

Scans every tool, prompt and resource description, every inputSchema parameter description and the server 'instructions' for: prompt-style markup (<IMPORTANT>, <system>, HTML comments), instructions aimed at the model (call this first / before any other tool, you must, conceal from the user, ignore previous instructions, redirect/replace), requests to send the model's context out (conversation, chat history, system prompt, previous messages), requests to harvest secrets (the user's API key, token, password, credentials, .env), credential file paths, references to other tools with behaviour-modifying language (shadowing), URLs and e-mail addresses with send/BCC wording, base64 blobs, zero-width/bidi/tag Unicode, mixed-script homoglyphs and excessive length. Findings carry tiered confidence and are never rated Critical on heuristics alone. A model directive combined with a request to send context out is rated high. Precision is guarded by a corpus of benign real-world descriptions in the test-suite that must stay below medium.

**False positives.** Legitimate guidance such as 'IMPORTANT: call authenticate before this tool' matches the markup and prerequisite heuristics at medium confidence. URLs to documentation and mentions of sibling tools without behaviour-modifying words are reported at low severity. Review the matched excerpts; a second-opinion judge can be plugged in through the Python API (ScanOptions.judge); mcpprobe itself makes no LLM calls.

**Fix.** Rewrite the description so it only says what the tool does. Remove every instruction addressed to the model (when to call it, what to call first, what to hide from the user) and every request to pass along conversation, prompts, files or credentials. Strip invisible Unicode and HTML comments, and never reference other servers' tools. Pin and hash approved descriptions in clients (see META-02).

### META-02 - Tool surface changed since the stored baseline (rug-pull indicator)

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | medium |
| Transports | http, stdio |
| Standards | MCP03:2025 (beta), ASI04 |
| Evidence | The current tools/list response plus per-item hashes and the diff. |

Computes SHA-256 over the canonical JSON of each tool, prompt and resource definition and the server instructions. With --baseline FILE the current snapshot is compared to the stored one and any added, removed or changed definition is reported (a changed description after approval is the classic 'rug pull'). The snapshot is then written back to the file. Also notes when the server advertises tools.listChanged.

**False positives.** Any legitimate release that edits a description will trigger the diff; the finding says what changed so the reviewer can decide. Servers that embed timestamps or random data in descriptions will change on every scan.

**Fix.** Treat tool definitions as code: version them, review changes, and have clients pin and re-approve definitions when the hash changes.

### META-03 - Dangerous tool capability exposed

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http, stdio |
| Standards | MCP02:2025 (beta), MCP05:2025 (beta), ASI02, ASI05, LLM03:2026, LLM06:2025 |
| Evidence | The tools/list response; each affected tool's complete definition is shown as proof. |

Classifies each tool by name, description and parameter names into capability classes. Tools that advertise arbitrary command execution, arbitrary file read or arbitrary file write (a shell/file capability selected by a free-form string argument with no enum, const or pattern) are rated high on their own and critical when the remote endpoint needs no authentication. The remaining high-impact surface (network, e-mail, credentials, payments) is summarised at low severity. Annotations that contradict the capability are reported by META-06 (until 0.2 they were reported here). Passive scanning sees the advertised capability, not whether the implementation really executes: the rating is based on the name, description and schema, and no tool is called.

**False positives.** Classification is keyword-based: a tool named 'delete_draft' that only removes the user's own draft will be classed 'delete'. A tool that advertises a shell but whose implementation is a stub is still reported, because clients and models act on the advertised capability.

**Fix.** For arbitrary command execution or file access: remove the tool, or sandbox it and replace the free-form argument with an allow-list (enum) of commands or files. Annotations come after that (META-06); they help a careful client warn the user but do nothing about the risk.

### META-04 - Tool schema hygiene problems

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http, stdio |
| Standards | MCP05:2025 (beta) |
| Evidence | The tools/list response; each affected tool's complete inputSchema is shown as proof. |

Checks tool names against [A-Za-z0-9_.-]{1,128} and for duplicates; checks that inputSchema is a JSON Schema object of type 'object'; flags free-form string arguments whose names suggest paths, commands, URLs or queries and that carry no enum, pattern, format or maxLength constraint. One finding lists every affected tool, with each tool's complete inputSchema and its specific problems (including arguments missing from 'required' and additionalProperties not set to false). Missing outputSchema cannot be judged without calling the tool and is not reported.

**False positives.** An unconstrained 'query' string is often unavoidable (search tools); the finding is Low severity and meant as a review prompt, not a defect.

**Fix.** Constrain every risky string argument (enum for a fixed set, pattern for a format, maxLength to bound size), list required arguments in 'required', set additionalProperties: false, and validate arguments on the server against the same schema instead of trusting the client to have done it.

### META-05 - Secret material in server metadata or configuration

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | high |
| Transports | http, stdio |
| Standards | MCP01:2025 (beta), LLM02:2026, LLM02:2025 |
| Evidence | The listing response that contained the match; values redacted. |

Pattern and entropy scan for AWS/GitHub/Slack/Stripe/Google keys, private key blocks, JWTs, bearer tokens, connection strings with passwords and generic 'key=...' assignments across tool/prompt/resource descriptions, parameter descriptions, resource URIs, server instructions and, for stdio targets, the command line and environment supplied to the scanner. Matched values are redacted in the report.

**False positives.** Example keys from vendor documentation (for instance the AWS sample key IDs ending in EXAMPLE) match the patterns. High-entropy strings are reported at Low severity and low confidence; identifiers such as content hashes trigger them. Secrets in a stdio server's environment are expected (the spec says stdio servers take credentials from the environment) and are reported as Low so the operator can confirm least privilege.

**Fix.** Remove secrets from descriptions and resources, rotate anything that was exposed, and pass credentials through the environment or a secret store, never through metadata.

### META-06 - Tool annotations missing or inconsistent with the tool

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | medium |
| Transports | http, stdio |
| Standards | MCP spec conformance / hygiene (no OWASP item) |
| Evidence | The tools/list response; each affected tool's name, title and annotations are shown as proof. |

Reads each tool's annotations from tools/list. Reported as missing: readOnlyHint, openWorldHint and a title (tool.title or annotations.title) on every tool, and destructiveHint and idempotentHint on every tool not marked readOnlyHint:true (the spec says those two are meaningful only when readOnlyHint is false). Reported as inconsistent: readOnlyHint:true on a tool that looks like it executes, writes, deletes, sends or pays; destructiveHint:false on a tool that looks like it executes, deletes or overwrites; openWorldHint:false on a tool that reaches the network; a hint that is not a boolean; and, as low-severity noise, destructiveHint:true on a tool that only appears to read. Medium when a dangerous-class tool is mislabelled, low when annotations are merely missing. One finding lists every affected tool. Anthropic's directory policy (5E) and OpenAI's app review both require accurate annotations.

**False positives.** The capability behind a contradiction is inferred from keywords in the tool's name, description and parameter names, so a narrowly scoped tool (for example 'delete_draft' that only removes the caller's own draft) may be misread. Missing annotations are a plain observation. Annotations are hints that clients must treat as untrusted; correcting them does not change what a tool can do.

**Fix.** Give every tool a title and set readOnlyHint and openWorldHint explicitly; for tools that are not read-only also set destructiveHint and idempotentHint. Make each value true to the implementation: readOnlyHint:true only when nothing is modified, destructiveHint:true for anything that executes, deletes or overwrites, openWorldHint:true for tools that reach the internet or other external systems. Anthropic's Software Directory Policy (5E, https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy) requires all applicable annotations, and OpenAI's app review (https://developers.openai.com/plugins/deploy/app-review.md) checks readOnlyHint, destructiveHint and openWorldHint for accuracy.

### META-07 - Toxic flow: private data, untrusted content and external send on one server

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | medium |
| Transports | http, stdio |
| Standards | ASI01, LLM01:2026, LLM01:2025 |
| Evidence | The tools/list response; each role lists its tools and the wording that put them there. |

Classifies every advertised tool into three roles from its capability class and wording: access to private data (files, databases, credentials, the user's mail), intake of untrusted content (fetching URLs, web search, reading mail or messages written by others) and a way to send data out (sending e-mail or messages, HTTP posts, webhooks, uploads). A tool advertising arbitrary command execution counts for all three; arbitrary file read counts as private data. When one server offers all three roles, text planted in the untrusted content can instruct the model to read the private data and send it away: the 'lethal trifecta' of prompt injection. Medium, high when the HTTP endpoint needs no authentication. One finding lists the tools in each role. No tool is called.

**False positives.** Roles are inferred from names, descriptions and capability keywords, not from behaviour. A 'fetch' tool restricted to one internal API, or a 'send' tool that only notifies the signed-in user, is still counted. Conversely a fetch tool with a free-form URL can leak data through the URL itself; that path is not counted as a send role.

**Fix.** Break the trifecta: split the tools across separate servers (or separate client configurations) so no single agent session combines private data, untrusted content and an outbound channel; or gate the send tool behind explicit per-call user confirmation and an allow-list of destinations; or constrain the intake tool to trusted sources. Keep the server authenticated so nobody else can drive the combination.

### ERR-01 - Verbose error responses leak stack traces, paths or versions

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | medium |
| Transports | http, stdio |
| Standards | MCP08:2025 (beta), LLM02:2026, LLM02:2025 |
| Evidence | Each malformed request and the error response body. |

Sends three malformed requests: truncated JSON, an unknown method and a request whose params is a string instead of an object. Error bodies and the Server header are inspected for stack traces, internal file paths and framework version strings.

**False positives.** A Server header with a version is reported as Info. Framework names without versions are not reported.

**Fix.** Return generic JSON-RPC errors (-32700/-32600/-32601/-32602) without 'data' containing exceptions, log details server-side, and strip the Server header version at the proxy.

### DOS-01 - No visible limits on request size, nesting or rate

| | |
|---|---|
| Mode | passive (implemented) |
| Default severity | low |
| Transports | http, stdio |
| Standards | ASI08, LLM06:2026, LLM10:2025 |
| Evidence | The oversized/nested requests (truncated) and timing; the burst responses' statuses. |

Three bounded probes, never more: (1) one tools/list whose 'cursor' is a 1 MB string, (2) one tools/list with params nested 64 levels deep, (3) 20 tools/list requests sent at the scan rate cap (5 req/s by default). A 5xx, a transport failure or a response slower than 5 s on (1)/(2) is reported; absence of any 429 during (3) is reported as informational. No tools are called.

**False positives.** The burst runs inside the scanner's own rate cap, so 'no 429 observed' is indicative only (low confidence) and many well-run servers legitimately allow 5 req/s. A 413 or connection reset on the oversized probe is treated as a correct defence.

**Fix.** Enforce a request body limit (e.g. 1 MB) and JSON depth limit at the edge, return 413/400 promptly, and rate-limit per client/session with 429 and Retry-After.

## Active checks (stubs)

Rules of engagement for when these are implemented: non-destructive, non-persistent canaries only; tools excluded with `--exclude-tool` or annotated `destructiveHint: true` are never called; at most one concurrent tool call; every payload is recorded as evidence; the scan stops on the first sign of an unintended side effect.

### INJ-01 - Command/code injection (safe canaries)

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | critical |
| Transports | http, stdio |
| Standards | MCP05:2025 (beta), ASI05, LLM10:2026 |
| Evidence | tools/call request with the canary and the timed response. |

ACTIVE, NOT IMPLEMENTED. Will call exec-class tools with time-based, non-destructive canaries and compare response timing. requires --active and verified ownership.

**False positives.** Network jitter can mimic a timing delta; the probe will repeat and require consistency.

**Fix.** Never pass tool arguments to a shell; use argument vectors and allow-lists.

### INJ-02 - Path traversal / arbitrary file read

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | high |
| Transports | http, stdio |
| Standards | MCP05:2025 (beta), ASI02 |
| Evidence | tools/call request with the traversal path and the response excerpt. |

ACTIVE, NOT IMPLEMENTED. Read-only traversal probes on path-typed arguments. requires --active and verified ownership.

**False positives.** Tools that intentionally expose the whole filesystem are a design decision, not a bug.

**Fix.** Canonicalise paths, resolve symlinks, and enforce a root directory check after resolution.

### INJ-03 - Server-side request forgery

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | high |
| Transports | http, stdio |
| Standards | MCP05:2025 (beta), ASI02 |
| Evidence | tools/call request with the callback URL and the callback log entry. |

ACTIVE, NOT IMPLEMENTED. Callback-based SSRF probes on URL-typed arguments. requires --active and verified ownership.

**False positives.** Fetch tools are often meant to fetch arbitrary URLs; the finding focuses on internal/metadata addresses.

**Fix.** Resolve and validate destination addresses, block link-local and private ranges, use an egress proxy.

### INJ-04 - SQL injection (safe markers)

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | high |
| Transports | http, stdio |
| Standards | MCP05:2025 (beta) |
| Evidence | tools/call requests and differential responses. |

ACTIVE, NOT IMPLEMENTED. Boolean and timing markers on query/filter arguments, plus error fingerprinting. requires --active and verified ownership.

**False positives.** Tools that accept raw SQL by design are reported as a capability (META-03), not an injection.

**Fix.** Use parameterised queries; never interpolate tool arguments into SQL.

### INJ-05 - Tool output returned without sanitisation (contextual payload path)

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | medium |
| Transports | http, stdio |
| Standards | MCP06:2025 (beta), MCP10:2025 (beta), ASI06, LLM01:2026, LLM01:2025 |
| Evidence | tools/call request and the returned content. |

ACTIVE, NOT IMPLEMENTED. Read-only tool calls against scanner-controlled canary content. requires --active and verified ownership.

**False positives.** Returning fetched content verbatim is normal; the finding documents the path for the client's risk assessment.

**Fix.** Mark tool output as untrusted data in content blocks and strip instruction-like markup where feasible.

### SUPPLY-01 - Package provenance and known vulnerabilities (stdio)

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | medium |
| Transports | stdio |
| Standards | MCP04:2025 (beta), ASI04, LLM04:2026, LLM03:2025 |
| Evidence | Registry metadata documents and OSV responses. |

ACTIVE, NOT IMPLEMENTED. Registry metadata, OSV lookup and install-script review for the stdio package. requires --active and verified ownership.

**False positives.** Unpinned versions are common in examples; severity will depend on install-script presence.

**Fix.** Pin versions, commit lockfiles, publish with provenance attestations, avoid install scripts.

### SUPPLY-02 - stdio configuration launches risky commands

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | high |
| Transports | stdio |
| Standards | MCP05:2025 (beta), MCP04:2025 (beta), ASI05 |
| Evidence | The configuration entry. |

ACTIVE, NOT IMPLEMENTED. Static review of a submitted client configuration file. requires --active and verified ownership.

**False positives.** npx -y with a pinned version is acceptable; unpinned is flagged.

**Fix.** Pin packages, avoid shell wrappers, keep secrets out of config files.

### SANDBOX-01 - Unexpected runtime behaviour during listing (stdio)

| | |
|---|---|
| Mode | active (stub (gated, not implemented)) |
| Default severity | high |
| Transports | stdio |
| Standards | MCP04:2025 (beta), ASI10, ASI04 |
| Evidence | Sandbox egress/file/process log. |

ACTIVE, NOT IMPLEMENTED. Sandboxed execution with egress and syscall logging. requires --active and verified ownership.

**False positives.** Telemetry and update checks are common; the finding will list hosts for review.

**Fix.** Do not contact the network or touch files outside the package during start-up and listing.

## Governance items (attestation only)

These cannot be assessed by an automated black-box scan. Every report lists them as `attestation-only` with the checklist below; mcpprobe never marks them passed or failed.

### GOV-01 - Audit logging and telemetry for tool invocations

Standards: MCP08:2025 (beta)

Whether a server logs and alerts on tool calls is not observable from outside.

- [ ] Every tools/call is logged with caller identity, tool name, arguments digest and outcome.
- [ ] Logs are shipped off-host, retained, and reviewed or alerted on.
- [ ] Authentication failures and authorisation denials are logged.

### GOV-02 - Shadow MCP servers (inventory of servers in use)

Standards: MCP09:2025 (beta)

An inventory problem across workstations and repositories, not an endpoint property.

- [ ] Maintain an inventory of approved MCP servers and their owners.
- [ ] Periodically review client configuration files (mcp.json and similar) for unapproved entries.

### GOV-03 - Data and model poisoning in training or fine-tuning pipelines

Standards: LLM05:2026, LLM04:2025

Training-pipeline integrity is not black-box testable.

- [ ] Training and retrieval data sources are provenance-tracked and access-controlled.
- [ ] Data changes are reviewed before they reach a model or index.

### GOV-04 - Inter-agent communication, cascading failures, human trust, rogue agents

Standards: ASI07, ASI08, ASI09, ASI10

Architecture and process items; multi-agent paths are not externally visible.

- [ ] Agent-to-agent channels are authenticated (the AUTH checks apply to any exposed endpoint).
- [ ] Failure of one tool or agent is contained (timeouts, circuit breakers, budgets).
- [ ] High-impact actions require explicit human approval with the full action shown.
- [ ] Agents can be stopped centrally and their credentials revoked.

### GOV-05 - Memory and context poisoning persistence

Standards: ASI06

Needs a customer-supplied test session across two conversations; not a server-side scan.

- [ ] Persistent memory is scoped per user and per tenant.
- [ ] Stored memories can be reviewed and deleted by the user.
- [ ] Content from tool output is not written to long-term memory without review.
