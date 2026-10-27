# Security policy

## Reporting a vulnerability in mcpprobe

Please report vulnerabilities in mcpprobe itself privately to
**hello@mcpprobe.tech** (subject line starting with `SECURITY`), or through
GitHub's private vulnerability reporting on this repository. Do not open a
public issue.

Include the version (`mcpprobe --version`), what you ran, what happened and
what you expected. We aim to acknowledge reports within 3 working days and to
ship a fix or mitigation within 30 days for high and critical issues. We will
credit you in the release notes unless you ask us not to.

Supported versions: the latest released minor version receives security fixes.

## Things we consider in scope

- Anything that makes mcpprobe send requests the documentation says it never
  sends (tool calls in passive mode, active probes without a verified
  authorisation record, traffic after an opt-out signal, rates above the
  10 requests/second ceiling).
- Bypasses of the active-mode authorisation gate or ownership verification.
- A scanned server being able to execute code, inject terminal escape
  sequences or markup, write files, or exfiltrate data from the machine
  running mcpprobe.
- Secrets leaking into JSON/SARIF reports or evidence despite redaction.

## Finding vulnerabilities in other people's MCP servers

mcpprobe is for servers you own or are explicitly authorised to test. If you
find an issue in a third-party server, report it privately to its maintainer
and allow reasonable time for a fix before any disclosure. Do not publish the
names of unpatched servers.

## Scanner identification and opt-out

Every request carries the user agent
`mcpprobe/<version> (+https://mcpprobe.tech/scanning-policy)`. Operators can
opt out of all mcpprobe scans by publishing either of:

- DNS: `_mcpprobe.<host>  TXT  "mcpprobe-opt-out=all"` (also honoured on parent
  domains), checked before any request reaches the host; or
- HTTP: any `200` response at `/.well-known/mcpprobe-opt-out`.

The CLI cannot be configured to ignore either signal. See
https://mcpprobe.tech/scanning-policy for the full policy.
