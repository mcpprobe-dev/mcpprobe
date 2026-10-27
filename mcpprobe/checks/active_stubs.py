"""Active checks: INJ-01..05, SUPPLY-01/02 and SANDBOX-01.

These are **stubs**. Each one is registered so that reports show it as
``not_implemented`` (when active mode is authorised) or ``skipped`` (otherwise),
but none sends a probe payload yet. When implemented they must follow the rules
of engagement in CHECKS.md: non-destructive, non-persistent canaries only;
tools excluded by the operator or marked ``destructiveHint: true`` are never
called; every payload is logged as evidence; an emergency stop aborts the run.
"""

from __future__ import annotations

from mcpprobe.checks.base import ActiveCheck, ScanContext
from mcpprobe.models import Finding, Severity, Standards

GATE_TEXT = "requires --active and verified ownership"


class _Stub(ActiveCheck):
    """Shared behaviour: enforce the gate, then report not-implemented."""

    async def run(self, ctx: ScanContext) -> list[Finding]:
        self.require_active(ctx)
        raise NotImplementedError(f"{self.id} is not implemented yet ({GATE_TEXT})")


class Inj01CommandInjection(_Stub):
    """TODO: time-based, non-destructive command-injection canaries.

    Plan: for tools classified ``exec``/``shell``/``file`` by META-03, submit
    arguments containing ``$(sleep N)``, backtick and ``;`` separated sleep
    markers, ``%0a`` and ``|| true`` and look for a timing delta or an echoed
    marker. Never submit payloads that write, delete or exfiltrate.
    """

    id = "INJ-01"
    title = "Command/code injection (safe canaries)"
    severity = Severity.CRITICAL
    standards = Standards(mcp=["MCP05:2025"], asi=["ASI05"], llm_2026=["LLM10:2026"])
    description = (
        "ACTIVE, NOT IMPLEMENTED. Will call exec-class tools with time-based, non-destructive "
        "canaries and compare response timing. " + GATE_TEXT + "."
    )
    evidence_type = "tools/call request with the canary and the timed response."
    false_positive_notes = (
        "Network jitter can mimic a timing delta; the probe will repeat and require consistency."
    )
    fix = "Never pass tool arguments to a shell; use argument vectors and allow-lists."


class Inj02PathTraversal(_Stub):
    """TODO: read-only path traversal probes against path-typed arguments.

    Plan: ``../../../etc/hostname``, ``..%2f`` encodings, absolute paths and
    symlink-style names (CVE-2025-53109/53110 class). Success means content was
    returned from outside the intended root. Read-only files only.
    """

    id = "INJ-02"
    title = "Path traversal / arbitrary file read"
    severity = Severity.HIGH
    standards = Standards(mcp=["MCP05:2025"], asi=["ASI02"])
    description = (
        "ACTIVE, NOT IMPLEMENTED. Read-only traversal probes on path-typed arguments. " + GATE_TEXT + "."
    )
    evidence_type = "tools/call request with the traversal path and the response excerpt."
    false_positive_notes = (
        "Tools that intentionally expose the whole filesystem are a design decision, not a bug."
    )
    fix = "Canonicalise paths, resolve symlinks, and enforce a root directory check after resolution."


class Inj03Ssrf(_Stub):
    """TODO: SSRF detection via a scanner-controlled callback host.

    Plan: URL-typed arguments receive a unique callback URL per scan plus denied
    targets (``169.254.169.254``, ``localhost``). A received callback confirms SSRF.
    Requires operator-supplied callback infrastructure; none is bundled.
    """

    id = "INJ-03"
    title = "Server-side request forgery"
    severity = Severity.HIGH
    standards = Standards(mcp=["MCP05:2025"], asi=["ASI02"])
    description = (
        "ACTIVE, NOT IMPLEMENTED. Callback-based SSRF probes on URL-typed arguments. " + GATE_TEXT + "."
    )
    evidence_type = "tools/call request with the callback URL and the callback log entry."
    false_positive_notes = "Fetch tools are often meant to fetch arbitrary URLs; the finding focuses on internal/metadata addresses."
    fix = "Resolve and validate destination addresses, block link-local and private ranges, use an egress proxy."


class Inj04SqlInjection(_Stub):
    """TODO: boolean/time-based SQL markers with no data modification."""

    id = "INJ-04"
    title = "SQL injection (safe markers)"
    severity = Severity.HIGH
    standards = Standards(mcp=["MCP05:2025"])
    description = (
        "ACTIVE, NOT IMPLEMENTED. Boolean and timing markers on query/filter arguments, plus error fingerprinting. "
        + GATE_TEXT
        + "."
    )
    evidence_type = "tools/call requests and differential responses."
    false_positive_notes = (
        "Tools that accept raw SQL by design are reported as a capability (META-03), not an injection."
    )
    fix = "Use parameterised queries; never interpolate tool arguments into SQL."


class Inj05ToolOutputInjection(_Stub):
    """TODO: canary instruction in scanner-controlled content fetched by read-only tools.

    Plan: call read-only fetch/search/resource tools against operator-provided
    content containing a canary instruction and check whether it is returned
    verbatim without marking or sanitisation.
    """

    id = "INJ-05"
    title = "Tool output returned without sanitisation (contextual payload path)"
    severity = Severity.MEDIUM
    standards = Standards(
        mcp=["MCP06:2025", "MCP10:2025"], asi=["ASI06"], llm_2025=["LLM01:2025"], llm_2026=["LLM01:2026"]
    )
    description = (
        "ACTIVE, NOT IMPLEMENTED. Read-only tool calls against scanner-controlled canary content. "
        + GATE_TEXT
        + "."
    )
    evidence_type = "tools/call request and the returned content."
    false_positive_notes = "Returning fetched content verbatim is normal; the finding documents the path for the client's risk assessment."
    fix = "Mark tool output as untrusted data in content blocks and strip instruction-like markup where feasible."


class Supply01PackageProvenance(_Stub):
    """TODO: npm/PyPI provenance for stdio packages.

    Plan: version pinning, lockfile presence, OSV vulnerability lookup, maintainer
    count, publish date vs repository tag, install scripts, ``eval``/``child_process.exec``
    usage, and artefact-vs-tag comparison. Network access to registries only.
    """

    id = "SUPPLY-01"
    title = "Package provenance and known vulnerabilities (stdio)"
    severity = Severity.MEDIUM
    applies_to = frozenset({"stdio"})
    standards = Standards(mcp=["MCP04:2025"], asi=["ASI04"], llm_2025=["LLM03:2025"], llm_2026=["LLM04:2026"])
    description = (
        "ACTIVE, NOT IMPLEMENTED. Registry metadata, OSV lookup and install-script review for the stdio package. "
        + GATE_TEXT
        + "."
    )
    evidence_type = "Registry metadata documents and OSV responses."
    false_positive_notes = (
        "Unpinned versions are common in examples; severity will depend on install-script presence."
    )
    fix = "Pin versions, commit lockfiles, publish with provenance attestations, avoid install scripts."


class Supply02StdioConfigInjection(_Stub):
    """TODO: config-to-command analysis of an ``mcp.json``-style file.

    Plan: flag ``command`` values with shell metacharacters or ``sh -c``, ``npx -y``
    of unpinned packages, and env blocks containing secrets. Pure file analysis,
    no network, but kept in active mode until the config input is designed.
    """

    id = "SUPPLY-02"
    title = "stdio configuration launches risky commands"
    severity = Severity.HIGH
    applies_to = frozenset({"stdio"})
    standards = Standards(mcp=["MCP05:2025", "MCP04:2025"], asi=["ASI05"])
    description = (
        "ACTIVE, NOT IMPLEMENTED. Static review of a submitted client configuration file. " + GATE_TEXT + "."
    )
    evidence_type = "The configuration entry."
    false_positive_notes = "npx -y with a pinned version is acceptable; unpinned is flagged."
    fix = "Pin packages, avoid shell wrappers, keep secrets out of config files."


class Sandbox01RuntimeBehaviour(_Stub):
    """TODO: run the stdio package in an egress-logged sandbox.

    Plan: observe outbound hosts, files touched and processes spawned during
    ``initialize`` + ``tools/list`` alone; report behaviour that the description
    does not explain. Requires a sandbox runner (not bundled).
    """

    id = "SANDBOX-01"
    title = "Unexpected runtime behaviour during listing (stdio)"
    severity = Severity.HIGH
    applies_to = frozenset({"stdio"})
    standards = Standards(mcp=["MCP04:2025"], asi=["ASI10", "ASI04"])
    description = (
        "ACTIVE, NOT IMPLEMENTED. Sandboxed execution with egress and syscall logging. " + GATE_TEXT + "."
    )
    evidence_type = "Sandbox egress/file/process log."
    false_positive_notes = "Telemetry and update checks are common; the finding will list hosts for review."
    fix = "Do not contact the network or touch files outside the package during start-up and listing."


ACTIVE_STUBS: list[type[ActiveCheck]] = [
    Inj01CommandInjection,
    Inj02PathTraversal,
    Inj03Ssrf,
    Inj04SqlInjection,
    Inj05ToolOutputInjection,
    Supply01PackageProvenance,
    Supply02StdioConfigInjection,
    Sandbox01RuntimeBehaviour,
]
