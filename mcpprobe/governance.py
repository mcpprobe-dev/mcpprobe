"""GOV-01..05: governance items that an automated scan cannot assess.

They are listed in every report as *attestation only*, with a short checklist
the operator can work through. mcpprobe never reports them as passed or failed.
"""

from __future__ import annotations

from mcpprobe.models import AttestationItem, Standards

GOVERNANCE_ITEMS: list[AttestationItem] = [
    AttestationItem(
        id="GOV-01",
        title="Audit logging and telemetry for tool invocations",
        standards=Standards(mcp=["MCP08:2025"]),
        reason="Whether a server logs and alerts on tool calls is not observable from outside.",
        checklist=[
            "Every tools/call is logged with caller identity, tool name, arguments digest and outcome.",
            "Logs are shipped off-host, retained, and reviewed or alerted on.",
            "Authentication failures and authorisation denials are logged.",
        ],
    ),
    AttestationItem(
        id="GOV-02",
        title="Shadow MCP servers (inventory of servers in use)",
        standards=Standards(mcp=["MCP09:2025"]),
        reason="An inventory problem across workstations and repositories, not an endpoint property.",
        checklist=[
            "Maintain an inventory of approved MCP servers and their owners.",
            "Periodically review client configuration files (mcp.json and similar) for unapproved entries.",
        ],
    ),
    AttestationItem(
        id="GOV-03",
        title="Data and model poisoning in training or fine-tuning pipelines",
        standards=Standards(llm_2025=["LLM04:2025"], llm_2026=["LLM05:2026"]),
        reason="Training-pipeline integrity is not black-box testable.",
        checklist=[
            "Training and retrieval data sources are provenance-tracked and access-controlled.",
            "Data changes are reviewed before they reach a model or index.",
        ],
    ),
    AttestationItem(
        id="GOV-04",
        title="Inter-agent communication, cascading failures, human trust, rogue agents",
        standards=Standards(asi=["ASI07", "ASI08", "ASI09", "ASI10"]),
        reason="Architecture and process items; multi-agent paths are not externally visible.",
        checklist=[
            "Agent-to-agent channels are authenticated (the AUTH checks apply to any exposed endpoint).",
            "Failure of one tool or agent is contained (timeouts, circuit breakers, budgets).",
            "High-impact actions require explicit human approval with the full action shown.",
            "Agents can be stopped centrally and their credentials revoked.",
        ],
    ),
    AttestationItem(
        id="GOV-05",
        title="Memory and context poisoning persistence",
        standards=Standards(asi=["ASI06"]),
        reason="Needs a customer-supplied test session across two conversations; not a server-side scan.",
        checklist=[
            "Persistent memory is scoped per user and per tenant.",
            "Stored memories can be reviewed and deleted by the user.",
            "Content from tool output is not written to long-term memory without review.",
        ],
    ),
]


def governance_items() -> list[AttestationItem]:
    """Fresh copies, so a report can be mutated without touching the module constant."""
    return [item.model_copy(deep=True) for item in GOVERNANCE_ITEMS]


__all__ = ["GOVERNANCE_ITEMS", "governance_items"]
