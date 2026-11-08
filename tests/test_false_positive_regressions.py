"""Regressions from owner feedback on disclosure notices (Nov 2026)."""

from mcpprobe.checks.capability import (
    ARBITRARY_EXEC,
    ARBITRARY_FILE_READ,
    arbitrary_capabilities,
    is_lookup_tool,
)
from mcpprobe.checks.metadata import find_secrets, is_documented_example


def _tool(name, desc, props):
    return {"name": name, "description": desc, "inputSchema": {"type": "object", "properties": props}}


# --- META-05: documented sample credentials -----------------------------------------------------
def test_aws_documented_example_key_is_not_a_secret():
    text = "Detects credentials such as AWS access keys (e.g. AKIAIOSFODNN7EXAMPLE) in tool metadata."
    assert find_secrets(text) == []


def test_aws_documented_secret_key_and_placeholders_are_skipped():
    for v in (
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "sk_live_xxxxxxxxxxxxxxxxxxxx",
        "AKIAAAAAAAAAAAAAAAAA",
        "ghp_your_token_goes_here_000000000000000",
    ):
        assert is_documented_example(v), v


def test_real_looking_aws_key_still_reported():
    hits = find_secrets("key " + "AKIA" + "2E0A8F3B244C9986" + " in description")
    assert [h["kind"] for h in hits] == ["AWS access key id"]


def test_real_looking_stripe_key_still_reported():
    hits = find_secrets("use " + "sk_" + "live_51Hq8vC2eZvKYlo2C0f9QnRtLm" + " here")
    assert any(h["kind"] == "Stripe key" for h in hits)


# --- META-03: lookup/reference tools ------------------------------------------------------------
def test_cli_reference_lookup_is_not_command_execution():
    t = _tool(
        "worlds_get_cli_command",
        "Return the reference entry (flags, arguments and source links) for a named CLI command.",
        {"command": {"type": "string", "description": "Command name to look up"}},
    )
    assert is_lookup_tool(t)
    assert ARBITRARY_EXEC not in arbitrary_capabilities(t)


def test_document_lookup_by_path_is_not_file_read():
    t = _tool(
        "worlds_get_document",
        "Read an excerpt of a published manual page. path is the document path in the reference corpus.",
        {"path": {"type": "string"}},
    )
    assert ARBITRARY_FILE_READ not in arbitrary_capabilities(t)


def test_lookup_name_with_explicit_execution_wording_is_still_flagged():
    t = _tool(
        "get_command_output",
        "Runs the given shell command and returns its output.",
        {"command": {"type": "string"}},
    )
    assert ARBITRARY_EXEC in arbitrary_capabilities(t)


def test_run_command_still_flagged():
    t = _tool("run_command", "Run a command on the host.", {"command": {"type": "string"}})
    assert ARBITRARY_EXEC in arbitrary_capabilities(t)


def test_read_file_still_flagged():
    t = _tool("read_file", "Read the contents of a file.", {"path": {"type": "string"}})
    assert ARBITRARY_FILE_READ in arbitrary_capabilities(t)


def test_get_file_contents_lookup_still_flagged():
    t = _tool("get_file_contents", "Return the contents of a file at path.", {"path": {"type": "string"}})
    assert ARBITRARY_FILE_READ in arbitrary_capabilities(t)


# --- P2/P4 queue: registry-declared API key ---------------------------------------------------
def test_declared_required_header_keeps_host_out_of_p2_and_p4():
    from mcpprobe.registry.aggregate import disclosure_reasons

    rec = {
        "host": "h",
        "status": "scanned",
        "outcomes": {"AUTH-01": "critical", "META-03": "critical", "META-07": "high"},
    }
    assert {p for p, _ in disclosure_reasons(rec)} == {"P2", "P4"}
    rec["needs_headers"] = True
    assert disclosure_reasons(rec) == []
