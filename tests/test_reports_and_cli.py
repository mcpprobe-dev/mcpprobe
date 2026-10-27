"""Reporters (JSON, SARIF 2.1.0, terminal) and the CLI contract (exit codes, gate, outputs)."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from mcpprobe.authz import expected_txt_record
from mcpprobe.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, cli, main
from mcpprobe.models import Severity
from mcpprobe.report import render, report_to_dict, to_sarif
from mcpprobe.report.sarif import validate_sarif
from mcpprobe.report.terminal import SEVERITY_HEX
from tests.conftest import run, stdio_command

SCHEMA = Path(__file__).parent / "data" / "sarif-schema-2.1.0.json"
REQUIRED_FINDING_FIELDS = {"id", "title", "severity", "standards", "evidence_excerpt", "fix", "confidence"}


def schema_errors(doc: dict) -> list[str]:
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft4Validator(json.loads(SCHEMA.read_text()))
    return [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(doc)]


# ----------------------------------------------------------------------------- SARIF
async def test_sarif_valid_for_vulnerable_server(make_server):
    async with make_server(preset="vulnerable") as srv:
        report = await run(srv.url)
    doc = to_sarif(report)
    assert validate_sarif(doc) == []
    assert schema_errors(doc) == []
    run_ = doc["runs"][0]
    rule_ids = [r["id"] for r in run_["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids)) and "AUTH-01" in rule_ids and "SANDBOX-01" in rule_ids
    assert {r["level"] for r in run_["results"]} <= {"error", "warning", "note"}
    for res in run_["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == srv.url
        assert res["partialFingerprints"]["mcpprobe/v1"].startswith(res["ruleId"])
    for rule in run_["tool"]["driver"]["rules"]:
        assert float(rule["properties"]["security-severity"]) >= 0
    assert [a["id"] for a in run_["properties"]["attestationOnly"]] == [f"GOV-0{i}" for i in range(1, 6)]


async def test_sarif_stdio_and_location_override():
    report = await run(stdio_command("--poisoned"), stdio=True)
    doc = to_sarif(report)
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("stdio:") and " " not in uri
    assert schema_errors(doc) == []
    doc2 = to_sarif(report, location_uri="server/main.py")
    assert (
        doc2["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "server/main.py"
    )


async def test_sarif_clean_scan_has_empty_results(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["TRANS-01"])
    doc = to_sarif(report)
    assert doc["runs"][0]["results"] == []
    assert validate_sarif(doc) == [] and schema_errors(doc) == []


def test_sarif_validator_catches_problems():
    bad = {
        "version": "2.0",
        "runs": [
            {
                "tool": {"driver": {"rules": [{"id": "A"}, {"id": "A"}]}},
                "invocations": [{}],
                "results": [
                    {
                        "ruleId": "A",
                        "ruleIndex": 5,
                        "level": "fatal",
                        "message": {},
                        "locations": [{"physicalLocation": {}}],
                    },
                    {"message": {"text": "x"}, "partialFingerprints": {"a": 1}, "kind": "nope", "x": None},
                ],
            }
        ],
    }
    problems = " | ".join(validate_sarif(bad))
    for needle in (
        "version must be '2.1.0'",
        "driver.name is required",
        "rule ids must be unique",
        "executionSuccessful",
        "ruleIndex out of range",
        "level invalid",
        "message with text or id",
        "needs artifactLocation.uri",
        "needs ruleId or ruleIndex",
        "partialFingerprints values must be strings",
        "kind invalid",
        "null is not allowed",
    ):
        assert needle in problems, needle
    assert validate_sarif([]) == ["sarifLog must be an object"]


# ----------------------------------------------------------------------------- JSON
async def test_json_report_shape(make_server):
    async with make_server(preset="vulnerable") as srv:
        report = await run(srv.url)
    data = report_to_dict(report)
    assert data["summary"]["max_severity"] == "high"
    assert sum(data["summary"]["counts"].values()) == len(data["findings"]) > 10
    assert [a["id"] for a in data["attestations"]] == ["GOV-01", "GOV-02", "GOV-03", "GOV-04", "GOV-05"]
    assert all(a["status"] == "attestation-only" for a in data["attestations"])
    for f in data["findings"]:
        assert REQUIRED_FINDING_FIELDS <= set(f)
        assert set(f["standards"]) == {"mcp", "asi", "llm_2025", "llm_2026"}
        assert f["fix"]
    with_ev = [f for f in data["findings"] if f["evidence"]]
    rec = with_ev[0]["evidence"][0]
    assert {"timestamp", "method", "status", "request_headers", "response_headers", "response_body"} <= set(
        rec
    )


# ----------------------------------------------------------------------------- terminal
async def test_terminal_palette_and_hostile_strings(make_server):
    hostile = [
        {
            "name": "evil[bold red]x[/bold red]",
            "description": "Normal text \x1b[31mred\x1b[0m [link=https://x.invalid]click[/link]",
            "inputSchema": {"type": "object", "properties": {}},
        }
    ]
    async with make_server(require_auth=True, accept_any_bearer=True, tools=hostile) as srv:
        auth_report = await run(srv.url, only=["AUTH-04"])
    async with make_server(tools=hostile) as srv:
        meta_report = await run(srv.url, only=["META-04"])
    assert auth_report.max_severity() == Severity.CRITICAL
    console = Console(record=True, force_terminal=True, color_system="truecolor", width=160)
    render(auth_report, console, fail_on=Severity.HIGH)
    ansi = console.export_text(styles=True)
    r, g, b = (int(SEVERITY_HEX[Severity.CRITICAL][i : i + 2], 16) for i in (1, 3, 5))
    assert f"{r};{g};{b}" in ansi  # critical #B3261E
    assert "Result: FAIL" in ansi

    console2 = Console(record=True, force_terminal=True, color_system="truecolor", width=200)
    render(meta_report, console2, verbose=True)
    text = console2.export_text()
    assert "evil[bold red]x[/bold red]" in text  # rendered literally, not as markup
    raw = console2.export_text(styles=True)
    assert "\x1b[31mred" not in raw  # server-supplied escape sequence neutralised
    assert SEVERITY_HEX == {
        Severity.CRITICAL: "#B3261E",
        Severity.HIGH: "#C2410C",
        Severity.MEDIUM: "#9A6200",
        Severity.LOW: "#4A5560",
        Severity.INFO: "#4A5560",
    }


async def test_terminal_clean_shows_pass(make_server):
    async with make_server() as srv:
        report = await run(srv.url, only=["TRANS-01"])
    console = Console(record=True, force_terminal=True, color_system="truecolor", width=120)
    render(report, console, fail_on=Severity.HIGH)
    out = console.export_text(styles=True)
    assert "No findings." in out and "Result: PASS" in out and "46;125;79" in out  # pass #2E7D4F


# ----------------------------------------------------------------------------- CLI
def invoke(*args: str):
    return CliRunner().invoke(cli, list(args), catch_exceptions=False)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_cli_help_and_checks():
    res = invoke("--help")
    assert res.exit_code == 0 and "scan" in res.output
    res = invoke("scan", "--help")
    assert "--authorised-by" in res.output and "--fail-on" in res.output
    res = invoke("checks", "--format", "markdown")
    assert res.exit_code == 0
    for cid in ("AUTH-01", "META-05", "DOS-01", "INJ-01", "SANDBOX-01"):
        assert f"[{cid}]" in res.output


def test_cli_default_subcommand(live_server):
    with live_server() as srv, pytest.raises(SystemExit) as exc:
        main([srv.url, "--only", "TRANS-01", "-q"])
    assert exc.value.code == EXIT_CLEAN


def test_cli_exit_1_on_findings_and_writes_reports(live_server, tmp_path):
    sarif, js = tmp_path / "r.sarif", tmp_path / "r.json"
    with live_server("vulnerable") as srv:
        res = invoke("scan", srv.url, "--rate", "10", "--sarif", str(sarif), "--json", str(js))
    assert res.exit_code == EXIT_FINDINGS, res.output
    doc = json.loads(sarif.read_text())
    assert validate_sarif(doc) == [] and schema_errors(doc) == []
    data = json.loads(js.read_text())
    assert data["evidence"] and data["summary"]["counts"]["high"] >= 1
    assert "Result: FAIL" in res.output


def test_cli_fail_on_threshold(live_server):
    with live_server("vulnerable") as srv:
        res = invoke("scan", srv.url, "--rate", "10", "--fail-on", "critical", "-q")
    assert res.exit_code == EXIT_CLEAN  # worst finding on loopback is high


def test_cli_exit_0_clean(live_server):
    with live_server() as srv:
        res = invoke("scan", srv.url, "--rate", "10", "--fail-on", "high")
    assert res.exit_code == EXIT_CLEAN, res.output


def test_cli_exit_2_unreachable():
    res = invoke("scan", f"http://127.0.0.1:{free_port()}/mcp", "-q")
    assert res.exit_code == EXIT_ERROR


def test_cli_exit_2_opt_out(live_server):
    with live_server(opt_out=True) as srv:
        res = invoke("scan", srv.url)
        assert [r["path"] for r in srv.requests] == ["/.well-known/mcpprobe-opt-out"]
    assert res.exit_code == EXIT_ERROR and "aborted" in res.output


def test_cli_exit_2_dns_opt_out(monkeypatch):
    import mcpprobe.policy

    monkeypatch.setattr(mcpprobe.policy, "default_txt_lookup", lambda name: ["mcpprobe-opt-out=all"])
    res = invoke("scan", "https://mcp.example.com/mcp")
    assert res.exit_code == EXIT_ERROR and "opted out" in res.output


def test_cli_exit_2_bad_rate_and_unknown_check(live_server):
    res = invoke("scan", "https://mcp.example.com/mcp", "--rate", "11")
    assert res.exit_code == EXIT_ERROR
    with live_server() as srv:
        res = invoke("scan", srv.url, "--only", "NOPE-99")
    assert res.exit_code == EXIT_ERROR


def test_cli_active_refused_without_gate_inputs(live_server):
    with live_server() as srv:
        res = invoke("scan", srv.url, "--active")
        assert srv.requests == []  # refused before any traffic
    assert res.exit_code == EXIT_ERROR and "authorisation refused" in res.output
    with live_server() as srv:
        res = invoke(
            "scan", srv.url, "--active", "--authorised-by", "me", "--scope", "x", "--verify", "local"
        )
        assert srv.requests == []
    assert res.exit_code == EXIT_ERROR and "only valid for stdio" in res.output


def test_cli_active_dns_verification_failure(live_server, monkeypatch):
    import mcpprobe.authz

    monkeypatch.setattr(mcpprobe.authz, "default_txt_lookup", lambda name: [])
    with live_server(host="localhost") as srv:
        res = invoke(
            "scan",
            srv.url,
            "--active",
            "--authorised-by",
            "me",
            "--scope",
            "x",
            "--verify",
            "dns-txt",
            "--token",
            "abc",
        )
        assert srv.requests == []
    assert res.exit_code == EXIT_ERROR and "verification failed" in res.output


def test_cli_active_dns_verified_writes_record(live_server, monkeypatch, tmp_path):
    import mcpprobe.authz

    seen: list[str] = []

    def lookup(name: str) -> list[str]:
        seen.append(name)
        return [expected_txt_record("abc")]

    monkeypatch.setattr(mcpprobe.authz, "default_txt_lookup", lookup)
    report = tmp_path / "scan.json"
    with live_server(host="localhost") as srv:
        res = invoke(
            "scan",
            srv.url,
            "--active",
            "--authorised-by",
            "owner (ticket 7)",
            "--scope",
            srv.url,
            "--verify",
            "dns-txt",
            "--token",
            "abc",
            "--json",
            str(report),
            "--rate",
            "10",
            "-q",
        )
        assert srv.tool_calls == []  # active stubs never call tools
    assert seen == ["_mcpprobe.localhost"]
    assert res.exit_code in (EXIT_CLEAN, EXIT_FINDINGS), res.output
    rec = json.loads((tmp_path / "scan.authorisation.json").read_text())
    assert rec["verification"]["verified"] and rec["authorised_by"] == "owner (ticket 7)"
    data = json.loads(report.read_text())
    assert data["mode"] == "active"
    assert {c["check_id"]: c["status"] for c in data["checks"]}["INJ-01"] == "not_implemented"


def test_cli_active_local_stdio(tmp_path):
    cmd = " ".join(stdio_command())
    out = tmp_path / "s.sarif"
    res = invoke(
        "scan",
        cmd,
        "--stdio",
        "--active",
        "--authorised-by",
        "me",
        "--scope",
        "local",
        "--verify",
        "local",
        "--sarif",
        str(out),
        "-q",
    )
    assert res.exit_code in (EXIT_CLEAN, EXIT_FINDINGS), res.output
    assert (tmp_path / "s.authorisation.json").exists()


def test_cli_token_command():
    res = invoke("token", "mcp.example.com")
    assert res.exit_code == 0
    assert "_mcpprobe.mcp.example.com.  TXT" in res.output and "mcpprobe-verification=" in res.output
