"""Docs stay in sync with code; the GitHub Action entry point maps inputs correctly."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpprobe.action import build_argv, describe, run
from mcpprobe.catalogue import checks_markdown
from mcpprobe.checks import ALL_CHECKS
from mcpprobe.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, EXIT_NOT_MCP, main
from mcpprobe.governance import GOVERNANCE_ITEMS
from tests.conftest import stdio_command

ROOT = Path(__file__).resolve().parent.parent


def test_checks_md_is_generated_from_metadata():
    assert (ROOT / "CHECKS.md").read_text() == checks_markdown(), (
        "run: mcpprobe checks --format markdown > CHECKS.md"
    )


def test_catalogue_covers_everything():
    text = checks_markdown()
    for cls in ALL_CHECKS:
        assert f"### {cls.id} - " in text
        assert cls.evidence_type and cls.false_positive_notes and cls.fix, cls.id
    for item in GOVERNANCE_ITEMS:
        assert f"### {item.id} - " in text


@pytest.mark.parametrize(
    "name", ["README.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "action.yml", "Dockerfile"]
)
def test_project_files_exist(name):
    assert (ROOT / name).stat().st_size > 100


def test_readme_contract():
    readme = (ROOT / "README.md").read_text()
    for needle in (
        "pipx run --spec mcpprobe-scanner mcpprobe https://your-server.example/mcp",
        "## Exit codes",
        "upload-sarif",
        "--authorised-by",
    ):
        assert needle in readme


def test_action_argv_mapping():
    env = {
        "INPUT_TARGET": "https://mcp.example.com/mcp",
        "INPUT_FAIL-ON": "medium",
        "INPUT_SARIF-OUTPUT": "out.sarif",
        "INPUT_HEADERS": "Authorization: Bearer x\nX-Test: 1\n",
        "INPUT_EXTRA-ARGS": "--skip DOS-01 -v",
    }
    argv = build_argv(env)
    assert argv[:2] == ["scan", "https://mcp.example.com/mcp"]
    assert argv[argv.index("--fail-on") + 1] == "medium"
    assert argv[argv.index("--rate") + 1] == "5"
    assert argv.count("--header") == 2
    assert argv[-3:] == ["--skip", "DOS-01", "-v"]
    with pytest.raises(ValueError):
        build_argv({})


def test_action_run_writes_outputs(live_server, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "gh_output"
    with live_server("vulnerable") as srv:
        code = run(
            {"INPUT_TARGET": srv.url, "INPUT_RATE": "10", "INPUT_EXTRA-ARGS": "-q", "GITHUB_OUTPUT": str(out)}
        )
    assert code == EXIT_FINDINGS
    assert (tmp_path / "mcpprobe.sarif").exists()
    assert out.read_text().splitlines() == ["sarif-file=mcpprobe.sarif", "exit-code=1", "result=findings"]
    assert run({}) == EXIT_ERROR


def test_action_surfaces_not_mcp(live_server, tmp_path, monkeypatch, capsys):
    """Exit 3 must be visible in the log, the outputs and the job summary, not just a red step."""
    monkeypatch.chdir(tmp_path)
    out, summary = tmp_path / "gh_output", tmp_path / "summary.md"
    with live_server("html") as srv:
        code = run(
            {
                "INPUT_TARGET": srv.url,
                "INPUT_RATE": "10",
                "INPUT_EXTRA-ARGS": "-q",
                "GITHUB_OUTPUT": str(out),
                "GITHUB_STEP_SUMMARY": str(summary),
            }
        )
    assert code == EXIT_NOT_MCP
    assert "exit-code=3" in out.read_text().splitlines()
    assert "result=not-mcp" in out.read_text().splitlines()
    assert "::error title=mcpprobe%3A not an MCP server::" in capsys.readouterr().err
    assert "not-mcp (exit 3" in summary.read_text()


def test_action_describe_every_exit_code():
    counts = {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0}
    assert describe(EXIT_CLEAN, "u", "critical", counts)[0] == "notice"
    level, title, message = describe(EXIT_FINDINGS, "u", "high", counts)
    assert (level, title) == ("error", "mcpprobe: findings") and "1 high, 2 medium" in message
    assert describe(EXIT_NOT_MCP, "u", "high", {})[1] == "mcpprobe: not an MCP server"
    assert describe(EXIT_ERROR, "u", "high", {})[1] == "mcpprobe: scan error"


def test_main_accepts_options_before_target():
    with pytest.raises(SystemExit) as exc:
        main(["--stdio", " ".join(stdio_command()), "--only", "META-01", "-q"])
    assert exc.value.code == 0
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


@pytest.mark.parametrize(
    "module",
    [
        "mcpprobe.policy",
        "mcpprobe.authz",
        "mcpprobe.checks",
        "mcpprobe.cli",
        "mcpprobe.scanner",
        "mcpprobe.report",
        "mcpprobe.action",
        "mcpprobe.transport",
    ],
)
def test_each_module_imports_first(module):
    """Guards against import cycles that only appear depending on import order."""
    import subprocess
    import sys

    subprocess.run([sys.executable, "-c", f"import {module}"], check=True, cwd=ROOT)
