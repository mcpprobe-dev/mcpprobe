"""Docs stay in sync with code; the GitHub Action entry point maps inputs correctly."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpprobe.action import build_argv, run
from mcpprobe.catalogue import checks_markdown
from mcpprobe.checks import ALL_CHECKS
from mcpprobe.cli import EXIT_ERROR, EXIT_FINDINGS, main
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
        "pipx run mcpprobe https://your-server.example/mcp",
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
    assert out.read_text().splitlines() == ["sarif-file=mcpprobe.sarif", "exit-code=1"]
    assert run({}) == EXIT_ERROR


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
