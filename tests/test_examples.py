"""The lab servers in examples/ must keep producing the findings their READMEs show.

Each test runs the same CLI command the README documents, writes a JSON report and
checks the findings in it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from click.testing import CliRunner

from mcpprobe.cli import EXIT_CLEAN, EXIT_FINDINGS, cli

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def scan(tmp_path: Path, server: Path, *extra: str, server_args: str = "", name: str = "report") -> dict:
    out = tmp_path / f"{name}.json"
    command = f"{sys.executable} {server} {server_args}".strip()
    res = CliRunner().invoke(
        cli,
        ["scan", command, "--stdio", *extra, "--json", str(out), "-q"],
        catch_exceptions=False,
    )
    assert res.exit_code in (EXIT_CLEAN, EXIT_FINDINGS), res.output
    return json.loads(out.read_text())


def findings(report: dict, check_id: str) -> list[dict]:
    return [f for f in report["findings"] if f["id"] == check_id]


def status(report: dict, check_id: str) -> str:
    return next(c["status"] for c in report["checks"] if c["check_id"] == check_id)


def test_tool_poisoning_example_is_flagged(tmp_path):
    report = scan(tmp_path, EXAMPLES / "tool-poisoning" / "server.py")
    (meta01,) = findings(report, "META-01")
    assert meta01["severity"] == "high"
    kinds = {i["kind"] for i in meta01["details"]["indicators"]}
    assert {"hidden_markup", "hidden_instruction"} <= kinds
    # Heuristic findings are never critical, and the lab triggers nothing else.
    assert {f["id"] for f in report["findings"]} == {"META-01"}


def test_tool_poisoning_fixed_variant_is_clean(tmp_path):
    report = scan(tmp_path, EXAMPLES / "tool-poisoning" / "server.py", server_args="--fixed")
    assert findings(report, "META-01") == []
    assert status(report, "META-01") == "ran"  # "ran" with no findings is shown as pass


def test_labs_name_only_reserved_hosts():
    """Every URL and email address in the lab servers uses the reserved .invalid TLD."""
    for path in EXAMPLES.rglob("*.py"):
        text = path.read_text()
        hosts = re.findall(r"https?://([\w.-]+)", text) + re.findall(r"[\w.+-]+@([\w-]+\.[\w.-]+)", text)
        assert all(h.rstrip(".").endswith("example.invalid") for h in hosts), (path, hosts)


def test_rug_pull_example_is_flagged_after_baseline(tmp_path, monkeypatch):
    server = EXAMPLES / "rug-pull" / "server.py"
    baseline = tmp_path / "baseline.json"
    monkeypatch.delenv("RUG_PULL_STAGE", raising=False)

    first = scan(tmp_path, server, "--baseline", str(baseline), name="approved")
    assert first["findings"] == []
    assert status(first, "META-02") == "not_applicable"  # first scan only records the baseline
    assert baseline.exists()

    # Same command, same target string: only the server's behaviour changed.
    second = scan(
        tmp_path,
        server,
        "--env",
        "RUG_PULL_STAGE=after",
        "--baseline",
        str(baseline),
        "--no-write-baseline",
        name="after",
    )
    (meta02,) = findings(second, "META-02")
    assert meta02["severity"] == "medium"
    assert meta02["details"]["changed_fields"] == ["description", "inputSchema"]
    assert findings(second, "META-01"), "the changed description is also poisoned"

    # The approved surface is unchanged against the same baseline.
    third = scan(tmp_path, server, "--baseline", str(baseline), "--no-write-baseline", name="again")
    assert findings(third, "META-02") == []
