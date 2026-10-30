"""Entry point for the Docker container GitHub Action (``action.yml``).

GitHub passes action inputs as ``INPUT_<NAME>`` environment variables (name
upper-cased, hyphens kept). This module turns them into a CLI invocation,
always writes SARIF, records outputs in ``$GITHUB_OUTPUT``, writes a job
summary to ``$GITHUB_STEP_SUMMARY``, emits one workflow annotation that names
the outcome, and exits with the scanner's exit code:

- 0 clean (no finding at or above ``fail-on``)
- 1 findings at or above ``fail-on``
- 2 error (unreachable target, bad input, opt-out, authorisation refused)
- 3 the target answered but is not an MCP server (wrong URL or path)

For exit codes 2 and 3 the SARIF file contains no results. Uploading it to
code scanning would close every open alert for the category, so workflows
should upload only when ``result`` is ``clean`` or ``findings``.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mcpprobe.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, EXIT_NOT_MCP, main

#: ``result`` output value for each exit code.
RESULTS: dict[int, str] = {
    EXIT_CLEAN: "clean",
    EXIT_FINDINGS: "findings",
    EXIT_ERROR: "error",
    EXIT_NOT_MCP: "not-mcp",
}
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _input(env: Mapping[str, str], name: str, default: str = "") -> str:
    return env.get(f"INPUT_{name.upper()}", default).strip()


def build_argv(env: Mapping[str, str]) -> list[str]:
    """Translate action inputs into ``mcpprobe scan`` arguments."""
    target = _input(env, "target")
    if not target:
        raise ValueError("input 'target' is required")
    argv = ["scan", target]
    argv += ["--fail-on", _input(env, "fail-on", "high") or "high"]
    argv += ["--rate", _input(env, "rate", "5") or "5"]
    argv += ["--sarif", _input(env, "sarif-output", "mcpprobe.sarif") or "mcpprobe.sarif"]
    if json_out := _input(env, "json-output"):
        argv += ["--json", json_out]
    if loc := _input(env, "sarif-location"):
        argv += ["--sarif-location", loc]
    if baseline := _input(env, "baseline"):
        argv += ["--baseline", baseline]
    for line in _input(env, "headers").splitlines():
        if line.strip():
            argv += ["--header", line.strip()]
    if extra := _input(env, "extra-args"):
        argv += shlex.split(extra)
    return argv


def _escape(text: str) -> str:
    """Escape a workflow-command message (``%``, CR and LF must be encoded)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    """Escape a workflow-command property value (also ``:`` and ``,``)."""
    return _escape(text).replace(":", "%3A").replace(",", "%2C")


def sarif_counts(path: Path) -> dict[str, int]:
    """Count SARIF results per mcpprobe severity (empty when the file is missing or unreadable)."""
    counts = dict.fromkeys(_SEVERITIES, 0)
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
        for run in data.get("runs", []):
            for result in run.get("results", []):
                sev = str(result.get("properties", {}).get("severity", "info"))
                counts[sev if sev in counts else "info"] += 1
    except (OSError, ValueError, AttributeError):
        return {}
    return counts


def describe(code: int, target: str, fail_on: str, counts: Mapping[str, int]) -> tuple[str, str, str]:
    """Return (annotation level, title, message) for an exit code."""
    total = sum(counts.values())
    breakdown = ", ".join(f"{counts[s]} {s}" for s in _SEVERITIES if counts.get(s))
    if code == EXIT_CLEAN:
        found = f" ({breakdown} below the threshold)" if breakdown else ""
        return "notice", "mcpprobe: passed", f"No finding at or above '{fail_on}' on {target}{found}."
    if code == EXIT_FINDINGS:
        return (
            "error",
            "mcpprobe: findings",
            f"{total} finding(s) on {target} ({breakdown}); at least one is at or above '{fail_on}'. "
            "See the job summary or the code scanning alerts.",
        )
    if code == EXIT_NOT_MCP:
        return (
            "error",
            "mcpprobe: not an MCP server",
            f"{target} answered, but not as an MCP server, so nothing was checked and nothing passed. "
            "Check the URL and path (Streamable HTTP endpoints are usually /mcp) and that the "
            "deployment is up. Do not upload this SARIF: it has no results and would close open alerts.",
        )
    return (
        "error",
        "mcpprobe: scan error",
        f"The scan of {target} did not complete (exit {code}): the target was unreachable, an input "
        "was invalid, the target opted out, or authorisation was refused. See the step log.",
    )


def _summary(code: int, target: str, fail_on: str, counts: Mapping[str, int], message: str) -> str:
    lines = [
        "## mcpprobe MCP security scan",
        "",
        f"**Target:** `{target}`  ",
        f"**Result:** {RESULTS.get(code, 'error')} (exit {code}, fail-on `{fail_on}`)",
        "",
        message,
        "",
    ]
    if code in (EXIT_CLEAN, EXIT_FINDINGS) and counts:
        lines += ["| Severity | Findings |", "|---|---|"]
        lines += [f"| {s} | {counts[s]} |" for s in _SEVERITIES]
        lines.append("")
    lines.append(
        "Docs: https://mcpprobe.tech · checks: https://github.com/mcpprobe-dev/mcpprobe/blob/main/CHECKS.md"
    )
    return "\n".join(lines) + "\n"


def run(env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    try:
        argv = build_argv(env)
    except ValueError as exc:
        print(
            f"::error title={_escape_property('mcpprobe: bad input')}::{_escape(str(exc))}", file=sys.stderr
        )
        return EXIT_ERROR
    code = EXIT_ERROR
    try:
        main(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_ERROR
    target = argv[1]
    fail_on = argv[argv.index("--fail-on") + 1]
    sarif = argv[argv.index("--sarif") + 1]
    counts = sarif_counts(Path(sarif))
    level, title, message = describe(code, target, fail_on, counts)
    print(f"::{level} title={_escape_property(title)}::{_escape(message)}", file=sys.stderr)
    out = env.get("GITHUB_OUTPUT")
    if out:
        with Path(out).open("a", encoding="utf-8") as fh:
            fh.write(f"sarif-file={sarif if Path(sarif).exists() else ''}\n")
            fh.write(f"exit-code={code}\n")
            fh.write(f"result={RESULTS.get(code, 'error')}\n")
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as fh:
            fh.write(_summary(code, target, fail_on, counts, message))
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
