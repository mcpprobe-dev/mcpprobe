"""Entry point for the Docker container GitHub Action (``action.yml``).

GitHub passes action inputs as ``INPUT_<NAME>`` environment variables (name
upper-cased, hyphens kept). This module turns them into a CLI invocation,
always writes SARIF, records outputs in ``$GITHUB_OUTPUT`` and exits with the
scanner's exit code (0 clean, 1 findings at or above ``fail-on``, 2 error).
"""

from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path

from mcpprobe.cli import EXIT_ERROR, main


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


def run(env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    try:
        argv = build_argv(env)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return EXIT_ERROR
    code = EXIT_ERROR
    try:
        main(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_ERROR
    out = env.get("GITHUB_OUTPUT")
    if out:
        sarif = argv[argv.index("--sarif") + 1]
        with Path(out).open("a", encoding="utf-8") as fh:
            fh.write(f"sarif-file={sarif}\n")
            fh.write(f"exit-code={code}\n")
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
