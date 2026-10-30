"""Command-line interface.

``mcpprobe <target>`` is shorthand for ``mcpprobe scan <target>``.

Exit codes: 0 = no findings at or above ``--fail-on``; 1 = findings at or
above ``--fail-on``; 2 = error (unreachable target, opt-out, authorisation
refused, bad arguments).
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Sequence

import click
from rich.console import Console

from mcpprobe import POLICY_URL, USER_AGENT, __version__
from mcpprobe.authz import (
    AuthorisationError,
    authorise,
    expected_txt_record,
    generate_token,
    save_token,
    write_record,
)
from mcpprobe.checks import ALL_CHECKS, ScanOptions
from mcpprobe.checks._util import host_of
from mcpprobe.dnsutil import record_name
from mcpprobe.judges import JudgeUnavailable, load_judge
from mcpprobe.models import CheckMode, Severity
from mcpprobe.policy import DEFAULT_RATE, MAX_RATE, OptOutError
from mcpprobe.report import render, write_json, write_sarif
from mcpprobe.scanner import ScanConfig, run_scan
from mcpprobe.transport import TransportError, ensure_url
from mcpprobe.transport.base import DEFAULT_THROTTLE_BUDGET

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
#: The target answered, but not as an MCP server (e.g. an ordinary web site). No check ran.
EXIT_NOT_MCP = 3

SEVERITIES = [s.value for s in Severity]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="mcpprobe")
def cli() -> None:
    """mcpprobe: security scanner for MCP servers. Scan only servers you own or are authorised to test."""


def _parse_kv(values: Sequence[str], what: str, sep: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values:
        key, found, value = item.partition(sep)
        if not found or not key.strip():
            raise click.BadParameter(f"{what} must be KEY{sep}VALUE, got {item!r}")
        out[key.strip()] = value.strip()
    return out


@cli.command("scan")
@click.argument("target")
@click.option("--stdio", is_flag=True, help="Treat TARGET as a local command to spawn (stdio transport).")
@click.option(
    "--env", "env_vars", multiple=True, help="Environment for the stdio server, KEY=VALUE (repeatable)."
)
@click.option(
    "--header",
    "headers",
    multiple=True,
    help="Extra HTTP header, 'Name: value' (repeatable), e.g. a bearer token you own.",
)
@click.option(
    "--active", is_flag=True, help="Enable active checks. Requires --authorised-by, --scope and --verify."
)
@click.option("--authorised-by", help="Who authorised this scan (name/role/ticket). Required for --active.")
@click.option(
    "--scope",
    help="Agreed scope statement, e.g. 'https://host/mcp, read-only tools only'. Required for --active.",
)
@click.option(
    "--verify",
    "verify_method",
    type=click.Choice(["dns-txt", "local"]),
    help="Ownership verification method for --active.",
)
@click.option(
    "--token", help="Verification token for --verify dns-txt (default: the one saved by 'mcpprobe token')."
)
@click.option(
    "--reference", help="Operator reference stored in the authorisation record (ticket, change number)."
)
@click.option(
    "--exclude-tool",
    "excluded_tools",
    multiple=True,
    help="Tool names that must never be called (repeatable).",
)
@click.option(
    "--rate",
    default=DEFAULT_RATE,
    show_default=True,
    type=click.FloatRange(min=0.1, max=MAX_RATE),
    help=f"Maximum requests per second (hard ceiling {MAX_RATE:g}).",
)
@click.option("--timeout", default=15.0, show_default=True, help="Per-request timeout in seconds.")
@click.option(
    "--fail-on",
    default="high",
    type=click.Choice(SEVERITIES),
    show_default=True,
    help="Exit 1 if any finding is at or above this severity.",
)
@click.option(
    "--json", "json_path", type=click.Path(dir_okay=False), help="Write the JSON report (with evidence) here."
)
@click.option(
    "--sarif", "sarif_path", type=click.Path(dir_okay=False), help="Write a SARIF 2.1.0 report here."
)
@click.option(
    "--sarif-location", help="Repository-relative file to anchor SARIF results to (default: the target URI)."
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(dir_okay=False),
    help="META-02 baseline file to compare against and update.",
)
@click.option("--no-write-baseline", is_flag=True, help="Compare against --baseline but do not overwrite it.")
@click.option(
    "--no-follow-as",
    is_flag=True,
    help="AUTH-03: do not fetch authorization-server metadata on third-party hosts.",
)
@click.option(
    "--rate-limit-wait",
    default=DEFAULT_THROTTLE_BUDGET,
    show_default=True,
    type=click.FloatRange(min=0, max=300),
    help="Total seconds to wait on HTTP 429 / Retry-After; when used up, affected checks are not applicable.",
)
@click.option(
    "--judge",
    "judge_spec",
    help="Opt-in second opinion for META-01, e.g. hf:<model-id-or-path> (needs mcpprobe-scanner[hf]).",
)
@click.option(
    "--judge-download",
    is_flag=True,
    help="Allow --judge hf:<model-id> to download the model from the Hugging Face Hub (default: local cache only).",
)
@click.option(
    "--judge-threshold",
    default=0.5,
    show_default=True,
    type=click.FloatRange(min=0.01, max=0.99),
    help="Classifier score at or above which the judge flags a description.",
)
@click.option("--only", multiple=True, help="Run only these check IDs (repeatable).")
@click.option("--skip", multiple=True, help="Skip these check IDs (repeatable).")
@click.option("--insecure", is_flag=True, help="Do not verify the target's TLS certificate.")
@click.option("--verbose", "-v", is_flag=True, help="Show descriptions and fixes in the terminal summary.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress the terminal summary.")
def scan_cmd(
    target: str,
    stdio: bool,
    env_vars: Sequence[str],
    headers: Sequence[str],
    active: bool,
    authorised_by: str | None,
    scope: str | None,
    verify_method: str | None,
    token: str | None,
    reference: str | None,
    excluded_tools: Sequence[str],
    rate: float,
    timeout: float,
    fail_on: str,
    json_path: str | None,
    sarif_path: str | None,
    sarif_location: str | None,
    baseline_path: str | None,
    no_write_baseline: bool,
    no_follow_as: bool,
    rate_limit_wait: float,
    judge_spec: str | None,
    judge_download: bool,
    judge_threshold: float,
    only: Sequence[str],
    skip: Sequence[str],
    insecure: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Scan TARGET (an http(s) URL, or a command with --stdio)."""
    console = Console(stderr=True)
    err = Console(stderr=True, style="bold red")
    try:
        if not stdio:
            target = ensure_url(target)
        transport_kind = "stdio" if stdio else "http"
        host = "" if stdio else host_of(target)
        try:
            record = authorise(
                target=target,
                transport=transport_kind,
                host=host,
                active=active,
                authorised_by=authorised_by,
                scope=scope,
                verify_method=verify_method,
                token=token,
                excluded_tools=excluded_tools,
                rate_cap_rps=rate,
                reference=reference,
            )
        except AuthorisationError as exc:
            err.print(f"authorisation refused: {exc}", markup=False, highlight=False)
            err.print("active mode was not started; no request was sent to the target.", markup=False)
            sys.exit(EXIT_ERROR)
        judge = None
        if judge_spec:
            try:
                judge = load_judge(judge_spec, allow_download=judge_download, threshold=judge_threshold)
            except JudgeUnavailable as exc:
                err.print(f"judge not loaded: {exc}", markup=False, highlight=False)
                sys.exit(EXIT_ERROR)
        options = ScanOptions(
            judge=judge,
            mode=CheckMode.ACTIVE if active else CheckMode.PASSIVE,
            baseline_path=baseline_path,
            write_baseline=not no_write_baseline,
            excluded_tools=set(excluded_tools),
            follow_authorization_server=not no_follow_as,
            timeout=timeout,
        )
        config = ScanConfig(
            target=target,
            stdio=stdio,
            stdio_env=_parse_kv(env_vars, "--env", "="),
            headers=_parse_kv(headers, "--header", ":"),
            timeout=timeout,
            rate=rate,
            options=options,
            only=list(only) or None,
            skip=list(skip) or None,
            authorisation=record if active else None,
            user_agent=USER_AGENT,
            verify_tls=not insecure,
            max_rate_limit_wait=rate_limit_wait,
        )
        if not quiet:
            console.print(
                f"[dim]mcpprobe {__version__} | {('active' if active else 'passive')} mode | rate {rate}/s | "
                f"scan only what you own or are authorised to test | {POLICY_URL}[/dim]"
            )
        report, evidence = asyncio.run(run_scan(config))
    except OptOutError as exc:
        err.print(f"aborted: {exc}", markup=False, highlight=False)
        sys.exit(EXIT_ERROR)
    except (TransportError, AuthorisationError) as exc:
        err.print(f"error: {exc}", markup=False, highlight=False)
        sys.exit(EXIT_ERROR)
    except click.ClickException:
        raise
    except KeyError as exc:
        err.print(f"error: {exc.args[0] if exc.args else exc}", markup=False, highlight=False)
        sys.exit(EXIT_ERROR)

    if active:
        path = write_record(record, json_path or sarif_path)
        report.authorisation_record = str(path)
    if json_path:
        write_json(report, json_path, evidence)
    if sarif_path:
        write_sarif(report, sarif_path, location_uri=sarif_location)
    threshold = Severity(fail_on)
    if report.target_kind != "mcp":
        if not quiet:
            render(report, Console(), verbose=verbose, show_evidence=True)
        err.print(
            report.fingerprint.error if report.fingerprint else report.target_kind,
            markup=False,
            highlight=False,
        )
        sys.exit(EXIT_NOT_MCP if report.target_kind == "not_mcp" else EXIT_ERROR)
    if not quiet:
        render(report, Console(), verbose=verbose, show_evidence=True, fail_on=threshold)
        outputs = (
            ("JSON", json_path),
            ("SARIF", sarif_path),
            ("authorisation record", report.authorisation_record),
        )
        for label, out_path in outputs:
            if out_path:
                console.print(f"{label}: {out_path}", style="dim", markup=False, highlight=False)
    worst = report.max_severity()
    sys.exit(EXIT_FINDINGS if worst is not None and worst >= threshold else EXIT_CLEAN)


@cli.command("checks")
@click.option("--format", "fmt", type=click.Choice(["table", "markdown"]), default="table", show_default=True)
def checks_cmd(fmt: str) -> None:
    """List every check with its mode, default severity and standards mapping."""
    if fmt == "markdown":
        from mcpprobe.catalogue import checks_markdown

        click.echo(checks_markdown(), nl=False)
        return
    from rich.table import Table

    table = Table(title=f"mcpprobe {__version__} checks")
    for col in ("ID", "Mode", "Severity", "Title", "Standards"):
        table.add_column(col)
    for c in ALL_CHECKS:
        table.add_row(c.id, c.mode.value, c.severity.value, c.title, ", ".join(c.standards.as_tags()) or "-")
    Console().print(table)


@cli.command("token")
@click.argument("host")
def token_cmd(host: str) -> None:
    """Generate and save an ownership-verification token for HOST and print the TXT record to publish."""
    token = generate_token()
    path = save_token(host, token)
    click.echo(f"Saved token for {host} in {path}")
    click.echo("Publish this DNS TXT record, then run with --active --verify dns-txt:")
    click.echo(f'  {record_name(host)}.  TXT  "{expected_txt_record(token)}"')


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point: default to the ``scan`` sub-command when the first argument is a target."""
    args = list(sys.argv[1:] if argv is None else argv)
    known = {"scan", "checks", "token"}
    group_options = {"-h", "--help", "--version"}
    if args and args[0] not in known and args[0] not in group_options:
        args.insert(0, "scan")
    cli.main(args=args, prog_name="mcpprobe", standalone_mode=True)


if __name__ == "__main__":  # pragma: no cover
    main()
