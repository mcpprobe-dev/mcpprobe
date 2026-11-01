"""Benchmark META-01 (heuristics) and, optionally, the Hugging Face judge.

Datasets:

* ``corpus``: the project's own benign/poisoned tool-description corpus
  (tests/data/meta01_corpus.json). The heuristics were tuned on it, so these
  numbers are in-sample.
* ``held-out``: tests/data/meta01_heldout.json, written for the 0.3 benchmark and
  not used to tune the heuristics (out-of-sample, still small).
* ``real-benign``: tests/data/meta01_real_benign.json, thousands of real tool and parameter
  descriptions harvested offline from published open-source MCP server packages, all
  labelled benign. Its ``tuning`` split was used while retuning META-01 in 0.3.1; its
  ``heldout`` split comes from different packages collected after the rules were frozen.
  Each text is analysed with its sibling tool names, as a scan would.
* ``hub:<dataset-id>``: a public prompt-injection dataset from the Hugging Face Hub
  (default ``deepset/prompt-injections``, columns ``text`` and ``label`` with 1 =
  injection). Needs ``pip install datasets`` and network access to the Hub. Those
  are user prompts, not tool descriptions: a different domain, reported separately.

Usage::

    python scripts/benchmark_judge.py                       # corpus + hub dataset if reachable
    python scripts/benchmark_judge.py --judge hf:<model>    # also the HF judge (needs [hf] extra)
    python scripts/benchmark_judge.py --write docs/benchmark.md
    python scripts/benchmark_judge.py --baseline-ref origin/registry-report   # before/after table

A text counts as flagged by the heuristics when META-01's analyser raises an
indicator at medium severity or above (the bar the test-suite uses), and, in a
second row, at any severity. Nothing here contacts an MCP server.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcpprobe import __version__  # noqa: E402
from mcpprobe.checks.poisoning import analyse_text  # noqa: E402
from mcpprobe.models import Severity  # noqa: E402

CORPUS = ROOT / "tests" / "data" / "meta01_corpus.json"
HELDOUT = ROOT / "tests" / "data" / "meta01_heldout.json"
REAL_BENIGN = ROOT / "tests" / "data" / "meta01_real_benign.json"
DEFAULT_HUB_DATASET = "deepset/prompt-injections"


@dataclass
class Scores:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted:
            self.fp += 1
        elif actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def fp_rate(self) -> float | None:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else None


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


#: A sample is (text, label, sibling tool names, own tool name).
Sample = tuple[str, bool, tuple[str, ...], str]
Detector = Callable[[Sample], bool]
Analyser = Callable[..., list[Any]]


def heuristic(min_severity: Severity, analyser: Analyser = analyse_text) -> Detector:
    def detect(sample: Sample) -> bool:
        text, _label, siblings, own = sample
        return any(
            i.severity >= min_severity for i in analyser(text, other_tool_names=siblings, own_name=own)
        )

    return detect


def load_baseline(ref: str) -> Analyser:
    """``analyse_text`` as it was at git ``ref`` (for the before/after table)."""
    source = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{ref}:mcpprobe/checks/poisoning.py"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(source)
    spec = importlib.util.spec_from_file_location("_meta01_baseline", fh.name)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    Path(fh.name).unlink()
    return module.analyse_text  # type: ignore[no-any-return]


def evaluate(detector: Detector, samples: Iterable[Sample]) -> Scores:
    scores = Scores()
    for sample in samples:
        scores.add(detector(sample), sample[1])
    return scores


def load_corpus(path: Path = CORPUS) -> list[Sample]:
    data = json.loads(path.read_text("utf-8"))
    return [(t, False, (), "") for t in data["benign"]] + [(t, True, (), "") for t in data["poisoned"]]


def load_real_benign(split: str, path: Path = REAL_BENIGN) -> list[Sample]:
    rows = json.loads(path.read_text("utf-8"))[split]
    siblings: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        if r["kind"] == "tool" and r["name"]:
            siblings[r["source"]].append(r["name"])
    return [(r["text"], False, tuple(siblings[r["source"]]), r["name"]) for r in rows]


def real_sources(split: str, path: Path = REAL_BENIGN) -> list[str]:
    return [r["source"] for r in json.loads(path.read_text("utf-8"))[split]]


def per_package(detector: Detector, split: str) -> tuple[int, int]:
    """(packages with at least one flagged text, packages): the analogue of a per-host survey rate."""
    flagged: dict[str, bool] = defaultdict(bool)
    for sample, source in zip(load_real_benign(split), real_sources(split), strict=True):
        flagged[source] |= detector(sample)
    return sum(flagged.values()), len(flagged)


def load_hub(dataset_id: str, split: str) -> tuple[list[Sample] | None, str]:
    """Return (samples, note). ``samples`` is None when the dataset could not be loaded."""
    try:
        import datasets  # type: ignore[import-not-found]
    except ImportError:
        return None, "the 'datasets' package is not installed (pip install datasets)"
    try:
        ds = datasets.load_dataset(dataset_id, split=split)
    except Exception as exc:  # network, auth or format problems are all reported, not raised
        return None, f"could not load {dataset_id} ({type(exc).__name__}: {str(exc).splitlines()[0][:200]})"
    rows: list[Sample] = [(str(r["text"]), bool(int(r["label"])), (), "") for r in ds]
    return rows, f"{dataset_id} split '{split}', {len(rows)} rows"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hub-dataset", default=DEFAULT_HUB_DATASET, help="Hub dataset id ('' to skip)")
    ap.add_argument("--split", default="test")
    ap.add_argument(
        "--judge", help="also evaluate a judge, e.g. hf:protectai/deberta-v3-base-prompt-injection-v2"
    )
    ap.add_argument("--judge-download", action="store_true", help="allow the judge model to be downloaded")
    ap.add_argument("--write", type=Path, help="write the Markdown report here")
    ap.add_argument(
        "--baseline-ref",
        default="a9481e7",
        help="git ref whose META-01 analyser is the 'before' column ('' to skip); default: the 0.3.0 rules the registry survey ran with",
    )
    args = ap.parse_args(argv)

    poisoned = [x for x in load_corpus() + load_corpus(HELDOUT) if x[1]]
    datasets_: list[tuple[str, list[Sample]]] = [
        ("mcpprobe corpus (in-sample)", load_corpus()),
        ("mcpprobe held-out set", load_corpus(HELDOUT)),
        ("real benign, tuning split + all poisoned", load_real_benign("tuning") + poisoned),
        ("real benign, held-out split + all poisoned", load_real_benign("heldout") + poisoned),
    ]
    notes: list[str] = [f"mcpprobe {__version__}, run {dt.date.today().isoformat()}."]
    if args.hub_dataset:
        rows, note = load_hub(args.hub_dataset, args.split)
        notes.append(f"Hub dataset: {note}.")
        if rows is not None:
            datasets_.append((f"{args.hub_dataset} ({args.split})", rows))

    detectors: list[tuple[str, Detector]] = [
        ("META-01 heuristics, medium or above", heuristic(Severity.MEDIUM)),
        ("META-01 heuristics, any indicator", heuristic(Severity.LOW)),
    ]
    if args.judge:
        from mcpprobe.judges import JudgeUnavailable, load_judge

        try:
            judge = load_judge(args.judge, allow_download=args.judge_download)
        except JudgeUnavailable as exc:
            notes.append(f"Judge {args.judge} not evaluated: {exc}")
        else:

            def judged(sample: Sample) -> bool:
                verdict = judge(sample[0], "benchmark")
                return bool(verdict and verdict.suspicious)

            detectors.append((f"judge {args.judge}", judged))
    else:
        notes.append("No judge evaluated (pass --judge hf:<model> with the [hf] extra installed).")

    lines = [
        "| Dataset | Detector | n | TP | FP | TN | FN | Precision | Recall | FP rate |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for ds_name, samples in datasets_:
        for det_name, det in detectors:
            s = evaluate(det, samples)
            lines.append(
                f"| {ds_name} | {det_name} | {s.n} | {s.tp} | {s.fp} | {s.tn} | {s.fn} | "
                f"{_pct(s.precision)} | {_pct(s.recall)} | {_pct(s.fp_rate)} |"
            )
    table = "\n".join(lines)
    if args.baseline_ref:
        table += "\n\n" + before_after(args.baseline_ref, datasets_[:4])
    misses = ["| Dataset | Detector | Kind | Text |", "|---|---|---|---|"]
    for ds_name, samples in datasets_[:4]:
        for det_name, det in detectors:
            for sample in samples:
                text, label = sample[0], sample[1]
                if ds_name.startswith("real") and label:
                    continue  # poisoned misses are already listed under the two mcpprobe sets
                if det(sample) != label:
                    kind = "missed (FN)" if label else "false alarm (FP)"
                    shown = text.encode("unicode_escape").decode("ascii") if not text.isascii() else text
                    shown = " ".join(shown.split())
                    if len(shown) > 300:
                        shown = shown[:300] + "..."
                    misses.append(f"| {ds_name} | {det_name} | {kind} | {shown.replace('|', '/')} |")
    if len(misses) > 2:
        table += "\n\n### Every miss\n\n" + "\n".join(misses)
    print(table)
    print("\n".join(notes))
    if args.write:
        args.write.write_text(render_report(table, notes), "utf-8")
        print(f"wrote {args.write}")
    return 0


def before_after(ref: str, datasets_: list[tuple[str, list[Sample]]]) -> str:
    """Before (analyser at ``ref``) and after (working tree) on the same samples."""
    try:
        old = load_baseline(ref)
    except (subprocess.CalledProcessError, OSError) as exc:
        return f"(before/after table skipped: could not load {ref}: {exc})"
    out = [
        f"### Before ({ref}) and after (this version)",
        "",
        "| Dataset | Bar | n | Precision before | Precision after | Recall before | Recall after "
        "| FP rate before | FP rate after |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for ds_name, samples in datasets_:
        for bar_name, bar in (("medium or above", Severity.MEDIUM), ("any indicator", Severity.LOW)):
            b = evaluate(heuristic(bar, old), samples)
            a = evaluate(heuristic(bar, analyse_text), samples)
            out.append(
                f"| {ds_name} | {bar_name} | {a.n} | {_pct(b.precision)} | {_pct(a.precision)} | "
                f"{_pct(b.recall)} | {_pct(a.recall)} | {_pct(b.fp_rate)} | {_pct(a.fp_rate)} |"
            )
    out += [
        "",
        "Per package (share of real packages with at least one flagged description; the analogue of "
        "the registry survey's per-host rate):",
        "",
        "| Split | Bar | Packages | Before | After |",
        "|---|---|---|---|---|",
    ]
    for split in ("tuning", "heldout"):
        for bar_name, bar in (("medium or above", Severity.MEDIUM), ("any indicator", Severity.LOW)):
            kb, n = per_package(heuristic(bar, old), split)
            ka, _ = per_package(heuristic(bar, analyse_text), split)
            out.append(f"| {split} | {bar_name} | {n} | {kb} ({_pct(kb / n)}) | {ka} ({_pct(ka / n)}) |")
    return "\n".join(out)


def render_report(table: str, notes: list[str]) -> str:
    return (
        "# META-01 benchmark\n\n"
        "Generated by `python scripts/benchmark_judge.py --write docs/benchmark.md`. "
        "Re-run it to refresh the numbers; edit the text around the generated table by hand only in the script.\n\n"
        + table
        + "\n\n## Run notes\n\n"
        + "\n".join(f"- {n}" for n in notes)
        + "\n\n## The 0.3.1 retune\n\n"
        "The first registry survey (0.3.0) flagged META-01 on 83% of servers that listed tools, 63% at medium "
        "or above. On real descriptions from published servers the 0.3.0 rules raised medium or above on "
        "2.8% of texts but on 22.5% of packages, because a server is flagged when any one of its tool, "
        "parameter or instruction texts matches, and the indicators that fired were ordinary documentation:\n\n"
        "- `cross_tool_reference` at medium whenever a sibling tool was named in a text that also contained "
        'any of `when, before, after, always, never, prefer, instead...` ("call list_projects before this '
        'tool"), and at low for any mention at all, including tools named with dictionary words such as '
        "`search` matching ordinary prose;\n"
        '- the `model directive` rule, which made usage guidance ("always use this tool to...", "you '
        'must call X first", "call this first when...") a medium finding on its own;\n'
        "- `url` at low for every documentation link, `sensitive_path` at medium for any mention of `.env`, "
        '`mcp.json` or `~/.ssh` (including "paths such as ~/.ssh are rejected"), and `email_redirect` '
        "at high for `user@example.com` in parameter docs;\n"
        "- server `initialize.instructions`, whose whole purpose is to steer the model, analysed exactly "
        "like a tool description.\n\n"
        "0.3.1 keeps every high-specificity rule and changes those: usage guidance only counts alongside "
        "another instruction category; shadowing needs wording that changes what another tool does "
        '("when send_email is used...", "do not use X", "X must route...", redirect/intercept/'
        "override); dictionary-word tool names count only when quoted; plain URLs and example.com addresses "
        "are not indicators; a credential path is medium only after a read/send verb and not negated; "
        "shadowing in server instructions is low. The demo's run_command and the 0.2.0 planted-instruction "
        "(`add` with `<IMPORTANT>` and `~/.ssh/id_rsa`) remain high.\n" + "\n## How to read this\n\n"
        "- A text is *flagged* by the heuristics when META-01 raises an indicator at medium severity or above "
        "(first row) or at any severity (second row). Low-severity indicators (a credential path without a "
        "read/send verb, a URL next to send wording, a long description) are review prompts, not verdicts.\n"
        "- The mcpprobe corpus is the one the heuristics were tuned on, so its numbers are in-sample and "
        "optimistic. The held-out set was written for this benchmark and not used for tuning; it is the "
        "better estimate, but it is small (60 texts) and written by the same project, so one miss moves "
        "recall by five points and it is not an independent sample.\n"
        "- The real-benign sets are thousands of descriptions from published MCP server packages (official "
        "reference servers and vendor servers on npm and PyPI), all labelled benign, each analysed with its "
        "sibling tool names. Precision there is computed against all 31 poisoned texts of the two mcpprobe "
        "sets, so it depends on that mix; the FP rate is the base-rate-free number. The tuning split was "
        "used while retuning in 0.3.1; the held-out split comes from other packages, collected after the "
        "rules were frozen, and is the honest false-positive estimate. Recall is measured only on the "
        "project's 31 poisoned texts; there is no independent corpus of real poisoned MCP descriptions.\n"
        "- The before/after table runs the 0.3.0 analyser (git ref shown) on the same samples.\n"
        "- Hub prompt-injection datasets contain user prompts and jailbreaks, not tool descriptions, and "
        "include non-English text; META-01 is written for English tool metadata, so recall there is expected "
        "to be low and is a lower bound on domain transfer, not a measure of META-01 on MCP servers.\n"
        "- No competitor publishes comparable detection rates; treat these as a regression baseline.\n"
        f"- The default Hub dataset is {DEFAULT_HUB_DATASET}. Its licence was not verified when this "
        "script was written (the Hub page could not be fetched); it is recalled as Apache-2.0. Check the "
        "dataset card before relying on it.\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())
