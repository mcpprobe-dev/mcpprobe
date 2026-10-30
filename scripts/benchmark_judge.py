"""Benchmark META-01 (heuristics) and, optionally, the Hugging Face judge.

Datasets:

* ``corpus``: the project's own benign/poisoned tool-description corpus
  (tests/data/meta01_corpus.json). The heuristics were tuned on it, so these
  numbers are in-sample.
* ``held-out``: tests/data/meta01_heldout.json, written for the 0.3 benchmark and
  not used to tune the heuristics (out-of-sample, still small).
* ``hub:<dataset-id>``: a public prompt-injection dataset from the Hugging Face Hub
  (default ``deepset/prompt-injections``, columns ``text`` and ``label`` with 1 =
  injection). Needs ``pip install datasets`` and network access to the Hub. Those
  are user prompts, not tool descriptions: a different domain, reported separately.

Usage::

    python scripts/benchmark_judge.py                       # corpus + hub dataset if reachable
    python scripts/benchmark_judge.py --judge hf:<model>    # also the HF judge (needs [hf] extra)
    python scripts/benchmark_judge.py --write docs/benchmark.md

A text counts as flagged by the heuristics when META-01's analyser raises an
indicator at medium severity or above (the bar the test-suite uses), and, in a
second row, at any severity. Nothing here contacts an MCP server.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcpprobe import __version__  # noqa: E402
from mcpprobe.checks.poisoning import analyse_text  # noqa: E402
from mcpprobe.models import Severity  # noqa: E402

CORPUS = ROOT / "tests" / "data" / "meta01_corpus.json"
HELDOUT = ROOT / "tests" / "data" / "meta01_heldout.json"
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


Detector = Callable[[str], bool]


def heuristic(min_severity: Severity) -> Detector:
    def detect(text: str) -> bool:
        return any(i.severity >= min_severity for i in analyse_text(text))

    return detect


def evaluate(detector: Detector, samples: Iterable[tuple[str, bool]]) -> Scores:
    scores = Scores()
    for text, label in samples:
        scores.add(detector(text), label)
    return scores


def load_corpus(path: Path = CORPUS) -> list[tuple[str, bool]]:
    data = json.loads(path.read_text("utf-8"))
    return [(t, False) for t in data["benign"]] + [(t, True) for t in data["poisoned"]]


def load_hub(dataset_id: str, split: str) -> tuple[list[tuple[str, bool]] | None, str]:
    """Return (samples, note). ``samples`` is None when the dataset could not be loaded."""
    try:
        import datasets  # type: ignore[import-not-found]
    except ImportError:
        return None, "the 'datasets' package is not installed (pip install datasets)"
    try:
        ds = datasets.load_dataset(dataset_id, split=split)
    except Exception as exc:  # network, auth or format problems are all reported, not raised
        return None, f"could not load {dataset_id} ({type(exc).__name__}: {str(exc).splitlines()[0][:200]})"
    rows = [(str(r["text"]), bool(int(r["label"]))) for r in ds]
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
    args = ap.parse_args(argv)

    datasets_: list[tuple[str, list[tuple[str, bool]]]] = [
        ("mcpprobe corpus (in-sample)", load_corpus()),
        ("mcpprobe held-out set", load_corpus(HELDOUT)),
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

            def judged(text: str) -> bool:
                verdict = judge(text, "benchmark")
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
    misses = ["| Dataset | Detector | Kind | Text |", "|---|---|---|---|"]
    for ds_name, samples in datasets_[:2]:
        for det_name, det in detectors:
            for text, label in samples:
                if det(text) != label:
                    kind = "missed (FN)" if label else "false alarm (FP)"
                    shown = text.encode("unicode_escape").decode("ascii") if not text.isascii() else text
                    misses.append(f"| {ds_name} | {det_name} | {kind} | {shown.replace('|', '/')} |")
    if len(misses) > 2:
        table += "\n\n### Every miss on the mcpprobe sets\n\n" + "\n".join(misses)
    print(table)
    print("\n".join(notes))
    if args.write:
        args.write.write_text(render_report(table, notes), "utf-8")
        print(f"wrote {args.write}")
    return 0


def render_report(table: str, notes: list[str]) -> str:
    return (
        "# META-01 benchmark\n\n"
        "Generated by `python scripts/benchmark_judge.py --write docs/benchmark.md`. "
        "Re-run it to refresh the numbers; edit the text around the generated table by hand only in the script.\n\n"
        + table
        + "\n\n## Run notes\n\n"
        + "\n".join(f"- {n}" for n in notes)
        + "\n\n## How to read this\n\n"
        "- A text is *flagged* by the heuristics when META-01 raises an indicator at medium severity or above "
        "(first row) or at any severity (second row). Low-severity indicators (a URL, a mention of another tool) "
        "are review prompts, not verdicts.\n"
        "- The mcpprobe corpus is the one the heuristics were tuned on, so its numbers are in-sample and "
        "optimistic. The held-out set was written for this benchmark and not used for tuning; it is the "
        "better estimate, but it is small (60 texts) and written by the same project, so one miss moves "
        "recall by five points and it is not an independent sample.\n"
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
