"""Local Hugging Face prompt-injection classifier as a META-01 second-opinion judge.

Opt-in only: ``mcpprobe <target> --judge hf:<model-id-or-path>`` with the optional
extra installed (``pip install 'mcpprobe-scanner[hf]'``, which brings transformers,
torch and safetensors). Safety rules, enforced in code:

* weights are loaded with ``use_safetensors=True``, so a model that only ships
  pickle (``.bin``) weights is refused rather than unpickled;
* ``trust_remote_code=False``: no model-supplied Python runs;
* nothing is downloaded unless ``allow_download`` is set (``--judge-download``); by
  default a hub id must already be in the local Hugging Face cache, and a local
  directory is loaded with ``local_files_only=True``;
* the model runs locally; descriptions are never sent anywhere.

The judge returns a :class:`~mcpprobe.checks.base.JudgeVerdict`; META-01 turns a
suspicious verdict into a medium-severity indicator next to its own heuristics. A
classifier alone never yields high confidence (see :data:`MEDIUM_SCORE`).

Licences differ per model; see docs/judges.md before using one.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcpprobe.checks.base import JudgeVerdict
from mcpprobe.judges import JudgeUnavailable
from mcpprobe.models import Confidence

#: Label names (upper-cased) that mean "this text is an injection".
POSITIVE_LABELS: frozenset[str] = frozenset(
    {"INJECTION", "JAILBREAK", "MALICIOUS", "UNSAFE", "PROMPT_INJECTION"}
)
#: Score at or above which a positive verdict carries medium confidence (otherwise low).
MEDIUM_SCORE = 0.9
#: Tokens fed to the classifier per text (longer descriptions are truncated).
MAX_TOKENS = 512

#: ``(model, tokenizer_kwargs) -> callable(text) -> [{"label": str, "score": float}, ...]``
PipelineFactory = Callable[[str, dict[str, Any]], Callable[[str], Any]]


def _transformers_pipeline(model: str, load_kwargs: dict[str, Any]) -> Callable[[str], Any]:
    try:
        import transformers
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise JudgeUnavailable(
            "the hf judge needs the optional extra: pip install 'mcpprobe-scanner[hf]'"
        ) from exc
    try:
        tokenizer = transformers.AutoTokenizer.from_pretrained(model, **load_kwargs)
        clf = transformers.AutoModelForSequenceClassification.from_pretrained(
            model, use_safetensors=True, **load_kwargs
        )
    except OSError as exc:  # pragma: no cover - depends on the local cache
        hint = (
            " It is not in the local Hugging Face cache; pass --judge-download to fetch it."
            if load_kwargs.get("local_files_only")
            else ""
        )
        raise JudgeUnavailable(f"could not load {model!r} with safetensors weights: {exc}.{hint}") from exc
    pipe = transformers.pipeline(
        "text-classification", model=clf, tokenizer=tokenizer, truncation=True, max_length=MAX_TOKENS
    )
    return lambda text: pipe(text, top_k=None)


class HuggingFaceJudge:
    """Callable judge: ``judge(text, task) -> JudgeVerdict | None``."""

    def __init__(
        self,
        model: str,
        *,
        threshold: float = 0.5,
        allow_download: bool = False,
        pipeline_factory: PipelineFactory | None = None,
    ) -> None:
        if not 0.0 < threshold < 1.0:
            raise JudgeUnavailable("threshold must be between 0 and 1")
        self.model = model
        self.threshold = threshold
        load_kwargs: dict[str, Any] = {"trust_remote_code": False}
        if Path(model).expanduser().is_dir():
            self.model = str(Path(model).expanduser())
            load_kwargs["local_files_only"] = True
        elif not allow_download:
            load_kwargs["local_files_only"] = True
        self.load_kwargs = load_kwargs
        factory = pipeline_factory or _transformers_pipeline
        self._classify = factory(self.model, load_kwargs)

    def scores(self, text: str) -> dict[str, float]:
        """Label -> score for one text."""
        raw = self._classify(text)
        if raw and isinstance(raw, list) and raw and isinstance(raw[0], list):
            raw = raw[0]  # some pipeline versions nest one level per input
        out: dict[str, float] = {}
        for item in raw or []:
            if isinstance(item, dict) and "label" in item and "score" in item:
                out[str(item["label"]).upper()] = float(item["score"])
        return out

    def __call__(self, text: str, task: str) -> JudgeVerdict | None:
        if not text.strip():
            return None
        scores = self.scores(text)
        positive = {label: s for label, s in scores.items() if label in POSITIVE_LABELS}
        if not scores:
            return None
        label, score = max(positive.items(), key=lambda kv: kv[1]) if positive else ("", 0.0)
        if score < self.threshold:
            return JudgeVerdict(
                suspicious=False, rationale=f"{self.model}: no injection label above {self.threshold}"
            )
        return JudgeVerdict(
            suspicious=True,
            rationale=f"{self.model} labelled the text {label} (score {score:.2f})",
            confidence=Confidence.MEDIUM if score >= MEDIUM_SCORE else Confidence.LOW,
        )


__all__ = ["MEDIUM_SCORE", "POSITIVE_LABELS", "HuggingFaceJudge"]
