"""Optional second-opinion judges for META-01 (off by default).

A judge is any ``Callable[[str, str], JudgeVerdict | None]`` passed as
:attr:`mcpprobe.checks.ScanOptions.judge`. This package ships one: a local
Hugging Face text classifier (:mod:`mcpprobe.judges.hf`), enabled only with
``--judge hf:<model-id-or-path>`` and the ``mcpprobe-scanner[hf]`` extra. Nothing
here is imported, loaded or downloaded unless the user asks for it.
"""

from __future__ import annotations

from mcpprobe.checks.base import JudgeFn


class JudgeUnavailable(Exception):  # noqa: N818 - user-facing condition, not a bug
    """The requested judge cannot be loaded (missing extra, model not cached, unsafe weights...)."""


def load_judge(spec: str, *, allow_download: bool = False, threshold: float = 0.5) -> JudgeFn:
    """Build a judge from a ``kind:argument`` spec, e.g. ``hf:protectai/deberta-v3-base-prompt-injection-v2``."""
    kind, sep, arg = spec.partition(":")
    if not sep or not arg:
        raise JudgeUnavailable(f"judge spec must look like 'hf:<model-id-or-path>', got {spec!r}")
    if kind == "hf":
        from mcpprobe.judges.hf import HuggingFaceJudge

        return HuggingFaceJudge(arg, allow_download=allow_download, threshold=threshold)
    raise JudgeUnavailable(f"unknown judge kind {kind!r}; supported: hf")


__all__ = ["JudgeUnavailable", "load_judge"]
