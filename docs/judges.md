# Optional judges for META-01

META-01 is a set of deterministic heuristics. A *judge* is an optional second opinion:
a function that looks at each description and may add one medium-severity indicator
("judge flagged: ..."). mcpprobe never calls a remote model. It ships one judge, a
local Hugging Face text classifier, and it is **off by default**.

## Enabling the Hugging Face judge

```console
$ pip install 'mcpprobe-scanner[hf]'                     # transformers, torch, safetensors
$ mcpprobe <target> --judge hf:/path/to/model             # a local directory
$ mcpprobe <target> --judge hf:<org>/<model>              # must already be in the HF cache
$ mcpprobe <target> --judge hf:<org>/<model> --judge-download   # allow one download from the Hub
$ mcpprobe <target> --judge hf:<org>/<model> --judge-threshold 0.8
```

From Python: `ScanOptions(judge=load_judge("hf:<model>", allow_download=False))`, or any
`Callable[[str, str], JudgeVerdict | None]` of your own.

What the code enforces (`mcpprobe/judges/hf.py`):

- **safetensors only.** Weights are loaded with `use_safetensors=True`; a model that
  ships only pickle (`.bin`/`.pt`) weights is refused, never unpickled.
- **No model code.** `trust_remote_code=False`.
- **No download unless asked.** Without `--judge-download`, a hub id is loaded with
  `local_files_only=True`; a local directory always is.
- **Local inference.** Descriptions stay on the machine. Texts are truncated to 512
  tokens.
- **Never decisive on its own.** A positive verdict is one medium-severity indicator,
  with medium confidence at a score of 0.9 or more and low confidence below that. Label
  names `INJECTION`, `JAILBREAK`, `MALICIOUS`, `UNSAFE` and `PROMPT_INJECTION` count as
  positive; any other label (`SAFE`, `BENIGN`, ...) does not.

The judge is called once per description (tools, parameters, prompts, resources and the
server instructions), so a large server means many local inferences.

## Candidate models and licences

**Licences were not verified for this release.** The Hugging Face pages below could
not be fetched from the environment this release was prepared in (the request was not
permitted), so the licence column is what the project recalls, marked unverified. Read
each model card and licence yourself before use, especially for commercial use or
redistribution; mcpprobe does not bundle or download any model on its own.

| Model | Labels | Licence (unverified) | Notes |
|---|---|---|---|
| [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | `SAFE`, `INJECTION` | Apache-2.0 (unverified) | DeBERTa-v3-base fine-tune for English prompt injection. Check that the repository has `model.safetensors`. Its card says it does not target jailbreaks and is English-only. |
| [meta-llama/Prompt-Guard-86M](https://huggingface.co/meta-llama/Prompt-Guard-86M) | `BENIGN`, `INJECTION`, `JAILBREAK` | Llama 3.1 Community License (unverified); gated: you must accept the licence on the Hub before downloading | mDeBERTa-based, multilingual. Its `INJECTION` label is meant for any instructions found in third-party data, and tool descriptions are instructions by nature, so expect many benign descriptions to be flagged; consider counting only `JAILBREAK` by raising the threshold or using a custom judge. A newer Prompt Guard 2 family may exist; check its licence separately. |

Caveats that apply to any classifier here:

- They were trained on user prompts and web/document injections, not on MCP tool
  descriptions. Domain transfer is unmeasured (see [benchmark.md](benchmark.md)).
- Scores are not calibrated across models; tune `--judge-threshold` on your own data.
- A judge can only add an indicator. It never removes or downgrades a heuristic finding.

## Benchmark

`scripts/benchmark_judge.py` evaluates the heuristics and, with `--judge`, a judge on
the project's corpora and on a public Hub dataset when it is reachable. Results:
[benchmark.md](benchmark.md).
