# Live comparison eval

`run_live.py` runs the same model through two paths:

1. the governed agent, which must call the deterministic context tool once; and
2. a retrieval-only agent, which receives the top lexical repository excerpts.

The oracle is the deterministic evaluator, not either model answer. A proof run
passes when the governed path matches every oracle decision and digest, makes
exactly one tool call per case, and beats retrieval-only on at least one case.

Run from the repository root:

```bash
.venv/bin/python evals/run_live.py
```

The command writes `evals/results/latest.json`. That file is ignored because
model output, trace identifiers, latency, and costs can vary between runs.
