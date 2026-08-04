# Live comparison evaluation

`run_live.py` runs the same explicit model through two paths:

1. the governed agent, which calls the deterministic context tool exactly once;
2. a full-packet reasoning baseline, which receives the complete bounded file
   inventory, UTF-8 contents, raw digests, and governance instructions.

The second path is information-rich but model-only. It has no independently
implemented resolver, policy executor, canonical serializer, or runtime observer,
so it is not described as a complete retrieval-plus-rules implementation.

The deterministic evaluator is the oracle. A run passes when the governed path
matches every oracle decision, trust state, trust issue set, and report digest;
makes exactly one repository tool call per case; and produces no false `READY`
answer. Comparator underperformance is not required.

Run from the repository root:

```bash
.venv/bin/python evals/run_live.py --repeats 3
```

The command writes `evals/results/latest.json`. That file is ignored because
model output, trace identifiers, latency, and usage can vary between runs.

Repeats reuse the same fixed cases, prompts, oracle, trust root, model, and
configuration. They measure observed stochastic repeat agreement rather than
independent case evidence. The harness reports the raw per-case matrix and no
run-level confidence interval.

Usage distinguishes repository tool calls from model API requests. A governed
case has exactly one repository tool call but normally two model requests: one
that emits the tool call and one that returns the typed final answer.
