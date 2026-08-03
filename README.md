# Agent Context Proof

A small, shareable experiment showing that reliable agent behavior depends on a
governed context layer—not just a stronger model or more retrieved text.

The repository uses a synthetic release called **Orion 1.0.0**. No proprietary
source, production data, or internal names are included.

![Governed context architecture](docs/agent-interactions.png)

## What this proves

The same model answers the same release-readiness questions through two paths:

- **Governed:** one read-only Agents SDK tool resolves identity, applies a typed
  policy, checks exact repository evidence, and returns an immutable decision
  with evidence paths and content digests.
- **Retrieval-only:** the model receives the top lexical excerpts but has no
  file inventory, identity resolver, policy executor, ownership contract, or
  path-existence oracle.

The deterministic evaluator is the oracle. The model may translate a question
and explain the result; it cannot create facts or override the decision.

The proof passes only when the governed path:

1. matches every oracle decision;
2. returns the exact oracle report digest;
3. calls the context tool exactly once per case; and
4. outperforms retrieval-only on at least one matched case.

This is evidence for the architecture, not a claim that every retrieval system
is weak or that this three-case synthetic eval predicts production quality.

## Run the deterministic proof

Python 3.11 or newer is required.

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m contextproof.cli
```

Expected decision for the checked-in demo repository:

```text
READY: release:orion:1.0.0
```

No API key is needed for the deterministic evaluator or offline tests.
The dependency contract also includes a smoke test for the validated Agents SDK
and OpenAI SDK compatibility window.

The setup intentionally uses a normal local wheel install. Some Python 3.13
runtimes skip setuptools' hidden editable-install `.pth` files, which can leave
package metadata present while making the CLI unimportable.

## Run the live comparison

Put an OpenAI project API key in the ignored `.env.local` file:

```text
OPENAI_API_KEY=...
```

Then run:

```bash
.venv/bin/python evals/run_live.py
```

The harness uses `gpt-5.6-sol` by default and writes the full local result to
`evals/results/latest.json`. It never commits the key or live result. To compare
another available model, pass `--model <model-id>`.

### Observed reference run

On 2026-08-03, the checked-in case matrix produced:

| Path | Exact oracle matches |
| --- | ---: |
| Governed context | 3 / 3 |
| Retrieval-only | 1 / 3 |

Every governed case also returned the exact oracle digest and exactly one tool
call. The recorded summary is
[`docs/proof-result.v0.1.json`](docs/proof-result.v0.1.json). Re-run the eval in
your own OpenAI project; the checked-in result is evidence, not a substitute for
independent reproduction.

![Matched evaluation sequence](docs/agent-sequence.png)

## Inspect failure modes yourself

The policy has five exact requirements: artifact bytes, manifest registration,
package version, security approval, and a passing release test.

```bash
# HOLD: required evidence is absent
cp -R demo/repository /tmp/orion-hold
rm /tmp/orion-hold/evidence/security-review.json
.venv/bin/python -m contextproof.cli \
  --repository-root /tmp/orion-hold \
  --contract-root context

# INDETERMINATE: evidence exists but cannot be parsed
cp -R demo/repository /tmp/orion-unknown
printf 'not-json\n' > /tmp/orion-unknown/evidence/test-run.json
.venv/bin/python -m contextproof.cli \
  --repository-root /tmp/orion-unknown \
  --contract-root context
```

These examples intentionally mutate temporary copies, not the repository.

## Repository map

```text
context/                 governed identity, ontology, ownership, and policy
demo/repository/         synthetic repository evidence
src/contextproof/        deterministic evaluator and one-tool agent
tests/                   offline invariants and agent contract tests
evals/                   live governed-vs-retrieval comparison
docs/                    prompt, diagrams, and proof protocol
```

## Design boundaries

- Decisions fail closed: missing evidence means `HOLD`; unreadable evidence
  means `INDETERMINATE`; only all-satisfied evidence means `READY`.
- Every evidence file is identified by a repository-relative path and SHA-256
  digest.
- Release aliases resolve to one canonical identity before policy evaluation.
- Ownership is explicit. It is not inferred from prose or commit history.
- Git commit and GitHub Actions coordinates produce a separate freshness
  envelope so runtime identity does not destabilize the policy report digest.
- The agent has no write, shell, browser, or network tool beyond the OpenAI model
  call itself.

See [docs/proof-protocol.md](docs/proof-protocol.md) for the falsifiable claims,
case matrix, and interpretation rules.

## References

- [“Your agents don’t have a model problem. They have a context problem.”](https://www.linkedin.com/pulse/your-agents-dont-have-model-problem-context-kumara-datta-dsg7f)
- [OpenAI Agents SDK guide](https://developers.openai.com/api/docs/guides/agents)
- [OpenAI agent evaluation guide](https://developers.openai.com/api/docs/guides/agent-evals)

## Security

`.env.local` is ignored and should remain local. For CI, add a repository secret
named `OPENAI_API_KEY` only if you choose to run the manual live-eval workflow.
The normal CI workflow is fully offline after dependency installation.

## License

MIT
