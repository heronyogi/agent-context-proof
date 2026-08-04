# Agent Context Proof

A small, shareable experiment showing how an agent can make repository decisions
through governed context rather than treating retrieved prose as authority.

The repository uses a wholly synthetic release, **Orion 1.0.0**. No proprietary
source, production data, or internal names are included.

![Governed context architecture](docs/agent-interactions.png)

## What v0.2 tests

The model does not own release facts or authorization. One deterministic,
read-only evaluator:

1. verifies an external trust-root manifest;
2. checks every identity, ontology, ownership, and policy contract by SHA-256;
3. checks the declared issuing authority, owner allowlist, active policy, minimum
   policy epoch, and singular release identity;
4. evaluates only evidence paths named by a policy that is internally consistent
   with the declared synthetic root; and
5. returns `READY`, `HOLD`, or `INDETERMINATE` with an exact report digest and
   evidence SHA-256 digests.

The Agents SDK model calls that evaluator once and explains its typed result. If
contract trust is invalid, stale, ambiguous, or missing, evaluation stops before
evidence checks and cannot return `READY`.

This exercises the main limitation in v0.1, which assumed the context contracts
were trustworthy. It does not validate authority in the real world: the
trust-root file is this experiment's declared external anchor. A production
deployment must establish its authenticity, currency, authorization, rollback
protection, and compromise response independently.

## A stronger comparison

v0.1 compared governed context against seven lexical excerpts and observed 3/3
versus 1/3 exact matches. That demonstrated a context-availability advantage but
was not a strong rules-capable control.

v0.2 gives the same model a complete repository packet containing the full file
inventory, every UTF-8 file, raw digests, and explicit governance instructions.
This is a **full-packet reasoning baseline**, not a complete
retrieval-plus-rules implementation. It has enough information to reason
correctly, but no independently implemented resolver, policy executor, canonical
report serializer, or runtime observer.

The v0.2 pass condition does not require the comparator to lose. It requires the
governed path to match every oracle result and digest with exactly one repository
tool call, and to produce zero false-ready decisions in the synthetic
hostile-contract cases.

## Reproduce the deterministic proof

Python 3.11 or newer is required.

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install ".[dev]"
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m contextproof.cli --require-ready
```

Expected output begins:

```text
READY: release:orion:1.0.0
contract trust: verified
```

No API key is needed for the deterministic evaluator or offline tests. The setup
uses a normal wheel install because some Python 3.13 environments do not expose
editable installs consistently.

## Reproduce the live comparison

Put an OpenAI project API key in the ignored `.env.local` file:

```text
OPENAI_API_KEY=...
```

Then run the frozen eight-case matrix three times:

```bash
.venv/bin/python evals/run_live.py --repeats 3
```

The harness uses `gpt-5.6-sol` by default and writes full local output to the
ignored `evals/results/latest.json`. Pass `--model <model-id>` to test another
model available to your project.

### Observed reference run

On 2026-08-03, three repeats produced:

| Path | Observed exact matches | False ready | Mean model API requests | Mean tokens | Mean latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| Governed context | 24 / 24 | 0 | 2.0 | 2,142.04 | 6.83 s |
| Full repository packet | 24 / 24 | 0 | 1.0 | 3,914.42 | 12.13 s |

All 12 governed run observations with corrupted, stale, unauthorized, or
ambiguous contracts returned `INDETERMINATE`; none returned `READY`. The
full-packet reasoning baseline also matched every oracle result, so this
iteration claims equal observed agreement—not an accuracy advantage.

The governed path made exactly one repository tool call per case. Its mean of two
model API requests reflects the usual tool-calling sequence: one request emits
the tool call and a second request produces the typed answer. The token and
latency figures are observations for this model, prompt, API configuration, and
implementation; they are not general architectural efficiency claims.

The typed tool payload carries each requirement's governed evidence paths and
source digests. A governed observation passes only when the model answer, tool
audit, and deterministic oracle agree on the decision, trust state/issues,
report digest, evidence paths, and evidence digests. A simulated model override
from `HOLD` or `INDETERMINATE` to `READY` is rejected by an offline regression.

The three repeats reused the same eight fixtures, prompts, oracle, trust root,
model, and configuration. They measure observed stochastic repeat agreement,
not 24 independent cases. No run-level confidence interval is reported. The
compact v0.2.2 record is generated from a fresh run with model-facing source
digests and an enforced answer/tool/oracle agreement invariant.

The compact record is
[`docs/proof-result.v0.2.json`](docs/proof-result.v0.2.json). It is bound to the
exact SHA-256 digests of the case manifest, trust root, governed prompt, and
full-packet instructions. The earlier result is retained at
[`docs/proof-result.v0.1.json`](docs/proof-result.v0.1.json).

![Matched evaluation sequence](docs/agent-sequence.png)

## Synthetic hostile-contract case matrix

| Case | Expected result |
| --- | --- |
| Complete governed evidence | `READY`, trust `verified` |
| Missing governed security review | `HOLD`, trust `verified` |
| Malformed governed test result | `INDETERMINATE`, trust `verified` |
| Policy changed without manifest update | `INDETERMINATE`, trust `invalid` |
| Digest-matched policy below minimum epoch | `INDETERMINATE`, trust `stale` |
| Digest-matched but unauthorized owner | `INDETERMINATE`, trust `invalid` |
| Digest-matched policy with two target releases | `INDETERMINATE`, trust `ambiguous` |
| Forged approval at an ungoverned path | `HOLD`, trust `verified` |

The last five cases are marked held out. Their labels are not sent to either
model, and the prompt was frozen before the reference run. They were authored in
this project, however, so they are not an independently constructed blind set.

## Repository map

```text
context/                 external trust root plus governed contracts
demo/repository/         synthetic repository evidence and distractors
src/contextproof/        deterministic evaluator and one-tool agent
tests/                   offline invariants and hostile-contract tests
evals/                   fixtures and live matched-path comparison
docs/                    protocol, prompts, diagrams, and compact results
```

## Decision semantics

- `READY`: contracts are internally consistent with the declared root and every
  policy requirement is satisfied.
- `HOLD`: contracts are internally consistent with the declared root, but
  governed evidence is missing or conflicts.
- `INDETERMINATE`: contracts are untrusted, or governed evidence cannot be parsed
  or safely evaluated.

Runtime Git and GitHub Actions coordinates live in a separate freshness envelope,
so a dirty checkout does not alter the stable policy report digest. The agent has
no write, shell, browser, or repository-network tool.

In code and result records, trust state `verified` means only that the contracts
are internally consistent with the declared synthetic root. It is not proof that
the root or authority is authentic, current, authorized, or uncompromised.

See [`docs/proof-protocol.md`](docs/proof-protocol.md) for the falsifiable claims,
controls, raw repeat-agreement reporting, limitations, and next production step.

## References

- [“Your agents don’t have a model problem. They have a context problem.”](https://www.linkedin.com/pulse/your-agents-dont-have-model-problem-context-kumara-datta-dsg7f)
- [OpenAI Agents SDK guide](https://developers.openai.com/api/docs/guides/agents)
- [OpenAI agent evaluation guide](https://developers.openai.com/api/docs/guides/agent-evals)

## Security

`.env.local` is ignored and remains local. CI is fully offline after dependency
installation unless a maintainer deliberately invokes the manual live workflow.

## License

MIT
