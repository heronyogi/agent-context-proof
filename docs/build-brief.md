# Standalone build brief

## Confirmed source findings

- Repository questions such as release readiness depend on exact identity,
  policy, ownership, evidence existence, and freshness—not prose alone.
- A deterministic evaluator can own those facts and return `READY`, `HOLD`, or
  `INDETERMINATE` with inspectable evidence paths and digests.
- An agent can safely translate natural language and explain the deterministic
  result when it has one narrow, read-only tool and a typed output contract.
- The proof must compare that real agent path with a retrieval-only baseline on
  matched cases rather than treating unit tests as evidence of model behavior.

## Bounded choices

- Use a wholly synthetic Orion release so the repository can be shared without
  exposing the source project's names, policies, code, or data.
- Keep runtime Git/CI freshness outside the stable policy report digest.
- Use one agent and one function tool; no write tools, handoffs, sandbox, or
  deployment layer are needed for this experiment.
- Treat the deterministic evaluator as the oracle and require an exact decision,
  exact report digest, and exactly one governed tool call.

## Application contract

- Input: a natural-language question containing an Orion 1.0.0 release alias.
- Output: typed status, canonical release, decision, explanation, explicit owner,
  freshness, report digest, evidence paths, and blocking requirements.
- Tool: one deterministic repository-context lookup.
- State: repository and contract roots remain in local SDK run context.
- Side effects: none beyond OpenAI API calls and an ignored local eval result.
- Proof command: `.venv/bin/python evals/run_live.py`.

## Success bar

- All offline tests and lint checks pass.
- The checked-in demo evaluates to `READY`.
- The governed agent matches every oracle decision and digest with one tool call.
- The governed path beats retrieval-only on at least one matched case.
