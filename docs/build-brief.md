# Standalone build brief: v0.2 hostile governance

## Confirmed source findings

- Repository decisions depend on trustworthy identity, policy, ownership,
  evidence coordinates, and runtime freshness—not prose alone.
- v0.1 showed that a deterministic evaluator plus one narrow agent tool could
  preserve exact decisions and report digests against a lexical-retrieval
  baseline.
- v0.2 tests the next boundary: the context contracts themselves may be
  corrupted, stale, semantically ambiguous, or issued to an unauthorized owner.
- The comparison must use a materially stronger control than top-k excerpts and
  must report equal performance honestly.

## Bounded choices

- Keep the wholly synthetic Orion release so the repository remains shareable.
- Add one external trust-root file containing the authority, authorized owners,
  active policy, minimum policy epoch, canonical target, and exact SHA-256 digest
  of every governed contract.
- Treat that trust root as the experiment's external anchor. Production would
  need to protect, sign, or retrieve the anchor from a separately trusted system.
- Fail closed to `INDETERMINATE` before evidence evaluation when contract trust
  is not `verified`.
- Retain one Agents SDK agent and one read-only function tool. The model explains
  a typed result; it never computes or overrides the governed decision.
- Compare against a full repository packet containing the complete inventory,
  every text file, and raw file digests, with explicit instructions to apply the
  same governance rules through model reasoning.

## Application contract

- Input: a natural-language question containing an Orion 1.0.0 release alias.
- Output: typed status, canonical release, decision, owner, contract-trust state
  and issues, freshness, report digest, evidence paths, and blockers.
- Tool: one deterministic repository-context lookup.
- State: repository and contract roots remain in local SDK run context.
- Side effects: OpenAI API calls and an ignored local result file only.
- Offline proof: `.venv/bin/python -m pytest` and
  `.venv/bin/python -m ruff check .`.
- Live proof: `.venv/bin/python evals/run_live.py --repeats 3`.

## Success bar

- Every governed run exactly matches oracle decision, trust state, trust issues,
  report digest, and one-tool-call audit.
- No corrupted, stale, unauthorized, or ambiguous contract case returns
  `READY`.
- Missing governed evidence remains `HOLD`; malformed evidence remains
  `INDETERMINATE`; plausible evidence at an ungoverned path has no effect.
- The stronger comparator's accuracy, false-ready rate, latency, requests, and
  token use are reported without requiring it to lose.
- The checked-in compact result is bound to the exact case-manifest and trust-root
  digests.
