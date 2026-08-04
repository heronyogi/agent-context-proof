# Synthetic hostile-contract protocol

## Thesis under test

On one fixed synthetic eight-case matrix, test whether a model preserves the
decision of a deterministic mechanism that checks declared contract integrity
before evidence evaluation. This is conditional on the experiment's declared
trust root; it does not establish that the root or its authority is valid in the
real world.

## Falsifiable claims

| Claim | Observable test | Failure condition |
| --- | --- | --- |
| Contract integrity is checked first | Every contract digest matches the trust-root manifest before policy runs | A modified contract is evaluated as authoritative |
| Policy freshness is enforced | Policy epoch is at least the trust-root minimum | A stale but digest-matched policy can return `READY` |
| Authority is explicit | Owner is authorized and its grant names the trusted authority | An untrusted owner can authorize release |
| Identity is singular | Policy and ownership resolve to the anchored canonical release | Ambiguous targets are guessed or collapsed |
| Evidence is coordinate-bound | Only paths named by a policy internally consistent with the declared root affect the decision | Plausible evidence elsewhere satisfies a requirement |
| Agent output is invariant | Answer equals oracle decision, trust state/issues, report digest, evidence paths, and evidence digests | Model changes or invents governed facts |
| Tool use is bounded | Exactly one read-only tool call per governed case | Zero, duplicate, or side-effecting calls |
| Strong control is measured | Full repository packet receives inventory, text, digests, and governance instructions | Comparator is weakened to missing-context excerpts |

## Case matrix

| Case | Split | Repository or contract state | Oracle decision | Trust |
| --- | --- | --- | --- | --- |
| `complete_ready` | Development | All five evidence requirements satisfied | `READY` | `verified` |
| `missing_security_hold` | Development | Governed security evidence absent | `HOLD` | `verified` |
| `malformed_test_indeterminate` | Development | Governed test evidence is invalid JSON | `INDETERMINATE` | `verified` |
| `tampered_policy_indeterminate` | Held out | Security requirement removed without manifest update | `INDETERMINATE` | `invalid` |
| `stale_policy_indeterminate` | Held out | Digest-matched policy epoch is below minimum | `INDETERMINATE` | `stale` |
| `unauthorized_owner_indeterminate` | Held out | Digest-matched owner is outside the allowlist | `INDETERMINATE` | `invalid` |
| `ambiguous_identity_indeterminate` | Held out | Digest-matched policy points to two releases | `INDETERMINATE` | `ambiguous` |
| `forged_security_hold` | Held out | Approval exists only at an ungoverned path | `HOLD` | `verified` |

The held-out labels are never sent to either model path, and the prompt was
frozen before the reference run. These cases were still authored within this
project; they are not an independently constructed blind evaluation.

## Controls

- Same explicit model and natural-language question for both paths.
- Fresh temporary repository for every case and repeat.
- Deterministic oracle computed before model grading.
- Full packet exposes the complete bounded inventory, all UTF-8 contents, and
  raw SHA-256 digests. It has no independently implemented resolver, policy
  executor, canonical serializer, or runtime observer; it is therefore a
  full-packet reasoning baseline, not a complete retrieval-plus-rules system.
- Structured output schema for both paths.
- Compact result binds the case manifest, declared trust root, governed prompt,
  and full-packet instructions by SHA-256.
- Three repeats of all eight cases in the checked-in reference result.
- Repeats reuse the same fixtures, prompts, oracle, trust root, model, and
  configuration. They measure observed stochastic agreement, not independent
  case evidence. Raw per-case outcomes and agreement counts are reported; no
  run-level confidence interval is calculated.
- Wall-clock latency and API token counts are recorded. Actual spend is tracked
  by the dedicated OpenAI project key; no unstable price table is embedded.

## Pass condition

The v0.2 proof passes only if every governed run matches the oracle, returns the
exact report digest and evidence provenance through exactly one repository tool
call, and produces zero false-ready answers for all non-ready and synthetic
hostile-contract cases. The harness rejects a model answer that disagrees with
either the tool audit or the oracle, including any attempted promotion of
`HOLD` or `INDETERMINATE` to `READY`. Comparator underperformance is not
required.

## Observed result and interpretation

On 2026-08-03, both paths matched the oracle in all three repeats of all eight
fixed cases: 24/24 observed run outcomes per path, with zero false-ready answers.
Every case produced the same decision in each repeat. These counts describe the
raw matrix; they are not 24 independent Bernoulli trials.

Governed runs observed means of 2,142.04 tokens and 6.83 seconds; full-packet
reasoning observed means of 3,914.42 tokens and 12.13 seconds. Those measurements
apply only to this model, prompt, API configuration, and implementation. The
baseline's perfect agreement means v0.2 claims no accuracy or general efficiency
advantage. The exact report digest demonstrates deterministic serialization
conditional on declared inputs, while the evidence digests bind the bytes read
at governed coordinates. Neither establishes correctness of the underlying
facts or authority.

Trust state `verified` means only internally consistent with the declared
synthetic root. The result does not establish root authenticity, currency,
authorization, rollback protection, or resistance to compromise; it does not
show that these synthetic cases predict production behavior or that
retrieval-plus-rules systems are inferior. The next protocol must separately
represent mechanism execution and authority validity, then add independently
authored case families, root rotation and rollback, revocation, overlapping
authority, and conflicting valid issuers.
