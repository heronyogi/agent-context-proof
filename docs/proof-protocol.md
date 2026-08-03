# Proof protocol

## Thesis under test

For repository decisions that depend on exact identity, policy, ownership,
existence, and freshness, a model with governed context should be more reliable
than the same model given only retrieved excerpts.

## Falsifiable claims

| Claim | Observable test | Failure condition |
| --- | --- | --- |
| Identity is canonical | Aliases resolve to `release:orion:1.0.0` | Alias is unresolved or maps to another release |
| Policy owns the decision | Agent decision equals deterministic oracle | Model changes or invents a decision |
| Evidence is inspectable | Report contains exact paths and SHA-256 digests | Decisive evidence has no source coordinate |
| Missing and malformed differ | Missing → `HOLD`; malformed → `INDETERMINATE` | Both collapse to one guessed state |
| Tool use is bounded | Exactly one read-only tool call per governed case | Zero, duplicate, or side-effecting calls |
| Context adds value | Governed path beats retrieval-only on ≥1 matched case | Retrieval-only matches or beats governed on all cases |

## Case matrix

| Case | Repository state | Oracle |
| --- | --- | --- |
| `complete_ready` | All five requirements satisfied | `READY` |
| `missing_security_hold` | Required security evidence absent | `HOLD` |
| `malformed_test_indeterminate` | Test evidence exists but is invalid JSON | `INDETERMINATE` |

The archived launch note is an intentional distractor. It says the release is
ready but is not referenced by policy and therefore cannot affect the oracle.

## Controls

- Same model and model settings for both paths.
- Same natural-language question per case.
- Same underlying repository snapshot per case.
- Structured output schema for both paths.
- Deterministic oracle computed before either model answer is graded.
- Report digest excludes live Git/CI coordinates; freshness is recorded in a
  separate runtime envelope.

## Interpretation

A passing run shows that this governed context implementation improves accuracy
on this bounded experiment. It does not establish universal superiority over
semantic search, graph RAG, larger datasets, or other agent architectures.

The next step toward production evidence is to replace the synthetic policy and
fixtures with a real decision boundary, collect representative cases, blind the
case author from prompt tuning, repeat runs, and measure accuracy, false-ready
rate, latency, tokens, and cost with confidence intervals.
