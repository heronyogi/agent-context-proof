# Independent case-authoring contract for v0.3

This contract defines when v0.3 cases may be described as independently authored
and blind. It does not authorize implementation or reveal expected labels.

## Author independence

An independent case author must not:

- implement or review executable decision logic for the governed evaluator,
  oracle, or retrieval-plus-rules comparator;
- tune prompts, retrieval settings, rule files, or thresholds used by evaluated
  paths; or
- inspect development-run failures before the blind pack is sealed.

An author may read the approved v0.3 protocol, public schemas, and the v0.2
repository. Authors must disclose any implementation involvement that could
invalidate independence.

## Two-part delivery

The author creates two archives with separate SHA-256 manifests.

### Public case pack

Visible before implementation freeze:

- case and family identifiers;
- split (`blind_validation` only for independently authored cases);
- question text;
- frozen validation time;
- repository and authority-ledger file inventory;
- fixture bytes and public mutation descriptions;
- declared permitted inputs for every evaluated path; and
- schema version and file digests.

The public pack must not contain oracle fields, expected failure labels, hidden
author notes, or filenames that disclose the answer.

### Sealed oracle pack

Withheld until after code, prompts, rules, dependencies, and development results
are frozen:

- expected disposition;
- expected mechanism status;
- expected authority status;
- expected trust and failure reasons;
- exact authority, contract, and evidence provenance paths and digests;
- a short deterministic rationale; and
- any adjudication notes needed after scoring.

The sealed pack's digest is published before implementation freeze. The archive
itself is released only for the one-way blind run.

## Required case record

Each public record contains:

```json
{
  "schema_version": "agent-context-proof-case-v0.3.0",
  "case_id": "blind_example_001",
  "family_id": "authority_rotation",
  "split": "blind_validation",
  "question": "Is Orion 1.0.0 ready to release, and why?",
  "validation_time": "2030-01-15T12:00:00Z",
  "fixture_directory": "cases/blind_example_001",
  "permitted_inputs_manifest": "cases/blind_example_001/inputs.sha256"
}
```

The matching sealed record adds:

```json
{
  "case_id": "blind_example_001",
  "oracle": {
    "disposition": "AUTHORITY_CONFLICT",
    "mechanism_status": "CONFORMANT",
    "authority_status": "CONFLICT",
    "reason_codes": ["VALID_ISSUER_CONFLICT"],
    "provenance": []
  },
  "rationale": "Two current equal-precedence issuers authorize incompatible owners."
}
```

The example values illustrate shape only and are not a required blind case.

## Family construction

- A family represents one independently varied causal mechanism, not cosmetic
  rewrites of one fixture.
- At least four independent families and twelve blind cases are required.
- Each family should include a positive control where practical, so a system
  cannot pass by always abstaining.
- Conflict families must include both unresolved equal-precedence conflicts and
  resolved overlaps with explicit precedence.
- Rotation families must distinguish valid successor endorsement from rollback.
- Evidence families must distinguish parse failure, semantic mismatch, and
  semantically unjudgeable claims.
- Cases should vary irrelevant filenames, ordering, and prose so lexical cues do
  not reveal labels.

## Pre-reveal validation

Before oracle reveal, implementers may check only:

- archive and manifest integrity;
- schema validity;
- uniqueness of case and family identifiers;
- absence of path traversal and unsafe file types;
- declared input completeness; and
- that fixtures can be copied into isolated temporary directories.

If a case fails these checks, its rejection and reason are recorded before any
label is visible. No replacement may be tuned from observed model behavior.

## Freeze and reveal record

The blind-run record must name:

- approved protocol commit;
- public-pack and sealed-pack digests;
- implementation freeze commit;
- governed prompt and rule digests;
- comparator prompt and rule digests;
- dependency lock or environment digest;
- model identifiers and settings;
- reveal timestamp; and
- case exclusions decided before reveal.

After reveal, changes to evaluated code, prompts, rules, cases, or labels create
a new experiment version. They cannot be folded into the original v0.3 result.

## Dispute handling

Oracle disputes are adjudicated at the case-family level. The author and
implementer record the contested inputs, rule interpretation, and resolution.
Post-reveal label changes remain visible in the result artifact and invalidate
any previously calculated aggregate until it is regenerated.
