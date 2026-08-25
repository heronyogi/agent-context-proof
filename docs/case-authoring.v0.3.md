# Independent case-authoring contract for v0.3

This contract defines when v0.3 cases may be described as independently authored
and blind. It does not authorize implementation or reveal expected labels.

## Auditable author independence

Each blind family must have a different eligible primary author. A v0.3 blind
evaluation requires at least four independently authored families, four distinct
eligible primary authors, and four independence clusters. More than one author
may collaborate on a family, but coauthorship does not create another independent
family.

An eligible independent case author must not:

- implement or review executable decision logic for the governed evaluator,
  oracle, or retrieval-plus-rules comparator;
- tune prompts, retrieval settings, rule files, or thresholds used by evaluated
  paths; or
- inspect development-run failures before the blind pack is sealed.

An author may read the approved v0.3 protocol, public schemas, and the v0.2
repository. Every family includes a sealed authorship declaration with:

- `family_id`, `primary_author_id`, and `coauthor_ids`;
- every evaluator, comparator, oracle, prompt, rule, and review role held by an
  author;
- digests for templates, datasets, examples, or other shared source material;
- direct coordination with other case authors;
- employment, funding, supervisory, or other conflicts of interest relevant to
  the experiment; and
- an attestation timestamp and non-cryptographic declaration.

The exact required keys are `family_id`, `primary_author_id`, `coauthor_ids`,
`implementation_roles`, `shared_sources`, `coordination_disclosures`,
`conflicts_of_interest`, `attestation_timestamp`, and
`declaration`, together with the schema-version discriminator. No key
may be omitted or null, and unknown keys are rejected by the committed schema.
`shared_sources` marks whether each source is outcome-determining, and every
coordination disclosure names the related family and whether expected outcomes
were discussed. The declarations do not authenticate real-world identity; the
oracle archive commitment prevents silent mutation, while the protocol reviewer
must verify author identity and eligibility from external evidence.

The protocol reviewer builds an undirected relatedness graph before case-pack
commitment. Families are connected when they share a primary or coauthor,
coordinate on expected outcomes, or use source material that substantially
determines the expected outcome. Connected components, not the authors' family
labels, are the independence clusters used for reporting. Cosmetic templates
and the required public schema may be shared when they contain no
outcome-determining content, but their digests must still be disclosed.

An undisclosed or disqualifying implementation role makes the family ineligible,
not merely caveated. If a relationship or shared source cannot be classified
confidently, the families are conservatively placed in the same cluster. A new
eligible family from a distinct primary author and cluster is required whenever
an exclusion or merger takes the blind pack below four.

## Three-envelope delivery

The coordinator creates two sealed archives plus one minimal public commitment.
Each artifact has a separate SHA-256 manifest.

### Public commitment

Before implementation freeze, implementers may see only:

- the public-commitment schema version, approved protocol commit, all governed
  artifact schema versions, and aggregate case and family counts;
- the sealed input-pack and oracle-pack SHA-256 digests;
- the authorship-collection and relatedness-graph digests; and
- the blinded leakage-review attestation digest.

The public commitment must not expose case or family identifiers, questions,
filenames, path or record ordering, fixture bytes, mutation descriptions, oracle
fields, reason codes, or author notes.

### Sealed input pack

The input pack contains the exact questions, validation times, ledger and
repository bytes, filenames, ordering, case identifiers, and permitted-input
manifests that evaluated paths will receive. Its digest is committed before
implementation freeze, but its contents remain unavailable to implementers and
runners until the implementation-freeze record is final.

After freeze, a runner receives the input pack and executes every path. The raw
path outputs and traces are committed by digest before the oracle pack is
released. Reading the input pack reopens implementation only as a new experiment
version; it cannot be used to tune the frozen v0.3 run.

### Sealed oracle pack

Withheld until every evaluated path's output digest is committed:

- expected disposition;
- expected mechanism status;
- expected authority status;
- expected trust and failure reasons;
- exact provenance paths, record IDs, and digests for every stage reached, plus
  an explicit list of stages not evaluated because an earlier classification
  terminated evaluation;
- a short deterministic rationale; and
- any adjudication notes needed after scoring.

The oracle pack's digest is published before implementation freeze. The archive
is released only for scoring the already committed outputs.

## Normative artifact schemas and closed validation

The following strict Draft 2020-12 schemas govern every record needed to seal,
freeze, reveal, and score a v0.3 experiment:

- [`case-record.v0.3.schema.json`](case-record.v0.3.schema.json)
- [`oracle-record.v0.3.schema.json`](oracle-record.v0.3.schema.json)
- [`result-record.v0.3.schema.json`](result-record.v0.3.schema.json)
- [`authorship-attestation.v0.3.schema.json`](authorship-attestation.v0.3.schema.json)
- [`authorship-collection.v0.3.schema.json`](authorship-collection.v0.3.schema.json)
- [`relatedness-graph.v0.3.schema.json`](relatedness-graph.v0.3.schema.json)
- [`leakage-review-attestation.v0.3.schema.json`](leakage-review-attestation.v0.3.schema.json)
- [`public-commitment.v0.3.schema.json`](public-commitment.v0.3.schema.json)
- [`sealed-pack-manifest.v0.3.schema.json`](sealed-pack-manifest.v0.3.schema.json)
- [`freeze-reveal-record.v0.3.schema.json`](freeze-reveal-record.v0.3.schema.json)
- [`population-freeze-record.v0.3.schema.json`](population-freeze-record.v0.3.schema.json)
- [`path-output-commitment.v0.3.schema.json`](path-output-commitment.v0.3.schema.json)
- [`oracle-reveal-record.v0.3.schema.json`](oracle-reveal-record.v0.3.schema.json)

All schemas reject unknown properties, null in required fields, duplicate JSON
members, out-of-vocabulary enum values, unsafe integers, malformed digests, and
non-canonical path shapes. The normative structural algorithm is
[`validate_v03_artifact.py`](../scripts/validate_v03_artifact.py). It performs
strict I-JSON parsing before schema validation and then applies the semantic
checks JSON Schema cannot express. `record` mode validates individual shapes and
never certifies a sealed experiment. `complete-pack` mode requires both exact
archives, both manifests, every control record, the population freeze, one
timestamped output commitment per declared path, the oracle reveal, and the
final receipt. It recomputes keyed uniqueness, exact case/family/population
sets, relatedness components, leakage coverage, canonical ordering, archive and
manifest byte/size/digest coverage, permitted-input coverage, authority-bundle
and provenance linkage, output-rule-reason relations, post-exclusion floors,
and strict phase ordering. A pack is structurally valid only when
`complete-pack` returns success. Model judgment or a model-authored validity
report is not a substitute.

The two modes are explicit:

```bash
python scripts/validate_v03_artifact.py record oracle_record=oracle.json
python scripts/validate_v03_artifact.py complete-pack \
  --public-commitment public.json \
  --input-archive sealed-input.tar \
  --input-manifest sealed-input.manifest.json \
  --oracle-archive sealed-oracle.tar \
  --oracle-manifest sealed-oracle.manifest.json \
  --population-freeze population-freeze.json \
  --output-commitment governed.commitment.json \
  --output-commitment retrieval-plus-rules.commitment.json \
  --oracle-reveal oracle-reveal.json \
  --freeze-reveal final-receipt.json
```

Both sealed packs are uncompressed `USTAR_CANONICAL_V0.3.7` archives. Members
are Unicode-code-point sorted regular files only, with uid/gid 0, empty owner
names, mtime 0, mode 0644, no PAX fields, safe relative POSIX paths, and exact
external manifest coverage. The complete-pack validator reserializes the
member map with the reference USTAR algorithm and requires byte equality,
including standard USTAR headers, zero-filled file padding, two zero end
blocks, and zero padding to the next 10,240-byte record. Validation reads
member bytes without extracting them. A permitted-input manifest uses sorted lines of
`sha256:<64 lowercase hex><two spaces><archive-relative path>` and ends with one
newline.

## Required case record

Each record in the sealed input pack contains:

```json
{
  "schema_version": "agent-context-proof-case-v0.3.7",
  "case_id": "blind_example_001",
  "family_id": "authority_rotation",
  "split": "blind_validation",
  "question": "Is Orion 1.0.0 ready to release, and why?",
  "validation_time": "2030-01-15T12:00:00Z",
  "case_coordinate": {
    "organization": "org:orion",
    "repository": "repo:orion-service",
    "artifact": "release:orion:1.0.0",
    "action": "release"
  },
  "fixture_directory": "cases/blind_example_001",
  "permitted_inputs_manifest": "cases/blind_example_001/inputs.sha256"
}
```

The matching sealed record contains an oracle payload of this shape:

```json
{
  "schema_version": "agent-context-proof-oracle-v0.3.7",
  "case_id": "blind_example_001",
  "case_coordinate": {
    "organization": "org:orion",
    "repository": "repo:orion-service",
    "artifact": "release:orion:1.0.0",
    "action": "release"
  },
  "validation_time": "2030-01-15T12:00:00Z",
  "oracle": {
    "disposition": "AUTHORITY_CONFLICT",
    "mechanism_status": "CONFORMANT",
    "authority_status": "CONFLICT",
    "oracle_rule_ids": [
      "OA2_CONFLICT",
      "V4_AUTHORITY_CONFLICT"
    ],
    "reason_codes": ["VALID_ISSUER_CONFLICT"],
    "provenance": {
      "authority_bundle_path": "authority/ledger.json",
      "authority_bundle_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "authority_evaluation_records": [
        {
          "record_id": "anchor:release-east",
          "payload_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          "classification": "VALID",
          "decisive": true
        },
        {
          "record_id": "anchor:release-west",
          "payload_sha256": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
          "classification": "VALID",
          "decisive": true
        },
        {
          "record_id": "entry:claim-owner-east",
          "payload_sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
          "classification": "VALID",
          "decisive": true
        },
        {
          "record_id": "entry:claim-owner-west",
          "payload_sha256": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
          "classification": "VALID",
          "decisive": true
        }
      ],
      "authority_chains": [
        {
          "issuer_id": "authority:release-east",
          "claim_entry_id": "entry:claim-owner-east",
          "chain_sha256": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
          "records": [
            {
              "record_id": "anchor:release-east",
              "payload_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            },
            {
              "record_id": "entry:claim-owner-east",
              "payload_sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            }
          ]
        },
        {
          "issuer_id": "authority:release-west",
          "claim_entry_id": "entry:claim-owner-west",
          "chain_sha256": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
          "records": [
            {
              "record_id": "anchor:release-west",
              "payload_sha256": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            },
            {
              "record_id": "entry:claim-owner-west",
              "payload_sha256": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            }
          ]
        }
      ],
      "authority_dependencies": [
        {
          "dependency_type": "identity_introduction",
          "record_id": "anchor:release-east",
          "payload_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          "authorization_records": [
            {
              "record_id": "anchor:release-east",
              "payload_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            }
          ],
          "decisive_for": ["entry:claim-owner-east"]
        },
        {
          "dependency_type": "identity_introduction",
          "record_id": "anchor:release-west",
          "payload_sha256": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
          "authorization_records": [
            {
              "record_id": "anchor:release-west",
              "payload_sha256": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            }
          ],
          "decisive_for": ["entry:claim-owner-west"]
        }
      ],
      "contract_records": [],
      "evidence_records": [],
      "unevaluated_stages": ["contract", "evidence"]
    }
  },
  "rationale": "Two current equal-precedence issuers authorize incompatible owners."
}
```

The excerpt illustrates the payload and provenance shape only; a complete
schema-valid oracle record also embeds exactly two distinct full annotations
and one distinct adjudication record. It is not a required blind case.
Contract and evidence provenance are empty because `AUTHORITY_CONFLICT`
terminates evaluation before those stages, not because conflict lacks decisive
provenance. Every undominated conflicting authority claim has its own chain.
Authority chains are sorted by the complete `(issuer_id, claim_entry_id,
chain_sha256)` tuple using Unicode code-point order.
`authority_evaluation_records` lists every anchor, recovery anchor, and signed
entry in the exact authority bundle once, with its recomputed payload digest,
classification, and decisiveness; it cannot silently omit an inconvenient
record. Authority dependencies are sorted by `(dependency_type, record_id,
payload_sha256)`; their authorization records retain anchor-to-dependency
semantic order and `decisive_for` is Unicode-code-point sorted. Contract and
evidence records are sorted by `(path, sha256)`; records inside one authority
chain retain anchor-to-claim semantic order.

## Oracle labeling and disagreement

At least two eligible annotators who did not implement either evaluated
resolver independently apply the committed oracle-classification tables. Each
annotation records the three output fields, the applicable `OA`, `OE`, and `V`
rule IDs, the complete case coordinate, validation time, decisive provenance,
and a deterministic rationale. The v0.3.7 record profile embeds exactly two
full annotations in the sealed
oracle record with a non-cryptographic declaration. An `OE` rule is required
only after `OA1_VALID`; mechanism failure instead records only `V7` or `V8`.

The protocol reviewer compares the annotations before pack commitment. Exact
agreement is recorded as `EXACT_AGREEMENT`; both embedded payloads must equal
the final oracle. A disagreement is recorded as `RULE_APPLICATION` and is
adjudicated only by applying the
committed rules to the committed bytes; neither majority vote nor a new semantic
rule is allowed. The two original annotations, adjudication, final rule IDs, and
rationale are sealed with the oracle pack. If the committed rules do not produce
one label, the case is `REJECT` and must be replaced before commitment. An
implementer may not act as annotator or adjudicator.

## Family construction

- A family represents one independently varied causal mechanism, not cosmetic
  rewrites of one fixture.
- At least four independently authored families, four distinct eligible primary
  authors, four independence clusters, and twelve blind cases are required.
- Each family should include a positive control where practical, so a system
  cannot pass by always abstaining.
- Conflict families must include both unresolved equal-precedence conflicts and
  resolved overlaps with explicit precedence.
- Rotation families must distinguish valid successor endorsement from rollback.
- Evidence families must distinguish parse failure, semantic mismatch, and
  semantically unjudgeable claims.
- Cases should vary irrelevant filenames, ordering, and prose across labels so
  those properties cannot become outcome-predictive shortcuts.

## Blinded leakage review

Leakage means an outcome-predictive feature that is not required by the family's
declared causal mechanism. Legitimate governed evidence may determine the
correct answer; a label-correlated filename, mutation phrase, byte pattern,
ordering convention, case ID, or family-specific template may not.

Before pack commitment, a reviewer who is neither an author nor an implementer
receives the exact candidate input pack with randomized case IDs and randomized
case order. The reviewer does not receive oracle labels, reason codes, mutation
descriptions, or author notes. For every case, the reviewer records predicted
output fields, suspected cues, and whether the basis is governed semantics or an
extraneous feature. An oracle custodian who is also outside the implementation
team compares those predictions and cues with the sealed labels and records one
of:

- `PASS`: no outcome-predictive extraneous cue was found;
- `REVISE`: a cue can be removed without changing the causal mechanism; or
- `REJECT`: leakage cannot be removed without changing the causal mechanism, or
  the case cannot be re-reviewed before commitment.

Only `PASS` cases enter the committed pack. A revision creates new input and
oracle digests and must be reviewed by a new blinded reviewer who has not seen
the earlier case label or leakage adjudication. A rejected case is recorded in
the private audit log and replaced only before pack commitment. The leakage
report remains hidden from implementers until after outputs are committed,
because its predictions and cue descriptions may themselves disclose labels.

## Pre-reveal structural validation

Before the input pack is revealed, implementers may check only the public
commitment. After implementation freeze but before execution, the runner may
check only:

- archive and manifest integrity;
- schema validity;
- uniqueness of case and family identifiers;
- absence of path traversal and unsafe file types;
- declared input completeness; and
- that fixtures can be copied into isolated temporary directories.

If a case fails these checks, its rejection and reason are recorded before any
label is visible. It is excluded from the frozen experiment; no post-freeze
replacement is allowed and no replacement may be tuned from observed model
behavior.

## Immutable freeze, commitment, and reveal records

The workflow uses four object-bound phases:

1. A `population-freeze` record binds the approved protocol, public commitment,
   both exact manifests, implementation commit, prompts, rules, environment,
   models, every pre-execution exclusion, the final included case IDs, and the
   input-reveal timestamp. Every exclusion precedes the freeze, and the freeze
   strictly precedes input reveal.
2. One `path-output-commitment` per declared model path binds that population,
   output and trace digests, included-case and repeat counts, and commitment
   time. `governed` and `retrieval_plus_rules` are always required.
3. An `oracle-reveal` record binds the exact population and every output-record
   digest. Every output commitment strictly precedes oracle reveal.
4. The final `freeze-reveal` receipt binds the preceding exact objects by
   digest. It cannot replace or retrospectively edit them.

Together those records must name or bind:

- approved protocol commit;
- public-commitment, sealed-input-pack, and sealed-oracle-pack digests;
- authorship records and the relatedness graph digest;
- blinded leakage-review and adjudication digests;
- oracle-annotation and oracle-adjudication digests;
- implementation freeze commit;
- governed prompt and rule digests;
- comparator prompt and rule digests;
- dependency lock or environment digest;
- model identifiers and settings;
- input-pack reveal timestamp;
- all-path output and trace commitment digests and timestamps;
- oracle reveal timestamp; and
- case exclusions decided before population freeze and the exact included set.

After reveal, changes to evaluated code, prompts, rules, cases, or labels create
a new experiment version. They cannot be folded into the original v0.3 result.

## Dispute handling

Oracle disputes are adjudicated at the case-family level by the protocol
reviewer, with the author and implementer separately recording the contested
inputs and rule interpretation. An author conflict disclosed only after reveal
is handled as an eligibility failure, and shared outcome-determining material
merges the affected families into one reporting cluster even if the aggregate
then falls below the minimum.

Post-reveal label changes remain visible in the result artifact and invalidate
any previously calculated aggregate until it is regenerated.
