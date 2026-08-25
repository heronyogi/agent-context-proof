from __future__ import annotations

import itertools
import json
import re
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_JSON = PROJECT_ROOT / "docs" / "proof-protocol.v0.3.json"
PROTOCOL_MD = PROJECT_ROOT / "docs" / "proof-protocol.v0.3.md"
AUTHORING_MD = PROJECT_ROOT / "docs" / "case-authoring.v0.3.md"
REVIEW_GUIDE = PROJECT_ROOT / "docs" / "v0.3-review-guide.md"
RECONCILIATION = (
    PROJECT_ROOT / "docs" / "reviews" / "v0.3.5-reconciliation-2026-08-24.json"
)
V036_DISPOSITION = (
    PROJECT_ROOT / "docs" / "reviews" / "v0.3.6-review-disposition-2026-08-24.json"
)
V037_DISPOSITION = (
    PROJECT_ROOT / "docs" / "reviews" / "v0.3.7-review-disposition-2026-08-24.json"
)
V038_DISPOSITION = (
    PROJECT_ROOT / "docs" / "reviews" / "v0.3.8-review-disposition-2026-08-24.json"
)
CI_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
LIVE_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "live-eval.yml"


def _protocol() -> dict[str, object]:
    return json.loads(PROTOCOL_JSON.read_text(encoding="utf-8"))


def _collapsed(text: str) -> str:
    return " ".join(text.split())


def _json_blocks(path: Path) -> list[dict[str, object]]:
    blocks = re.findall(
        r"```json\n(.*?)\n```",
        path.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    )
    return [json.loads(block) for block in blocks]


def _markdown_table(path: Path, heading: str) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    heading_index = lines.index(heading)
    table_lines: list[str] = []
    for line in lines[heading_index + 1 :]:
        if line.startswith("#"):
            break
        if line.startswith("|"):
            table_lines.append(line)
        elif table_lines:
            break
    assert len(table_lines) >= 3, f"missing table under {heading}"

    def cells(line: str) -> list[str]:
        values = [value.strip() for value in line.strip("|").split("|")]
        return [
            value[1:-1]
            if value.startswith("`") and value.endswith("`") and value.count("`") == 2
            else value
            for value in values
        ]

    headers = cells(table_lines[0])
    return [dict(zip(headers, cells(line), strict=True)) for line in table_lines[2:]]


def test_v03_protocol_is_review_gated_and_bound_to_approved_v02() -> None:
    protocol = _protocol()
    assert protocol["schema_version"] == "agent-context-proof-protocol-v0.3.9"
    assert protocol["status"] == "PROTOCOL_DRAFT"
    assert protocol["implementation_gate"] == "AWAITING_INDEPENDENT_PROTOCOL_REVIEW"
    assert protocol["base_commit"] == "3741aae69b779af36882705e7a8fb61bf734474a"


def test_v035_conflicting_review_records_are_preserved_and_reconciled() -> None:
    record = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
    assert record["subject"]["commit"] == ("f29adba84d5711eecbd6be3f9871cbc8c08127d3")
    assert record["prior_public_decision"] == {
        "outcome": "APPROVE_FOR_CASE_SEALING",
        "comment_url": (
            "https://github.com/heronyogi/agent-context-proof/pull/2"
            "#issuecomment-5181725385"
        ),
        "annotated_tag": "v0.3.5-protocol-approved-for-case-sealing",
        "preserved_as_historical_exact_subject_record": True,
        "revoked_by_this_record": False,
    }
    later = record["later_independent_review"]
    assert later["outcome"] == "REQUEST_CHANGES"
    assert later["blocking_finding_ids"] == [
        f"ACP-V03-00{index}" for index in range(1, 7)
    ]
    reconciliation = record["owner_reconciliation"]
    assert reconciliation["disposition"] == "ACCEPT_FINDINGS_AND_PREPARE_SUCCESSOR"
    assert reconciliation["case_sealing_state"] == "HELD_PENDING_SUCCESSOR_REVIEW"
    assert reconciliation["implementation_state"] == "CLOSED"
    assert reconciliation["blind_case_exposure_state"] == "PROHIBITED"


def test_v036_request_changes_is_preserved_for_its_exact_object() -> None:
    disposition = json.loads(V036_DISPOSITION.read_text(encoding="utf-8"))
    assert disposition["subject"] == {
        "repository": "https://github.com/heronyogi/agent-context-proof",
        "pull_request": "https://github.com/heronyogi/agent-context-proof/pull/5",
        "commit": "903fef2ddd57af7e15f3c972d45b7db2a07b515e",
        "tree": "4ab2373b26d454085fbb372e54dbf37462a4fcf1",
        "git_archive_tar_sha256": (
            "856458a3fedeae8e1106e0cb6e29f5b735b015f2168994fd09065d241f875acd"
        ),
    }
    assert disposition["independent_review"]["outcome"] == "REQUEST_CHANGES"
    assert disposition["owner_disposition"]["case_sealing"] == (
        "HELD_PENDING_SUCCESSOR_REVIEW"
    )
    assert disposition["owner_disposition"]["successor_requires_new_exact_sha_review"]


def test_v037_request_changes_is_preserved_for_its_exact_object() -> None:
    disposition = json.loads(V037_DISPOSITION.read_text(encoding="utf-8"))
    assert disposition["subject"] == {
        "repository": "https://github.com/heronyogi/agent-context-proof",
        "pull_request": "https://github.com/heronyogi/agent-context-proof/pull/6",
        "commit": "4b34da1fe0caa85f55453a87fcdba6ab1d6d98a4",
        "tree": "720309f783e9e910abfc6f420aa623b09d73c2e7",
        "git_archive_tar_sha256": (
            "7ff6fd986b8d6e35046df900bdabdd4addecb67146bfc663fbcb0ad58d527a82"
        ),
    }
    assert disposition["independent_review"]["outcome"] == "REQUEST_CHANGES"
    assert disposition["independent_review"]["blocking_classes"] == [
        f"ACP-V03-{index:03d}_{suffix}"
        for index, suffix in (
            (7, "RESULT_AND_TRACE_CLOSURE"),
            (8, "DEPENDENCY_REPRESENTATION"),
            (9, "EXCLUSION_INTEGRITY"),
            (10, "ADJUDICATION_STATE"),
            (11, "RELATEDNESS_EVIDENCE"),
            (12, "NUMERIC_DOMAIN"),
        )
    ]
    assert disposition["owner_disposition"]["successor_version"] == "v0.3.8"
    assert disposition["owner_disposition"]["case_sealing"] == (
        "HELD_PENDING_SUCCESSOR_REVIEW"
    )
    assert disposition["owner_disposition"]["successor_requires_new_exact_sha_review"]


def test_v038_request_changes_is_preserved_for_its_exact_object() -> None:
    disposition = json.loads(V038_DISPOSITION.read_text(encoding="utf-8"))
    assert disposition["subject"] == {
        "repository": "https://github.com/heronyogi/agent-context-proof",
        "pull_request": "https://github.com/heronyogi/agent-context-proof/pull/7",
        "commit": "6689088e71a00af969c040b22dbc45063596c6fe",
        "tree": "b101d471f45bd576635f11497d5f55e15717ed4d",
        "git_archive_tar_sha256": (
            "4a9149c61ca5578bda0d03f370d4cc26f5ebfe86cbc90f96340a5f7a6da379dd"
        ),
    }
    assert disposition["independent_review"]["outcome"] == "REQUEST_CHANGES"
    assert disposition["independent_review"]["blocking_classes"] == [
        "ACP-V03-013_CANONICAL_DEPENDENCY_GRAPH"
    ]
    assert disposition["owner_disposition"]["successor_version"] == "v0.3.9"
    assert disposition["owner_disposition"]["case_sealing"] == (
        "HELD_PENDING_SUCCESSOR_REVIEW"
    )
    assert disposition["owner_disposition"]["successor_requires_new_exact_sha_review"]


def test_valid_output_table_exactly_mirrors_the_machine_contract() -> None:
    markdown_rows = _markdown_table(PROTOCOL_MD, "### Valid combinations")
    markdown_contract = [
        {
            "authority_status": row["Authority"],
            "disposition": row["Disposition"],
            "id": row["Rule ID"],
            "mechanism_status": row["Mechanism"],
            "rule": row["Normative rule"],
        }
        for row in markdown_rows
    ]
    assert markdown_contract == _protocol()["valid_output_combinations"]


def test_valid_output_combinations_are_closed_and_fail_safe() -> None:
    protocol = _protocol()
    combinations = protocol["valid_output_combinations"]
    allowed = {
        (
            item["disposition"],
            item["mechanism_status"],
            item["authority_status"],
        )
        for item in combinations
    }
    assert len(allowed) == len(combinations) == 8

    universe = set(
        itertools.product(
            protocol["dispositions"],
            protocol["mechanism_statuses"],
            protocol["authority_statuses"],
        )
    )
    assert len(universe) == 48
    assert len(universe - allowed) == 40

    for disposition, mechanism, authority in allowed:
        if mechanism != "CONFORMANT":
            assert (disposition, authority) == ("INDETERMINATE", "INDETERMINATE")
        if disposition in {"READY", "HOLD"}:
            assert (mechanism, authority) == ("CONFORMANT", "VALID")
        if disposition == "AUTHORITY_CONFLICT" or authority == "CONFLICT":
            assert (disposition, mechanism, authority) == (
                "AUTHORITY_CONFLICT",
                "CONFORMANT",
                "CONFLICT",
            )


def test_conflict_algorithm_exactly_mirrors_the_machine_contract() -> None:
    markdown_rows = _markdown_table(
        PROTOCOL_MD,
        "### Operational conflict resolution",
    )
    markdown_steps = [
        {"id": row["Rule ID"], "rule": row["Normative operation"]}
        for row in markdown_rows
    ]
    conflict = _protocol()["conflict_resolution"]
    assert markdown_steps == conflict["ordered_steps"]
    assert [step["id"] for step in markdown_steps] == [
        "C1_COORDINATE",
        "C2_VALIDATE",
        "C3_FILTER",
        "C4_LINEAGE",
        "C5_PRECEDENCE",
        "C6_MAXIMA",
        "C7_DEDUPLICATE",
        "C8_CLASSIFY",
    ]


def test_conflict_and_ledger_rules_have_consistent_boundaries() -> None:
    protocol = _protocol()
    ledger = protocol["authority_ledger"]
    conflict = protocol["conflict_resolution"]
    valid = protocol["valid_output_combinations"]

    assert conflict["combine_operators"] == []
    assert conflict["decision_key"] == ["resolved_scope_coordinate", "claim_name"]
    assert conflict["specificity_dominance"] is False
    assert ledger["scope_profile"]["specificity_implies_precedence"] is False
    assert ledger["time_profile"]["interval"] == "[not_before,not_after)"
    assert ledger["time_profile"]["revocation_effective_boundary"] == "inclusive"
    assert ledger["epoch_profile"]["comparison_domain"] == "same_lineage_only"
    assert ledger["epoch_profile"]["rotation_increment"] == 1
    assert ledger["precedence_profile"]["active_cycle"] == "INDETERMINATE"
    assert conflict["precedence_cycle_result"] == "INDETERMINATE"
    assert conflict["scope_or_time_disjoint_result"] == "not_a_conflict"
    assert conflict["deduplication_timing"] == ("after_lineage_precedence_and_maxima")
    assert conflict["deduplicated_group_retains"] == [
        "issuer_id",
        "lineage_id",
        "claim_entry_id",
        "provenance_chain",
    ]

    conflict_rows = [row for row in valid if row["authority_status"] == "CONFLICT"]
    assert len(conflict_rows) == 1
    assert conflict_rows[0]["disposition"] == "AUTHORITY_CONFLICT"
    assert protocol["pass_conditions"]["allowed_missed_authority_conflicts"] == 0


def test_equal_claims_preserve_issuer_identity_through_dominance() -> None:
    claims = [
        {"issuer": "A", "lineage": "L-A", "value": "X"},
        {"issuer": "B", "lineage": "L-B", "value": "X"},
        {"issuer": "C", "lineage": "L-C", "value": "Y"},
    ]
    precedence_edges = {("C", "A")}

    undominated = [
        claim
        for claim in claims
        if not any(
            higher == other["issuer"] and lower == claim["issuer"]
            for higher, lower in precedence_edges
            for other in claims
        )
    ]
    grouped: dict[str, set[str]] = {}
    for claim in undominated:
        grouped.setdefault(claim["value"], set()).add(claim["issuer"])

    assert {claim["issuer"] for claim in undominated} == {"B", "C"}
    assert grouped == {"X": {"B"}, "Y": {"C"}}
    assert len(grouped) == 2


def test_ledger_profile_exactly_mirrors_the_machine_contract() -> None:
    markdown_rows = _markdown_table(PROTOCOL_MD, "### Ledger profile")
    markdown_primitives = [
        {"id": row["Primitive"], "requirement": row["Normative requirement"]}
        for row in markdown_rows
    ]
    assert markdown_primitives == _protocol()["authority_ledger"]["primitives"]


def test_signature_epoch_revocation_and_precedence_are_fully_pinned() -> None:
    ledger = _protocol()["authority_ledger"]
    signature = ledger["signature_profile"]
    epoch = ledger["epoch_profile"]
    precedence = ledger["precedence_profile"]

    assert signature == {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785_JCS",
        "key_id": "sha256:<lowercase_hex_sha256_raw_32_byte_public_key>",
        "public_key_encoding": "base64url_no_padding_raw_32_bytes",
        "signature_bytes": 64,
        "signature_encoding": "base64url_no_padding",
        "signed_payload": "utf8_jcs(entry_without_top_level_signature_member)",
    }
    assert epoch == {
        "comparison_domain": "same_lineage_only",
        "effective_epoch": (
            "highest_validated_successor_whose_boundary_is_at_or_before_validation_time"
        ),
        "minimum": 0,
        "parallel_different_successors": "INDETERMINATE",
        "rotation_increment": 1,
        "same_lineage_same_epoch_different_successor": "INDETERMINATE",
        "successor_endorsement_entry_type": "rotation",
        "unlinked_higher_epoch": "INVALID",
    }
    assert precedence["representation"] == "signed_scoped_time_bounded_directed_edges"
    assert precedence["transitive"] is True
    assert precedence["edge_fields"] == [
        "higher_issuer_id",
        "lower_issuer_id",
        "scope",
        "not_before",
        "not_after",
    ]


def test_ledger_entry_and_validation_tables_mirror_machine_contract() -> None:
    protocol = _protocol()
    entry_rows = _markdown_table(PROTOCOL_MD, "### Ledger entry types")
    markdown_entries = [
        {
            "entry_type": row["Entry type"],
            "required_fields": re.findall(
                r"`([^`]+)`", row["Required type-specific fields"]
            ),
            "rule": row["Authority rule"],
        }
        for row in entry_rows
    ]
    assert markdown_entries == protocol["authority_ledger"]["entry_types"]

    validation_rows = _markdown_table(PROTOCOL_MD, "### Ledger validation order")
    markdown_validation = [
        {"id": row["Rule ID"], "rule": row["Normative operation"]}
        for row in validation_rows
    ]
    assert markdown_validation == protocol["authority_ledger"]["validation_order"]


def test_oracle_tables_mirror_machine_contract_and_valid_outputs() -> None:
    protocol = _protocol()
    oracle = protocol["oracle_classification"]
    authority_rows = _markdown_table(PROTOCOL_MD, "### Authority classification")
    markdown_authority = [
        {
            "authority_status": row["Authority status"],
            "disposition_route": row["Disposition route"],
            "id": row["Rule ID"],
            "rule": row["Condition"],
        }
        for row in authority_rows
    ]
    assert markdown_authority == oracle["authority_rules"]

    evidence_rows = _markdown_table(PROTOCOL_MD, "### Evidence classification")
    markdown_evidence = [
        {
            "disposition": row["Disposition"],
            "evidence_state": row["Evidence state"],
            "id": row["Rule ID"],
            "rule": row["Condition"],
        }
        for row in evidence_rows
    ]
    assert markdown_evidence == oracle["evidence_rules"]

    valid = {item["id"]: item for item in protocol["valid_output_combinations"]}
    authority_routes = {
        item["id"]: item["disposition_route"] for item in oracle["authority_rules"]
    }
    assert authority_routes == {
        "OA1_VALID": "EVIDENCE_CLASSIFICATION",
        "OA2_CONFLICT": valid["V4_AUTHORITY_CONFLICT"]["disposition"],
        "OA3_INVALID": valid["V5_AUTHORITY_INVALID"]["disposition"],
        "OA4_UNKNOWN": valid["V6_AUTHORITY_UNKNOWN"]["disposition"],
    }
    assert oracle["evidence_aggregation_precedence"] == [
        "UNKNOWN",
        "UNSATISFIED",
        "SATISFIED",
    ]
    assert {
        item["evidence_state"]: item["disposition"] for item in oracle["evidence_rules"]
    } == {
        "UNKNOWN": valid["V3_EVIDENCE_UNKNOWN"]["disposition"],
        "UNSATISFIED": valid["V2_HOLD"]["disposition"],
        "SATISFIED": valid["V1_READY"]["disposition"],
    }


def test_conflict_example_has_exact_provenance_for_every_competing_chain() -> None:
    protocol = _protocol()
    provenance_contract = protocol["provenance_contract"]
    rows = _markdown_table(PROTOCOL_MD, "### Provenance requirements")
    markdown_rules = [
        {"id": row["Rule ID"], "rule": row["Normative rule"]} for row in rows
    ]
    assert markdown_rules == provenance_contract["ordered_rules"]
    assert provenance_contract["conflict_minimum_authority_chains"] == 2
    assert protocol["pass_conditions"]["exact_provenance_required"] is True
    assert provenance_contract["stage_order"] == [
        "authority",
        "contract",
        "evidence",
    ]
    assert provenance_contract["unevaluated_stages_rule"] == (
        "ordered_suffix_of_stage_order"
    )
    assert provenance_contract["array_ordering"] == {
        "authority_chains": (
            "ascending_unicode_code_point_tuple(issuer_id,claim_entry_id,chain_sha256)"
        ),
        "authority_evaluation_records": (
            "ascending_unicode_code_point_tuple(record_id,payload_sha256)"
        ),
        "authority_dependencies": (
            "ascending_unicode_code_point_tuple(dependency_type,record_id,"
            "payload_sha256)"
        ),
        "authorization_records_within_dependency": (
            "unique_canonical_signer_introduction_path_from_correct_anchor_to_"
            "dependency_record"
        ),
        "contract_records": "ascending_unicode_code_point_tuple(path,sha256)",
        "evidence_records": "ascending_unicode_code_point_tuple(path,sha256)",
        "records_within_authority_chain": ("semantic_chain_order_from_anchor_to_claim"),
        "unevaluated_stages": "stage_order_suffix",
    }

    oracle_example = next(
        block for block in _json_blocks(AUTHORING_MD) if "oracle" in block
    )
    oracle = oracle_example["oracle"]
    assert oracle["disposition"] == "AUTHORITY_CONFLICT"
    provenance = oracle["provenance"]
    assert set(provenance) == set(provenance_contract["provenance_required_fields"])
    chains = provenance["authority_chains"]
    assert len(chains) >= provenance_contract["conflict_minimum_authority_chains"]
    assert provenance["contract_records"] == []
    assert provenance["evidence_records"] == []
    assert provenance["unevaluated_stages"] == ["contract", "evidence"]
    assert chains == sorted(
        chains,
        key=lambda item: (item["issuer_id"], item["claim_entry_id"]),
    )
    stage_order = provenance_contract["stage_order"]
    first_skipped = stage_order.index(provenance["unevaluated_stages"][0])
    assert provenance["unevaluated_stages"] == stage_order[first_skipped:]

    digest_pattern = re.compile(r"^sha256:[0-9a-f]{64}$")
    assert digest_pattern.fullmatch(provenance["authority_bundle_sha256"])
    bundle_path = PurePosixPath(provenance["authority_bundle_path"])
    assert not bundle_path.is_absolute()
    assert not {".", ".."} & set(bundle_path.parts)
    claim_ids = set()
    for chain in chains:
        assert set(chain) == set(provenance_contract["authority_chain_required_fields"])
        records = chain["records"]
        assert records
        assert records[-1]["record_id"] == chain["claim_entry_id"]
        assert chain["claim_entry_id"] not in claim_ids
        claim_ids.add(chain["claim_entry_id"])
        for record in records:
            assert set(record) == set(
                provenance_contract["authority_record_required_fields"]
            )
            assert digest_pattern.fullmatch(record["payload_sha256"])

    dependencies = provenance["authority_dependencies"]
    assert dependencies == sorted(
        dependencies,
        key=lambda item: (
            item["dependency_type"],
            item["record_id"],
            item["payload_sha256"],
        ),
    )
    for dependency in dependencies:
        assert set(dependency) == set(
            provenance_contract["authority_dependency_required_fields"]
        )
        assert (
            dependency["dependency_type"]
            in provenance_contract["authority_dependency_types"]
        )
        assert dependency["authorization_records"]


def test_scoring_population_exactly_mirrors_and_constrains_pass_rules() -> None:
    protocol = _protocol()
    population = protocol["scoring_population"]
    rows = _markdown_table(PROTOCOL_MD, "## Scoring population")
    markdown_rules = [
        {"id": row["Rule ID"], "rule": row["Normative rule"]} for row in rows
    ]
    assert markdown_rules == population["ordered_rules"]
    assert population["proof_gating_path"] == "governed"
    assert population["case_accuracy_denominator"] == "included_unique_case_ids"
    assert population["comparator_population"] == "same_included_case_ids"
    assert population["comparator_accuracy_gates_proof"] is False
    assert population["post_reveal_exclusions_allowed"] is False
    assert population["minimum_committed_population"] == {
        "cases": protocol["blind_case_minimum"],
        "distinct_primary_authors": 4,
        "independence_clusters": protocol["blind_family_minimum"],
    }

    conditions = protocol["pass_conditions"]
    assert conditions["proof_gating_path"] == population["proof_gating_path"]
    assert conditions["comparator_accuracy_gates_proof"] is False
    assert conditions["post_reveal_exclusions_allowed"] is False
    assert conditions["missing_governed_output_counts_as_failure"] is True
    assert conditions["every_governed_repeat_must_match"] is True


def test_blind_families_are_independently_authored_and_auditable() -> None:
    protocol = _protocol()
    authorship = protocol["blind_evaluation"]["authorship"]
    assert protocol["blind_family_minimum"] == 4
    assert authorship["minimum_distinct_primary_authors"] == 4
    assert authorship["minimum_independence_clusters"] == 4
    assert authorship["relatedness_cluster_rule"] == "connected_components"
    assert authorship["shared_outcome_determining_source_rule"] == (
        "same_independence_cluster"
    )
    assert authorship["author_conflict_rule"] == "ineligible_family"

    authoring_text = AUTHORING_MD.read_text(encoding="utf-8")
    for field in authorship["required_record_fields"]:
        assert field in authoring_text
    collapsed = _collapsed(authoring_text)
    assert "four distinct eligible primary authors" in collapsed
    assert "Connected components" in authoring_text


def test_three_envelopes_prevent_input_and_oracle_leakage() -> None:
    protocol = _protocol()
    envelopes = protocol["blind_evaluation"]["envelopes"]
    public = envelopes["public_commitment"]
    prohibited = set(public["prohibited_before_freeze"])
    assert not set(public["allowed_before_freeze"]) & prohibited
    assert {
        "case_ids",
        "family_ids",
        "questions",
        "filenames",
        "path_order",
        "fixture_bytes",
        "mutation_descriptions",
        "oracle_fields",
    } <= prohibited
    assert envelopes["sealed_input_pack"]["reveal_after"] == "implementation_freeze"
    assert envelopes["sealed_input_pack"][
        "runner_output_commitment_required_before_oracle_reveal"
    ]
    assert envelopes["sealed_oracle_pack"]["reveal_after"] == (
        "all_path_outputs_digest_committed"
    )

    conditions = protocol["pass_conditions"]
    assert conditions["input_pack_must_remain_sealed_until_implementation_freeze"]
    assert conditions["oracle_pack_must_remain_sealed_until_output_commitment"]


def test_leakage_review_can_only_pass_revise_or_reject_before_commitment() -> None:
    leakage = _protocol()["blind_evaluation"]["leakage_review"]
    assert leakage["allowed_dispositions"] == ["PASS", "REVISE", "REJECT"]
    assert leakage["case_acceptance"] == "PASS_before_pack_commitment"
    assert leakage["unremovable_leak"] == "REJECT"
    assert leakage["revision_requires"] == ("new_pack_digest_and_new_blinded_reviewer")
    assert {
        "oracle_labels",
        "reason_codes",
        "mutation_descriptions",
        "author_notes",
    } == set(leakage["blinded_reviewer_must_not_see"])

    authoring_text = _collapsed(AUTHORING_MD.read_text(encoding="utf-8"))
    assert "randomized case IDs and randomized case order" in authoring_text
    assert "Only `PASS` cases enter the committed pack" in authoring_text
    assert "new blinded reviewer" in authoring_text


def test_oracle_labeling_requires_independent_rules_and_disagreement() -> None:
    labeling = _protocol()["blind_evaluation"]["oracle_labeling"]
    assert labeling == {
        "disagreement_if_unresolved": "REJECT_BEFORE_PACK_COMMITMENT",
        "implementer_may_annotate": False,
        "minimum_independent_annotators": 2,
        "required_rule_id_classes": [
            "mechanism_or_valid_output",
            "authority",
            "evidence_when_authority_valid",
        ],
        "sealed_artifacts": [
            "independent_annotations",
            "adjudication_record",
            "oracle_rule_ids",
            "rationale",
        ],
    }
    authoring_text = _collapsed(AUTHORING_MD.read_text(encoding="utf-8"))
    assert "At least two eligible annotators" in authoring_text
    assert "neither majority vote nor a new semantic rule is allowed" in authoring_text
    assert "the case is `REJECT`" in authoring_text


def test_v03_requires_a_true_independent_rules_comparator() -> None:
    comparator = _protocol()["compared_paths"]["retrieval_plus_rules"]
    assert comparator == {
        "independent_authority_resolver": True,
        "independent_policy_executor": True,
        "may_import_oracle_or_governed_evaluator": False,
        "required": True,
        "same_permitted_inputs": True,
    }


def test_v03_retains_zero_unsafe_promotions_and_clustered_repeats() -> None:
    protocol = _protocol()
    conditions = protocol["pass_conditions"]
    metrics = protocol["metrics"]
    assert protocol["blind_case_minimum"] >= 12
    assert conditions["allowed_false_ready"] == 0
    assert conditions["allowed_missed_authority_conflicts"] == 0
    assert conditions["model_override_allowed"] is False
    assert metrics["raw_case_repeat_matrix"] is True
    assert metrics["repeat_as_independent_observation"] is False
    assert metrics["probability_calibration_only_when_emitted"] is True
    assert protocol["blind_evaluation"]["statistical_independence_unit"] == (
        "independence_cluster"
    )


def test_readme_exposes_protocol_draft_without_claiming_a_result() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/proof-protocol.v0.3.md" in readme
    assert "No v0.3 implementation or result is claimed" in readme
    assert "v0.3 is a protocol draft under independent review" in readme
    assert "tests/fixtures/authority-ledger.v0.3.vectors.json" in readme
    assert "docs/authority-ledger.v0.3.vectors.json" not in readme


def test_reviewer_guide_maps_the_frozen_boundary_and_artifacts() -> None:
    guide = REVIEW_GUIDE.read_text(encoding="utf-8")
    for relative_path in [
        "docs/proof-protocol.v0.3.md",
        "docs/proof-protocol.v0.3.json",
        "docs/case-authoring.v0.3.md",
        "docs/authority-ledger-entry.v0.3.schema.json",
        "docs/authority-ledger-bundle.v0.3.schema.json",
        "tests/fixtures/authority-ledger.v0.3.vectors.json",
        "scripts/generate_authority_vectors.py",
        "tests/test_protocol_v03.py",
        "tests/test_authority_ledger_protocol.py",
    ]:
        assert (PROJECT_ROOT / relative_path).is_file()
        assert Path(relative_path).name in guide

    assert "APPROVE_FOR_CASE_SEALING" in guide
    assert "REQUEST_CHANGES" in guide
    assert "No final blind case may be authored" in guide
    assert "no v0.3 evaluator" in guide.lower()
    assert "not production data" in guide


def test_vectors_are_isolated_and_prominently_marked_test_only() -> None:
    protocol = _protocol()
    fixture_path = PROJECT_ROOT / protocol["authority_ledger"]["reference_vectors"]
    fixture_text = fixture_path.read_text(encoding="utf-8")
    fixture_readme = (fixture_path.parent / "README.md").read_text(encoding="utf-8")

    assert fixture_path.parent == PROJECT_ROOT / "tests" / "fixtures"
    assert not (PROJECT_ROOT / "docs" / fixture_path.name).exists()
    assert "private_seed_base64url_TEST_ONLY" in fixture_text
    assert "public, synthetic, non-production test material" in fixture_readme
    assert "must never be used" in fixture_readme


def test_workflow_triggers_make_live_evaluation_manual_and_non_gating() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    live = LIVE_WORKFLOW.read_text(encoding="utf-8")
    guide = REVIEW_GUIDE.read_text(encoding="utf-8")

    assert "\n  pull_request:" in ci
    assert "\n  push:" in ci
    assert "OPENAI_API_KEY" not in ci
    assert "python -m pytest" in ci
    assert "python -m ruff check ." in ci

    assert "workflow_dispatch:" in live
    assert "pull_request:" not in live
    assert "\n  push:" not in live
    assert "secrets.OPENAI_API_KEY" in live
    assert "retention-days: 14" in live
    assert "not a v0.3 protocol review gate" in live
    assert "not a v0.3 review check or proof gate" in guide
