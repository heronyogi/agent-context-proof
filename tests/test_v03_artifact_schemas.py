from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = PROJECT_ROOT / "scripts" / "validate_v03_artifact.py"
VECTOR_PATH = (
    PROJECT_ROOT / "tests" / "fixtures" / "authority-ledger.v0.3.vectors.json"
)
PROTOCOL_PATH = PROJECT_ROOT / "docs" / "proof-protocol.v0.3.json"
COMMON_SCHEMA_PATH = PROJECT_ROOT / "docs" / "protocol-artifact-defs.v0.3.schema.json"

ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
TWO = "sha256:" + "2" * 64
THREE = "sha256:" + "3" * 64
COMMIT = "a" * 40
NOW = "2030-01-01T00:00:00Z"


def _validator_module():
    spec = importlib.util.spec_from_file_location("v03_validator", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    return path


def _provenance(dependency_type: str = "identity_introduction") -> dict[str, object]:
    dependencies = [
        {
            "dependency_type": "identity_introduction",
            "record_id": "anchor:root",
            "payload_sha256": ONE,
            "authorization_records": [
                {"record_id": "anchor:root", "payload_sha256": ONE}
            ],
            "decisive_for": ["entry:claim"],
        }
    ]
    if dependency_type != "identity_introduction":
        dependencies.append(
            {
                "dependency_type": dependency_type,
                "record_id": f"entry:{dependency_type}",
                "payload_sha256": THREE,
                "authorization_records": [
                    {"record_id": "anchor:operator", "payload_sha256": TWO},
                    {
                        "record_id": f"entry:{dependency_type}",
                        "payload_sha256": THREE,
                    },
                ],
                "decisive_for": ["entry:claim"],
            }
        )
    return {
        "authority_bundle_path": "authority/ledger.json",
        "authority_bundle_sha256": ZERO,
        "authority_chains": [
            {
                "issuer_id": "authority:root",
                "claim_entry_id": "entry:claim",
                "records": [
                    {"record_id": "anchor:root", "payload_sha256": ONE},
                    {"record_id": "entry:claim", "payload_sha256": TWO},
                ],
            }
        ],
        "authority_dependencies": dependencies,
        "contract_records": [
            {"path": "context/policy.json", "sha256": TWO}
        ],
        "evidence_records": [
            {"path": "evidence/test-run.json", "sha256": THREE}
        ],
        "unevaluated_stages": [],
    }


def _case(case_id: str, family_id: str) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-case-v0.3.6",
        "case_id": case_id,
        "family_id": family_id,
        "split": "blind_validation",
        "question": "Is the synthetic release ready?",
        "validation_time": NOW,
        "fixture_directory": f"cases/{case_id}",
        "permitted_inputs_manifest": f"cases/{case_id}/inputs.sha256",
    }


def _oracle(case_id: str, dependency_type: str = "identity_introduction") -> dict:
    reason = {
        "identity_introduction": "ALL_REQUIREMENTS_SATISFIED",
        "precedence": "PRECEDENCE_RESOLVED",
        "recovery": "RECOVERY_EFFECTIVE",
        "revocation": "REVOCATION_EFFECTIVE",
    }[dependency_type]
    return {
        "schema_version": "agent-context-proof-oracle-v0.3.6",
        "case_id": case_id,
        "oracle": {
            "disposition": "READY",
            "mechanism_status": "CONFORMANT",
            "authority_status": "VALID",
            "oracle_rule_ids": ["OA1_VALID", "OE8_ALL_SATISFIED", "V1_READY"],
            "reason_codes": [reason],
            "provenance": _provenance(dependency_type),
        },
        "rationale": "The committed rules produce one deterministic result.",
    }


def _result(case_id: str) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-result-v0.3.6",
        "case_id": case_id,
        "path_id": "governed",
        "repeat_index": 0,
        "disposition": "READY",
        "mechanism_status": "CONFORMANT",
        "authority_status": "VALID",
        "reason_codes": ["ALL_REQUIREMENTS_SATISFIED"],
        "provenance": _provenance(),
        "trace_sha256": ZERO,
    }


def _authorship(family_id: str, author: str) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-authorship-v0.3.6",
        "family_id": family_id,
        "primary_author_id": author,
        "coauthor_ids": [],
        "implementation_roles": [],
        "shared_source_digests": [],
        "coordination_disclosures": [],
        "conflicts_of_interest": [],
        "attestation_timestamp": NOW,
        "attestation_signature": "synthetic-test-signature",
    }


def _schema_versions() -> dict[str, str]:
    return {
        "authorship_attestation": "agent-context-proof-authorship-v0.3.6",
        "case_record": "agent-context-proof-case-v0.3.6",
        "freeze_reveal_record": "agent-context-proof-freeze-reveal-v0.3.6",
        "leakage_review_attestation": (
            "agent-context-proof-leakage-review-v0.3.6"
        ),
        "oracle_record": "agent-context-proof-oracle-v0.3.6",
        "pack_manifest": "agent-context-proof-pack-manifest-v0.3.6",
        "public_commitment": "agent-context-proof-public-commitment-v0.3.6",
        "result_record": "agent-context-proof-result-v0.3.6",
    }


def _public_commitment() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-public-commitment-v0.3.6",
        "approved_protocol_commit": COMMIT,
        "schema_versions": _schema_versions(),
        "aggregate_case_count": 12,
        "aggregate_family_count": 4,
        "sealed_input_pack_sha256": ONE,
        "sealed_oracle_pack_sha256": TWO,
        "authorship_attestation_sha256": THREE,
        "leakage_review_attestation_sha256": ZERO,
    }


def _pack(pack_type: str, digest: str) -> dict[str, object]:
    prefix = "cases" if pack_type == "sealed_input_pack" else "oracle"
    return {
        "schema_version": "agent-context-proof-pack-manifest-v0.3.6",
        "pack_type": pack_type,
        "archive_sha256": digest,
        "case_count": 12,
        "family_count": 4,
        "entries": [
            {"path": f"{prefix}/index.json", "sha256": ZERO, "size_bytes": 1}
        ],
    }


def _leakage() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-leakage-review-v0.3.6",
        "input_pack_sha256": ONE,
        "randomized_input_pack_sha256": TWO,
        "reviewer_id": "reviewer:one",
        "oracle_custodian_id": "custodian:one",
        "cases": [
            {
                "randomized_case_id": "random:one",
                "predicted_disposition": "READY",
                "predicted_mechanism_status": "CONFORMANT",
                "predicted_authority_status": "VALID",
                "suspected_cues": [],
                "basis": "GOVERNED_SEMANTICS",
                "disposition": "PASS",
                "rationale": "No extraneous cue was found.",
            }
        ],
        "attestation_timestamp": NOW,
        "reviewer_signature": "synthetic-reviewer-signature",
        "custodian_signature": "synthetic-custodian-signature",
    }


def _freeze() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-freeze-reveal-v0.3.6",
        "experiment_id": "experiment:v03",
        "approved_protocol_commit": COMMIT,
        "public_commitment_sha256": ZERO,
        "sealed_input_pack_sha256": ONE,
        "sealed_oracle_pack_sha256": TWO,
        "authorship_records_sha256": THREE,
        "relatedness_graph_sha256": ZERO,
        "leakage_review_sha256": ONE,
        "oracle_annotations_sha256": TWO,
        "oracle_adjudication_sha256": THREE,
        "implementation_freeze_commit": "b" * 40,
        "governed_prompt_sha256": ZERO,
        "governed_rules_sha256": ONE,
        "comparator_prompt_sha256": TWO,
        "comparator_rules_sha256": THREE,
        "environment_sha256": ZERO,
        "models": [
            {"path_id": "governed", "model_id": "none", "settings_sha256": ONE}
        ],
        "input_pack_revealed_at": NOW,
        "all_path_commitments": [
            {"path_id": "governed", "outputs_sha256": TWO, "traces_sha256": THREE}
        ],
        "oracle_pack_revealed_at": "2030-01-02T00:00:00Z",
        "case_exclusions": [],
        "exclusion_set_sha256": ZERO,
    }


def test_artifact_schemas_mirror_protocol_vocabularies_and_file_map() -> None:
    validator = _validator_module()
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    common = json.loads(COMMON_SCHEMA_PATH.read_text(encoding="utf-8"))

    schema_triplets = {
        (
            item["properties"]["disposition"]["const"],
            item["properties"]["mechanism_status"]["const"],
            item["properties"]["authority_status"]["const"],
        )
        for item in common["$defs"]["valid_output_triplet"]["oneOf"]
    }
    protocol_triplets = {
        (
            item["disposition"],
            item["mechanism_status"],
            item["authority_status"],
        )
        for item in protocol["valid_output_combinations"]
    }
    assert schema_triplets == protocol_triplets
    assert common["$defs"]["reason_code"]["enum"] == protocol["reason_codes"]

    declared_files = protocol["blind_evaluation"]["artifact_schema_contract"][
        "schema_files"
    ]
    assert declared_files == {
        kind: str(path.relative_to(PROJECT_ROOT))
        for kind, path in validator.SCHEMA_FILES.items()
        if kind != "authority_bundle"
    }
    for path in validator.SCHEMA_FILES.values():
        assert path.is_file()


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("case_record", _case("case:one", "family:one")),
        ("oracle_record", _oracle("case:one")),
        ("result_record", _result("case:one")),
        ("authorship_attestation", _authorship("family:one", "author:one")),
        ("leakage_review_attestation", _leakage()),
        ("public_commitment", _public_commitment()),
        ("pack_manifest", _pack("sealed_input_pack", ONE)),
        ("freeze_reveal_record", _freeze()),
    ],
)
def test_each_case_sealing_artifact_has_a_strict_valid_shape(
    tmp_path: Path, kind: str, value: dict[str, object]
) -> None:
    validator = _validator_module()
    path = _write(tmp_path / f"{kind}.json", value)
    validator.validate_artifacts([(kind, path)])


def test_schemas_reject_unknown_null_invalid_combo_and_reason_code(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    invalid_values = []

    unknown = _case("case:one", "family:one")
    unknown["unexpected"] = True
    invalid_values.append(("case_record", unknown))

    null_required = _case("case:one", "family:one")
    null_required["question"] = None
    invalid_values.append(("case_record", null_required))

    invalid_combo = _result("case:one")
    invalid_combo["authority_status"] = "CONFLICT"
    invalid_values.append(("result_record", invalid_combo))

    invalid_reason = _result("case:one")
    invalid_reason["reason_codes"] = ["AUTHOR_DEFINED_REASON"]
    invalid_values.append(("result_record", invalid_reason))

    for index, (kind, value) in enumerate(invalid_values):
        path = _write(tmp_path / f"invalid-{index}.json", value)
        with pytest.raises(validator.StructuralValidationError):
            validator.validate_artifacts([(kind, path)])


def test_strict_parser_rejects_duplicate_json_members(tmp_path: Path) -> None:
    validator = _validator_module()
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"x","schema_version":"y"}', encoding="utf-8")
    with pytest.raises(validator.StructuralValidationError, match="duplicate JSON"):
        validator.load_strict_json(path)


def test_closed_validator_links_cases_oracles_authorship_commitment_and_manifests(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    assignments: list[tuple[str, Path]] = []
    for index in range(12):
        case_id = f"case:{index:02d}"
        family_id = f"family:{index % 4}"
        assignments.append(
            (
                "case_record",
                _write(
                    tmp_path / f"case-{index}.json",
                    _case(case_id, family_id),
                ),
            )
        )
        assignments.append(
            (
                "oracle_record",
                _write(tmp_path / f"oracle-{index}.json", _oracle(case_id)),
            )
        )
    for index in range(4):
        assignments.append(
            (
                "authorship_attestation",
                _write(
                    tmp_path / f"author-{index}.json",
                    _authorship(f"family:{index}", f"author:{index}"),
                ),
            )
        )
    commitment_path = _write(tmp_path / "commitment.json", _public_commitment())
    input_manifest_path = _write(
        tmp_path / "input-manifest.json", _pack("sealed_input_pack", ONE)
    )
    oracle_manifest_path = _write(
        tmp_path / "oracle-manifest.json", _pack("sealed_oracle_pack", TWO)
    )
    assignments.extend(
        [
            ("public_commitment", commitment_path),
            ("pack_manifest", input_manifest_path),
            ("pack_manifest", oracle_manifest_path),
        ]
    )
    validator.validate_artifacts(assignments)

    mismatched = _pack("sealed_input_pack", THREE)
    _write(input_manifest_path, mismatched)
    with pytest.raises(
        validator.StructuralValidationError,
        match="input-pack digest does not match",
    ):
        validator.validate_artifacts(assignments)


def test_conflicting_lineage_head_pin_is_schema_valid_but_semantically_invalid(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    bundle = deepcopy(vectors["example_bundle"])
    conflicting = deepcopy(bundle["lineage_heads"][0])
    conflicting["epoch"] -= 1
    conflicting["entry_id"] = "entry:rotation-root-a-epoch-1"
    conflicting["payload_sha256"] = ZERO
    bundle["lineage_heads"].append(conflicting)
    path = _write(tmp_path / "bundle.json", bundle)

    registry = validator._registry()
    schema_validator = validator._validator("authority_bundle", registry)
    assert not list(schema_validator.iter_errors(bundle))
    with pytest.raises(
        validator.StructuralValidationError,
        match="duplicate lineage_heads lineage_id",
    ):
        validator.validate_artifacts([("authority_bundle", path)])


@pytest.mark.parametrize("dependency_type", ["precedence", "recovery", "revocation"])
def test_decisive_side_dependencies_have_exact_canonical_provenance(
    tmp_path: Path, dependency_type: str
) -> None:
    validator = _validator_module()
    oracle = _oracle(f"case:{dependency_type}", dependency_type)
    path = _write(tmp_path / f"{dependency_type}.json", oracle)
    validator.validate_artifacts([("oracle_record", path)])

    dependencies = oracle["oracle"]["provenance"]["authority_dependencies"]
    assert [item["dependency_type"] for item in dependencies] == [
        "identity_introduction",
        dependency_type,
    ]
    side_dependency = dependencies[1]
    assert side_dependency == {
        "dependency_type": dependency_type,
        "record_id": f"entry:{dependency_type}",
        "payload_sha256": THREE,
        "authorization_records": [
            {"record_id": "anchor:operator", "payload_sha256": TWO},
            {"record_id": f"entry:{dependency_type}", "payload_sha256": THREE},
        ],
        "decisive_for": ["entry:claim"],
    }
