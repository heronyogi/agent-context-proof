from __future__ import annotations

import hashlib
import importlib.util
import json
import tarfile
from copy import deepcopy
from io import BytesIO
from pathlib import Path

import pytest
import rfc8785

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = PROJECT_ROOT / "scripts" / "validate_v03_artifact.py"
VECTOR_PATH = PROJECT_ROOT / "tests" / "fixtures" / "authority-ledger.v0.3.vectors.json"
PROTOCOL_PATH = PROJECT_ROOT / "docs" / "proof-protocol.v0.3.json"
COMMON_SCHEMA_PATH = PROJECT_ROOT / "docs" / "protocol-artifact-defs.v0.3.schema.json"

ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
TWO = "sha256:" + "2" * 64
THREE = "sha256:" + "3" * 64
COMMIT = "a" * 40
NOW = "2030-01-01T00:00:00Z"
COORDINATE = {
    "organization": "org:orion",
    "repository": "repo:orion-service",
    "artifact": "release:orion:1.0.0",
    "action": "release",
}


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
            }
        )
    chain = {
        "issuer_id": "authority:root",
        "claim_entry_id": "entry:claim",
        "records": [
            {"record_id": "anchor:root", "payload_sha256": ONE},
            {"record_id": "entry:claim", "payload_sha256": TWO},
        ],
    }
    chain["chain_sha256"] = "sha256:" + hashlib.sha256(rfc8785.dumps(chain)).hexdigest()
    return {
        "authority_bundle_path": "authority/ledger.json",
        "authority_bundle_sha256": ZERO,
        "authority_evaluation_records": [
            {
                "record_id": "anchor:root",
                "payload_sha256": ONE,
                "classification": "VALID",
                "decisive": True,
            },
            {
                "record_id": "entry:claim",
                "payload_sha256": TWO,
                "classification": "VALID",
                "decisive": True,
            },
        ],
        "authority_chains": [chain],
        "authority_dependencies": dependencies,
        "contract_records": [{"path": "context/policy.json", "sha256": TWO}],
        "evidence_records": [{"path": "evidence/test-run.json", "sha256": THREE}],
        "unevaluated_stages": [],
    }


def _case(case_id: str, family_id: str) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-case-v0.3.11",
        "case_id": case_id,
        "family_id": family_id,
        "split": "blind_validation",
        "question": "Is the synthetic release ready?",
        "validation_time": NOW,
        "case_coordinate": deepcopy(COORDINATE),
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
    oracle = {
        "disposition": "READY",
        "mechanism_status": "CONFORMANT",
        "authority_status": "VALID",
        "oracle_rule_ids": ["OA1_VALID", "OE8_ALL_SATISFIED", "V1_READY"],
        "reason_codes": sorted({"ALL_REQUIREMENTS_SATISFIED", reason}),
        "provenance": _provenance(dependency_type),
    }
    rationale = "The committed rules produce one deterministic result."
    return {
        "schema_version": "agent-context-proof-oracle-v0.3.11",
        "case_id": case_id,
        "case_coordinate": deepcopy(COORDINATE),
        "validation_time": NOW,
        "oracle": oracle,
        "rationale": rationale,
        "annotations": [
            {
                "annotator_id": "annotator:one",
                "case_id": case_id,
                "case_coordinate": deepcopy(COORDINATE),
                "validation_time": NOW,
                "annotation": deepcopy(oracle),
                "rationale": rationale,
                "declaration": "I independently applied the committed rules.",
            },
            {
                "annotator_id": "annotator:two",
                "case_id": case_id,
                "case_coordinate": deepcopy(COORDINATE),
                "validation_time": NOW,
                "annotation": deepcopy(oracle),
                "rationale": rationale,
                "declaration": "I independently applied the committed rules.",
            },
        ],
        "adjudication": {
            "adjudicator_id": "adjudicator:one",
            "case_id": case_id,
            "case_coordinate": deepcopy(COORDINATE),
            "validation_time": NOW,
            "resolution": "EXACT_AGREEMENT",
            "oracle": deepcopy(oracle),
            "rationale": rationale,
            "declaration": "I compared both annotations under the protocol.",
        },
    }


def _result(case_id: str) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-result-v0.3.11",
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
        "schema_version": "agent-context-proof-authorship-v0.3.11",
        "family_id": family_id,
        "primary_author_id": author,
        "coauthor_ids": [],
        "implementation_roles": [],
        "shared_sources": [],
        "coordination_disclosures": [],
        "conflicts_of_interest": [],
        "attestation_timestamp": NOW,
        "declaration": "Synthetic test authorship declaration.",
    }


def _schema_versions() -> dict[str, str]:
    return {
        "authorship_attestation": "agent-context-proof-authorship-v0.3.11",
        "authorship_collection": "agent-context-proof-authorship-collection-v0.3.11",
        "case_record": "agent-context-proof-case-v0.3.11",
        "freeze_reveal_record": "agent-context-proof-freeze-reveal-v0.3.11",
        "leakage_review_attestation": ("agent-context-proof-leakage-review-v0.3.11"),
        "oracle_record": "agent-context-proof-oracle-v0.3.11",
        "oracle_reveal_record": "agent-context-proof-oracle-reveal-v0.3.11",
        "pack_manifest": "agent-context-proof-pack-manifest-v0.3.11",
        "path_artifact_manifest": (
            "agent-context-proof-path-artifact-manifest-v0.3.11"
        ),
        "path_output_commitment": (
            "agent-context-proof-path-output-commitment-v0.3.11"
        ),
        "path_run_record": "agent-context-proof-path-run-v0.3.11",
        "population_freeze_record": ("agent-context-proof-population-freeze-v0.3.11"),
        "public_commitment": "agent-context-proof-public-commitment-v0.3.11",
        "relatedness_graph": "agent-context-proof-relatedness-graph-v0.3.11",
        "result_record": "agent-context-proof-result-v0.3.11",
        "trace_record": "agent-context-proof-trace-v0.3.11",
    }


def _public_commitment() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-public-commitment-v0.3.11",
        "approved_protocol_commit": COMMIT,
        "schema_versions": _schema_versions(),
        "aggregate_case_count": 12,
        "aggregate_family_count": 4,
        "sealed_input_pack_sha256": ONE,
        "sealed_oracle_pack_sha256": TWO,
        "authorship_collection_sha256": THREE,
        "relatedness_graph_sha256": THREE,
        "leakage_review_attestation_sha256": ZERO,
    }


def _approved_protocol_manifest() -> dict[str, object]:
    validator = _validator_module()
    return {
        "schema_version": ("agent-context-proof-approved-protocol-manifest-v0.3.11"),
        "approved_protocol_commit": COMMIT,
        "files": [
            {
                "path": relative_path,
                "sha256": _digest((PROJECT_ROOT / relative_path).read_bytes()),
            }
            for relative_path in validator.APPROVED_PROTOCOL_PATHS
        ],
    }


def _pack(pack_type: str, digest: str) -> dict[str, object]:
    prefix = "cases" if pack_type == "sealed_input_pack" else "oracle"
    return {
        "schema_version": "agent-context-proof-pack-manifest-v0.3.11",
        "pack_type": pack_type,
        "archive_format": "USTAR_CANONICAL_V0.3.11",
        "archive_sha256": digest,
        "case_count": 12,
        "family_count": 4,
        "entries": [{"path": f"{prefix}/index.json", "sha256": ZERO, "size_bytes": 1}],
    }


def _leakage() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-leakage-review-v0.3.11",
        "input_pack_sha256": ONE,
        "randomized_input_pack_sha256": TWO,
        "reviewer_id": "reviewer:one",
        "oracle_custodian_id": "custodian:one",
        "cases": [
            {
                "case_id": "case:one",
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
        "reviewer_declaration": "Synthetic reviewer declaration.",
        "custodian_declaration": "Synthetic custodian declaration.",
    }


def _freeze() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-freeze-reveal-v0.3.11",
        "experiment_id": "experiment:v03",
        "population_freeze_sha256": ZERO,
        "output_commitment_sha256s": [ONE, TWO],
        "oracle_reveal_sha256": THREE,
        "finalized_at": "2030-01-03T00:00:00Z",
    }


def _authorship_collection() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-authorship-collection-v0.3.11",
        "records": [
            _authorship(f"family:{index}", f"author:{index}") for index in range(4)
        ],
    }


def _relatedness_graph() -> dict[str, object]:
    family_ids = [f"family:{index}" for index in range(4)]
    return {
        "schema_version": "agent-context-proof-relatedness-graph-v0.3.11",
        "family_ids": family_ids,
        "edges": [],
        "clusters": [
            {"cluster_id": family_id, "family_ids": [family_id]}
            for family_id in family_ids
        ],
    }


def _population_freeze() -> dict[str, object]:
    case_ids = [f"case:{index:02d}" for index in range(12)]
    population_sha256 = (
        "sha256:"
        + hashlib.sha256(
            rfc8785.dumps({"included_case_ids": case_ids, "repeat_count": 1})
        ).hexdigest()
    )
    return {
        "schema_version": "agent-context-proof-population-freeze-v0.3.11",
        "experiment_id": "experiment:v03",
        "approved_protocol_commit": COMMIT,
        "public_commitment_sha256": ZERO,
        "input_manifest_sha256": ONE,
        "oracle_manifest_sha256": TWO,
        "implementation_freeze_commit": "b" * 40,
        "governed_prompt_sha256": ZERO,
        "governed_rules_sha256": ONE,
        "comparator_prompt_sha256": TWO,
        "comparator_rules_sha256": THREE,
        "environment_sha256": ZERO,
        "models": [
            {
                "path_id": "governed",
                "model_id": "none",
                "settings_sha256": ONE,
                "observer_rules_sha256": ONE,
            },
            {
                "path_id": "retrieval_plus_rules",
                "model_id": "none",
                "settings_sha256": TWO,
                "observer_rules_sha256": THREE,
            },
        ],
        "case_exclusions": [],
        "repeat_count": 1,
        "included_case_ids": case_ids,
        "population_sha256": population_sha256,
        "frozen_at": NOW,
        "input_pack_revealed_at": "2030-01-02T00:00:00Z",
    }


def _path_output_commitment(path_id: str) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-path-output-commitment-v0.3.11",
        "experiment_id": "experiment:v03",
        "population_freeze_sha256": ZERO,
        "path_id": path_id,
        "outputs_sha256": ONE,
        "outputs_manifest_sha256": THREE,
        "traces_sha256": TWO,
        "traces_manifest_sha256": ZERO,
        "included_case_count": 12,
        "repeat_count": 1,
        "committed_at": "2030-01-02T12:00:00Z",
    }


def _oracle_reveal() -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-oracle-reveal-v0.3.11",
        "experiment_id": "experiment:v03",
        "population_freeze_sha256": ZERO,
        "output_commitment_sha256s": [ONE, TWO],
        "oracle_pack_revealed_at": "2030-01-03T00:00:00Z",
    }


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_tar(files: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, data in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, BytesIO(data))
    return output.getvalue()


def _archive_manifest(
    pack_type: str, archive: bytes, files: dict[str, bytes]
) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-pack-manifest-v0.3.11",
        "pack_type": pack_type,
        "archive_format": "USTAR_CANONICAL_V0.3.11",
        "archive_sha256": _digest(archive),
        "case_count": 12,
        "family_count": 4,
        "entries": [
            {"path": path, "sha256": _digest(data), "size_bytes": len(data)}
            for path, data in sorted(files.items())
        ],
    }


def _path_artifact_manifest(
    artifact_type: str,
    path_id: str,
    population_digest: str,
    archive: bytes,
    files: dict[str, bytes],
) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-path-artifact-manifest-v0.3.11",
        "artifact_type": artifact_type,
        "path_id": path_id,
        "population_freeze_sha256": population_digest,
        "archive_format": "USTAR_CANONICAL_V0.3.11",
        "archive_sha256": _digest(archive),
        "case_count": 12,
        "repeat_count": 1,
        "entries": [
            {"path": file_name, "sha256": _digest(data), "size_bytes": len(data)}
            for file_name, data in sorted(files.items())
        ],
    }


def _trace_record(case_id: str, path_id: str, observer_rules: str) -> dict[str, object]:
    return {
        "schema_version": "agent-context-proof-trace-v0.3.11",
        "case_id": case_id,
        "path_id": path_id,
        "repeat_index": 0,
        "observer_rules_sha256": observer_rules,
        "events": [
            {
                "sequence": 0,
                "event_type": "resolver:completed",
                "subject": case_id,
                "payload_sha256": ZERO,
                "observed_at": "2030-01-02T01:00:00Z",
            }
        ],
    }


def _path_run_record(
    case_id: str,
    path_id: str,
    trace_digest: str,
    provenance: dict[str, object],
) -> dict[str, object]:
    result = _result(case_id)
    result["path_id"] = path_id
    result["trace_sha256"] = trace_digest
    result["provenance"] = deepcopy(provenance)
    return {
        "schema_version": "agent-context-proof-path-run-v0.3.11",
        "case_id": case_id,
        "path_id": path_id,
        "repeat_index": 0,
        "run_status": "COMPLETE",
        "trace_sha256": trace_digest,
        "result": result,
    }


def _bundle_provenance(bundle: dict, bundle_bytes: bytes) -> dict[str, object]:
    records: dict[str, dict] = {}
    digests: dict[str, str] = {}
    for anchor in [*bundle["trust_anchors"], *bundle["recovery_trust_anchors"]]:
        record_id = anchor["anchor_id"]
        records[record_id] = anchor
        digests[record_id] = _digest(rfc8785.dumps(anchor))
    for entry in bundle["entries"]:
        record_id = entry["entry_id"]
        records[record_id] = entry
        payload = deepcopy(entry)
        payload.pop("signature")
        digests[record_id] = _digest(rfc8785.dumps(payload))

    claim_id = "entry:claim-release-owner"
    root_id = "anchor:root-a-epoch-0"
    recovery_anchor_id = "anchor:recovery-a-epoch-0"
    rotation_id = "entry:rotation-root-a-epoch-1"
    recovery_id = "entry:recovery-root-a"
    decisive = {claim_id, root_id, recovery_anchor_id, rotation_id, recovery_id}
    evaluation_records = [
        {
            "record_id": record_id,
            "payload_sha256": digest,
            "classification": "VALID" if record_id in decisive else "NONMATCHING",
            "decisive": record_id in decisive,
        }
        for record_id, digest in sorted(digests.items())
    ]
    chain_core = {
        "issuer_id": "authority:root-a-recovered",
        "claim_entry_id": claim_id,
        "records": [
            {"record_id": record_id, "payload_sha256": digests[record_id]}
            for record_id in [root_id, rotation_id, recovery_id, claim_id]
        ],
    }
    chain = {**chain_core, "chain_sha256": _digest(rfc8785.dumps(chain_core))}

    def dependency(
        dependency_type: str, record_id: str, authorization_ids: list[str]
    ) -> dict[str, object]:
        return {
            "dependency_type": dependency_type,
            "record_id": record_id,
            "payload_sha256": digests[record_id],
            "authorization_records": [
                {"record_id": item, "payload_sha256": digests[item]}
                for item in authorization_ids
            ],
        }

    dependencies = [
        dependency("identity_introduction", root_id, [root_id]),
        dependency("identity_introduction", recovery_anchor_id, [recovery_anchor_id]),
        dependency(
            "identity_introduction", recovery_id, [recovery_anchor_id, recovery_id]
        ),
        dependency("identity_introduction", rotation_id, [root_id, rotation_id]),
        dependency("lineage_head", recovery_id, [recovery_anchor_id, recovery_id]),
        dependency("recovery", recovery_id, [recovery_anchor_id, recovery_id]),
    ]
    dependencies.sort(
        key=lambda item: (
            item["dependency_type"],
            item["record_id"],
            item["payload_sha256"],
        )
    )
    return {
        "authority_bundle_path": "authority/ledger.json",
        "authority_bundle_sha256": _digest(bundle_bytes),
        "authority_evaluation_records": evaluation_records,
        "authority_chains": [chain],
        "authority_dependencies": dependencies,
        "contract_records": [{"path": "context/policy.json", "sha256": _digest(b"{}")}],
        "evidence_records": [
            {"path": "evidence/test-run.txt", "sha256": _digest(b"pass\n")}
        ],
        "unevaluated_stages": [],
    }


def _set_classification(
    provenance: dict[str, object], record_id: str, classification: str
) -> None:
    record = next(
        item
        for item in provenance["authority_evaluation_records"]
        if item["record_id"] == record_id
    )
    record["classification"] = classification


def _build_complete_pack(tmp_path: Path) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    validator = _validator_module()
    approved_protocol_manifest = {
        "schema_version": ("agent-context-proof-approved-protocol-manifest-v0.3.11"),
        "approved_protocol_commit": COMMIT,
        "files": [
            {
                "path": relative_path,
                "sha256": _digest((PROJECT_ROOT / relative_path).read_bytes()),
            }
            for relative_path in validator.APPROVED_PROTOCOL_PATHS
        ],
    }
    approved_protocol_manifest_path = _write(
        tmp_path / "approved-protocol-manifest.json",
        approved_protocol_manifest,
    )
    vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    bundle = vectors["example_bundle"]
    bundle_bytes = _json_bytes(bundle)
    provenance = _bundle_provenance(bundle, bundle_bytes)
    case_ids = [f"case:{index:02d}" for index in range(12)]
    input_files: dict[str, bytes] = {}
    oracle_files: dict[str, bytes] = {}
    for index, case_id in enumerate(case_ids):
        family_id = f"family:{index % 4}"
        directory = f"cases/{case_id}"
        fixture_files = {
            f"{directory}/authority/ledger.json": bundle_bytes,
            f"{directory}/context/policy.json": b"{}",
            f"{directory}/evidence/test-run.txt": b"pass\n",
        }
        input_files.update(fixture_files)
        permitted = "".join(
            f"{_digest(data)}  {path}\n" for path, data in sorted(fixture_files.items())
        ).encode()
        input_files[f"{directory}/inputs.sha256"] = permitted
        case = _case(case_id, family_id)
        case["validation_time"] = bundle["validation_time"]
        input_files[f"{directory}/case.json"] = _json_bytes(case)
        oracle = _oracle(case_id)
        oracle["case_coordinate"] = deepcopy(bundle["case_coordinate"])
        oracle["validation_time"] = bundle["validation_time"]
        for annotation in oracle["annotations"]:
            annotation["case_coordinate"] = deepcopy(bundle["case_coordinate"])
            annotation["validation_time"] = bundle["validation_time"]
        oracle["adjudication"]["case_coordinate"] = deepcopy(bundle["case_coordinate"])
        oracle["adjudication"]["validation_time"] = bundle["validation_time"]
        for payload in [
            oracle["oracle"],
            *(item["annotation"] for item in oracle["annotations"]),
            oracle["adjudication"]["oracle"],
        ]:
            payload["provenance"] = deepcopy(provenance)
        oracle_files[f"oracles/{case_id}.json"] = _json_bytes(oracle)

    input_archive = _canonical_tar(input_files)
    input_archive_path = tmp_path / "input.tar"
    input_archive_path.write_bytes(input_archive)

    authorship = _authorship_collection()
    graph = _relatedness_graph()
    leakage = _leakage()
    leakage["input_pack_sha256"] = _digest(input_archive)
    leakage["cases"] = [
        {
            "case_id": case_id,
            "randomized_case_id": f"random:{index:02d}",
            "predicted_disposition": "READY",
            "predicted_mechanism_status": "CONFORMANT",
            "predicted_authority_status": "VALID",
            "suspected_cues": [],
            "basis": "GOVERNED_SEMANTICS",
            "disposition": "PASS",
            "rationale": "No extraneous cue was found.",
        }
        for index, case_id in enumerate(case_ids)
    ]
    oracle_files["authorship-collection.json"] = _json_bytes(authorship)
    oracle_files["relatedness-graph.json"] = _json_bytes(graph)
    oracle_files["leakage-review.json"] = _json_bytes(leakage)
    oracle_archive = _canonical_tar(oracle_files)
    oracle_archive_path = tmp_path / "oracle.tar"
    oracle_archive_path.write_bytes(oracle_archive)

    input_manifest = _archive_manifest("sealed_input_pack", input_archive, input_files)
    oracle_manifest = _archive_manifest(
        "sealed_oracle_pack", oracle_archive, oracle_files
    )
    input_manifest_path = _write(tmp_path / "input-manifest.json", input_manifest)
    oracle_manifest_path = _write(tmp_path / "oracle-manifest.json", oracle_manifest)
    public_commitment = _public_commitment()
    public_commitment.update(
        {
            "sealed_input_pack_sha256": _digest(input_archive),
            "sealed_oracle_pack_sha256": _digest(oracle_archive),
            "authorship_collection_sha256": _digest(
                oracle_files["authorship-collection.json"]
            ),
            "relatedness_graph_sha256": _digest(oracle_files["relatedness-graph.json"]),
            "leakage_review_attestation_sha256": _digest(
                oracle_files["leakage-review.json"]
            ),
        }
    )
    public_path = _write(tmp_path / "public.json", public_commitment)

    population = _population_freeze()
    population.update(
        {
            "public_commitment_sha256": _digest(public_path.read_bytes()),
            "input_manifest_sha256": _digest(input_manifest_path.read_bytes()),
            "oracle_manifest_sha256": _digest(oracle_manifest_path.read_bytes()),
        }
    )
    population_path = _write(tmp_path / "population.json", population)
    population_digest = _digest(population_path.read_bytes())
    commitment_paths: list[Path] = []
    result_archive_paths: list[Path] = []
    result_manifest_paths: list[Path] = []
    trace_archive_paths: list[Path] = []
    trace_manifest_paths: list[Path] = []
    result_files_by_path: dict[str, dict[str, bytes]] = {}
    trace_files_by_path: dict[str, dict[str, bytes]] = {}
    for path_id in ("governed", "retrieval_plus_rules"):
        observer_rules = ONE if path_id == "governed" else THREE
        trace_files: dict[str, bytes] = {}
        result_files: dict[str, bytes] = {}
        for case_id in case_ids:
            trace = _trace_record(case_id, path_id, observer_rules)
            trace_bytes = _json_bytes(trace)
            trace_files[f"traces/{path_id}/{case_id}/0.json"] = trace_bytes
            run = _path_run_record(
                case_id,
                path_id,
                _digest(trace_bytes),
                provenance,
            )
            result_files[f"results/{path_id}/{case_id}/0.json"] = _json_bytes(run)
        result_files_by_path[path_id] = result_files
        trace_files_by_path[path_id] = trace_files
        result_archive = _canonical_tar(result_files)
        trace_archive = _canonical_tar(trace_files)
        result_archive_path = tmp_path / f"results-{path_id}.tar"
        trace_archive_path = tmp_path / f"traces-{path_id}.tar"
        result_archive_path.write_bytes(result_archive)
        trace_archive_path.write_bytes(trace_archive)
        result_manifest_path = _write(
            tmp_path / f"results-{path_id}-manifest.json",
            _path_artifact_manifest(
                "result_records",
                path_id,
                population_digest,
                result_archive,
                result_files,
            ),
        )
        trace_manifest_path = _write(
            tmp_path / f"traces-{path_id}-manifest.json",
            _path_artifact_manifest(
                "trace_records",
                path_id,
                population_digest,
                trace_archive,
                trace_files,
            ),
        )
        result_archive_paths.append(result_archive_path)
        result_manifest_paths.append(result_manifest_path)
        trace_archive_paths.append(trace_archive_path)
        trace_manifest_paths.append(trace_manifest_path)
        commitment = _path_output_commitment(path_id)
        commitment["population_freeze_sha256"] = population_digest
        commitment["outputs_sha256"] = _digest(result_archive)
        commitment["outputs_manifest_sha256"] = _digest(
            result_manifest_path.read_bytes()
        )
        commitment["traces_sha256"] = _digest(trace_archive)
        commitment["traces_manifest_sha256"] = _digest(trace_manifest_path.read_bytes())
        commitment_paths.append(
            _write(tmp_path / f"commitment-{path_id}.json", commitment)
        )
    commitment_digests = sorted(_digest(path.read_bytes()) for path in commitment_paths)
    reveal = _oracle_reveal()
    reveal["population_freeze_sha256"] = population_digest
    reveal["output_commitment_sha256s"] = commitment_digests
    reveal_path = _write(tmp_path / "oracle-reveal.json", reveal)
    final = _freeze()
    final["population_freeze_sha256"] = population_digest
    final["output_commitment_sha256s"] = commitment_digests
    final["oracle_reveal_sha256"] = _digest(reveal_path.read_bytes())
    final_path = _write(tmp_path / "final.json", final)
    return {
        "expected_approved_protocol_commit": COMMIT,
        "approved_protocol_manifest_path": approved_protocol_manifest_path,
        "expected_approved_protocol_manifest_sha256": _digest(
            approved_protocol_manifest_path.read_bytes()
        ),
        "public_commitment_path": public_path,
        "input_archive_path": input_archive_path,
        "input_manifest_path": input_manifest_path,
        "oracle_archive_path": oracle_archive_path,
        "oracle_manifest_path": oracle_manifest_path,
        "population_freeze_path": population_path,
        "output_commitment_paths": commitment_paths,
        "result_archive_paths": result_archive_paths,
        "result_manifest_paths": result_manifest_paths,
        "trace_archive_paths": trace_archive_paths,
        "trace_manifest_paths": trace_manifest_paths,
        "oracle_reveal_path": reveal_path,
        "freeze_reveal_path": final_path,
        "input_files": input_files,
        "oracle_files": oracle_files,
        "result_files_by_path": result_files_by_path,
        "trace_files_by_path": trace_files_by_path,
    }


def _rebind_complete_pack(pack: dict[str, object]) -> None:
    input_files = pack["input_files"]
    oracle_files = pack["oracle_files"]
    input_archive = _canonical_tar(input_files)
    oracle_archive = _canonical_tar(oracle_files)
    pack["input_archive_path"].write_bytes(input_archive)
    pack["oracle_archive_path"].write_bytes(oracle_archive)
    _write(
        pack["input_manifest_path"],
        _archive_manifest("sealed_input_pack", input_archive, input_files),
    )
    _write(
        pack["oracle_manifest_path"],
        _archive_manifest("sealed_oracle_pack", oracle_archive, oracle_files),
    )
    public = json.loads(pack["public_commitment_path"].read_text())
    public.update(
        {
            "sealed_input_pack_sha256": _digest(input_archive),
            "sealed_oracle_pack_sha256": _digest(oracle_archive),
            "authorship_collection_sha256": _digest(
                oracle_files["authorship-collection.json"]
            ),
            "relatedness_graph_sha256": _digest(oracle_files["relatedness-graph.json"]),
            "leakage_review_attestation_sha256": _digest(
                oracle_files["leakage-review.json"]
            ),
        }
    )
    _write(pack["public_commitment_path"], public)
    population = json.loads(pack["population_freeze_path"].read_text())
    population.update(
        {
            "public_commitment_sha256": _digest(
                pack["public_commitment_path"].read_bytes()
            ),
            "input_manifest_sha256": _digest(pack["input_manifest_path"].read_bytes()),
            "oracle_manifest_sha256": _digest(
                pack["oracle_manifest_path"].read_bytes()
            ),
        }
    )
    _write(pack["population_freeze_path"], population)
    population_digest = _digest(pack["population_freeze_path"].read_bytes())
    result_manifests: dict[str, tuple[Path, dict[str, object]]] = {}
    trace_manifests: dict[str, tuple[Path, dict[str, object]]] = {}
    for manifest_path in pack["result_manifest_paths"]:
        manifest = json.loads(manifest_path.read_text())
        manifest["population_freeze_sha256"] = population_digest
        _write(manifest_path, manifest)
        result_manifests[manifest["path_id"]] = (manifest_path, manifest)
    for manifest_path in pack["trace_manifest_paths"]:
        manifest = json.loads(manifest_path.read_text())
        manifest["population_freeze_sha256"] = population_digest
        _write(manifest_path, manifest)
        trace_manifests[manifest["path_id"]] = (manifest_path, manifest)
    for commitment_path in pack["output_commitment_paths"]:
        commitment = json.loads(commitment_path.read_text())
        commitment["population_freeze_sha256"] = population_digest
        path_id = commitment["path_id"]
        commitment["outputs_manifest_sha256"] = _digest(
            result_manifests[path_id][0].read_bytes()
        )
        commitment["traces_manifest_sha256"] = _digest(
            trace_manifests[path_id][0].read_bytes()
        )
        _write(commitment_path, commitment)
    commitment_digests = sorted(
        _digest(commitment_path.read_bytes())
        for commitment_path in pack["output_commitment_paths"]
    )
    reveal = json.loads(pack["oracle_reveal_path"].read_text())
    reveal["population_freeze_sha256"] = population_digest
    reveal["output_commitment_sha256s"] = commitment_digests
    _write(pack["oracle_reveal_path"], reveal)
    final = json.loads(pack["freeze_reveal_path"].read_text())
    final["population_freeze_sha256"] = population_digest
    final["output_commitment_sha256s"] = commitment_digests
    final["oracle_reveal_sha256"] = _digest(pack["oracle_reveal_path"].read_bytes())
    _write(pack["freeze_reveal_path"], final)


def _rebind_path_artifacts(pack: dict[str, object], path_id: str) -> None:
    population_digest = _digest(pack["population_freeze_path"].read_bytes())
    result_files = pack["result_files_by_path"][path_id]
    trace_files = pack["trace_files_by_path"][path_id]
    result_archive = _canonical_tar(result_files)
    trace_archive = _canonical_tar(trace_files)
    result_archive_path = next(
        item
        for item in pack["result_archive_paths"]
        if item.name == f"results-{path_id}.tar"
    )
    trace_archive_path = next(
        item
        for item in pack["trace_archive_paths"]
        if item.name == f"traces-{path_id}.tar"
    )
    result_manifest_path = next(
        item
        for item in pack["result_manifest_paths"]
        if item.name == f"results-{path_id}-manifest.json"
    )
    trace_manifest_path = next(
        item
        for item in pack["trace_manifest_paths"]
        if item.name == f"traces-{path_id}-manifest.json"
    )
    result_archive_path.write_bytes(result_archive)
    trace_archive_path.write_bytes(trace_archive)
    _write(
        result_manifest_path,
        _path_artifact_manifest(
            "result_records",
            path_id,
            population_digest,
            result_archive,
            result_files,
        ),
    )
    _write(
        trace_manifest_path,
        _path_artifact_manifest(
            "trace_records",
            path_id,
            population_digest,
            trace_archive,
            trace_files,
        ),
    )
    commitment_path = next(
        item
        for item in pack["output_commitment_paths"]
        if json.loads(item.read_text())["path_id"] == path_id
    )
    commitment = json.loads(commitment_path.read_text())
    commitment.update(
        {
            "outputs_sha256": _digest(result_archive),
            "outputs_manifest_sha256": _digest(result_manifest_path.read_bytes()),
            "traces_sha256": _digest(trace_archive),
            "traces_manifest_sha256": _digest(trace_manifest_path.read_bytes()),
        }
    )
    _write(commitment_path, commitment)
    _rebind_reveal_receipt(pack)


def _rebind_reveal_receipt(pack: dict[str, object]) -> None:
    commitment_digests = sorted(
        _digest(item.read_bytes()) for item in pack["output_commitment_paths"]
    )
    reveal = json.loads(pack["oracle_reveal_path"].read_text())
    reveal["output_commitment_sha256s"] = commitment_digests
    _write(pack["oracle_reveal_path"], reveal)
    final = json.loads(pack["freeze_reveal_path"].read_text())
    final["output_commitment_sha256s"] = commitment_digests
    final["oracle_reveal_sha256"] = _digest(pack["oracle_reveal_path"].read_bytes())
    _write(pack["freeze_reveal_path"], final)


def _complete_pack_kwargs(pack: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in pack.items()
        if key
        not in {
            "input_files",
            "oracle_files",
            "result_files_by_path",
            "trace_files_by_path",
        }
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
    relations = protocol["oracle_record_relations"]
    assert relations["authority_rule_by_status"] == validator.AUTHORITY_TO_OA_RULE
    assert {
        key: set(value) for key, value in relations["evidence_rules_by_v_rule"].items()
    } == validator.V_RULE_TO_EVIDENCE_RULES
    assert {
        key: set(value)
        for key, value in relations["required_reason_codes_by_v_rule"].items()
    } == validator.V_RULE_REQUIRED_REASONS
    assert {
        key: set(value)
        for key, value in relations["allowed_reason_codes_by_v_rule"].items()
    } == validator.V_RULE_ALLOWED_REASONS

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
    trusted_input = protocol["blind_evaluation"]["artifact_schema_contract"][
        "closed_validation_trusted_input"
    ]
    assert trusted_input["governed_file_set"] == validator.APPROVED_PROTOCOL_PATHS


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("approved_protocol_manifest", _approved_protocol_manifest()),
        ("case_record", _case("case:one", "family:one")),
        ("oracle_record", _oracle("case:one")),
        ("result_record", _result("case:one")),
        ("authorship_attestation", _authorship("family:one", "author:one")),
        ("authorship_collection", _authorship_collection()),
        ("relatedness_graph", _relatedness_graph()),
        ("leakage_review_attestation", _leakage()),
        ("public_commitment", _public_commitment()),
        ("pack_manifest", _pack("sealed_input_pack", ONE)),
        (
            "path_artifact_manifest",
            _path_artifact_manifest(
                "result_records", "governed", ZERO, b"archive", {"one": b"1"}
            ),
        ),
        (
            "path_run_record",
            _path_run_record("case:one", "governed", ZERO, _provenance()),
        ),
        ("population_freeze_record", _population_freeze()),
        (
            "path_output_commitment",
            _path_output_commitment("governed"),
        ),
        ("oracle_reveal_record", _oracle_reveal()),
        ("freeze_reveal_record", _freeze()),
        ("trace_record", _trace_record("case:one", "governed", ONE)),
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


def test_removed_unverifiable_provenance_fields_are_schema_invalid(
    tmp_path: Path,
) -> None:
    validator = _validator_module()

    oracle = _oracle("case:unverifiable-edge")
    oracle["oracle"]["provenance"]["authority_dependencies"][0]["decisive_for"] = [
        "entry:claim"
    ]
    oracle_path = _write(tmp_path / "decisive-for.json", oracle)
    with pytest.raises(
        validator.StructuralValidationError,
        match="Additional properties are not allowed",
    ):
        validator.validate_artifacts([("oracle_record", oracle_path)])

    run = {
        "schema_version": "agent-context-proof-path-run-v0.3.11",
        "case_id": "case:unbound-failure-detail",
        "path_id": "governed",
        "repeat_index": 0,
        "run_status": "MISSING",
        "trace_sha256": ZERO,
        "failure_code": "MISSING_OUTPUT",
        "failure_detail_sha256": ONE,
    }
    run_path = _write(tmp_path / "failure-detail.json", run)
    with pytest.raises(
        validator.StructuralValidationError,
        match="Additional properties are not allowed",
    ):
        validator.validate_artifacts([("path_run_record", run_path)])


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


def test_signed_delayed_delegation_is_semantically_invalid(tmp_path: Path) -> None:
    validator = _validator_module()
    vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    bundle = deepcopy(vectors["example_bundle"])
    delayed = vectors["adversarial_time_scenarios"][0]["invalid_introduction"][
        "signed_entry"
    ]
    bundle["entries"].append(delayed)
    path = _write(tmp_path / "delayed-bundle.json", bundle)
    with pytest.raises(
        validator.StructuralValidationError,
        match="issued_at == not_before",
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
    }


def test_authorization_path_distinguishes_ordinary_and_recovery_anchors() -> None:
    validator = _validator_module()
    shared_identity = {
        "issuer_id": "authority:shared",
        "lineage_id": "lineage:shared",
        "epoch": 0,
        "key_id": "ed25519:shared",
    }
    records = {
        "anchor:ordinary": {
            "kind": "trust_anchor",
            "value": deepcopy(shared_identity),
        },
        "anchor:recovery": {
            "kind": "recovery_anchor",
            "value": deepcopy(shared_identity),
        },
        "entry:rotation": {
            "kind": "rotation",
            "value": {
                "issuer_id": shared_identity["issuer_id"],
                "lineage_id": shared_identity["lineage_id"],
                "issuer_epoch": shared_identity["epoch"],
                "issuer_key_id": shared_identity["key_id"],
                "predecessor_entry_id": "anchor:ordinary",
                "successor_issuer_id": "authority:successor",
                "successor_key_id": "ed25519:successor",
                "successor_epoch": 1,
            },
        },
        "entry:recovery": {
            "kind": "recovery",
            "value": {
                "issuer_id": shared_identity["issuer_id"],
                "lineage_id": shared_identity["lineage_id"],
                "issuer_epoch": shared_identity["epoch"],
                "issuer_key_id": shared_identity["key_id"],
                "replacement_issuer_id": "authority:replacement",
                "replacement_lineage_id": "lineage:replacement",
                "replacement_epoch": 1,
                "replacement_key_id": "ed25519:replacement",
            },
        },
    }
    decisive_ids = set(records)
    classifications = {record_id: "VALID" for record_id in records}

    assert validator._canonical_authorization_path(
        "entry:rotation",
        records,
        decisive_ids,
        classifications,
        "case:anchor-class",
    ) == ["anchor:ordinary", "entry:rotation"]
    assert validator._canonical_authorization_path(
        "entry:recovery",
        records,
        decisive_ids,
        classifications,
        "case:anchor-class",
    ) == ["anchor:recovery", "entry:recovery"]


def test_equal_prefix_authority_chains_have_one_total_order(tmp_path: Path) -> None:
    validator = _validator_module()
    oracle = _oracle("case:branching")
    first = oracle["oracle"]["provenance"]["authority_chains"][0]
    second = deepcopy(first)
    second["records"][0]["payload_sha256"] = THREE
    core = {
        "issuer_id": second["issuer_id"],
        "claim_entry_id": second["claim_entry_id"],
        "records": second["records"],
    }
    second["chain_sha256"] = "sha256:" + hashlib.sha256(rfc8785.dumps(core)).hexdigest()
    ordered = sorted([first, second], key=lambda item: item["chain_sha256"])
    for payload in [
        oracle["oracle"],
        *(item["annotation"] for item in oracle["annotations"]),
        oracle["adjudication"]["oracle"],
    ]:
        payload["provenance"]["authority_chains"] = deepcopy(ordered)
    validator.validate_artifacts(
        [("oracle_record", _write(tmp_path / "ordered.json", oracle))]
    )

    reversed_oracle = deepcopy(oracle)
    for payload in [
        reversed_oracle["oracle"],
        *(item["annotation"] for item in reversed_oracle["annotations"]),
        reversed_oracle["adjudication"]["oracle"],
    ]:
        payload["provenance"]["authority_chains"] = list(
            reversed(payload["provenance"]["authority_chains"])
        )
    with pytest.raises(validator.StructuralValidationError, match="authority_chains"):
        validator.validate_artifacts(
            [("oracle_record", _write(tmp_path / "reversed.json", reversed_oracle))]
        )


def test_valid_authority_cannot_omit_decisive_provenance(tmp_path: Path) -> None:
    validator = _validator_module()
    oracle = _oracle("case:empty")
    for payload in [
        oracle["oracle"],
        *(item["annotation"] for item in oracle["annotations"]),
        oracle["adjudication"]["oracle"],
    ]:
        payload["provenance"]["authority_chains"] = []
        payload["provenance"]["authority_dependencies"] = []
    with pytest.raises(
        validator.StructuralValidationError,
        match="requires at least one authority chain",
    ):
        validator.validate_artifacts(
            [("oracle_record", _write(tmp_path / "empty.json", oracle))]
        )


def test_oracle_rules_reasons_and_annotations_are_closed(tmp_path: Path) -> None:
    validator = _validator_module()
    invalid = _oracle("case:invalid-rules")
    for payload in [
        invalid["oracle"],
        *(item["annotation"] for item in invalid["annotations"]),
        invalid["adjudication"]["oracle"],
    ]:
        payload["oracle_rule_ids"] = [
            "OA4_UNKNOWN",
            "V6_AUTHORITY_UNKNOWN",
        ]
        payload["reason_codes"] = ["AUTHORITY_INVALID"]
    with pytest.raises(validator.StructuralValidationError):
        validator.validate_artifacts(
            [("oracle_record", _write(tmp_path / "bad-rules.json", invalid))]
        )

    unrelated_reason = _oracle("case:unrelated-reason")
    for payload in [
        unrelated_reason["oracle"],
        *(item["annotation"] for item in unrelated_reason["annotations"]),
        unrelated_reason["adjudication"]["oracle"],
    ]:
        payload["reason_codes"] = [
            "ALL_REQUIREMENTS_SATISFIED",
            "AUTHORITY_INVALID",
        ]
    with pytest.raises(
        validator.StructuralValidationError, match="unrelated reason code"
    ):
        validator.validate_artifacts(
            [
                (
                    "oracle_record",
                    _write(tmp_path / "unrelated-reason.json", unrelated_reason),
                )
            ]
        )

    missing_annotations = _oracle("case:no-annotations")
    missing_annotations.pop("annotations")
    with pytest.raises(validator.StructuralValidationError, match="annotations"):
        validator.validate_artifacts(
            [
                (
                    "oracle_record",
                    _write(tmp_path / "no-annotations.json", missing_annotations),
                )
            ]
        )


def test_authorship_and_phase_records_reject_review_counterexamples(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    collection = _authorship_collection()
    collection["records"].append(_authorship("family:4", "author:4"))
    for record in collection["records"]:
        record["primary_author_id"] = "author:one"
    with pytest.raises(validator.StructuralValidationError, match="primary_author_id"):
        validator.validate_artifacts(
            [
                (
                    "authorship_collection",
                    _write(tmp_path / "same-author.json", collection),
                )
            ]
        )

    duplicated_source = _authorship("family:duplicate-source", "author:source")
    source = {
        "path": "shared/source.json",
        "sha256": ONE,
        "outcome_determining": True,
    }
    duplicated_source["shared_sources"] = [deepcopy(source), deepcopy(source)]
    with pytest.raises(validator.StructuralValidationError, match="shared source path"):
        validator.validate_artifacts(
            [
                (
                    "authorship_attestation",
                    _write(tmp_path / "duplicate-source.json", duplicated_source),
                )
            ]
        )


def test_complete_pack_mode_closes_archives_population_and_phases(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    validator.validate_complete_pack(
        **{
            key: value
            for key, value in pack.items()
            if key
            not in {
                "input_files",
                "oracle_files",
                "result_files_by_path",
                "trace_files_by_path",
            }
        }
    )


def test_canonical_archive_rejects_extra_zero_records(tmp_path: Path) -> None:
    validator = _validator_module()
    path = tmp_path / "noncanonical.tar"
    path.write_bytes(_canonical_tar({"one.txt": b"one"}) + b"\0" * 10_240)
    with pytest.raises(
        validator.StructuralValidationError,
        match="canonical USTAR serializer",
    ):
        validator._load_canonical_ustar(path)


def test_complete_pack_rejects_unlinked_leakage_and_reveal_before_outputs(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    leakage_pack = _build_complete_pack(tmp_path / "leakage")
    leakage = json.loads(leakage_pack["oracle_files"]["leakage-review.json"])
    leakage["cases"] = leakage["cases"][:1]
    leakage_pack["oracle_files"]["leakage-review.json"] = _json_bytes(leakage)
    _rebind_complete_pack(leakage_pack)
    with pytest.raises(
        validator.StructuralValidationError,
        match="every committed case requires exactly one PASS",
    ):
        validator.validate_complete_pack(
            **{
                key: value
                for key, value in leakage_pack.items()
                if key
                not in {
                    "input_files",
                    "oracle_files",
                    "result_files_by_path",
                    "trace_files_by_path",
                }
            }
        )

    phase_pack = _build_complete_pack(tmp_path / "phase")
    reveal = json.loads(phase_pack["oracle_reveal_path"].read_text())
    reveal["oracle_pack_revealed_at"] = "2030-01-02T06:00:00Z"
    _write(phase_pack["oracle_reveal_path"], reveal)
    final = json.loads(phase_pack["freeze_reveal_path"].read_text())
    final["oracle_reveal_sha256"] = _digest(
        phase_pack["oracle_reveal_path"].read_bytes()
    )
    _write(phase_pack["freeze_reveal_path"], final)
    with pytest.raises(
        validator.StructuralValidationError,
        match="output commitment must precede oracle reveal",
    ):
        validator.validate_complete_pack(
            **{
                key: value
                for key, value in phase_pack.items()
                if key
                not in {
                    "input_files",
                    "oracle_files",
                    "result_files_by_path",
                    "trace_files_by_path",
                }
            }
        )


def test_complete_pack_rejects_fake_manifest_and_duplicate_path_ids(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    manifest_pack = _build_complete_pack(tmp_path / "manifest")
    manifest = json.loads(manifest_pack["input_manifest_path"].read_text())
    manifest["entries"] = manifest["entries"][:1]
    _write(manifest_pack["input_manifest_path"], manifest)
    with pytest.raises(
        validator.StructuralValidationError,
        match="manifest entries must exactly equal archive",
    ):
        validator.validate_complete_pack(
            **{
                key: value
                for key, value in manifest_pack.items()
                if key
                not in {
                    "input_files",
                    "oracle_files",
                    "result_files_by_path",
                    "trace_files_by_path",
                }
            }
        )

    path_pack = _build_complete_pack(tmp_path / "paths")
    second = path_pack["output_commitment_paths"][1]
    commitment = json.loads(second.read_text())
    commitment["path_id"] = "governed"
    _write(second, commitment)
    commitment_digests = sorted(
        _digest(path.read_bytes()) for path in path_pack["output_commitment_paths"]
    )
    reveal = json.loads(path_pack["oracle_reveal_path"].read_text())
    reveal["output_commitment_sha256s"] = commitment_digests
    _write(path_pack["oracle_reveal_path"], reveal)
    final = json.loads(path_pack["freeze_reveal_path"].read_text())
    final["output_commitment_sha256s"] = commitment_digests
    final["oracle_reveal_sha256"] = _digest(
        path_pack["oracle_reveal_path"].read_bytes()
    )
    _write(path_pack["freeze_reveal_path"], final)
    with pytest.raises(validator.StructuralValidationError, match="output path_id"):
        validator.validate_complete_pack(
            **{
                key: value
                for key, value in path_pack.items()
                if key
                not in {
                    "input_files",
                    "oracle_files",
                    "result_files_by_path",
                    "trace_files_by_path",
                }
            }
        )


def test_complete_pack_closes_result_trace_and_repeat_commitments(
    tmp_path: Path,
) -> None:
    validator = _validator_module()

    missing = _build_complete_pack(tmp_path / "missing")
    missing["result_files_by_path"]["governed"].pop("results/governed/case:00/0.json")
    _rebind_path_artifacts(missing, "governed")
    with pytest.raises(
        validator.StructuralValidationError,
        match="exact case-repeat matrix",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(missing))

    unbound = _build_complete_pack(tmp_path / "unbound")
    commitment_path = unbound["output_commitment_paths"][0]
    commitment = json.loads(commitment_path.read_text())
    commitment["outputs_sha256"] = ZERO
    _write(commitment_path, commitment)
    _rebind_reveal_receipt(unbound)
    with pytest.raises(
        validator.StructuralValidationError,
        match="does not bind exact artifacts",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(unbound))

    repeats = _build_complete_pack(tmp_path / "repeats")
    commitment_path = repeats["output_commitment_paths"][0]
    commitment = json.loads(commitment_path.read_text())
    commitment["repeat_count"] = 2
    _write(commitment_path, commitment)
    _rebind_reveal_receipt(repeats)
    with pytest.raises(
        validator.StructuralValidationError,
        match="output commitment does not match frozen run",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(repeats))


def test_missing_run_is_visible_in_the_exact_result_matrix(tmp_path: Path) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    result_path = "results/governed/case:00/0.json"
    existing = json.loads(pack["result_files_by_path"]["governed"][result_path])
    pack["result_files_by_path"]["governed"][result_path] = _json_bytes(
        {
            "schema_version": "agent-context-proof-path-run-v0.3.11",
            "case_id": "case:00",
            "path_id": "governed",
            "repeat_index": 0,
            "run_status": "MISSING",
            "trace_sha256": existing["trace_sha256"],
            "failure_code": "MISSING_OUTPUT",
        }
    )
    _rebind_path_artifacts(pack, "governed")
    validator.validate_complete_pack(**_complete_pack_kwargs(pack))


def test_claim_spine_rejects_non_introduction_side_dependencies(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    oracle_path = "oracles/case:00.json"
    oracle = json.loads(pack["oracle_files"][oracle_path])
    for payload in [
        oracle["oracle"],
        *(item["annotation"] for item in oracle["annotations"]),
        oracle["adjudication"]["oracle"],
    ]:
        evaluation = payload["provenance"]["authority_evaluation_records"]
        precedence = next(
            item
            for item in evaluation
            if item["record_id"].startswith("entry:precedence")
        )
        precedence["classification"] = "VALID"
        precedence["decisive"] = True
        chain = payload["provenance"]["authority_chains"][0]
        chain["records"].insert(
            -1,
            {
                "record_id": precedence["record_id"],
                "payload_sha256": precedence["payload_sha256"],
            },
        )
        core = {
            "issuer_id": chain["issuer_id"],
            "claim_entry_id": chain["claim_entry_id"],
            "records": chain["records"],
        }
        chain["chain_sha256"] = _digest(rfc8785.dumps(core))
    pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    with pytest.raises(
        validator.StructuralValidationError,
        match="non-introduction side dependency",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


def test_dependency_authorization_path_rejects_an_unrelated_anchor(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle = json.loads(oracle_bytes)
        for payload in [
            oracle["oracle"],
            *(item["annotation"] for item in oracle["annotations"]),
            oracle["adjudication"]["oracle"],
        ]:
            provenance = payload["provenance"]
            rotation_dependency = next(
                item
                for item in provenance["authority_dependencies"]
                if item["dependency_type"] == "identity_introduction"
                and item["record_id"] == "entry:rotation-root-a-epoch-1"
            )
            recovery_anchor = next(
                item
                for item in provenance["authority_evaluation_records"]
                if item["record_id"] == "anchor:recovery-a-epoch-0"
            )
            rotation_dependency["authorization_records"][0] = {
                "record_id": recovery_anchor["record_id"],
                "payload_sha256": recovery_anchor["payload_sha256"],
            }
        pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    with pytest.raises(
        validator.StructuralValidationError,
        match="canonical signer-introduction path",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


def test_dependency_collection_rejects_an_omitted_decisive_dependency(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    oracle_path = "oracles/case:00.json"
    oracle = json.loads(pack["oracle_files"][oracle_path])
    for payload in [
        oracle["oracle"],
        *(item["annotation"] for item in oracle["annotations"]),
        oracle["adjudication"]["oracle"],
    ]:
        dependencies = payload["provenance"]["authority_dependencies"]
        dependencies[:] = [
            item
            for item in dependencies
            if not (
                item["dependency_type"] == "lineage_head"
                and item["record_id"] == "entry:recovery-root-a"
            )
        ]
    pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    with pytest.raises(
        validator.StructuralValidationError,
        match="exact decisive set",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


def test_dependency_type_must_match_its_target_kind(tmp_path: Path) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    oracle_path = "oracles/case:00.json"
    oracle = json.loads(pack["oracle_files"][oracle_path])
    for payload in [
        oracle["oracle"],
        *(item["annotation"] for item in oracle["annotations"]),
        oracle["adjudication"]["oracle"],
    ]:
        dependencies = payload["provenance"]["authority_dependencies"]
        root = next(
            item
            for item in dependencies
            if item["dependency_type"] == "identity_introduction"
            and item["record_id"] == "anchor:root-a-epoch-0"
        )
        root["dependency_type"] = "precedence"
        dependencies.sort(
            key=lambda item: (
                item["dependency_type"],
                item["record_id"],
                item["payload_sha256"],
            )
        )
    pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    with pytest.raises(
        validator.StructuralValidationError,
        match="dependency type does not match target",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


@pytest.mark.parametrize("classification", ["INVALID", "UNRESOLVED", "NONMATCHING"])
def test_claim_chain_support_requires_a_coherent_valid_classification(
    tmp_path: Path,
    classification: str,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    rotation_id = "entry:rotation-root-a-epoch-1"
    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle = json.loads(oracle_bytes)
        for payload in [
            oracle["oracle"],
            *(item["annotation"] for item in oracle["annotations"]),
            oracle["adjudication"]["oracle"],
        ]:
            _set_classification(payload["provenance"], rotation_id, classification)
        pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    for result_files in pack["result_files_by_path"].values():
        for result_path, result_bytes in list(result_files.items()):
            run = json.loads(result_bytes)
            _set_classification(
                run["result"]["provenance"], rotation_id, classification
            )
            result_files[result_path] = _json_bytes(run)
    _rebind_complete_pack(pack)
    for path_id in ("governed", "retrieval_plus_rules"):
        _rebind_path_artifacts(pack, path_id)
    with pytest.raises(
        validator.StructuralValidationError,
        match="authority chain support|UNRESOLVED|NONMATCHING",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


def test_dependency_authorization_prefix_must_be_classified_valid(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    recovery_anchor_id = "anchor:recovery-a-epoch-0"
    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle = json.loads(oracle_bytes)
        for payload in [
            oracle["oracle"],
            *(item["annotation"] for item in oracle["annotations"]),
            oracle["adjudication"]["oracle"],
        ]:
            _set_classification(payload["provenance"], recovery_anchor_id, "INVALID")
        pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    for result_files in pack["result_files_by_path"].values():
        for result_path, result_bytes in list(result_files.items()):
            run = json.loads(result_bytes)
            _set_classification(
                run["result"]["provenance"], recovery_anchor_id, "INVALID"
            )
            result_files[result_path] = _json_bytes(run)
    _rebind_complete_pack(pack)
    for path_id in ("governed", "retrieval_plus_rules"):
        _rebind_path_artifacts(pack, path_id)
    with pytest.raises(
        validator.StructuralValidationError,
        match="no decisive signer-introduction path",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


@pytest.mark.parametrize("annotation_index", [0, 1])
@pytest.mark.parametrize("classification", ["INVALID", "UNRESOLVED", "NONMATCHING"])
def test_each_annotation_gets_closed_claim_chain_provenance_validation(
    tmp_path: Path,
    annotation_index: int,
    classification: str,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    rotation_id = "entry:rotation-root-a-epoch-1"
    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle = json.loads(oracle_bytes)
        provenance = oracle["annotations"][annotation_index]["annotation"][
            "provenance"
        ]
        _set_classification(provenance, rotation_id, classification)
        oracle["adjudication"]["resolution"] = "RULE_APPLICATION"
        pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    with pytest.raises(
        validator.StructuralValidationError,
        match="authority chain support|UNRESOLVED|NONMATCHING",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


@pytest.mark.parametrize("annotation_index", [0, 1])
def test_each_annotation_gets_closed_dependency_prefix_validation(
    tmp_path: Path,
    annotation_index: int,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    recovery_anchor_id = "anchor:recovery-a-epoch-0"
    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle = json.loads(oracle_bytes)
        provenance = oracle["annotations"][annotation_index]["annotation"][
            "provenance"
        ]
        _set_classification(provenance, recovery_anchor_id, "INVALID")
        oracle["adjudication"]["resolution"] = "RULE_APPLICATION"
        pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    with pytest.raises(
        validator.StructuralValidationError,
        match="no decisive signer-introduction path",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


@pytest.mark.parametrize("annotation_index", [0, 1])
@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("missing_bundle", "not a permitted input"),
        ("wrong_evaluation_digest", "must cover the exact bundle"),
        ("omitted_dependency", "exact decisive set"),
        ("wrong_dependency_type", "dependency type does not match target"),
    ],
)
def test_each_annotation_gets_closed_input_and_dependency_validation(
    tmp_path: Path,
    annotation_index: int,
    mutation: str,
    expected_error: str,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle = json.loads(oracle_bytes)
        provenance = oracle["annotations"][annotation_index]["annotation"][
            "provenance"
        ]
        if mutation == "missing_bundle":
            provenance["authority_bundle_path"] = "authority/nonexistent.json"
            provenance["authority_bundle_sha256"] = ZERO
        elif mutation == "wrong_evaluation_digest":
            provenance["authority_evaluation_records"][0]["payload_sha256"] = ZERO
        elif mutation == "omitted_dependency":
            provenance["authority_dependencies"].pop()
        else:
            root = next(
                item
                for item in provenance["authority_dependencies"]
                if item["dependency_type"] == "identity_introduction"
                and item["record_id"] == "anchor:root-a-epoch-0"
            )
            root["dependency_type"] = "precedence"
            provenance["authority_dependencies"].sort(
                key=lambda item: (
                    item["dependency_type"],
                    item["record_id"],
                    item["payload_sha256"],
                )
            )
        oracle["adjudication"]["resolution"] = "RULE_APPLICATION"
        pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    with pytest.raises(validator.StructuralValidationError, match=expected_error):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


@pytest.mark.parametrize("annotation_index", [0, 1])
def test_complete_pack_preserves_coherent_annotation_disagreement(
    tmp_path: Path,
    annotation_index: int,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    claim_id = "entry:claim-release-owner"
    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle = json.loads(oracle_bytes)
        annotation = oracle["annotations"][annotation_index]["annotation"]
        annotation["disposition"] = "INDETERMINATE"
        annotation["mechanism_status"] = "CONFORMANT"
        annotation["authority_status"] = "INVALID"
        annotation["oracle_rule_ids"] = ["OA3_INVALID", "V5_AUTHORITY_INVALID"]
        annotation["reason_codes"] = ["AUTHORITY_INVALID"]
        provenance = annotation["provenance"]
        _set_classification(provenance, claim_id, "INVALID")
        provenance["authority_chains"] = []
        provenance["contract_records"] = []
        provenance["evidence_records"] = []
        provenance["unevaluated_stages"] = ["contract", "evidence"]
        oracle["adjudication"]["resolution"] = "RULE_APPLICATION"
        pack["oracle_files"][oracle_path] = _json_bytes(oracle)
    _rebind_complete_pack(pack)
    validator.validate_complete_pack(**_complete_pack_kwargs(pack))


@pytest.mark.parametrize(
    ("authority_status", "classification", "oracle_rules", "reason_code"),
    [
        (
            "INVALID",
            "INVALID",
            ["OA3_INVALID", "V5_AUTHORITY_INVALID"],
            "AUTHORITY_INVALID",
        ),
        (
            "INDETERMINATE",
            "UNRESOLVED",
            ["OA4_UNKNOWN", "V6_AUTHORITY_UNKNOWN"],
            "AUTHORITY_INDETERMINATE",
        ),
    ],
)
def test_terminal_authority_status_has_matching_decisive_classification(
    tmp_path: Path,
    authority_status: str,
    classification: str,
    oracle_rules: list[str],
    reason_code: str,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    claim_id = "entry:claim-release-owner"

    def make_terminal(payload: dict[str, object], *, oracle: bool) -> None:
        payload["disposition"] = "INDETERMINATE"
        payload["mechanism_status"] = "CONFORMANT"
        payload["authority_status"] = authority_status
        payload["reason_codes"] = [reason_code]
        if oracle:
            payload["oracle_rule_ids"] = oracle_rules
        provenance = payload["provenance"]
        _set_classification(provenance, claim_id, classification)
        provenance["authority_chains"] = []
        provenance["contract_records"] = []
        provenance["evidence_records"] = []
        provenance["unevaluated_stages"] = ["contract", "evidence"]

    for oracle_path, oracle_bytes in list(pack["oracle_files"].items()):
        if not oracle_path.startswith("oracles/"):
            continue
        oracle_record = json.loads(oracle_bytes)
        for payload in [
            oracle_record["oracle"],
            *(item["annotation"] for item in oracle_record["annotations"]),
            oracle_record["adjudication"]["oracle"],
        ]:
            make_terminal(payload, oracle=True)
        pack["oracle_files"][oracle_path] = _json_bytes(oracle_record)
    for result_files in pack["result_files_by_path"].values():
        for result_path, result_bytes in list(result_files.items()):
            run = json.loads(result_bytes)
            make_terminal(run["result"], oracle=False)
            result_files[result_path] = _json_bytes(run)
    _rebind_complete_pack(pack)
    for path_id in ("governed", "retrieval_plus_rules"):
        _rebind_path_artifacts(pack, path_id)
    validator.validate_complete_pack(**_complete_pack_kwargs(pack))


def test_complete_pack_binds_the_trusted_approved_protocol_commit(
    tmp_path: Path,
) -> None:
    validator = _validator_module()

    wrong_expected = _build_complete_pack(tmp_path / "wrong-expected")
    wrong_expected["expected_approved_protocol_commit"] = "b" * 40
    with pytest.raises(
        validator.StructuralValidationError,
        match="approved protocol manifest commit does not match",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(wrong_expected))

    self_asserted = _build_complete_pack(tmp_path / "self-asserted")
    public = json.loads(self_asserted["public_commitment_path"].read_text())
    public["approved_protocol_commit"] = "b" * 40
    _write(self_asserted["public_commitment_path"], public)
    population = json.loads(self_asserted["population_freeze_path"].read_text())
    population["approved_protocol_commit"] = "b" * 40
    _write(self_asserted["population_freeze_path"], population)
    _rebind_complete_pack(self_asserted)
    with pytest.raises(
        validator.StructuralValidationError,
        match="public commitment protocol commit does not match",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(self_asserted))

    malformed = _build_complete_pack(tmp_path / "malformed")
    malformed["expected_approved_protocol_commit"] = "main"
    with pytest.raises(
        validator.StructuralValidationError,
        match="40 lowercase hexadecimal",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(malformed))


def test_complete_pack_verifies_the_content_addressed_protocol_manifest(
    tmp_path: Path,
) -> None:
    validator = _validator_module()

    wrong_digest = _build_complete_pack(tmp_path / "wrong-digest")
    wrong_digest["expected_approved_protocol_manifest_sha256"] = ZERO
    with pytest.raises(
        validator.StructuralValidationError,
        match="trusted external digest",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(wrong_digest))

    wrong_file = _build_complete_pack(tmp_path / "wrong-file")
    manifest = json.loads(wrong_file["approved_protocol_manifest_path"].read_text())
    validator_entry = next(
        item
        for item in manifest["files"]
        if item["path"] == "scripts/validate_v03_artifact.py"
    )
    validator_entry["sha256"] = ZERO
    _write(wrong_file["approved_protocol_manifest_path"], manifest)
    wrong_file["expected_approved_protocol_manifest_sha256"] = _digest(
        wrong_file["approved_protocol_manifest_path"].read_bytes()
    )
    with pytest.raises(
        validator.StructuralValidationError,
        match="approved protocol file digest mismatch",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(wrong_file))

    missing_file = _build_complete_pack(tmp_path / "missing-file")
    manifest = json.loads(missing_file["approved_protocol_manifest_path"].read_text())
    manifest["files"] = manifest["files"][:-1]
    _write(missing_file["approved_protocol_manifest_path"], manifest)
    missing_file["expected_approved_protocol_manifest_sha256"] = _digest(
        missing_file["approved_protocol_manifest_path"].read_bytes()
    )
    with pytest.raises(
        validator.StructuralValidationError,
        match="exact governed file set",
    ):
        validator.validate_complete_pack(**_complete_pack_kwargs(missing_file))


def test_population_freeze_cannot_exclude_a_committed_candidate(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    pack = _build_complete_pack(tmp_path)
    population = json.loads(pack["population_freeze_path"].read_text())
    population["case_exclusions"] = [
        {
            "case_id": "case:00",
            "reason_code": "SCHEMA_INVALID",
            "recorded_at": population["frozen_at"],
        }
    ]
    _write(pack["population_freeze_path"], population)
    with pytest.raises(validator.StructuralValidationError, match="case_exclusions"):
        validator.validate_complete_pack(**_complete_pack_kwargs(pack))


def test_rule_application_requires_actual_annotation_disagreement(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    oracle = _oracle("case:agreement")
    oracle["adjudication"]["resolution"] = "RULE_APPLICATION"
    with pytest.raises(
        validator.StructuralValidationError,
        match="EXACT_AGREEMENT is required exactly",
    ):
        validator.validate_artifacts(
            [("oracle_record", _write(tmp_path / "false-dispute.json", oracle))]
        )


def test_relatedness_edges_are_unique_exact_and_evidence_bound(
    tmp_path: Path,
) -> None:
    validator = _validator_module()
    collection = _authorship_collection()
    shared = {"path": "shared/rules.json", "sha256": ONE, "outcome_determining": True}
    collection["records"][0]["shared_sources"] = [deepcopy(shared)]
    collection["records"][1]["shared_sources"] = [deepcopy(shared)]
    evidence = {
        "coordination_evidence_sha256s": [],
        "family_ids": ["family:0", "family:1"],
        "outcome_determining_source_sha256s": [ONE],
        "shared_author_ids": [],
    }
    edge = {
        "family_ids": ["family:0", "family:1"],
        "relation_types": ["OUTCOME_DETERMINING_SOURCE"],
        "evidence_sha256": _digest(rfc8785.dumps(evidence)),
    }
    graph = _relatedness_graph()
    collection["records"].append(_authorship("family:4", "author:4"))
    graph["family_ids"].append("family:4")
    graph["edges"] = [edge]
    graph["clusters"] = [
        {"cluster_id": "family:0", "family_ids": ["family:0", "family:1"]},
        {"cluster_id": "family:2", "family_ids": ["family:2"]},
        {"cluster_id": "family:3", "family_ids": ["family:3"]},
        {"cluster_id": "family:4", "family_ids": ["family:4"]},
    ]
    collection_path = _write(tmp_path / "collection.json", collection)
    graph_path = _write(tmp_path / "graph.json", graph)
    validator.validate_artifacts(
        [("authorship_collection", collection_path), ("relatedness_graph", graph_path)]
    )

    duplicate = deepcopy(graph)
    duplicate["edges"].append(deepcopy(edge))
    with pytest.raises(
        validator.StructuralValidationError,
        match="duplicate relatedness family pair",
    ):
        validator.validate_artifacts(
            [
                ("authorship_collection", collection_path),
                ("relatedness_graph", _write(tmp_path / "duplicate.json", duplicate)),
            ]
        )

    unbound = deepcopy(graph)
    unbound["edges"][0]["evidence_sha256"] = TWO
    with pytest.raises(
        validator.StructuralValidationError,
        match="canonical disclosed facts",
    ):
        validator.validate_artifacts(
            [
                ("authorship_collection", collection_path),
                ("relatedness_graph", _write(tmp_path / "unbound.json", unbound)),
            ]
        )


@pytest.mark.parametrize(
    "number",
    [
        "9007199254740992",
        "9007199254740992.0",
        "9.007199254740992e15",
        "1e100",
        "1e999999999999999999999999999999",
        "0.5",
    ],
)
def test_numeric_domain_is_independent_of_unsafe_lexical_form(number: str) -> None:
    validator = _validator_module()
    with pytest.raises(validator.StructuralValidationError, match="unsafe number"):
        validator.parse_strict_json_bytes(f'{{"value":{number}}}'.encode(), number)


def test_numeric_domain_normalizes_equivalent_safe_forms() -> None:
    validator = _validator_module()
    values = [
        validator.parse_strict_json_bytes(item, "safe")["value"]
        for item in (b'{"value":100}', b'{"value":100.0}', b'{"value":1e2}')
    ]
    assert values == [100, 100, 100]


def test_population_freeze_rejects_duplicate_model_path(tmp_path: Path) -> None:
    validator = _validator_module()

    population = _population_freeze()
    population["models"].append(deepcopy(population["models"][0]))
    with pytest.raises(validator.StructuralValidationError, match="model path_id"):
        validator.validate_artifacts(
            [
                (
                    "population_freeze_record",
                    _write(tmp_path / "duplicate-path.json", population),
                )
            ]
        )
