#!/usr/bin/env python3
"""Validate v0.3.8 protocol artifacts without model judgment."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS = PROJECT_ROOT / "docs"
SAFE_INTEGER = 9_007_199_254_740_991
STAGE_ORDER = ["authority", "contract", "evidence"]

TRIPLET_TO_V_RULE = {
    ("READY", "CONFORMANT", "VALID"): "V1_READY",
    ("HOLD", "CONFORMANT", "VALID"): "V2_HOLD",
    ("INDETERMINATE", "CONFORMANT", "VALID"): "V3_EVIDENCE_UNKNOWN",
    ("AUTHORITY_CONFLICT", "CONFORMANT", "CONFLICT"): "V4_AUTHORITY_CONFLICT",
    ("INDETERMINATE", "CONFORMANT", "INVALID"): "V5_AUTHORITY_INVALID",
    ("INDETERMINATE", "CONFORMANT", "INDETERMINATE"): "V6_AUTHORITY_UNKNOWN",
    ("INDETERMINATE", "NONCONFORMANT", "INDETERMINATE"): ("V7_MECHANISM_NONCONFORMANT"),
    ("INDETERMINATE", "INDETERMINATE", "INDETERMINATE"): ("V8_MECHANISM_UNKNOWN"),
}
AUTHORITY_TO_OA_RULE = {
    "VALID": "OA1_VALID",
    "CONFLICT": "OA2_CONFLICT",
    "INVALID": "OA3_INVALID",
    "INDETERMINATE": "OA4_UNKNOWN",
}
V_RULE_TO_EVIDENCE_RULES = {
    "V1_READY": {"OE8_ALL_SATISFIED"},
    "V2_HOLD": {
        "OE1_REQUIRED_ABSENT",
        "OE2_POLICY_FALSE",
        "OE3_TRUST_OR_TIME_FALSE",
    },
    "V3_EVIDENCE_UNKNOWN": {
        "OE4_UNREADABLE",
        "OE5_UNRESOLVED_CONTRADICTION",
        "OE6_SEMANTICALLY_UNJUDGEABLE",
        "OE7_INVENTORY_UNKNOWN",
    },
}
V_RULE_REQUIRED_REASONS = {
    "V1_READY": {"ALL_REQUIREMENTS_SATISFIED"},
    "V2_HOLD": {
        "POLICY_UNSATISFIED",
        "REQUIRED_EVIDENCE_ABSENT",
        "TRUST_OR_TIME_UNSATISFIED",
    },
    "V3_EVIDENCE_UNKNOWN": {
        "EVIDENCE_CONTRADICTION",
        "EVIDENCE_UNREADABLE",
        "INVENTORY_INCOMPLETE",
        "SEMANTICALLY_UNJUDGEABLE",
    },
    "V4_AUTHORITY_CONFLICT": {"VALID_ISSUER_CONFLICT"},
    "V5_AUTHORITY_INVALID": {"AUTHORITY_INVALID"},
    "V6_AUTHORITY_UNKNOWN": {"AUTHORITY_INDETERMINATE"},
    "V7_MECHANISM_NONCONFORMANT": {"MECHANISM_NONCONFORMANT"},
    "V8_MECHANISM_UNKNOWN": {"MECHANISM_INDETERMINATE"},
}
V_RULE_ALLOWED_REASONS = {
    "V1_READY": {
        "ALL_REQUIREMENTS_SATISFIED",
        "AUTHORITY_VALID",
        "PRECEDENCE_RESOLVED",
        "RECOVERY_EFFECTIVE",
        "REVOCATION_EFFECTIVE",
    },
    "V2_HOLD": {
        "AUTHORITY_VALID",
        "POLICY_UNSATISFIED",
        "PRECEDENCE_RESOLVED",
        "RECOVERY_EFFECTIVE",
        "REQUIRED_EVIDENCE_ABSENT",
        "REVOCATION_EFFECTIVE",
        "TRUST_OR_TIME_UNSATISFIED",
    },
    "V3_EVIDENCE_UNKNOWN": {
        "AUTHORITY_VALID",
        "EVIDENCE_CONTRADICTION",
        "EVIDENCE_UNREADABLE",
        "INVENTORY_INCOMPLETE",
        "PRECEDENCE_RESOLVED",
        "RECOVERY_EFFECTIVE",
        "REVOCATION_EFFECTIVE",
        "SEMANTICALLY_UNJUDGEABLE",
    },
    "V4_AUTHORITY_CONFLICT": {
        "RECOVERY_EFFECTIVE",
        "REVOCATION_EFFECTIVE",
        "VALID_ISSUER_CONFLICT",
    },
    "V5_AUTHORITY_INVALID": {
        "AUTHORITY_INVALID",
        "DUPLICATE_LINEAGE_HEAD",
        "IDENTITY_BINDING_MISMATCH",
        "ROLLBACK_DETECTED",
        "SCOPE_ESCALATION",
        "TRUST_OR_TIME_UNSATISFIED",
    },
    "V6_AUTHORITY_UNKNOWN": {"AUTHORITY_INDETERMINATE"},
    "V7_MECHANISM_NONCONFORMANT": {"MECHANISM_NONCONFORMANT"},
    "V8_MECHANISM_UNKNOWN": {"MECHANISM_INDETERMINATE"},
}

SCHEMA_FILES = {
    "authorship_attestation": DOCS / "authorship-attestation.v0.3.schema.json",
    "authorship_collection": DOCS / "authorship-collection.v0.3.schema.json",
    "authority_bundle": DOCS / "authority-ledger-bundle.v0.3.schema.json",
    "case_record": DOCS / "case-record.v0.3.schema.json",
    "freeze_reveal_record": DOCS / "freeze-reveal-record.v0.3.schema.json",
    "leakage_review_attestation": (
        DOCS / "leakage-review-attestation.v0.3.schema.json"
    ),
    "oracle_record": DOCS / "oracle-record.v0.3.schema.json",
    "oracle_reveal_record": DOCS / "oracle-reveal-record.v0.3.schema.json",
    "path_artifact_manifest": DOCS / "path-artifact-manifest.v0.3.schema.json",
    "pack_manifest": DOCS / "sealed-pack-manifest.v0.3.schema.json",
    "path_output_commitment": DOCS / "path-output-commitment.v0.3.schema.json",
    "path_run_record": DOCS / "path-run-record.v0.3.schema.json",
    "population_freeze_record": DOCS / "population-freeze-record.v0.3.schema.json",
    "public_commitment": DOCS / "public-commitment.v0.3.schema.json",
    "relatedness_graph": DOCS / "relatedness-graph.v0.3.schema.json",
    "result_record": DOCS / "result-record.v0.3.schema.json",
    "trace_record": DOCS / "trace-record.v0.3.schema.json",
}
REGISTRY_FILES = [
    DOCS / "protocol-artifact-defs.v0.3.schema.json",
    DOCS / "authority-ledger-entry.v0.3.schema.json",
]


class StructuralValidationError(ValueError):
    """A deterministic structural or cross-record invariant failed."""


def _reject_constant(value: str) -> None:
    raise StructuralValidationError(f"non-finite JSON number: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StructuralValidationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _normalize_json_numbers(value: Any, location: str = "$") -> Any:
    if isinstance(value, Decimal):
        if (
            not value.is_finite()
            or value != value.to_integral_value()
            or abs(value) > SAFE_INTEGER
        ):
            raise StructuralValidationError(f"unsafe number at {location}")
        return int(value)
    if isinstance(value, list):
        return [
            _normalize_json_numbers(item, f"{location}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        return {
            key: _normalize_json_numbers(item, f"{location}.{key}")
            for key, item in value.items()
        }
    return value


def _check_ijson(value: Any, location: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise StructuralValidationError(f"malformed Unicode at {location}")
        return
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
            raise StructuralValidationError(f"unsafe integer at {location}")
        return
    if isinstance(value, float):
        raise StructuralValidationError(f"unsafe number at {location}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_ijson(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _check_ijson(key, f"{location}.<key>")
            _check_ijson(item, f"{location}.{key}")
        return
    raise StructuralValidationError(f"unsupported JSON value at {location}")


def parse_strict_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=Decimal,
            parse_int=Decimal,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise StructuralValidationError(f"{label}: {error}") from error
    value = _normalize_json_numbers(value)
    _check_ijson(value)
    if not isinstance(value, dict):
        raise StructuralValidationError(f"{label}: top-level value must be an object")
    return value


def load_strict_json(path: Path) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise StructuralValidationError(f"{path}: {error}") from error
    return parse_strict_json_bytes(data, str(path))


def _load_schema(path: Path) -> dict[str, Any]:
    value = load_strict_json(path)
    Draft202012Validator.check_schema(value)
    return value


def _registry() -> Registry:
    registry = Registry()
    for path in REGISTRY_FILES:
        schema = _load_schema(path)
        registry = registry.with_resource(
            str(schema["$id"]), Resource.from_contents(schema)
        )
    return registry


def _validator(kind: str, registry: Registry) -> Draft202012Validator:
    schema = _load_schema(SCHEMA_FILES[kind])
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


def _require_unique(values: Iterable[str], label: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise StructuralValidationError(f"duplicate {label}: {value}")
        seen.add(value)


def _require_sorted(values: list[Any], expected: list[Any], label: str) -> None:
    if values != expected:
        raise StructuralValidationError(f"non-canonical {label} order")


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _jcs_sha256(value: Any) -> str:
    try:
        return _sha256_bytes(rfc8785.dumps(value))
    except rfc8785.CanonicalizationError as error:
        raise StructuralValidationError(
            f"RFC 8785 canonicalization failed: {error}"
        ) from error


def _validate_interval_records(value: dict[str, Any]) -> None:
    for anchor in [*value["trust_anchors"], *value["recovery_trust_anchors"]]:
        if _timestamp(anchor["not_before"]) >= _timestamp(anchor["not_after"]):
            raise StructuralValidationError(
                f"anchor {anchor['anchor_id']} requires not_before < not_after"
            )

    for entry in value["entries"]:
        issued = _timestamp(entry["issued_at"])
        not_before = _timestamp(entry["not_before"])
        not_after = _timestamp(entry["not_after"])
        if not not_before < not_after:
            raise StructuralValidationError(
                f"entry {entry['entry_id']} requires not_before < not_after"
            )
        if entry["entry_type"] in {"claim", "delegation", "precedence"}:
            if issued != not_before:
                raise StructuralValidationError(
                    f"entry {entry['entry_id']} requires issued_at == not_before"
                )
            continue
        effective = (
            not_before
            if entry["entry_type"] == "rotation"
            else _timestamp(entry["effective_at"])
        )
        if not issued <= not_before <= effective < not_after:
            raise StructuralValidationError(
                f"entry {entry['entry_id']} has invalid transition time order"
            )


def _validate_provenance(provenance: dict[str, Any]) -> None:
    evaluation_records = provenance["authority_evaluation_records"]
    _require_unique(
        (item["record_id"] for item in evaluation_records),
        "authority evaluation record_id",
    )
    _require_sorted(
        evaluation_records,
        sorted(
            evaluation_records,
            key=lambda item: (item["record_id"], item["payload_sha256"]),
        ),
        "authority_evaluation_records",
    )
    chains = provenance["authority_chains"]
    for chain in chains:
        core = {
            "issuer_id": chain["issuer_id"],
            "claim_entry_id": chain["claim_entry_id"],
            "records": chain["records"],
        }
        if chain["chain_sha256"] != _jcs_sha256(core):
            raise StructuralValidationError(
                f"authority chain digest mismatch for {chain['claim_entry_id']}"
            )
    _require_sorted(
        chains,
        sorted(
            chains,
            key=lambda item: (
                item["issuer_id"],
                item["claim_entry_id"],
                item["chain_sha256"],
            ),
        ),
        "authority_chains",
    )
    dependencies = provenance["authority_dependencies"]
    _require_sorted(
        dependencies,
        sorted(
            dependencies,
            key=lambda item: (
                item["dependency_type"],
                item["record_id"],
                item["payload_sha256"],
            ),
        ),
        "authority_dependencies",
    )
    for dependency in dependencies:
        decisive_for = dependency["decisive_for"]
        _require_sorted(
            decisive_for,
            sorted(decisive_for),
            f"decisive_for in {dependency['record_id']}",
        )
    for field in ("contract_records", "evidence_records"):
        records = provenance[field]
        _require_sorted(
            records,
            sorted(records, key=lambda item: (item["path"], item["sha256"])),
            field,
        )
    unevaluated = provenance["unevaluated_stages"]
    valid_suffixes = [STAGE_ORDER[index:] for index in range(len(STAGE_ORDER) + 1)]
    if unevaluated not in valid_suffixes:
        raise StructuralValidationError(
            "unevaluated_stages must be an ordered suffix of stage order"
        )


def _output_triplet(value: dict[str, Any]) -> tuple[str, str, str]:
    return (
        value["disposition"],
        value["mechanism_status"],
        value["authority_status"],
    )


def _validate_output_contract(value: dict[str, Any], *, oracle: bool) -> None:
    v_rule = TRIPLET_TO_V_RULE[_output_triplet(value)]
    reasons = set(value["reason_codes"])
    if not reasons & V_RULE_REQUIRED_REASONS[v_rule]:
        raise StructuralValidationError(f"{v_rule} requires a matching reason code")
    if not reasons <= V_RULE_ALLOWED_REASONS[v_rule]:
        raise StructuralValidationError(f"{v_rule} contains an unrelated reason code")

    provenance = value["provenance"]
    if (
        value["authority_status"] in {"VALID", "CONFLICT"}
        and not provenance["authority_chains"]
    ):
        raise StructuralValidationError(
            "VALID or CONFLICT authority requires at least one authority chain"
        )
    if value["authority_status"] == "VALID":
        if provenance["unevaluated_stages"]:
            raise StructuralValidationError(
                "VALID authority routed to evidence cannot skip a stage"
            )
        if not provenance["contract_records"] or not provenance["evidence_records"]:
            raise StructuralValidationError(
                "VALID authority output requires contract and evidence provenance"
            )
    elif value["mechanism_status"] == "CONFORMANT":
        if provenance["contract_records"] or provenance["evidence_records"]:
            raise StructuralValidationError(
                "terminal authority output cannot contain contract or evidence records"
            )
        if provenance["unevaluated_stages"] != ["contract", "evidence"]:
            raise StructuralValidationError(
                "terminal authority output must skip contract and evidence"
            )

    if not oracle:
        return
    rules = set(value["oracle_rule_ids"])
    if v_rule in {"V7_MECHANISM_NONCONFORMANT", "V8_MECHANISM_UNKNOWN"}:
        expected = {v_rule}
        if rules != expected:
            raise StructuralValidationError(
                f"{v_rule} oracle_rule_ids must equal {sorted(expected)}"
            )
        return

    oa_rule = AUTHORITY_TO_OA_RULE[value["authority_status"]]
    expected_base = {v_rule, oa_rule}
    evidence_allowed = V_RULE_TO_EVIDENCE_RULES.get(v_rule)
    if evidence_allowed is None:
        if rules != expected_base:
            raise StructuralValidationError(
                f"{v_rule} oracle_rule_ids must equal {sorted(expected_base)}"
            )
        return
    evidence_rules = rules - expected_base
    if not evidence_rules or not evidence_rules <= evidence_allowed:
        raise StructuralValidationError(f"{v_rule} has invalid evidence rule IDs")
    if rules != expected_base | evidence_rules:
        raise StructuralValidationError(f"{v_rule} has unrelated oracle rule IDs")


def _validate_oracle_record(value: dict[str, Any]) -> None:
    _validate_output_contract(value["oracle"], oracle=True)
    annotators = [item["annotator_id"] for item in value["annotations"]]
    _require_unique(annotators, "oracle annotator_id")
    for annotation in value["annotations"]:
        if (
            annotation["case_id"] != value["case_id"]
            or annotation["case_coordinate"] != value["case_coordinate"]
            or annotation["validation_time"] != value["validation_time"]
        ):
            raise StructuralValidationError(
                "oracle annotation case binding does not match its record"
            )
        _require_sorted(
            annotation["annotation"]["oracle_rule_ids"],
            sorted(annotation["annotation"]["oracle_rule_ids"]),
            "annotation oracle_rule_ids",
        )
        _require_sorted(
            annotation["annotation"]["reason_codes"],
            sorted(annotation["annotation"]["reason_codes"]),
            "annotation reason_codes",
        )
        _validate_provenance(annotation["annotation"]["provenance"])
        _validate_output_contract(annotation["annotation"], oracle=True)
    adjudication = value["adjudication"]
    if adjudication["adjudicator_id"] in annotators:
        raise StructuralValidationError(
            "oracle adjudicator must be distinct from both annotators"
        )
    if (
        adjudication["case_id"] != value["case_id"]
        or adjudication["case_coordinate"] != value["case_coordinate"]
        or adjudication["validation_time"] != value["validation_time"]
    ):
        raise StructuralValidationError(
            "oracle adjudication case binding does not match its record"
        )
    _require_sorted(
        adjudication["oracle"]["oracle_rule_ids"],
        sorted(adjudication["oracle"]["oracle_rule_ids"]),
        "adjudication oracle_rule_ids",
    )
    _require_sorted(
        adjudication["oracle"]["reason_codes"],
        sorted(adjudication["oracle"]["reason_codes"]),
        "adjudication reason_codes",
    )
    _validate_provenance(adjudication["oracle"]["provenance"])
    _validate_output_contract(adjudication["oracle"], oracle=True)
    if adjudication["oracle"] != value["oracle"]:
        raise StructuralValidationError(
            "oracle record must equal the adjudicated oracle payload"
        )
    annotations_agree = all(
        item["annotation"] == value["oracle"] for item in value["annotations"]
    )
    if (adjudication["resolution"] == "EXACT_AGREEMENT") != annotations_agree:
        raise StructuralValidationError(
            "EXACT_AGREEMENT is required exactly when both annotations equal "
            "the final oracle"
        )


def _validate_authorship(value: dict[str, Any]) -> None:
    coauthors = value["coauthor_ids"]
    _require_sorted(coauthors, sorted(coauthors), "coauthor_ids")
    if value["primary_author_id"] in coauthors:
        raise StructuralValidationError("primary author cannot also be a coauthor")
    _require_sorted(
        value["shared_sources"],
        sorted(
            value["shared_sources"], key=lambda item: (item["path"], item["sha256"])
        ),
        "shared_sources",
    )
    _require_unique(
        (item["path"] for item in value["shared_sources"]),
        "shared source path",
    )
    _require_sorted(
        value["coordination_disclosures"],
        sorted(
            value["coordination_disclosures"],
            key=lambda item: (item["related_family_id"], item["evidence_sha256"]),
        ),
        "coordination_disclosures",
    )
    _require_unique(
        (
            f"{item['related_family_id']}\0{item['evidence_sha256']}"
            for item in value["coordination_disclosures"]
        ),
        "coordination disclosure",
    )
    if any(
        item["related_family_id"] == value["family_id"]
        for item in value["coordination_disclosures"]
    ):
        raise StructuralValidationError(
            "coordination disclosure cannot target its own family"
        )


def _graph_components(
    family_ids: list[str], edges: list[dict[str, Any]]
) -> list[list[str]]:
    adjacency = {family_id: set() for family_id in family_ids}
    for edge in edges:
        left, right = edge["family_ids"]
        if left not in adjacency or right not in adjacency:
            raise StructuralValidationError("relatedness edge names an unknown family")
        adjacency[left].add(right)
        adjacency[right].add(left)
    components: list[list[str]] = []
    unseen = set(family_ids)
    while unseen:
        root = min(unseen)
        stack = [root]
        component: set[str] = set()
        while stack:
            node = stack.pop()
            if node in component:
                continue
            component.add(node)
            stack.extend(adjacency[node] - component)
        unseen -= component
        components.append(sorted(component))
    return sorted(components, key=lambda item: item[0])


def _validate_relatedness_graph(value: dict[str, Any]) -> None:
    family_ids = value["family_ids"]
    _require_sorted(family_ids, sorted(family_ids), "relatedness family_ids")
    for edge in value["edges"]:
        _require_sorted(
            edge["family_ids"], sorted(edge["family_ids"]), "edge family_ids"
        )
        _require_sorted(
            edge["relation_types"],
            sorted(edge["relation_types"]),
            "edge relation_types",
        )
    _require_unique(
        ("\0".join(item["family_ids"]) for item in value["edges"]),
        "relatedness family pair",
    )
    _require_sorted(
        value["edges"],
        sorted(
            value["edges"],
            key=lambda item: (
                item["family_ids"][0],
                item["family_ids"][1],
                item["relation_types"],
                item["evidence_sha256"],
            ),
        ),
        "relatedness edges",
    )
    expected_components = _graph_components(family_ids, value["edges"])
    clusters = value["clusters"]
    for cluster in clusters:
        _require_sorted(
            cluster["family_ids"], sorted(cluster["family_ids"]), "cluster family_ids"
        )
        if cluster["cluster_id"] != cluster["family_ids"][0]:
            raise StructuralValidationError(
                "cluster_id must equal the first family_id in its component"
            )
    _require_sorted(
        clusters,
        sorted(clusters, key=lambda item: item["cluster_id"]),
        "relatedness clusters",
    )
    if [item["family_ids"] for item in clusters] != expected_components:
        raise StructuralValidationError(
            "relatedness clusters must equal the graph connected components"
        )


def _semantic_validate(kind: str, value: dict[str, Any]) -> None:
    if kind == "authority_bundle":
        anchors = [*value["trust_anchors"], *value["recovery_trust_anchors"]]
        record_ids = [item["anchor_id"] for item in anchors]
        record_ids.extend(item["entry_id"] for item in value["entries"])
        _require_unique(record_ids, "anchor_id or entry_id")
        _require_unique(
            (item["lineage_id"] for item in value["lineage_heads"]),
            "lineage_heads lineage_id",
        )
        _validate_interval_records(value)
        records, digests = _record_index(value)
        for head in value["lineage_heads"]:
            resolved = records.get(head["entry_id"])
            if resolved is None or digests[head["entry_id"]] != head["payload_sha256"]:
                raise StructuralValidationError(
                    f"lineage head does not resolve exactly: {head['entry_id']}"
                )
            record = resolved["value"]
            if resolved["kind"] == "anchor":
                lineage_id = record["lineage_id"]
                epoch = record["epoch"]
            elif resolved["kind"] == "delegation":
                lineage_id = record["subject_lineage_id"]
                epoch = record["subject_epoch"]
            elif resolved["kind"] == "rotation":
                lineage_id = record["lineage_id"]
                epoch = record["successor_epoch"]
            elif resolved["kind"] == "recovery":
                lineage_id = record["replacement_lineage_id"]
                epoch = record["replacement_epoch"]
            else:
                raise StructuralValidationError(
                    f"lineage head is not an authority introduction: {head['entry_id']}"
                )
            if head["lineage_id"] != lineage_id or head["epoch"] != epoch:
                raise StructuralValidationError(
                    f"lineage head tuple mismatch: {head['entry_id']}"
                )
    elif kind in {"pack_manifest", "path_artifact_manifest"}:
        entries = value["entries"]
        paths = [item["path"] for item in entries]
        _require_unique(paths, "manifest path")
        _require_sorted(paths, sorted(paths), "manifest path")
    elif kind == "oracle_record":
        _require_sorted(
            value["oracle"]["oracle_rule_ids"],
            sorted(value["oracle"]["oracle_rule_ids"]),
            "oracle_rule_ids",
        )
        _require_sorted(
            value["oracle"]["reason_codes"],
            sorted(value["oracle"]["reason_codes"]),
            "oracle reason_codes",
        )
        _validate_provenance(value["oracle"]["provenance"])
        _validate_oracle_record(value)
    elif kind == "result_record":
        _require_sorted(
            value["reason_codes"],
            sorted(value["reason_codes"]),
            "result reason_codes",
        )
        _validate_provenance(value["provenance"])
        _validate_output_contract(value, oracle=False)
    elif kind == "path_run_record":
        if value["run_status"] == "COMPLETE":
            result = value["result"]
            if any(
                result[field] != value[field]
                for field in ("case_id", "path_id", "repeat_index", "trace_sha256")
            ):
                raise StructuralValidationError(
                    "complete path run identity must match its nested result"
                )
            _semantic_validate("result_record", result)
    elif kind == "trace_record":
        events = value["events"]
        if [item["sequence"] for item in events] != list(range(len(events))):
            raise StructuralValidationError(
                "trace event sequence must be contiguous from zero"
            )
        event_times = [_timestamp(item["observed_at"]) for item in events]
        if event_times != sorted(event_times):
            raise StructuralValidationError(
                "trace events must be in nondecreasing observed_at order"
            )
    elif kind == "authorship_attestation":
        _validate_authorship(value)
    elif kind == "authorship_collection":
        records = value["records"]
        _require_sorted(
            records,
            sorted(records, key=lambda item: item["family_id"]),
            "authorship records",
        )
        _require_unique((item["family_id"] for item in records), "authorship family_id")
        _require_unique(
            (item["primary_author_id"] for item in records),
            "authorship primary_author_id",
        )
        for record in records:
            _validate_authorship(record)
    elif kind == "relatedness_graph":
        _validate_relatedness_graph(value)
    elif kind == "leakage_review_attestation":
        _require_unique((item["case_id"] for item in value["cases"]), "leakage case_id")
        _require_unique(
            (item["randomized_case_id"] for item in value["cases"]),
            "leakage randomized_case_id",
        )
        _require_sorted(
            value["cases"],
            sorted(value["cases"], key=lambda item: item["case_id"]),
            "leakage cases",
        )
    elif kind == "population_freeze_record":
        _require_unique((item["path_id"] for item in value["models"]), "model path_id")
        _require_sorted(
            value["models"],
            sorted(value["models"], key=lambda item: item["path_id"]),
            "models",
        )
        if value["case_exclusions"]:
            raise StructuralValidationError(
                "a committed v0.3.8 candidate pack cannot exclude individual cases"
            )
        _require_sorted(
            value["included_case_ids"],
            sorted(value["included_case_ids"]),
            "included_case_ids",
        )
    elif kind in {"oracle_reveal_record", "freeze_reveal_record"}:
        _require_sorted(
            value["output_commitment_sha256s"],
            sorted(value["output_commitment_sha256s"]),
            "output commitment digests",
        )


def _validate_value(
    kind: str,
    value: dict[str, Any],
    label: str,
    registry: Registry,
    validators: dict[str, Draft202012Validator],
) -> None:
    validator = validators.setdefault(kind, _validator(kind, registry))
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.absolute_path) or "$"
        raise StructuralValidationError(f"{label}:{location}: {first.message}")
    _semantic_validate(kind, value)


def _safe_archive_path(value: str) -> bool:
    return bool(
        value
        and not value.startswith("/")
        and "\\" not in value
        and "\x00" not in value
        and "//" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _canonical_ustar_bytes(files: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for name in sorted(files):
            data = files[name]
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            archive.addfile(member, BytesIO(data))
    return output.getvalue()


def _load_canonical_ustar(path: Path) -> tuple[bytes, dict[str, bytes]]:
    try:
        archive_bytes = path.read_bytes()
    except OSError as error:
        raise StructuralValidationError(f"{path}: {error}") from error
    if len(archive_bytes) % 512 or not archive_bytes.endswith(b"\0" * 1024):
        raise StructuralValidationError(
            f"{path}: archive must use complete 512-byte blocks and zero trailer"
        )
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            _require_sorted(names, sorted(names), f"{path} archive paths")
            _require_unique(names, f"{path} archive path")
            for member in members:
                if not member.isfile() or member.type != tarfile.REGTYPE:
                    raise StructuralValidationError(
                        f"{path}:{member.name}: only regular USTAR files are allowed"
                    )
                if not _safe_archive_path(member.name):
                    raise StructuralValidationError(
                        f"{path}:{member.name}: unsafe archive path"
                    )
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                    or member.mode != 0o644
                    or member.pax_headers
                ):
                    raise StructuralValidationError(
                        f"{path}:{member.name}: non-canonical USTAR metadata"
                    )
                header = archive_bytes[member.offset : member.offset + 512]
                if header[257:263] != b"ustar\0" or header[263:265] != b"00":
                    raise StructuralValidationError(
                        f"{path}:{member.name}: USTAR header required"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise StructuralValidationError(
                        f"{path}:{member.name}: file bytes unavailable"
                    )
                files[member.name] = extracted.read()
    except (OSError, tarfile.TarError) as error:
        raise StructuralValidationError(f"{path}: {error}") from error
    if not files:
        raise StructuralValidationError(f"{path}: archive is empty")
    if archive_bytes != _canonical_ustar_bytes(files):
        raise StructuralValidationError(
            f"{path}: archive bytes do not match the canonical USTAR serializer"
        )
    return archive_bytes, files


def _verify_manifest(
    manifest: dict[str, Any], archive_bytes: bytes, files: dict[str, bytes]
) -> None:
    if manifest["archive_format"] != "USTAR_CANONICAL_V0.3.8":
        raise StructuralValidationError("unsupported archive format")
    if manifest["archive_sha256"] != _sha256_bytes(archive_bytes):
        raise StructuralValidationError("manifest archive digest mismatch")
    entries = {item["path"]: item for item in manifest["entries"]}
    if set(entries) != set(files):
        raise StructuralValidationError(
            "manifest entries must exactly equal archive regular files"
        )
    for path, data in files.items():
        entry = entries[path]
        if entry["size_bytes"] != len(data):
            raise StructuralValidationError(f"manifest size mismatch for {path}")
        if entry["sha256"] != _sha256_bytes(data):
            raise StructuralValidationError(f"manifest digest mismatch for {path}")


def _parse_permitted_inputs(data: bytes, label: str) -> list[tuple[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise StructuralValidationError(f"{label}: not UTF-8") from error
    if not text.endswith("\n"):
        raise StructuralValidationError(f"{label}: final newline required")
    records: list[tuple[str, str]] = []
    for line in text.splitlines():
        digest, separator, path = line.partition("  ")
        if (
            not separator
            or len(digest) != 71
            or not digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in digest[7:])
            or not _safe_archive_path(path)
        ):
            raise StructuralValidationError(f"{label}: malformed manifest line")
        records.append((path, digest))
    _require_unique((item[0] for item in records), f"{label} path")
    _require_sorted(records, sorted(records), label)
    return records


def _record_index(
    authority_bundle: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    records: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    for anchor in [
        *authority_bundle["trust_anchors"],
        *authority_bundle["recovery_trust_anchors"],
    ]:
        record_id = anchor["anchor_id"]
        records[record_id] = {"kind": "anchor", "value": anchor}
        digests[record_id] = _jcs_sha256(anchor)
    for entry in authority_bundle["entries"]:
        record_id = entry["entry_id"]
        records[record_id] = {"kind": entry["entry_type"], "value": entry}
        payload = dict(entry)
        payload.pop("signature")
        digests[record_id] = _jcs_sha256(payload)
    return records, digests


def _validate_case_provenance(
    case: dict[str, Any],
    oracle: dict[str, Any],
    input_files: dict[str, bytes],
    permitted: dict[str, str],
    registry: Registry,
    validators: dict[str, Draft202012Validator],
) -> None:
    provenance = oracle["oracle"]["provenance"]
    fixture_directory = case["fixture_directory"]

    def resolve(relative_path: str) -> tuple[str, bytes]:
        full_path = f"{fixture_directory}/{relative_path}"
        if full_path not in permitted or full_path not in input_files:
            raise StructuralValidationError(
                f"{case['case_id']}: provenance path is not a permitted input: "
                f"{relative_path}"
            )
        data = input_files[full_path]
        if permitted[full_path] != _sha256_bytes(data):
            raise StructuralValidationError(
                f"{case['case_id']}: permitted-input digest mismatch: {relative_path}"
            )
        return full_path, data

    _, bundle_bytes = resolve(provenance["authority_bundle_path"])
    if _sha256_bytes(bundle_bytes) != provenance["authority_bundle_sha256"]:
        raise StructuralValidationError(
            f"{case['case_id']}: authority bundle byte digest mismatch"
        )
    authority_bundle = parse_strict_json_bytes(
        bundle_bytes, f"{case['case_id']} authority bundle"
    )
    _validate_value(
        "authority_bundle",
        authority_bundle,
        f"{case['case_id']} authority bundle",
        registry,
        validators,
    )
    if (
        authority_bundle["validation_time"] != case["validation_time"]
        or authority_bundle["case_coordinate"] != case["case_coordinate"]
    ):
        raise StructuralValidationError(
            f"{case['case_id']}: authority bundle case binding mismatch"
        )
    records, digests = _record_index(authority_bundle)
    evaluation_records = provenance["authority_evaluation_records"]
    evaluation_index = {
        item["record_id"]: item["payload_sha256"] for item in evaluation_records
    }
    if evaluation_index != digests:
        raise StructuralValidationError(
            f"{case['case_id']}: authority_evaluation_records must cover "
            "the exact bundle"
        )
    decisive_ids = {
        item["record_id"] for item in evaluation_records if item["decisive"]
    }
    claim_ids = {item["claim_entry_id"] for item in provenance["authority_chains"]}
    for chain in provenance["authority_chains"]:
        chain_ids = [item["record_id"] for item in chain["records"]]
        _require_unique(chain_ids, f"{case['case_id']} chain record_id")
        if chain_ids[-1] != chain["claim_entry_id"]:
            raise StructuralValidationError(
                f"{case['case_id']}: claim chain must end at claim_entry_id"
            )
        first_chain_record = records.get(chain_ids[0])
        if first_chain_record is None or first_chain_record["kind"] != "anchor":
            raise StructuralValidationError(
                f"{case['case_id']}: claim chain must begin at an external anchor"
            )
        claim_record = records.get(chain["claim_entry_id"])
        if claim_record is None or claim_record["kind"] != "claim":
            raise StructuralValidationError(
                f"{case['case_id']}: claim_entry_id must resolve to a claim"
            )
        current_id = chain_ids[0]
        current_issuer = first_chain_record["value"]["issuer_id"]
        for introduction_id in chain_ids[1:-1]:
            introduction = records.get(introduction_id)
            if introduction is None or introduction["kind"] not in {
                "delegation",
                "rotation",
                "recovery",
            }:
                raise StructuralValidationError(
                    f"{case['case_id']}: claim chain contains a non-introduction "
                    f"side dependency: {introduction_id}"
                )
            item = introduction["value"]
            if introduction["kind"] == "delegation":
                if item["issuer_id"] != current_issuer:
                    raise StructuralValidationError(
                        f"{case['case_id']}: disconnected delegation in claim chain"
                    )
                current_issuer = item["subject_issuer_id"]
            elif introduction["kind"] == "rotation":
                if (
                    item["issuer_id"] != current_issuer
                    or item["predecessor_entry_id"] != current_id
                ):
                    raise StructuralValidationError(
                        f"{case['case_id']}: disconnected rotation in claim chain"
                    )
                current_issuer = item["successor_issuer_id"]
            else:
                if (
                    item["compromised_issuer_id"] != current_issuer
                    or item["predecessor_entry_id"] != current_id
                ):
                    raise StructuralValidationError(
                        f"{case['case_id']}: disconnected recovery in claim chain"
                    )
                current_issuer = item["replacement_issuer_id"]
            current_id = introduction_id
        if (
            claim_record["value"]["issuer_id"] != current_issuer
            or chain["issuer_id"] != current_issuer
        ):
            raise StructuralValidationError(
                f"{case['case_id']}: authority chain issuer_id mismatch"
            )
        if chain["claim_entry_id"] not in decisive_ids:
            raise StructuralValidationError(
                f"{case['case_id']}: claim chain endpoint is not marked decisive"
            )
        for authority_record in chain["records"]:
            record_id = authority_record["record_id"]
            if (
                record_id not in digests
                or authority_record["payload_sha256"] != digests[record_id]
            ):
                raise StructuralValidationError(
                    f"{case['case_id']}: authority chain record mismatch: {record_id}"
                )
            if record_id not in decisive_ids:
                raise StructuralValidationError(
                    f"{case['case_id']}: authority chain contains a nondecisive record"
                )

    dependency_pairs: set[tuple[str, str]] = set()
    for dependency in provenance["authority_dependencies"]:
        record_id = dependency["record_id"]
        pair = (dependency["dependency_type"], record_id)
        if pair in dependency_pairs:
            raise StructuralValidationError(
                f"{case['case_id']}: duplicate authority dependency {pair}"
            )
        dependency_pairs.add(pair)
        if (
            record_id not in digests
            or dependency["payload_sha256"] != digests[record_id]
        ):
            raise StructuralValidationError(
                f"{case['case_id']}: authority dependency record mismatch: {record_id}"
            )
        authorization_ids = [
            item["record_id"] for item in dependency["authorization_records"]
        ]
        if authorization_ids[-1] != record_id:
            raise StructuralValidationError(
                f"{case['case_id']}: dependency authorization path must end "
                "at dependency"
            )
        first_authorization_record = records.get(authorization_ids[0])
        if (
            first_authorization_record is None
            or first_authorization_record["kind"] != "anchor"
        ):
            raise StructuralValidationError(
                f"{case['case_id']}: dependency path must begin at an anchor"
            )
        for authority_record in dependency["authorization_records"]:
            authorization_id = authority_record["record_id"]
            if (
                authorization_id not in digests
                or authority_record["payload_sha256"] != digests[authorization_id]
            ):
                raise StructuralValidationError(
                    f"{case['case_id']}: dependency authorization record mismatch"
                )
        if not set(dependency["decisive_for"]) <= claim_ids:
            raise StructuralValidationError(
                f"{case['case_id']}: decisive_for must name a reported claim endpoint"
            )

    required_dependencies: set[tuple[str, str]] = set()
    for record_id in decisive_ids:
        kind = records[record_id]["kind"]
        if kind in {"anchor", "delegation", "rotation", "recovery"}:
            required_dependencies.add(("identity_introduction", record_id))
        if kind in {"precedence", "recovery", "revocation"}:
            required_dependencies.add((kind, record_id))
    for head in authority_bundle["lineage_heads"]:
        required_dependencies.add(("lineage_head", head["entry_id"]))
    if not required_dependencies <= dependency_pairs:
        missing = sorted(required_dependencies - dependency_pairs)
        raise StructuralValidationError(
            f"{case['case_id']}: missing decisive authority dependencies: {missing}"
        )

    for field in ("contract_records", "evidence_records"):
        for file_record in provenance[field]:
            _, data = resolve(file_record["path"])
            if file_record["sha256"] != _sha256_bytes(data):
                raise StructuralValidationError(
                    f"{case['case_id']}: {field} digest mismatch"
                )


def _validate_authorship_graph(
    collection: dict[str, Any], graph: dict[str, Any]
) -> None:
    records = collection["records"]
    by_family = {item["family_id"]: item for item in records}
    if set(by_family) != set(graph["family_ids"]):
        raise StructuralValidationError(
            "authorship and relatedness family sets must be identical"
        )
    graph_edges = {tuple(item["family_ids"]): item for item in graph["edges"]}
    expected_edges: dict[tuple[str, str], dict[str, Any]] = {}
    family_ids = sorted(by_family)
    for index, left_id in enumerate(family_ids):
        left = by_family[left_id]
        left_authors = {left["primary_author_id"], *left["coauthor_ids"]}
        left_sources = {
            item["sha256"]
            for item in left["shared_sources"]
            if item["outcome_determining"]
        }
        for right_id in family_ids[index + 1 :]:
            right = by_family[right_id]
            right_authors = {right["primary_author_id"], *right["coauthor_ids"]}
            right_sources = {
                item["sha256"]
                for item in right["shared_sources"]
                if item["outcome_determining"]
            }
            shared_authors = sorted(left_authors & right_authors)
            shared_sources = sorted(left_sources & right_sources)
            coordination_evidence = sorted(
                {
                    item["evidence_sha256"]
                    for item in left["coordination_disclosures"]
                    if item["related_family_id"] == right_id
                    and item["expected_outcomes_discussed"]
                }
                | {
                    item["evidence_sha256"]
                    for item in right["coordination_disclosures"]
                    if item["related_family_id"] == left_id
                    and item["expected_outcomes_discussed"]
                }
            )
            relation_types: list[str] = []
            if coordination_evidence:
                relation_types.append("EXPECTED_OUTCOME_COORDINATION")
            if shared_sources:
                relation_types.append("OUTCOME_DETERMINING_SOURCE")
            if shared_authors:
                relation_types.append("SHARED_AUTHOR")
            relation_types.sort()
            if not relation_types:
                continue
            evidence = {
                "coordination_evidence_sha256s": coordination_evidence,
                "family_ids": [left_id, right_id],
                "outcome_determining_source_sha256s": shared_sources,
                "shared_author_ids": shared_authors,
            }
            expected_edges[(left_id, right_id)] = {
                "family_ids": [left_id, right_id],
                "relation_types": relation_types,
                "evidence_sha256": _jcs_sha256(evidence),
            }
    if graph_edges != expected_edges:
        raise StructuralValidationError(
            "relatedness edges must exactly equal the canonical disclosed facts"
        )


def _load_path_artifacts(
    *,
    manifest_paths: list[Path],
    archive_paths: list[Path],
    artifact_type: str,
    population_digest: str,
    case_count: int,
    repeat_count: int,
    registry: Registry,
    validators: dict[str, Draft202012Validator],
) -> dict[str, dict[str, Any]]:
    archives: dict[str, tuple[bytes, dict[str, bytes]]] = {}
    for archive_path in archive_paths:
        archive_bytes, files = _load_canonical_ustar(archive_path)
        digest = _sha256_bytes(archive_bytes)
        if digest in archives:
            raise StructuralValidationError(
                f"duplicate {artifact_type} archive digest: {digest}"
            )
        archives[digest] = (archive_bytes, files)

    artifact_sets: dict[str, dict[str, Any]] = {}
    referenced_archives: set[str] = set()
    for manifest_path in manifest_paths:
        manifest_bytes = manifest_path.read_bytes()
        manifest = parse_strict_json_bytes(manifest_bytes, str(manifest_path))
        _validate_value(
            "path_artifact_manifest",
            manifest,
            str(manifest_path),
            registry,
            validators,
        )
        if manifest["artifact_type"] != artifact_type:
            raise StructuralValidationError(
                f"{manifest_path}: expected artifact_type {artifact_type}"
            )
        if (
            manifest["population_freeze_sha256"] != population_digest
            or manifest["case_count"] != case_count
            or manifest["repeat_count"] != repeat_count
        ):
            raise StructuralValidationError(
                f"{manifest_path}: path manifest does not match frozen population"
            )
        path_id = manifest["path_id"]
        if path_id in artifact_sets:
            raise StructuralValidationError(
                f"duplicate {artifact_type} manifest path_id: {path_id}"
            )
        archive_digest = manifest["archive_sha256"]
        resolved = archives.get(archive_digest)
        if resolved is None:
            raise StructuralValidationError(
                f"{manifest_path}: path manifest archive was not supplied"
            )
        archive_bytes, files = resolved
        _verify_manifest(manifest, archive_bytes, files)
        artifact_sets[path_id] = {
            "archive_bytes": archive_bytes,
            "files": files,
            "manifest": manifest,
            "manifest_bytes": manifest_bytes,
        }
        referenced_archives.add(archive_digest)
    if referenced_archives != set(archives):
        raise StructuralValidationError(
            f"{artifact_type} manifests must exactly cover supplied archives"
        )
    return artifact_sets


def validate_complete_pack(
    *,
    public_commitment_path: Path,
    input_archive_path: Path,
    input_manifest_path: Path,
    oracle_archive_path: Path,
    oracle_manifest_path: Path,
    population_freeze_path: Path,
    output_commitment_paths: list[Path],
    result_archive_paths: list[Path],
    result_manifest_paths: list[Path],
    trace_archive_paths: list[Path],
    trace_manifest_paths: list[Path],
    oracle_reveal_path: Path,
    freeze_reveal_path: Path,
) -> None:
    registry = _registry()
    validators: dict[str, Draft202012Validator] = {}

    public_bytes = public_commitment_path.read_bytes()
    public_commitment = parse_strict_json_bytes(
        public_bytes, str(public_commitment_path)
    )
    input_manifest_bytes = input_manifest_path.read_bytes()
    input_manifest = parse_strict_json_bytes(
        input_manifest_bytes, str(input_manifest_path)
    )
    oracle_manifest_bytes = oracle_manifest_path.read_bytes()
    oracle_manifest = parse_strict_json_bytes(
        oracle_manifest_bytes, str(oracle_manifest_path)
    )
    _validate_value(
        "public_commitment",
        public_commitment,
        str(public_commitment_path),
        registry,
        validators,
    )
    _validate_value(
        "pack_manifest",
        input_manifest,
        str(input_manifest_path),
        registry,
        validators,
    )
    _validate_value(
        "pack_manifest",
        oracle_manifest,
        str(oracle_manifest_path),
        registry,
        validators,
    )
    if input_manifest["pack_type"] != "sealed_input_pack":
        raise StructuralValidationError("input manifest has the wrong pack_type")
    if oracle_manifest["pack_type"] != "sealed_oracle_pack":
        raise StructuralValidationError("oracle manifest has the wrong pack_type")
    input_archive_bytes, input_files = _load_canonical_ustar(input_archive_path)
    oracle_archive_bytes, oracle_files = _load_canonical_ustar(oracle_archive_path)
    _verify_manifest(input_manifest, input_archive_bytes, input_files)
    _verify_manifest(oracle_manifest, oracle_archive_bytes, oracle_files)
    if public_commitment["sealed_input_pack_sha256"] != _sha256_bytes(
        input_archive_bytes
    ) or public_commitment["sealed_oracle_pack_sha256"] != _sha256_bytes(
        oracle_archive_bytes
    ):
        raise StructuralValidationError(
            "public commitment does not bind the exact sealed archives"
        )

    case_paths = sorted(
        path
        for path in input_files
        if path.startswith("cases/") and path.endswith("/case.json")
    )
    cases: list[dict[str, Any]] = []
    permitted_by_case: dict[str, dict[str, str]] = {}
    claimed_input_paths: set[str] = set()
    for path in case_paths:
        case = parse_strict_json_bytes(input_files[path], path)
        _validate_value("case_record", case, path, registry, validators)
        expected_directory = f"cases/{case['case_id']}"
        if case["fixture_directory"] != expected_directory or path != (
            f"{expected_directory}/case.json"
        ):
            raise StructuralValidationError(
                f"{case['case_id']}: non-canonical fixture directory or case path"
            )
        expected_manifest = f"{expected_directory}/inputs.sha256"
        if case["permitted_inputs_manifest"] != expected_manifest:
            raise StructuralValidationError(
                f"{case['case_id']}: non-canonical permitted-input manifest path"
            )
        manifest_data = input_files.get(expected_manifest)
        if manifest_data is None:
            raise StructuralValidationError(
                f"{case['case_id']}: missing permitted-input manifest"
            )
        permitted_records = _parse_permitted_inputs(manifest_data, expected_manifest)
        permitted = dict(permitted_records)
        fixture_files = {
            item
            for item in input_files
            if item.startswith(expected_directory + "/")
            and item not in {path, expected_manifest}
        }
        if set(permitted) != fixture_files:
            raise StructuralValidationError(
                f"{case['case_id']}: permitted inputs must exactly cover fixture files"
            )
        for permitted_path, digest in permitted.items():
            if digest != _sha256_bytes(input_files[permitted_path]):
                raise StructuralValidationError(
                    f"{case['case_id']}: permitted-input digest mismatch"
                )
        cases.append(case)
        permitted_by_case[case["case_id"]] = permitted
        claimed_input_paths.update({path, expected_manifest, *permitted})
    _require_unique((item["case_id"] for item in cases), "complete-pack case_id")
    if len(cases) < 12:
        raise StructuralValidationError("complete pack requires at least twelve cases")
    case_ids = {item["case_id"] for item in cases}
    family_ids = {item["family_id"] for item in cases}
    if claimed_input_paths != set(input_files):
        raise StructuralValidationError(
            "input archive contains a file outside the exact case fixture sets"
        )

    required_oracle_roots = {
        "authorship-collection.json",
        "relatedness-graph.json",
        "leakage-review.json",
    }
    oracle_paths = {f"oracles/{case_id}.json" for case_id in case_ids}
    if set(oracle_files) != required_oracle_roots | oracle_paths:
        raise StructuralValidationError(
            "oracle archive must contain exactly the oracles and three control records"
        )
    oracles: dict[str, dict[str, Any]] = {}
    for case in cases:
        path = f"oracles/{case['case_id']}.json"
        oracle = parse_strict_json_bytes(oracle_files[path], path)
        _validate_value("oracle_record", oracle, path, registry, validators)
        if (
            oracle["case_id"] != case["case_id"]
            or oracle["case_coordinate"] != case["case_coordinate"]
            or oracle["validation_time"] != case["validation_time"]
        ):
            raise StructuralValidationError(f"{path}: oracle-to-case binding mismatch")
        oracles[case["case_id"]] = oracle
    authorship = parse_strict_json_bytes(
        oracle_files["authorship-collection.json"], "authorship-collection.json"
    )
    graph = parse_strict_json_bytes(
        oracle_files["relatedness-graph.json"], "relatedness-graph.json"
    )
    leakage = parse_strict_json_bytes(
        oracle_files["leakage-review.json"], "leakage-review.json"
    )
    _validate_value(
        "authorship_collection",
        authorship,
        "authorship-collection.json",
        registry,
        validators,
    )
    _validate_value(
        "relatedness_graph", graph, "relatedness-graph.json", registry, validators
    )
    _validate_value(
        "leakage_review_attestation",
        leakage,
        "leakage-review.json",
        registry,
        validators,
    )
    if {item["family_id"] for item in authorship["records"]} != family_ids:
        raise StructuralValidationError(
            "authorship family set must equal case family set"
        )
    if set(graph["family_ids"]) != family_ids:
        raise StructuralValidationError(
            "relatedness family set must equal case family set"
        )
    _validate_authorship_graph(authorship, graph)
    all_authors = {
        author_id
        for record in authorship["records"]
        for author_id in [record["primary_author_id"], *record["coauthor_ids"]]
    }
    for record in authorship["records"]:
        if any(
            item["related_family_id"] not in family_ids
            for item in record["coordination_disclosures"]
        ):
            raise StructuralValidationError(
                "coordination disclosure names an unknown family"
            )
    if (
        leakage["reviewer_id"] == leakage["oracle_custodian_id"]
        or leakage["reviewer_id"] in all_authors
        or leakage["oracle_custodian_id"] in all_authors
    ):
        raise StructuralValidationError(
            "leakage reviewer and custodian must be distinct non-authors"
        )
    if set(item["case_id"] for item in leakage["cases"]) != case_ids or any(
        item["disposition"] != "PASS" for item in leakage["cases"]
    ):
        raise StructuralValidationError(
            "every committed case requires exactly one PASS leakage review"
        )
    if leakage["input_pack_sha256"] != _sha256_bytes(input_archive_bytes):
        raise StructuralValidationError("leakage review is not bound to the input pack")
    committed_controls = {
        "authorship_collection_sha256": _sha256_bytes(
            oracle_files["authorship-collection.json"]
        ),
        "relatedness_graph_sha256": _sha256_bytes(
            oracle_files["relatedness-graph.json"]
        ),
        "leakage_review_attestation_sha256": _sha256_bytes(
            oracle_files["leakage-review.json"]
        ),
    }
    for field, digest in committed_controls.items():
        if public_commitment[field] != digest:
            raise StructuralValidationError(
                f"public commitment does not bind exact {field} bytes"
            )
    if public_commitment["aggregate_case_count"] != len(cases) or public_commitment[
        "aggregate_family_count"
    ] != len(family_ids):
        raise StructuralValidationError("public commitment aggregate counts mismatch")
    for manifest in (input_manifest, oracle_manifest):
        if manifest["case_count"] != len(cases) or manifest["family_count"] != len(
            family_ids
        ):
            raise StructuralValidationError("pack manifest aggregate counts mismatch")
    for case in cases:
        _validate_case_provenance(
            case,
            oracles[case["case_id"]],
            input_files,
            permitted_by_case[case["case_id"]],
            registry,
            validators,
        )

    population_bytes = population_freeze_path.read_bytes()
    population = parse_strict_json_bytes(population_bytes, str(population_freeze_path))
    _validate_value(
        "population_freeze_record",
        population,
        str(population_freeze_path),
        registry,
        validators,
    )
    if population["public_commitment_sha256"] != _sha256_bytes(public_bytes):
        raise StructuralValidationError(
            "population freeze does not bind public commitment"
        )
    if population["input_manifest_sha256"] != _sha256_bytes(
        input_manifest_bytes
    ) or population["oracle_manifest_sha256"] != _sha256_bytes(oracle_manifest_bytes):
        raise StructuralValidationError(
            "population freeze does not bind both manifests"
        )
    if (
        population["approved_protocol_commit"]
        != public_commitment["approved_protocol_commit"]
    ):
        raise StructuralValidationError("protocol commit mismatch across phase records")
    if population["case_exclusions"]:
        raise StructuralValidationError(
            "a committed candidate defect invalidates the whole experiment"
        )
    included_ids = sorted(case_ids)
    if population["included_case_ids"] != included_ids:
        raise StructuralValidationError(
            "included_case_ids do not equal candidates minus exclusions"
        )
    population_core = {
        "included_case_ids": included_ids,
        "repeat_count": population["repeat_count"],
    }
    if population["population_sha256"] != _jcs_sha256(population_core):
        raise StructuralValidationError("population digest mismatch")
    frozen_at = _timestamp(population["frozen_at"])
    input_revealed_at = _timestamp(population["input_pack_revealed_at"])
    if frozen_at >= input_revealed_at:
        raise StructuralValidationError("population must freeze before input reveal")
    included_cases = [item for item in cases if item["case_id"] in included_ids]
    included_families = {item["family_id"] for item in included_cases}
    author_by_family = {
        item["family_id"]: item["primary_author_id"] for item in authorship["records"]
    }
    included_authors = {author_by_family[item] for item in included_families}
    included_edges = [
        item for item in graph["edges"] if set(item["family_ids"]) <= included_families
    ]
    included_clusters = _graph_components(sorted(included_families), included_edges)
    if (
        len(included_cases) < 12
        or len(included_families) < 4
        or len(included_authors) < 4
        or len(included_clusters) < 4
    ):
        raise StructuralValidationError(
            "complete committed population is below a protocol floor"
        )
    if any(item["implementation_roles"] for item in authorship["records"]):
        raise StructuralValidationError(
            "blind-pack authorship records cannot contain implementation roles"
        )

    population_digest = _sha256_bytes(population_bytes)
    model_by_path = {item["path_id"]: item for item in population["models"]}
    model_paths = set(model_by_path)
    if not {"governed", "retrieval_plus_rules"} <= model_paths:
        raise StructuralValidationError("required evaluated paths are missing")
    if (
        model_by_path["governed"]["observer_rules_sha256"]
        != population["governed_rules_sha256"]
        or model_by_path["retrieval_plus_rules"]["observer_rules_sha256"]
        != population["comparator_rules_sha256"]
    ):
        raise StructuralValidationError(
            "required path observers do not bind their frozen rule sets"
        )

    result_sets = _load_path_artifacts(
        manifest_paths=result_manifest_paths,
        archive_paths=result_archive_paths,
        artifact_type="result_records",
        population_digest=population_digest,
        case_count=len(included_ids),
        repeat_count=population["repeat_count"],
        registry=registry,
        validators=validators,
    )
    trace_sets = _load_path_artifacts(
        manifest_paths=trace_manifest_paths,
        archive_paths=trace_archive_paths,
        artifact_type="trace_records",
        population_digest=population_digest,
        case_count=len(included_ids),
        repeat_count=population["repeat_count"],
        registry=registry,
        validators=validators,
    )
    if set(result_sets) != model_paths or set(trace_sets) != model_paths:
        raise StructuralValidationError(
            "result and trace archives must exactly cover frozen model paths"
        )

    cases_by_id = {item["case_id"]: item for item in included_cases}
    expected_coordinates = {
        (case_id, repeat_index)
        for case_id in included_ids
        for repeat_index in range(population["repeat_count"])
    }
    for path_id in sorted(model_paths):
        result_files = result_sets[path_id]["files"]
        trace_files = trace_sets[path_id]["files"]
        expected_result_paths = {
            f"results/{path_id}/{case_id}/{repeat_index}.json"
            for case_id, repeat_index in expected_coordinates
        }
        expected_trace_paths = {
            f"traces/{path_id}/{case_id}/{repeat_index}.json"
            for case_id, repeat_index in expected_coordinates
        }
        if set(result_files) != expected_result_paths:
            raise StructuralValidationError(
                f"{path_id}: result archive does not contain the exact "
                "case-repeat matrix"
            )
        if set(trace_files) != expected_trace_paths:
            raise StructuralValidationError(
                f"{path_id}: trace archive does not contain the exact "
                "case-repeat matrix"
            )

        parsed_traces: dict[tuple[str, int], dict[str, Any]] = {}
        for case_id, repeat_index in sorted(expected_coordinates):
            trace_path = f"traces/{path_id}/{case_id}/{repeat_index}.json"
            trace = parse_strict_json_bytes(trace_files[trace_path], trace_path)
            _validate_value("trace_record", trace, trace_path, registry, validators)
            if (
                trace["case_id"] != case_id
                or trace["path_id"] != path_id
                or trace["repeat_index"] != repeat_index
                or trace["observer_rules_sha256"]
                != model_by_path[path_id]["observer_rules_sha256"]
            ):
                raise StructuralValidationError(
                    f"{trace_path}: trace does not match its frozen coordinate"
                )
            if any(
                _timestamp(event["observed_at"]) < input_revealed_at
                for event in trace["events"]
            ):
                raise StructuralValidationError(
                    f"{trace_path}: trace event precedes input reveal"
                )
            parsed_traces[(case_id, repeat_index)] = trace

            result_path = f"results/{path_id}/{case_id}/{repeat_index}.json"
            run = parse_strict_json_bytes(result_files[result_path], result_path)
            _validate_value("path_run_record", run, result_path, registry, validators)
            if (
                run["case_id"] != case_id
                or run["path_id"] != path_id
                or run["repeat_index"] != repeat_index
                or run["trace_sha256"] != _sha256_bytes(trace_files[trace_path])
            ):
                raise StructuralValidationError(
                    f"{result_path}: path run does not bind its exact trace"
                )
            if run["run_status"] == "COMPLETE":
                _validate_case_provenance(
                    cases_by_id[case_id],
                    {"oracle": run["result"]},
                    input_files,
                    permitted_by_case[case_id],
                    registry,
                    validators,
                )
        trace_sets[path_id]["parsed_traces"] = parsed_traces

    commitments: list[tuple[dict[str, Any], bytes]] = []
    for path in output_commitment_paths:
        data = path.read_bytes()
        value = parse_strict_json_bytes(data, str(path))
        _validate_value(
            "path_output_commitment", value, str(path), registry, validators
        )
        commitments.append((value, data))
    _require_unique((item[0]["path_id"] for item in commitments), "output path_id")
    if {item[0]["path_id"] for item in commitments} != model_paths:
        raise StructuralValidationError(
            "output commitments must exactly cover model paths"
        )
    for commitment, _ in commitments:
        if (
            commitment["experiment_id"] != population["experiment_id"]
            or commitment["population_freeze_sha256"] != population_digest
            or commitment["included_case_count"] != len(included_ids)
            or commitment["repeat_count"] != population["repeat_count"]
            or _timestamp(commitment["committed_at"]) < input_revealed_at
        ):
            raise StructuralValidationError(
                "output commitment does not match frozen run"
            )
        path_id = commitment["path_id"]
        result_set = result_sets[path_id]
        trace_set = trace_sets[path_id]
        if (
            commitment["outputs_sha256"] != _sha256_bytes(result_set["archive_bytes"])
            or commitment["outputs_manifest_sha256"]
            != _sha256_bytes(result_set["manifest_bytes"])
            or commitment["traces_sha256"] != _sha256_bytes(trace_set["archive_bytes"])
            or commitment["traces_manifest_sha256"]
            != _sha256_bytes(trace_set["manifest_bytes"])
        ):
            raise StructuralValidationError(
                f"{path_id}: output commitment does not bind exact artifacts"
            )
        committed_at = _timestamp(commitment["committed_at"])
        if any(
            _timestamp(event["observed_at"]) > committed_at
            for trace in trace_set["parsed_traces"].values()
            for event in trace["events"]
        ):
            raise StructuralValidationError(
                f"{path_id}: trace event occurs after output commitment"
            )
    commitment_digests = sorted(_sha256_bytes(data) for _, data in commitments)

    reveal_bytes = oracle_reveal_path.read_bytes()
    reveal = parse_strict_json_bytes(reveal_bytes, str(oracle_reveal_path))
    _validate_value(
        "oracle_reveal_record", reveal, str(oracle_reveal_path), registry, validators
    )
    if (
        reveal["experiment_id"] != population["experiment_id"]
        or reveal["population_freeze_sha256"] != population_digest
        or reveal["output_commitment_sha256s"] != commitment_digests
    ):
        raise StructuralValidationError("oracle reveal does not bind frozen outputs")
    oracle_revealed_at = _timestamp(reveal["oracle_pack_revealed_at"])
    if any(
        _timestamp(commitment["committed_at"]) >= oracle_revealed_at
        for commitment, _ in commitments
    ):
        raise StructuralValidationError(
            "every output commitment must precede oracle reveal"
        )

    final = load_strict_json(freeze_reveal_path)
    _validate_value(
        "freeze_reveal_record", final, str(freeze_reveal_path), registry, validators
    )
    if (
        final["experiment_id"] != population["experiment_id"]
        or final["population_freeze_sha256"] != population_digest
        or final["output_commitment_sha256s"] != commitment_digests
        or final["oracle_reveal_sha256"] != _sha256_bytes(reveal_bytes)
        or _timestamp(final["finalized_at"]) < oracle_revealed_at
    ):
        raise StructuralValidationError(
            "final receipt does not bind the ordered phases"
        )


def validate_artifacts(assignments: list[tuple[str, Path]]) -> None:
    """Validate supplied record shapes and any directly comparable records.

    This partial mode never certifies a sealed experiment. Use
    :func:`validate_complete_pack` for the closed archive and phase workflow.
    """
    registry = _registry()
    validators: dict[str, Draft202012Validator] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_paths: dict[str, list[Path]] = defaultdict(list)

    for kind, path in assignments:
        if kind not in SCHEMA_FILES:
            raise StructuralValidationError(f"unknown artifact kind: {kind}")
        value = load_strict_json(path)
        _validate_value(kind, value, str(path), registry, validators)
        grouped[kind].append(value)
        grouped_paths[kind].append(path)

    _require_unique((item["case_id"] for item in grouped["case_record"]), "case_id")
    _require_unique(
        (item["case_id"] for item in grouped["oracle_record"]), "oracle case_id"
    )
    _require_unique(
        (item["family_id"] for item in grouped["authorship_attestation"]),
        "authorship family_id",
    )
    _require_unique(
        (
            f"{item['artifact_type']}\0{item['path_id']}"
            for item in grouped["path_artifact_manifest"]
        ),
        "path artifact manifest coordinate",
    )
    for kind in ("path_run_record", "result_record", "trace_record"):
        _require_unique(
            (
                f"{item['path_id']}\0{item['case_id']}\0{item['repeat_index']}"
                for item in grouped[kind]
            ),
            f"{kind} coordinate",
        )

    cases = grouped["case_record"]
    oracles = grouped["oracle_record"]
    if cases and oracles:
        case_ids = {item["case_id"] for item in cases}
        oracle_ids = {item["case_id"] for item in oracles}
        if case_ids != oracle_ids:
            raise StructuralValidationError(
                "oracle case IDs must exactly equal input case IDs"
            )
    authorship = grouped["authorship_attestation"]
    if cases and authorship:
        case_families = {item["family_id"] for item in cases}
        attested_families = {item["family_id"] for item in authorship}
        if case_families != attested_families:
            raise StructuralValidationError(
                "case family IDs must exactly equal authorship family IDs"
            )
    for commitment in grouped["public_commitment"]:
        if cases and commitment["aggregate_case_count"] != len(cases):
            raise StructuralValidationError(
                "public aggregate_case_count does not equal validated cases"
            )
        if cases and commitment["aggregate_family_count"] != len(
            {item["family_id"] for item in cases}
        ):
            raise StructuralValidationError(
                "public aggregate_family_count does not equal validated families"
            )

    for singleton_kind in (
        "authorship_collection",
        "freeze_reveal_record",
        "leakage_review_attestation",
        "oracle_reveal_record",
        "population_freeze_record",
        "public_commitment",
        "relatedness_graph",
    ):
        if len(grouped[singleton_kind]) > 1:
            raise StructuralValidationError(
                f"more than one {singleton_kind} was supplied"
            )

    manifests = grouped["pack_manifest"]
    manifest_by_type = {item["pack_type"]: item for item in manifests}
    if len(manifest_by_type) != len(manifests):
        raise StructuralValidationError("duplicate pack_type manifest")
    for manifest in manifests:
        if cases and manifest["case_count"] != len(cases):
            raise StructuralValidationError(
                f"{manifest['pack_type']} case_count does not equal validated cases"
            )
        if cases and manifest["family_count"] != len(
            {item["family_id"] for item in cases}
        ):
            raise StructuralValidationError(
                f"{manifest['pack_type']} family_count does not equal "
                "validated families"
            )

    commitments = grouped["public_commitment"]
    if commitments:
        commitment = commitments[0]
        input_manifest = manifest_by_type.get("sealed_input_pack")
        oracle_manifest = manifest_by_type.get("sealed_oracle_pack")
        if (
            input_manifest
            and commitment["sealed_input_pack_sha256"]
            != input_manifest["archive_sha256"]
        ):
            raise StructuralValidationError(
                "public commitment input-pack digest does not match manifest"
            )
        if (
            oracle_manifest
            and commitment["sealed_oracle_pack_sha256"]
            != (oracle_manifest["archive_sha256"])
        ):
            raise StructuralValidationError(
                "public commitment oracle-pack digest does not match manifest"
            )

    authorship_collections = grouped["authorship_collection"]
    graphs = grouped["relatedness_graph"]
    if authorship_collections and graphs:
        _validate_authorship_graph(authorship_collections[0], graphs[0])

    population_records = grouped["population_freeze_record"]
    if population_records and commitments:
        population = population_records[0]
        public_path = grouped_paths["public_commitment"][0]
        if population["public_commitment_sha256"] != _sha256_bytes(
            public_path.read_bytes()
        ):
            raise StructuralValidationError(
                "population freeze does not bind the exact public commitment bytes"
            )
        if (
            population["approved_protocol_commit"]
            != commitments[0]["approved_protocol_commit"]
        ):
            raise StructuralValidationError(
                "population freeze approved_protocol_commit mismatch"
            )

    path_commitments = grouped["path_output_commitment"]
    _require_unique(
        (item["path_id"] for item in path_commitments), "output commitment path_id"
    )
    reveal_records = grouped["oracle_reveal_record"]
    if reveal_records and path_commitments:
        expected = sorted(
            _sha256_bytes(path.read_bytes())
            for path in grouped_paths["path_output_commitment"]
        )
        if reveal_records[0]["output_commitment_sha256s"] != expected:
            raise StructuralValidationError(
                "oracle reveal does not bind the supplied output commitments"
            )

    final_records = grouped["freeze_reveal_record"]
    if final_records and reveal_records:
        reveal_path = grouped_paths["oracle_reveal_record"][0]
        if final_records[0]["oracle_reveal_sha256"] != _sha256_bytes(
            reveal_path.read_bytes()
        ):
            raise StructuralValidationError(
                "final receipt does not bind the supplied oracle-reveal record"
            )


def _assignment(value: str) -> tuple[str, Path]:
    kind, separator, raw_path = value.partition("=")
    if not separator or not kind or not raw_path:
        raise argparse.ArgumentTypeError("expected KIND=PATH")
    return kind, Path(raw_path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate v0.3.8 record shapes or one complete sealed workflow."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    record_parser = subparsers.add_parser(
        "record", help="validate record shapes; never certifies a complete pack"
    )
    record_parser.add_argument(
        "artifacts",
        nargs="+",
        type=_assignment,
        metavar="KIND=PATH",
        help="artifact kind and JSON path",
    )
    complete_parser = subparsers.add_parser(
        "complete-pack", help="validate exact archives and the ordered sealing phases"
    )
    for option in (
        "public_commitment",
        "input_archive",
        "input_manifest",
        "oracle_archive",
        "oracle_manifest",
        "population_freeze",
        "oracle_reveal",
        "freeze_reveal",
    ):
        complete_parser.add_argument(
            "--" + option.replace("_", "-"),
            type=Path,
            required=True,
        )
    complete_parser.add_argument(
        "--output-commitment",
        type=Path,
        action="append",
        required=True,
        dest="output_commitments",
    )
    for option in (
        "result_archive",
        "result_manifest",
        "trace_archive",
        "trace_manifest",
    ):
        complete_parser.add_argument(
            "--" + option.replace("_", "-"),
            type=Path,
            action="append",
            required=True,
            dest=option + "s",
        )
    args = parser.parse_args()
    try:
        if args.mode == "record":
            validate_artifacts(args.artifacts)
            print(f"VALID_RECORDS: {len(args.artifacts)} artifact(s)")
        else:
            validate_complete_pack(
                public_commitment_path=args.public_commitment.resolve(),
                input_archive_path=args.input_archive.resolve(),
                input_manifest_path=args.input_manifest.resolve(),
                oracle_archive_path=args.oracle_archive.resolve(),
                oracle_manifest_path=args.oracle_manifest.resolve(),
                population_freeze_path=args.population_freeze.resolve(),
                output_commitment_paths=[
                    item.resolve() for item in args.output_commitments
                ],
                result_archive_paths=[item.resolve() for item in args.result_archives],
                result_manifest_paths=[
                    item.resolve() for item in args.result_manifests
                ],
                trace_archive_paths=[item.resolve() for item in args.trace_archives],
                trace_manifest_paths=[item.resolve() for item in args.trace_manifests],
                oracle_reveal_path=args.oracle_reveal.resolve(),
                freeze_reveal_path=args.freeze_reveal.resolve(),
            )
            print("VALID_COMPLETE_PACK")
    except (OSError, StructuralValidationError) as error:
        print(f"INVALID: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
