#!/usr/bin/env python3
"""Validate v0.3.6 protocol artifacts without model judgment."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS = PROJECT_ROOT / "docs"
SAFE_INTEGER = 9_007_199_254_740_991
STAGE_ORDER = ["authority", "contract", "evidence"]

SCHEMA_FILES = {
    "authorship_attestation": DOCS / "authorship-attestation.v0.3.schema.json",
    "authority_bundle": DOCS / "authority-ledger-bundle.v0.3.schema.json",
    "case_record": DOCS / "case-record.v0.3.schema.json",
    "freeze_reveal_record": DOCS / "freeze-reveal-record.v0.3.schema.json",
    "leakage_review_attestation": (
        DOCS / "leakage-review-attestation.v0.3.schema.json"
    ),
    "oracle_record": DOCS / "oracle-record.v0.3.schema.json",
    "pack_manifest": DOCS / "sealed-pack-manifest.v0.3.schema.json",
    "public_commitment": DOCS / "public-commitment.v0.3.schema.json",
    "result_record": DOCS / "result-record.v0.3.schema.json",
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
        if not math.isfinite(value):
            raise StructuralValidationError(f"non-finite number at {location}")
        return
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


def load_strict_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StructuralValidationError(f"{path}: {error}") from error
    _check_ijson(value)
    if not isinstance(value, dict):
        raise StructuralValidationError(f"{path}: top-level value must be an object")
    return value


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


def _validate_provenance(provenance: dict[str, Any]) -> None:
    chains = provenance["authority_chains"]
    _require_sorted(
        chains,
        sorted(chains, key=lambda item: (item["issuer_id"], item["claim_entry_id"])),
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
    elif kind == "pack_manifest":
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
    elif kind == "result_record":
        _require_sorted(
            value["reason_codes"],
            sorted(value["reason_codes"]),
            "result reason_codes",
        )
        _validate_provenance(value["provenance"])


def validate_artifacts(assignments: list[tuple[str, Path]]) -> None:
    registry = _registry()
    validators: dict[str, Draft202012Validator] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_paths: dict[str, list[Path]] = defaultdict(list)

    for kind, path in assignments:
        if kind not in SCHEMA_FILES:
            raise StructuralValidationError(f"unknown artifact kind: {kind}")
        value = load_strict_json(path)
        validator = validators.setdefault(kind, _validator(kind, registry))
        errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
        if errors:
            first = errors[0]
            location = ".".join(str(item) for item in first.absolute_path) or "$"
            raise StructuralValidationError(f"{path}:{location}: {first.message}")
        _semantic_validate(kind, value)
        grouped[kind].append(value)
        grouped_paths[kind].append(path)

    _require_unique(
        (item["case_id"] for item in grouped["case_record"]), "case_id"
    )
    _require_unique(
        (item["case_id"] for item in grouped["oracle_record"]), "oracle case_id"
    )
    _require_unique(
        (item["family_id"] for item in grouped["authorship_attestation"]),
        "authorship family_id",
    )

    cases = grouped["case_record"]
    oracles = grouped["oracle_record"]
    authorship = grouped["authorship_attestation"]
    if cases and oracles:
        case_ids = {item["case_id"] for item in cases}
        oracle_ids = {item["case_id"] for item in oracles}
        if case_ids != oracle_ids:
            raise StructuralValidationError(
                "oracle case IDs must exactly equal input case IDs"
            )
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

    for singleton_kind in ("public_commitment", "freeze_reveal_record"):
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
        if input_manifest and commitment["sealed_input_pack_sha256"] != input_manifest[
            "archive_sha256"
        ]:
            raise StructuralValidationError(
                "public commitment input-pack digest does not match manifest"
            )
        if oracle_manifest and commitment["sealed_oracle_pack_sha256"] != (
            oracle_manifest["archive_sha256"]
        ):
            raise StructuralValidationError(
                "public commitment oracle-pack digest does not match manifest"
            )

    freeze_records = grouped["freeze_reveal_record"]
    if freeze_records and commitments:
        freeze = freeze_records[0]
        commitment = commitments[0]
        commitment_path = grouped_paths["public_commitment"][0]
        commitment_digest = (
            "sha256:" + hashlib.sha256(commitment_path.read_bytes()).hexdigest()
        )
        if freeze["public_commitment_sha256"] != commitment_digest:
            raise StructuralValidationError(
                "freeze record does not bind the exact public commitment bytes"
            )
        for field in (
            "approved_protocol_commit",
            "sealed_input_pack_sha256",
            "sealed_oracle_pack_sha256",
        ):
            if freeze[field] != commitment[field]:
                raise StructuralValidationError(
                    f"freeze record {field} does not match public commitment"
                )


def _assignment(value: str) -> tuple[str, Path]:
    kind, separator, raw_path = value.partition("=")
    if not separator or not kind or not raw_path:
        raise argparse.ArgumentTypeError("expected KIND=PATH")
    return kind, Path(raw_path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate v0.3.6 artifacts and cross-record structure."
    )
    parser.add_argument(
        "artifacts",
        nargs="+",
        type=_assignment,
        metavar="KIND=PATH",
        help="artifact kind and JSON path; repeat to validate a complete set",
    )
    args = parser.parse_args()
    try:
        validate_artifacts(args.artifacts)
    except StructuralValidationError as error:
        print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print(f"VALID: {len(args.artifacts)} artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
