from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENTRY_SCHEMA_PATH = (
    PROJECT_ROOT / "docs" / "authority-ledger-entry.v0.3.schema.json"
)
BUNDLE_SCHEMA_PATH = (
    PROJECT_ROOT / "docs" / "authority-ledger-bundle.v0.3.schema.json"
)
VECTOR_PATH = PROJECT_ROOT / "docs" / "authority-ledger.v0.3.vectors.json"
PROTOCOL_PATH = PROJECT_ROOT / "docs" / "proof-protocol.v0.3.json"
GENERATOR_PATH = PROJECT_ROOT / "scripts" / "generate_authority_vectors.py"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _generator_module():
    spec = importlib.util.spec_from_file_location("authority_vectors", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validators():
    entry_schema = _load(ENTRY_SCHEMA_PATH)
    bundle_schema = _load(BUNDLE_SCHEMA_PATH)
    Draft202012Validator.check_schema(entry_schema)
    Draft202012Validator.check_schema(bundle_schema)
    registry = Registry().with_resource(
        str(entry_schema["$id"]),
        Resource.from_contents(entry_schema),
    )
    format_checker = FormatChecker()
    return (
        Draft202012Validator(entry_schema, format_checker=format_checker),
        Draft202012Validator(
            bundle_schema,
            registry=registry,
            format_checker=format_checker,
        ),
    )


def test_authority_vectors_are_generated_and_schema_valid() -> None:
    vectors = _load(VECTOR_PATH)
    generator = _generator_module()
    assert generator.build_vectors() == vectors

    entry_validator, bundle_validator = _validators()
    bundle_validator.validate(vectors["example_bundle"])
    entries = [item["signed_entry"] for item in vectors["vectors"]]
    for entry in entries:
        entry_validator.validate(entry)
    assert {entry["entry_type"] for entry in entries} == {
        "claim",
        "delegation",
        "precedence",
        "recovery",
        "revocation",
        "rotation",
    }


def test_reference_keys_and_actual_ed25519_signatures_verify() -> None:
    vectors = _load(VECTOR_PATH)
    generator = _generator_module()
    keys = {item["key_id"]: item for item in vectors["keys"]}

    for key_id, key in keys.items():
        public_bytes = _b64url(key["public_key_base64url"])
        assert len(public_bytes) == 32
        assert key_id == f"sha256:{hashlib.sha256(public_bytes).hexdigest()}"

    for vector in vectors["vectors"]:
        signed = deepcopy(vector["signed_entry"])
        signature = signed.pop("signature")
        assert signature["key_id"] == signed["issuer_key_id"]
        canonical = generator._ascii_jcs(signed)
        assert canonical.decode("utf-8") == vector["canonical_payload"]
        assert vector["canonical_payload_sha256"] == (
            f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        )
        public = Ed25519PublicKey.from_public_bytes(
            _b64url(keys[signature["key_id"]]["public_key_base64url"])
        )
        public.verify(_b64url(signature["value"]), canonical)


def test_bundle_resolves_signing_keys_without_an_unstated_registry() -> None:
    vectors = _load(VECTOR_PATH)
    bundle = vectors["example_bundle"]
    resolved = {
        anchor["key_id"]: anchor["public_key_base64url"]
        for anchor in [*bundle["trust_anchors"], *bundle["recovery_trust_anchors"]]
    }
    for vector in vectors["vectors"]:
        entry = vector["signed_entry"]
        assert resolved[entry["signature"]["key_id"]]
        if entry["entry_type"] == "delegation":
            resolved[entry["subject_key_id"]] = entry[
                "subject_public_key_base64url"
            ]
        elif entry["entry_type"] == "rotation":
            resolved[entry["successor_key_id"]] = entry[
                "successor_public_key_base64url"
            ]
        elif entry["entry_type"] == "recovery":
            resolved[entry["replacement_key_id"]] = entry[
                "replacement_public_key_base64url"
            ]

    introduced = {
        item["key_id"] for item in vectors["keys"] if item["name"] != "recovery"
    }
    assert introduced <= set(resolved)


def test_tampering_a_signed_claim_fails_cryptographic_verification() -> None:
    vectors = _load(VECTOR_PATH)
    generator = _generator_module()
    keys = {item["key_id"]: item for item in vectors["keys"]}
    claim_vector = next(
        item for item in vectors["vectors"] if item["entry_type"] == "claim"
    )
    tampered = deepcopy(claim_vector["signed_entry"])
    signature = tampered.pop("signature")
    tampered["claim_value"] = "owner:attacker"
    public = Ed25519PublicKey.from_public_bytes(
        _b64url(keys[signature["key_id"]]["public_key_base64url"])
    )
    with pytest.raises(InvalidSignature):
        public.verify(
            _b64url(signature["value"]),
            generator._ascii_jcs(tampered),
        )


def test_entry_schema_and_protocol_require_the_same_type_specific_fields() -> None:
    schema = _load(ENTRY_SCHEMA_PATH)
    protocol = _load(PROTOCOL_PATH)
    declared = {
        item["entry_type"]: item["required_fields"]
        for item in protocol["authority_ledger"]["entry_types"]
    }
    schema_required = {
        entry_type: schema["$defs"][entry_type]["allOf"][1]["required"]
        for entry_type in declared
    }
    assert schema_required == declared
    assert schema["$defs"]["scope"]["required"] == protocol[
        "authority_ledger"
    ]["scope_profile"]["coordinate_fields"]
    assert protocol["authority_ledger"]["schema_files"] == {
        "bundle": "docs/authority-ledger-bundle.v0.3.schema.json",
        "entry": "docs/authority-ledger-entry.v0.3.schema.json",
    }


def test_rotation_recovery_revocation_and_precedence_cross_field_invariants() -> None:
    vectors = _load(VECTOR_PATH)
    keys = {item["issuer_id"]: item for item in vectors["keys"]}
    entries = {
        item["entry_type"]: item["signed_entry"] for item in vectors["vectors"]
    }

    rotation = entries["rotation"]
    successor = keys[rotation["successor_issuer_id"]]
    assert rotation["successor_epoch"] == rotation["issuer_epoch"] + 1
    assert successor["lineage_id"] == rotation["lineage_id"]
    assert successor["key_id"] == rotation["successor_key_id"]
    assert successor["public_key_base64url"] == rotation[
        "successor_public_key_base64url"
    ]
    assert rotation["successor_permissions"] == sorted(
        set(rotation["successor_permissions"])
    )

    delegation = entries["delegation"]
    delegate = keys[delegation["subject_issuer_id"]]
    assert delegation["subject_key_id"] == delegate["key_id"]
    assert delegation["subject_public_key_base64url"] == delegate[
        "public_key_base64url"
    ]
    assert delegation["subject_lineage_id"] == delegate["lineage_id"]
    assert delegation["permissions"] == sorted(set(delegation["permissions"]))

    recovery = entries["recovery"]
    recovery_signer = keys[recovery["issuer_id"]]
    compromised = keys[recovery["compromised_issuer_id"]]
    replacement = keys[recovery["replacement_issuer_id"]]
    assert recovery_signer["name"] == "recovery"
    assert recovery_signer["lineage_id"] != compromised["lineage_id"]
    assert recovery["replacement_key_id"] == replacement["key_id"]
    assert recovery["replacement_public_key_base64url"] == replacement[
        "public_key_base64url"
    ]
    assert recovery["replacement_lineage_id"] == replacement["lineage_id"]
    assert recovery["replacement_permissions"] == sorted(
        set(recovery["replacement_permissions"])
    )
    recovery_anchor = vectors["example_bundle"]["recovery_trust_anchors"][0]
    assert set(recovery["replacement_permissions"]) <= set(
        recovery_anchor["replacement_permissions_ceiling"]
    )

    revocation = entries["revocation"]
    boundary = _timestamp(revocation["effective_at"])
    assert _timestamp("2030-05-31T23:59:59Z") < boundary
    assert _timestamp("2030-06-01T00:00:00Z") >= boundary

    precedence = entries["precedence"]
    assert _timestamp(precedence["issued_at"]) >= _timestamp(
        rotation["not_before"]
    )
    assert precedence["higher_issuer_id"] != precedence["lower_issuer_id"]
    assert precedence["scope"] == vectors["example_bundle"]["case_coordinate"]

    claim = entries["claim"]
    assert _timestamp(claim["issued_at"]) >= _timestamp(rotation["not_before"])

    heads = {
        item["lineage_id"]: item
        for item in vectors["example_bundle"]["lineage_heads"]
    }
    rotation_vector = next(
        item for item in vectors["vectors"] if item["entry_type"] == "rotation"
    )
    assert heads[rotation["lineage_id"]] == {
        "entry_id": rotation["entry_id"],
        "epoch": rotation["successor_epoch"],
        "lineage_id": rotation["lineage_id"],
        "payload_sha256": rotation_vector["canonical_payload_sha256"],
    }
    delegation_vector = next(
        item
        for item in vectors["vectors"]
        if item["entry_type"] == "delegation"
    )
    assert heads[delegation["subject_lineage_id"]] == {
        "entry_id": delegation["entry_id"],
        "epoch": delegation["subject_epoch"],
        "lineage_id": delegation["subject_lineage_id"],
        "payload_sha256": delegation_vector["canonical_payload_sha256"],
    }


def test_rollback_head_contract_is_bound_to_the_bundle_schema() -> None:
    protocol = _load(PROTOCOL_PATH)
    bundle_schema = _load(BUNDLE_SCHEMA_PATH)
    bundle = _load(VECTOR_PATH)["example_bundle"]
    rollback = protocol["authority_ledger"]["rollback_profile"]

    assert "lineage_heads" in bundle_schema["required"]
    assert bundle_schema["$defs"]["lineage_head"]["required"] == rollback[
        "head_pin_fields"
    ]
    assert rollback["head_pin_coverage"] == (
        "every_signer_and_endpoint_lineage_of_a_potentially_matching_claim_or_"
        "active_precedence_at_validation_time"
    )
    assert rollback["head_record_rule"] == (
        "epoch_zero_head_is_a_trust_anchor_or_valid_delegation;later_head_is_a_"
        "valid_rotation_or_recovery;compatible_same_epoch_reendorsement_does_"
        "not_change_the_head"
    )
    assert rollback["payload_rule"] == (
        "sha256_of_utf8_rfc8785_jcs_head_record_with_top_level_signature_"
        "removed_when_present"
    )
    assert rollback["record_id_uniqueness"] == (
        "anchor_id_and_entry_id_values_are_unique_across_the_bundle"
    )
    assert rollback["historical_transitions_remain_provenance"] is True
    record_ids = [
        *(anchor["anchor_id"] for anchor in bundle["trust_anchors"]),
        *(anchor["anchor_id"] for anchor in bundle["recovery_trust_anchors"]),
        *(entry["entry_id"] for entry in bundle["entries"]),
    ]
    assert len(record_ids) == len(set(record_ids))


def test_schema_rejects_unknown_fields_and_malformed_signatures() -> None:
    vectors = _load(VECTOR_PATH)
    entry_validator, _ = _validators()
    entry = deepcopy(vectors["vectors"][0]["signed_entry"])
    entry["undeclared"] = True
    assert list(entry_validator.iter_errors(entry))

    malformed = deepcopy(vectors["vectors"][0]["signed_entry"])
    malformed["signature"]["value"] = "short"
    assert list(entry_validator.iter_errors(malformed))


def test_strict_i_json_profile_rejects_duplicate_members() -> None:
    protocol = _load(PROTOCOL_PATH)
    assert protocol["authority_ledger"]["json_profile"][
        "duplicate_member_names"
    ] == "REJECT"

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate member: {key}")
            result[key] = value
        return result

    with pytest.raises(ValueError, match="duplicate member"):
        json.loads(
            '{"entry_id":"first","entry_id":"second"}',
            object_pairs_hook=reject_duplicates,
        )
