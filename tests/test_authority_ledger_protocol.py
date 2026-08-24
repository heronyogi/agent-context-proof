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
VECTOR_PATH = (
    PROJECT_ROOT / "tests" / "fixtures" / "authority-ledger.v0.3.vectors.json"
)
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
    assert vectors["schema_version"] == (
        "agent-context-proof-authority-vectors-v0.3.2"
    )

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


@pytest.mark.parametrize(
    "introduction_type", ["trust_anchor", "delegation", "rotation", "recovery"]
)
@pytest.mark.parametrize("declared_field", ["issuer_id", "lineage_id", "issuer_epoch"])
def test_signed_entries_must_match_the_identity_tuple_introduced_for_the_key(
    introduction_type: str, declared_field: str
) -> None:
    vectors = _load(VECTOR_PATH)
    generator = _generator_module()
    entry_validator, _ = _validators()
    keys = {item["name"]: item for item in vectors["keys"]}
    entries = {
        item["entry_type"]: item["signed_entry"] for item in vectors["vectors"]
    }
    anchor = vectors["example_bundle"]["trust_anchors"][0]
    introductions = {
        "trust_anchor": (
            keys["root"],
            (
                anchor["issuer_id"],
                anchor["lineage_id"],
                anchor["epoch"],
                anchor["key_id"],
            ),
        ),
        "delegation": (
            keys["delegate"],
            (
                entries["delegation"]["subject_issuer_id"],
                entries["delegation"]["subject_lineage_id"],
                entries["delegation"]["subject_epoch"],
                entries["delegation"]["subject_key_id"],
            ),
        ),
        "rotation": (
            keys["successor"],
            (
                entries["rotation"]["successor_issuer_id"],
                entries["rotation"]["lineage_id"],
                entries["rotation"]["successor_epoch"],
                entries["rotation"]["successor_key_id"],
            ),
        ),
        "recovery": (
            keys["recovered"],
            (
                entries["recovery"]["replacement_issuer_id"],
                entries["recovery"]["replacement_lineage_id"],
                entries["recovery"]["replacement_epoch"],
                entries["recovery"]["replacement_key_id"],
            ),
        ),
    }
    key, introduced_tuple = introductions[introduction_type]
    entry = deepcopy(entries["claim"])
    entry.pop("signature")
    entry.update(
        {
            "entry_id": f"entry:identity-{introduction_type}-{declared_field}",
            "issuer_id": introduced_tuple[0],
            "lineage_id": introduced_tuple[1],
            "issuer_epoch": introduced_tuple[2],
            "issuer_key_id": introduced_tuple[3],
        }
    )
    entry[declared_field] = {
        "issuer_id": "authority:spoofed",
        "lineage_id": "lineage:spoofed",
        "issuer_epoch": 777,
    }[declared_field]
    signed = generator._sign(entry, key)["signed_entry"]

    entry_validator.validate(signed)
    payload = deepcopy(signed)
    signature = payload.pop("signature")
    public = Ed25519PublicKey.from_public_bytes(
        _b64url(key["public_key_base64url"])
    )
    public.verify(_b64url(signature["value"]), generator._ascii_jcs(payload))
    declared_tuple = (
        signed["issuer_id"],
        signed["lineage_id"],
        signed["issuer_epoch"],
        signed["issuer_key_id"],
    )
    assert declared_tuple != introduced_tuple
    assert _load(PROTOCOL_PATH)["authority_ledger"]["identity_profile"][
        "resolved_tuple_mismatch_result"
    ] == "INVALID"


def test_one_key_introduced_for_conflicting_identity_tuples_is_invalid() -> None:
    profile = _load(PROTOCOL_PATH)["authority_ledger"]["identity_profile"]
    key_id = "sha256:" + "0" * 64
    introduced = {
        ("authority:one", "lineage:one", 0, key_id),
        ("authority:two", "lineage:two", 0, key_id),
    }
    assert len(introduced) == 2
    assert profile["identity_collision_result"] == "INVALID"


def _scope_contains(parent: dict[str, str], child: dict[str, str]) -> bool:
    return all(parent[field] == "*" or parent[field] == child[field] for field in (
        "organization",
        "repository",
        "artifact",
        "action",
    ))


@pytest.mark.parametrize(
    "entry_type",
    ["delegation", "rotation", "revocation", "recovery", "precedence", "claim"],
)
def test_signed_entry_scope_cannot_expand_an_exact_authorizing_grant(
    entry_type: str,
) -> None:
    vectors = _load(VECTOR_PATH)
    generator = _generator_module()
    entry_validator, _ = _validators()
    keys = {item["key_id"]: item for item in vectors["keys"]}
    signed_entry = next(
        item["signed_entry"]
        for item in vectors["vectors"]
        if item["entry_type"] == entry_type
    )
    parent_scope = deepcopy(signed_entry["scope"])
    widened = deepcopy(signed_entry)
    widened.pop("signature")
    widened["scope"]["repository"] = "*"
    key = keys[widened["issuer_key_id"]]
    resigned = generator._sign(widened, key)["signed_entry"]

    entry_validator.validate(resigned)
    payload = deepcopy(resigned)
    signature = payload.pop("signature")
    public = Ed25519PublicKey.from_public_bytes(
        _b64url(key["public_key_base64url"])
    )
    public.verify(_b64url(signature["value"]), generator._ascii_jcs(payload))
    assert not _scope_contains(parent_scope, resigned["scope"])
    assert _load(PROTOCOL_PATH)["authority_ledger"]["scope_profile"][
        "wildcard_expansion_result"
    ] == "INVALID"


def test_wildcard_parent_scope_may_narrow_to_an_exact_child_scope() -> None:
    vectors = _load(VECTOR_PATH)
    child = vectors["example_bundle"]["case_coordinate"]
    parent = deepcopy(child)
    parent["repository"] = "*"
    assert _scope_contains(parent, child)
    assert not _scope_contains(child, parent)


def test_anchor_activation_precedes_equal_timestamp_entry_authorization() -> None:
    protocol = _load(PROTOCOL_PATH)
    profile = protocol["authority_ledger"]["time_profile"]
    vectors = _load(VECTOR_PATH)
    anchor = vectors["example_bundle"]["trust_anchors"][0]
    delegation = next(
        item["signed_entry"]
        for item in vectors["vectors"]
        if item["entry_type"] == "delegation"
    )
    timestamp = _timestamp(delegation["issued_at"])

    assert _timestamp(anchor["not_before"]) == timestamp
    assert _timestamp(anchor["not_before"]) <= timestamp
    assert not (_timestamp(anchor["not_before"]) < timestamp)
    assert profile["timestamp_event_order"][0] == (
        "activate_external_anchors_and_expire_intervals_at_t"
    )
    assert profile["timestamp_event_order"][2] == (
        "authorize_all_entries_with_issued_at_equal_to_t_against_one_frozen_"
        "post_transition_snapshot"
    )
    assert profile["same_timestamp_dependency"].startswith("prohibited;")


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
    assert protocol["authority_ledger"]["reference_vectors"] == (
        "tests/fixtures/authority-ledger.v0.3.vectors.json"
    )


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
    assert recovery["predecessor_entry_id"] == rotation["entry_id"]
    assert recovery["compromised_issuer_id"] == rotation[
        "successor_issuer_id"
    ]
    assert recovery["compromised_lineage_id"] == rotation["lineage_id"]
    assert recovery["replacement_key_id"] == replacement["key_id"]
    assert recovery["replacement_public_key_base64url"] == replacement[
        "public_key_base64url"
    ]
    assert recovery["replacement_lineage_id"] == replacement["lineage_id"]
    assert recovery["replacement_lineage_id"] == recovery[
        "compromised_lineage_id"
    ]
    assert recovery["replacement_epoch"] == rotation["successor_epoch"] + 1
    assert recovery["replacement_permissions"] == sorted(
        set(recovery["replacement_permissions"])
    )
    recovery_anchor = vectors["example_bundle"]["recovery_trust_anchors"][0]
    assert set(recovery["replacement_permissions"]) <= set(
        recovery_anchor["replacement_permissions_ceiling"]
    )
    assert set(recovery["replacement_permissions"]) <= set(
        rotation["successor_permissions"]
    )

    revocation = entries["revocation"]
    boundary = _timestamp(revocation["effective_at"])
    assert _timestamp(revocation["issued_at"]) < _timestamp(
        rotation["not_before"]
    )
    assert _timestamp(rotation["not_before"]) < boundary
    assert _timestamp("2030-05-31T23:59:59Z") < boundary
    assert _timestamp("2030-06-01T00:00:00Z") >= boundary

    precedence = entries["precedence"]
    assert _timestamp(precedence["issued_at"]) >= _timestamp(
        recovery["effective_at"]
    )
    assert precedence["higher_issuer_id"] != precedence["lower_issuer_id"]
    assert precedence["scope"] == vectors["example_bundle"]["case_coordinate"]

    claim = entries["claim"]
    assert _timestamp(claim["issued_at"]) >= _timestamp(
        recovery["effective_at"]
    )

    heads = {
        item["lineage_id"]: item
        for item in vectors["example_bundle"]["lineage_heads"]
    }
    recovery_vector = next(
        item for item in vectors["vectors"] if item["entry_type"] == "recovery"
    )
    assert heads[rotation["lineage_id"]] == {
        "entry_id": recovery["entry_id"],
        "epoch": recovery["replacement_epoch"],
        "lineage_id": rotation["lineage_id"],
        "payload_sha256": recovery_vector["canonical_payload_sha256"],
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


def test_recovery_transition_rejects_lineage_epoch_and_predecessor_mismatch() -> None:
    vectors = _load(VECTOR_PATH)
    protocol = _load(PROTOCOL_PATH)
    entries = {
        item["entry_type"]: item["signed_entry"] for item in vectors["vectors"]
    }
    recovery = entries["recovery"]
    predecessor = entries["rotation"]
    profile = protocol["authority_ledger"]["recovery_profile"]

    def errors(candidate):
        found = []
        if candidate["predecessor_entry_id"] != predecessor["entry_id"]:
            found.append("predecessor")
        if candidate["compromised_issuer_id"] != predecessor[
            "successor_issuer_id"
        ]:
            found.append("issuer")
        if candidate["compromised_lineage_id"] != predecessor["lineage_id"]:
            found.append("compromised_lineage")
        if candidate["replacement_lineage_id"] != candidate[
            "compromised_lineage_id"
        ]:
            found.append("replacement_lineage")
        if candidate["replacement_epoch"] != predecessor["successor_epoch"] + 1:
            found.append("epoch")
        return found

    assert errors(recovery) == []
    for field, invalid_value, expected_error in [
        ("predecessor_entry_id", "entry:unknown", "predecessor"),
        ("compromised_issuer_id", "authority:unknown", "issuer"),
        ("compromised_lineage_id", "lineage:unknown", "compromised_lineage"),
        ("replacement_lineage_id", "lineage:unrelated", "replacement_lineage"),
        ("replacement_epoch", 7, "epoch"),
    ]:
        mutated = deepcopy(recovery)
        mutated[field] = invalid_value
        assert expected_error in errors(mutated)

    assert profile["new_lineage_allowed"] is False
    assert profile["replacement_epoch_rule"] == "predecessor_epoch_plus_one"
    assert profile["parallel_different_replacements"] == "INDETERMINATE"
    assert profile["boundary_precondition_failure"] == (
        "INVALID_if_resolved_mismatch_else_INDETERMINATE"
    )


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


def test_delayed_transitions_authorize_once_and_apply_at_the_boundary() -> None:
    protocol = _load(PROTOCOL_PATH)
    ledger = protocol["authority_ledger"]
    validation = {
        item["id"]: item["rule"] for item in ledger["validation_order"]
    }
    vectors = _load(VECTOR_PATH)
    entries = {
        item["entry_type"]: item["signed_entry"] for item in vectors["vectors"]
    }

    assert ledger["time_profile"]["entry_authorization_time"] == (
        "state_at_issued_at_after_external_anchor_boundaries_and_earlier_issued_"
        "transition_effects_before_same_timestamp_entry_effects"
    )
    assert ledger["time_profile"]["timestamp_event_order"] == [
        "activate_external_anchors_and_expire_intervals_at_t",
        "apply_effects_at_t_of_transitions_with_issued_at_before_t",
        "authorize_all_entries_with_issued_at_equal_to_t_against_one_frozen_"
        "post_transition_snapshot",
        "apply_immediate_effects_at_t_of_entries_authorized_in_the_same_"
        "timestamp_batch",
    ]
    assert ledger["time_profile"]["delayed_transition_application"] == (
        "apply_at_effective_boundary_without_signer_reauthorization"
    )
    assert ledger["time_profile"]["delayed_transition_time_order"] == (
        "issued_at_at_or_before_not_before_at_or_before_effective_boundary"
    )
    assert ledger["time_profile"][
        "boundary_must_be_within_validity_interval"
    ] is True
    assert ledger["revocation_profile"][
        "signer_reauthorized_at_effective_boundary"
    ] is False
    assert "forbid same-timestamp entries" in validation["L8_AUTHORIZE_BATCH"]
    assert "without reauthorizing signers" in validation["L9_BOUNDARIES"]

    revocation = entries["revocation"]
    rotation = entries["rotation"]
    assert revocation["issuer_id"] == rotation["issuer_id"]
    assert _timestamp(revocation["issued_at"]) < _timestamp(
        rotation["not_before"]
    ) < _timestamp(revocation["effective_at"])

    for entry in entries.values():
        assert _timestamp(entry["issued_at"]) <= _timestamp(entry["not_before"])
        if "not_after" in entry:
            assert _timestamp(entry["not_before"]) < _timestamp(
                entry["not_after"]
            )
    for entry_type, boundary_field in {
        "recovery": "effective_at",
        "revocation": "effective_at",
        "rotation": "not_before",
    }.items():
        entry = entries[entry_type]
        boundary = _timestamp(entry[boundary_field])
        assert _timestamp(entry["not_before"]) <= boundary
        assert boundary < _timestamp(entry["not_after"])


def test_revocation_targets_and_same_boundary_order_are_fully_pinned() -> None:
    protocol = _load(PROTOCOL_PATH)
    profile = protocol["authority_ledger"]["revocation_profile"]
    vectors = _load(VECTOR_PATH)
    entries = {
        item["entry_type"]: item["signed_entry"] for item in vectors["vectors"]
    }
    revocation = entries["revocation"]
    delegation = entries["delegation"]

    assert profile["target_record_types"] == [
        "trust_anchor",
        "delegation",
        "rotation",
        "recovery",
    ]
    assert profile["target_introduced_issuer_fields"] == {
        "delegation": "subject_issuer_id",
        "recovery": "replacement_issuer_id",
        "rotation": "successor_issuer_id",
        "trust_anchor": "issuer_id",
    }
    assert revocation["target_entry_id"] == delegation["entry_id"]
    assert revocation["target_issuer_id"] == delegation["subject_issuer_id"]
    assert profile["durability"] == (
        "authorized_revocation_remains_effective_if_issuer_is_later_revoked"
    )
    assert profile["dependency_invalidation"] == (
        "recursive_non_revocation_records_depending_exclusively_on_revoked_"
        "authority_record"
    )
    assert profile["same_boundary_unresolved_dependency"] == "INDETERMINATE"

    revoked_grants = {"anchor:root-a-epoch-0"}
    same_boundary_records = {
        "revocation": {
            "entry_type": "revocation",
            "signer_grant": "anchor:root-a-epoch-0",
        },
        "rotation": {
            "entry_type": "rotation",
            "signer_grant": "anchor:root-a-epoch-0",
        },
        "recovery": {
            "entry_type": "recovery",
            "signer_grant": "anchor:recovery-a-epoch-0",
        },
    }
    unsuppressed = {
        name
        for name, record in same_boundary_records.items()
        if record["entry_type"] == "revocation"
        or record["signer_grant"] not in revoked_grants
    }
    assert unsuppressed == {"revocation", "recovery"}

    validation = {
        item["id"]: item["rule"]
        for item in protocol["authority_ledger"]["validation_order"]
    }
    assert "freeze the pre-boundary heads" in validation["L9_BOUNDARIES"]
    assert "recursively suppress" in validation["L9_BOUNDARIES"]


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
