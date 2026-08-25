#!/usr/bin/env python3
"""Generate public, test-only synthetic v0.3 authority-ledger vectors."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tests" / "fixtures" / "authority-ledger.v0.3.vectors.json"
SCHEMA_VERSION = "agent-context-proof-authority-entry-v0.3.2"
VECTOR_VERSION = "agent-context-proof-authority-vectors-v0.3.3"
SCOPE = {
    "action": "release",
    "artifact": "release:orion:1.0.0",
    "organization": "org:orion",
    "repository": "repo:orion-service",
}
ROOT_PERMISSIONS = [
    "claim",
    "delegate",
    "revoke",
    "rotate",
    "set_precedence",
]


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _ascii_jcs(value: object) -> bytes:
    """Return JCS bytes for the deliberately ASCII/integer-only vectors."""

    def assert_profile(item: object) -> None:
        if isinstance(item, str):
            item.encode("ascii")
        elif isinstance(item, bool) or item is None:
            return
        elif isinstance(item, int):
            if not -(2**53) + 1 <= item <= 2**53 - 1:
                raise ValueError("vector integer exceeds the I-JSON safe range")
        elif isinstance(item, list):
            for child in item:
                assert_profile(child)
        elif isinstance(item, dict):
            for key, child in item.items():
                key.encode("ascii")
                assert_profile(child)
        else:
            raise TypeError("vectors may contain only ASCII strings and safe integers")

    assert_profile(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _key(name: str, seed_start: int, issuer_id: str, lineage_id: str) -> dict[str, str]:
    seed = bytes(range(seed_start, seed_start + 32))
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "issuer_id": issuer_id,
        "key_id": f"sha256:{hashlib.sha256(public).hexdigest()}",
        "lineage_id": lineage_id,
        "name": name,
        "private_seed_base64url_TEST_ONLY": _b64url(seed),
        "public_key_base64url": _b64url(public),
    }


def _base(
    *,
    entry_id: str,
    entry_type: str,
    issuer: dict[str, str],
    issuer_epoch: int,
    issued_at: str = "2030-01-01T00:00:00Z",
    not_before: str = "2030-01-01T00:00:00Z",
    not_after: str = "2031-01-01T00:00:00Z",
) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "entry_type": entry_type,
        "issued_at": issued_at,
        "issuer_epoch": issuer_epoch,
        "issuer_id": issuer["issuer_id"],
        "issuer_key_id": issuer["key_id"],
        "lineage_id": issuer["lineage_id"],
        "not_after": not_after,
        "not_before": not_before,
        "schema_version": SCHEMA_VERSION,
        "scope": deepcopy(SCOPE),
    }


def _sign(entry: dict[str, Any], key: dict[str, str]) -> dict[str, Any]:
    payload = _ascii_jcs(entry)
    padding = "=" * (-len(key["private_seed_base64url_TEST_ONLY"]) % 4)
    seed = base64.urlsafe_b64decode(key["private_seed_base64url_TEST_ONLY"] + padding)
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(payload)
    signed = deepcopy(entry)
    signed["signature"] = {
        "key_id": key["key_id"],
        "value": _b64url(signature),
    }
    return {
        "canonical_payload": payload.decode("utf-8"),
        "canonical_payload_sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "entry_type": entry["entry_type"],
        "signed_entry": signed,
        "vector_id": f"vector:{entry['entry_type']}",
    }


def build_vectors() -> dict[str, Any]:
    root = _key("root", 0, "authority:root-a", "lineage:root-a")
    successor = _key(
        "successor",
        32,
        "authority:root-a-successor",
        "lineage:root-a",
    )
    recovery = _key(
        "recovery",
        64,
        "authority:recovery-a",
        "lineage:recovery-a",
    )
    delegate = _key(
        "delegate",
        96,
        "authority:release-council",
        "lineage:release-council",
    )
    recovered = _key(
        "recovered",
        128,
        "authority:root-a-recovered",
        "lineage:root-a",
    )
    keys = [root, successor, recovery, delegate, recovered]

    delegation = _base(
        entry_id="entry:delegation-release-council",
        entry_type="delegation",
        issuer=root,
        issuer_epoch=0,
    )
    delegation.update(
        {
            "permissions": ["claim"],
            "subject_epoch": 0,
            "subject_issuer_id": delegate["issuer_id"],
            "subject_key_id": delegate["key_id"],
            "subject_lineage_id": delegate["lineage_id"],
            "subject_public_key_base64url": delegate["public_key_base64url"],
        }
    )

    rotation = _base(
        entry_id="entry:rotation-root-a-epoch-1",
        entry_type="rotation",
        issuer=root,
        issuer_epoch=0,
        not_before="2030-03-01T00:00:00Z",
    )
    rotation.update(
        {
            "predecessor_entry_id": "anchor:root-a-epoch-0",
            "successor_epoch": 1,
            "successor_issuer_id": successor["issuer_id"],
            "successor_key_id": successor["key_id"],
            "successor_permissions": ROOT_PERMISSIONS,
            "successor_public_key_base64url": successor["public_key_base64url"],
        }
    )

    revocation = _base(
        entry_id="entry:revoke-release-council",
        entry_type="revocation",
        issuer=root,
        issuer_epoch=0,
    )
    revocation.update(
        {
            "effective_at": "2030-06-01T00:00:00Z",
            "target_entry_id": delegation["entry_id"],
            "target_issuer_id": delegate["issuer_id"],
        }
    )

    recovery_entry = _base(
        entry_id="entry:recovery-root-a",
        entry_type="recovery",
        issuer=recovery,
        issuer_epoch=0,
        issued_at="2030-04-01T00:00:00Z",
        not_before="2030-04-01T00:00:00Z",
    )
    recovery_entry.update(
        {
            "compromised_issuer_id": successor["issuer_id"],
            "compromised_lineage_id": successor["lineage_id"],
            "effective_at": "2030-05-01T00:00:00Z",
            "predecessor_entry_id": rotation["entry_id"],
            "replacement_epoch": 2,
            "replacement_issuer_id": recovered["issuer_id"],
            "replacement_key_id": recovered["key_id"],
            "replacement_lineage_id": recovered["lineage_id"],
            "replacement_permissions": ROOT_PERMISSIONS,
            "replacement_public_key_base64url": recovered["public_key_base64url"],
        }
    )

    precedence = _base(
        entry_id="entry:precedence-recovered-over-council",
        entry_type="precedence",
        issuer=recovered,
        issuer_epoch=2,
        issued_at="2030-05-02T00:00:00Z",
        not_before="2030-05-02T00:00:00Z",
    )
    precedence.update(
        {
            "higher_issuer_id": recovered["issuer_id"],
            "lower_issuer_id": delegate["issuer_id"],
        }
    )

    claim = _base(
        entry_id="entry:claim-release-owner",
        entry_type="claim",
        issuer=recovered,
        issuer_epoch=2,
        issued_at="2030-05-02T00:00:00Z",
        not_before="2030-05-02T00:00:00Z",
    )
    claim.update(
        {
            "claim_name": "release_owner",
            "claim_value": "owner:release-council",
        }
    )

    vectors = [
        _sign(delegation, root),
        _sign(rotation, root),
        _sign(revocation, root),
        _sign(recovery_entry, recovery),
        _sign(precedence, recovered),
        _sign(claim, recovered),
    ]
    delayed_delegation = deepcopy(delegation)
    delayed_delegation["entry_id"] = "entry:delayed-delegation-invalid"
    delayed_delegation["not_before"] = "2030-02-01T00:00:00Z"
    dependent_claim = _base(
        entry_id="entry:premature-dependent-claim",
        entry_type="claim",
        issuer=delegate,
        issuer_epoch=0,
        issued_at="2030-01-15T00:00:00Z",
        not_before="2030-01-15T00:00:00Z",
    )
    dependent_claim.update(
        {
            "claim_name": "release_owner",
            "claim_value": "owner:premature-delegate",
        }
    )
    delayed_delegation_scenario = {
        "dependent_claim": _sign(dependent_claim, delegate),
        "expected_authority_status": "INVALID",
        "expected_reason_code": "TRUST_OR_TIME_UNSATISFIED",
        "invalid_introduction": _sign(delayed_delegation, root),
        "rule": "non_transition_issued_at_must_equal_not_before",
        "scenario_id": "time:delayed-delegation-does-not-authorize-premature-claim",
    }
    return {
        "adversarial_time_scenarios": [delayed_delegation_scenario],
        "example_bundle": {
            "case_coordinate": deepcopy(SCOPE),
            "entries": [item["signed_entry"] for item in vectors],
            "lineage_heads": [
                {
                    "entry_id": recovery_entry["entry_id"],
                    "epoch": 2,
                    "lineage_id": root["lineage_id"],
                    "payload_sha256": vectors[3]["canonical_payload_sha256"],
                },
                {
                    "entry_id": delegation["entry_id"],
                    "epoch": 0,
                    "lineage_id": delegate["lineage_id"],
                    "payload_sha256": vectors[0]["canonical_payload_sha256"],
                },
            ],
            "recovery_trust_anchors": [
                {
                    "anchor_id": "anchor:recovery-a-epoch-0",
                    "epoch": 0,
                    "issuer_id": recovery["issuer_id"],
                    "key_id": recovery["key_id"],
                    "lineage_id": recovery["lineage_id"],
                    "not_after": "2031-01-01T00:00:00Z",
                    "not_before": "2030-01-01T00:00:00Z",
                    "permissions": ["recover"],
                    "public_key_base64url": recovery["public_key_base64url"],
                    "replacement_permissions_ceiling": ROOT_PERMISSIONS,
                    "scope": deepcopy(SCOPE),
                }
            ],
            "schema_version": "agent-context-proof-authority-bundle-v0.3.3",
            "trust_anchors": [
                {
                    "anchor_id": "anchor:root-a-epoch-0",
                    "epoch": 0,
                    "issuer_id": root["issuer_id"],
                    "key_id": root["key_id"],
                    "lineage_id": root["lineage_id"],
                    "not_after": "2031-01-01T00:00:00Z",
                    "not_before": "2030-01-01T00:00:00Z",
                    "permissions": ROOT_PERMISSIONS,
                    "public_key_base64url": root["public_key_base64url"],
                    "scope": deepcopy(SCOPE),
                }
            ],
            "validation_time": "2030-07-01T00:00:00Z",
        },
        "keys": keys,
        "profile": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785_JCS",
            "note": (
                "Private seeds are public, synthetic test material and MUST NOT "
                "be used outside conformance tests."
            ),
            "signature_encoding": "base64url_no_padding",
        },
        "schema_version": VECTOR_VERSION,
        "vectors": vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build_vectors(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"authority vectors are stale: run {Path(__file__).name}")
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
