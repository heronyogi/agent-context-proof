"""Deterministic, model-independent repository context evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

CONTEXT_VERSION = "agent-context-proof-v0.2.0"
TRUST_ROOT_SCHEMA = "agent-context-trust-root-v0.2.0"
CONTRACT_PATHS = ("identity.json", "ontology.json", "ownership.json", "policy.json")
REQUIRED_ENTITY_KINDS = frozenset(
    {"authority", "evidence", "owner", "policy", "release", "requirement", "trust-root"}
)
REQUIRED_RELATIONS = frozenset(
    {
        ("authority", "ATTESTS", "trust-root"),
        ("trust-root", "AUTHORIZES_OWNER", "owner"),
        ("trust-root", "AUTHORIZES_POLICY", "policy"),
        ("policy", "GOVERNS", "release"),
        ("release", "OWNED_BY", "owner"),
        ("release", "RELEASE_REQUIRES", "requirement"),
        ("requirement", "EVIDENCED_BY", "evidence"),
        ("requirement", "BLOCKED_BY", "evidence"),
    }
)
SEMVER = re.compile(r"(?<![0-9])v?([0-9]+\.[0-9]+\.[0-9]+)(?![0-9])")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class RequirementState(StrEnum):
    SATISFIED = "satisfied"
    BLOCKED = "blocked"
    MISSING = "missing"
    INDETERMINATE = "indeterminate"


class Decision(StrEnum):
    READY = "ready"
    HOLD = "hold"
    INDETERMINATE = "indeterminate"


class IdentityStatus(StrEnum):
    EXACT = "exact"
    ALIAS = "alias"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


class Freshness(StrEnum):
    CURRENT = "current"
    DIRTY = "dirty"
    STALE = "stale"
    UNKNOWN = "unknown"


class ContractTrustState(StrEnum):
    VERIFIED = "verified"
    INVALID = "invalid"
    STALE = "stale"
    AMBIGUOUS = "ambiguous"
    MISSING = "missing"


@dataclass(frozen=True)
class IdentityResolution:
    status: IdentityStatus
    references: tuple[str, ...]
    candidates: tuple[str, ...]
    canonical_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "references": list(self.references),
            "candidates": list(self.candidates),
            "canonical_id": self.canonical_id,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    requirement_id: str
    check: str
    state: RequirementState
    source_paths: tuple[str, ...]
    source_digests: tuple[str, ...]
    expected: Any
    observed: Any
    finding: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "requirement_id": self.requirement_id,
            "check": self.check,
            "state": self.state.value,
            "source_paths": list(self.source_paths),
            "source_digests": list(self.source_digests),
            "expected": self.expected,
            "observed": self.observed,
            "finding": self.finding,
        }


@dataclass(frozen=True)
class RequirementEvaluation:
    requirement_id: str
    label: str
    state: RequirementState
    evidence_id: str
    finding: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "label": self.label,
            "state": self.state.value,
            "evidence_id": self.evidence_id,
            "finding": self.finding,
        }


@dataclass(frozen=True)
class ContractTrustReport:
    state: ContractTrustState
    trust_root_id: str
    authority_id: str
    trust_root_digest: str | None
    expected_target: str
    active_policy_id: str
    policy_epoch: int | None
    minimum_policy_epoch: int | None
    authorized_owner_ids: tuple[str, ...]
    verified_contract_paths: tuple[str, ...]
    issues: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "trust_root_id": self.trust_root_id,
            "authority_id": self.authority_id,
            "trust_root_digest": self.trust_root_digest,
            "expected_target": self.expected_target,
            "active_policy_id": self.active_policy_id,
            "policy_epoch": self.policy_epoch,
            "minimum_policy_epoch": self.minimum_policy_epoch,
            "authorized_owner_ids": list(self.authorized_owner_ids),
            "verified_contract_paths": list(self.verified_contract_paths),
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class ContextReport:
    repository_label: str
    target_release: str
    policy_id: str
    owner_id: str
    contract_trust: ContractTrustReport
    identity: IdentityResolution
    decision: Decision
    requirements: tuple[RequirementEvaluation, ...]
    evidence: tuple[EvidenceRecord, ...]
    graph: dict[str, Any]

    @property
    def graph_digest(self) -> str:
        return digest(self.graph)

    @property
    def report_digest(self) -> str:
        return digest(self.to_dict(include_digests=False))

    def to_dict(self, *, include_digests: bool = True) -> dict[str, Any]:
        payload = {
            "context_version": CONTEXT_VERSION,
            "repository_label": self.repository_label,
            "target_release": self.target_release,
            "policy_id": self.policy_id,
            "owner_id": self.owner_id,
            "contract_trust": self.contract_trust.to_dict(),
            "identity": self.identity.to_dict(),
            "decision": self.decision.value,
            "requirements": [item.to_dict() for item in self.requirements],
            "evidence": [item.to_dict() for item in self.evidence],
            "graph": self.graph,
        }
        if include_digests:
            payload["graph_digest"] = self.graph_digest
            payload["report_digest"] = self.report_digest
        return payload


@dataclass(frozen=True)
class ExecutionContext:
    local_commit_sha: str | None
    git_ref: str | None
    worktree_state: str
    dirty_paths: tuple[str, ...]
    ci_provider: str | None
    ci_run_id: str | None
    ci_commit_sha: str | None
    freshness: Freshness

    def to_dict(self) -> dict[str, Any]:
        return {
            "local_commit_sha": self.local_commit_sha,
            "git_ref": self.git_ref,
            "worktree_state": self.worktree_state,
            "dirty_paths": list(self.dirty_paths),
            "ci_provider": self.ci_provider,
            "ci_run_id": self.ci_run_id,
            "ci_commit_sha": self.ci_commit_sha,
            "freshness": self.freshness.value,
        }


@dataclass(frozen=True)
class ContextEnvelope:
    execution_context: ExecutionContext
    report: ContextReport

    @property
    def envelope_digest(self) -> str:
        return digest(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        payload = {
            "context_version": CONTEXT_VERSION,
            "execution_context": self.execution_context.to_dict(),
            "report": self.report.to_dict(),
        }
        if include_digest:
            payload["envelope_digest"] = self.envelope_digest
        return payload


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def digest(value: Any) -> str:
    encoded = canonical_json(value).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _file_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _safe_relative_path(value: str) -> PurePosixPath:
    candidate = PurePosixPath(value)
    if not value.strip() or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"unsafe repository path: {value!r}")
    return candidate


def _resolve(root: Path, value: str) -> Path:
    relative = _safe_relative_path(value)
    target = (root / relative).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError("repository evidence path escapes the repository root")
    return target


def _select(value: Any, dotted: str) -> Any:
    current = value
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(dotted)
        current = current[part]
    return current


def load_identity(contract_root: str | Path) -> dict[str, Any]:
    return _load_json(Path(contract_root) / "identity.json")


def load_policy(contract_root: str | Path) -> dict[str, Any]:
    return _load_json(Path(contract_root) / "policy.json")


def load_ownership(contract_root: str | Path) -> dict[str, Any]:
    return _load_json(Path(contract_root) / "ownership.json")


def load_trust_root(contract_root: str | Path) -> dict[str, Any]:
    return _load_json(Path(contract_root) / "trust-root.json")


def resolve_release_identity(
    references: tuple[str, ...] | list[str], identity: Mapping[str, Any]
) -> IdentityResolution:
    normalized = tuple(sorted(set(references)))
    canonical_name = str(identity["canonical_name"]).casefold()
    aliases = tuple(str(item).casefold() for item in identity["aliases"])
    candidates: set[str] = set()
    for reference in normalized:
        lowered = reference.casefold().strip()
        match = SEMVER.search(lowered)
        if match is None:
            continue
        remainder = SEMVER.sub("", lowered).strip(" -_:/")
        if remainder and not any(alias in remainder for alias in aliases):
            continue
        candidates.add(f"release:{canonical_name}:{match.group(1)}")
    ordered = tuple(sorted(candidates))
    if not ordered:
        status = IdentityStatus.UNRESOLVED
        canonical_id = None
    elif len(ordered) > 1:
        status = IdentityStatus.AMBIGUOUS
        canonical_id = None
    else:
        status = IdentityStatus.EXACT if len(normalized) == 1 else IdentityStatus.ALIAS
        canonical_id = ordered[0]
    return IdentityResolution(status, normalized, ordered, canonical_id)


def trusted_reference_matches(reference: str, trust_root: Mapping[str, Any]) -> bool:
    """Match a requested alias against coordinates anchored in the trust root."""

    target = trust_root.get("target")
    if not isinstance(target, Mapping):
        return False
    allowed = {
        str(item).casefold().strip() for item in target.get("references", [])
    }
    allowed.add(str(target.get("canonical_id", "")).casefold().strip())
    return reference.casefold().strip() in allowed


def _unresolved_identity(references: tuple[str, ...] = ()) -> IdentityResolution:
    return IdentityResolution(
        status=IdentityStatus.UNRESOLVED,
        references=references,
        candidates=(),
        canonical_id=None,
    )


def _verify_contracts(
    contracts: Path,
) -> tuple[
    ContractTrustReport,
    dict[str, dict[str, Any]],
    IdentityResolution,
    IdentityResolution,
]:
    trust_path = contracts / "trust-root.json"
    if not trust_path.is_file():
        return (
            ContractTrustReport(
                state=ContractTrustState.MISSING,
                trust_root_id="<missing>",
                authority_id="<missing>",
                trust_root_digest=None,
                expected_target="<untrusted>",
                active_policy_id="<untrusted>",
                policy_epoch=None,
                minimum_policy_epoch=None,
                authorized_owner_ids=(),
                verified_contract_paths=(),
                issues=("trust root is missing",),
            ),
            {},
            _unresolved_identity(),
            _unresolved_identity(),
        )
    trust_digest = _file_digest(trust_path)
    try:
        root = _load_json(trust_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return (
            ContractTrustReport(
                state=ContractTrustState.INVALID,
                trust_root_id="<invalid>",
                authority_id="<invalid>",
                trust_root_digest=trust_digest,
                expected_target="<untrusted>",
                active_policy_id="<untrusted>",
                policy_epoch=None,
                minimum_policy_epoch=None,
                authorized_owner_ids=(),
                verified_contract_paths=(),
                issues=(f"trust root cannot be parsed: {type(exc).__name__}",),
            ),
            {},
            _unresolved_identity(),
            _unresolved_identity(),
        )

    target = root.get("target") if isinstance(root.get("target"), dict) else {}
    trust_root_id = str(root.get("id", "<invalid>"))
    authority_id = str(root.get("authority_id", "<invalid>"))
    expected_target = str(target.get("canonical_id", "<untrusted>"))
    active_policy_id = str(root.get("active_policy_id", "<untrusted>"))
    raw_minimum_epoch = root.get("minimum_policy_epoch")
    minimum_epoch = raw_minimum_epoch if isinstance(raw_minimum_epoch, int) else None
    raw_owners = root.get("authorized_owner_ids")
    authorized_owners = (
        tuple(sorted(str(item) for item in raw_owners))
        if isinstance(raw_owners, list)
        else ()
    )

    invalid: list[str] = []
    missing: list[str] = []
    stale: list[str] = []
    ambiguous: list[str] = []
    if root.get("schema_version") != TRUST_ROOT_SCHEMA:
        invalid.append("trust root schema version is unsupported")
    if not authority_id.startswith("authority:"):
        invalid.append("trust root authority is invalid")
    if not expected_target.startswith("release:"):
        invalid.append("trust root target is invalid")
    if not active_policy_id or active_policy_id == "<untrusted>":
        invalid.append("trust root active policy is invalid")
    if minimum_epoch is None:
        invalid.append("minimum policy epoch is invalid")
    if not authorized_owners:
        invalid.append("trust root authorizes no owners")

    entries = root.get("contracts")
    expected_digests: dict[str, str] = {}
    if not isinstance(entries, list):
        invalid.append("trust root contract manifest is invalid")
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            invalid.append("trust root contains a malformed contract entry")
            continue
        path = str(entry.get("path", ""))
        expected_digest = str(entry.get("sha256", ""))
        if path in expected_digests:
            invalid.append(f"duplicate contract manifest entry: {path}")
            continue
        if path not in CONTRACT_PATHS:
            invalid.append(f"unrecognized contract manifest path: {path or '<empty>'}")
            continue
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
            invalid.append(f"invalid contract digest: {path}")
            continue
        expected_digests[path] = expected_digest
    undeclared = sorted(set(CONTRACT_PATHS) - set(expected_digests))
    if undeclared:
        invalid.append(f"contract manifest omits: {', '.join(undeclared)}")

    verified: list[str] = []
    for relative in CONTRACT_PATHS:
        if relative not in expected_digests:
            continue
        path = contracts / relative
        if not path.is_file():
            missing.append(f"declared contract is missing: {relative}")
        elif _file_digest(path) != expected_digests[relative]:
            invalid.append(f"contract digest mismatch: {relative}")
        else:
            verified.append(relative)

    documents: dict[str, dict[str, Any]] = {}
    if not invalid and not missing:
        for relative in CONTRACT_PATHS:
            try:
                documents[relative] = _load_json(contracts / relative)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                invalid.append(
                    "authorized contract cannot be parsed: "
                    f"{relative} ({type(exc).__name__})"
                )

    identity = _unresolved_identity()
    owner_identity = _unresolved_identity()
    policy_epoch: int | None = None
    if not invalid and not missing:
        identity_contract = documents["identity.json"]
        ontology = documents["ontology.json"]
        policy = documents["policy.json"]
        ownership = documents["ownership.json"]
        required_identity = {"canonical_name", "aliases"}
        required_ontology = {"id", "allowed_relations", "entity_kinds"}
        required_policy = {
            "id",
            "epoch",
            "label",
            "requirements",
            "target_label",
            "target_references",
        }
        required_ownership = {
            "granted_by",
            "owner_id",
            "owner_label",
            "target_references",
        }
        if not required_identity.issubset(identity_contract):
            invalid.append("identity contract schema is incomplete")
        if not required_ontology.issubset(ontology):
            invalid.append("ontology contract schema is incomplete")
        if not required_policy.issubset(policy):
            invalid.append("policy contract schema is incomplete")
        if not required_ownership.issubset(ownership):
            invalid.append("ownership contract schema is incomplete")
        if not isinstance(policy.get("requirements"), list) or not policy.get(
            "requirements"
        ):
            invalid.append("policy requirements are invalid")
        elif any(
            not isinstance(rule, dict)
            or not {"check", "id", "label", "source"}.issubset(rule)
            for rule in policy["requirements"]
        ):
            invalid.append("policy contains a malformed requirement")
        elif len({str(rule["id"]) for rule in policy["requirements"]}) != len(
            policy["requirements"]
        ):
            invalid.append("policy contains duplicate requirement identifiers")
        allowed_relations = ontology.get("allowed_relations")
        if not isinstance(allowed_relations, list):
            invalid.append("ontology relations are invalid")
        else:
            required_relation_fields = {"source_kind", "relation", "target_kind"}
            if any(
                not isinstance(item, dict)
                or not required_relation_fields.issubset(item)
                for item in allowed_relations
            ):
                invalid.append("ontology contains a malformed relation")
            else:
                declared_relations = {
                    (
                        str(item["source_kind"]),
                        str(item["relation"]),
                        str(item["target_kind"]),
                    )
                    for item in allowed_relations
                }
                if not REQUIRED_RELATIONS.issubset(declared_relations):
                    invalid.append("ontology omits a required relation")
        entity_kinds = ontology.get("entity_kinds")
        if not isinstance(entity_kinds, list) or not REQUIRED_ENTITY_KINDS.issubset(
            str(item) for item in entity_kinds
        ):
            invalid.append("ontology omits a required entity kind")
        if str(policy.get("id")) != active_policy_id:
            invalid.append("policy does not match the active policy authorization")
        raw_epoch = policy.get("epoch")
        if isinstance(raw_epoch, int):
            policy_epoch = raw_epoch
            if minimum_epoch is not None and policy_epoch < minimum_epoch:
                stale.append(
                    f"policy epoch {policy_epoch} is below required epoch "
                    f"{minimum_epoch}"
                )
        else:
            invalid.append("policy epoch is invalid")
        owner_id = str(ownership.get("owner_id", ""))
        if owner_id not in authorized_owners:
            invalid.append(f"owner is not authorized: {owner_id or '<missing>'}")
        if str(ownership.get("granted_by", "")) != authority_id:
            invalid.append("ownership grant does not come from the trusted authority")
        try:
            identity = resolve_release_identity(
                tuple(str(item) for item in policy["target_references"]),
                identity_contract,
            )
            owner_identity = resolve_release_identity(
                tuple(str(item) for item in ownership["target_references"]),
                identity_contract,
            )
        except (KeyError, TypeError, ValueError):
            invalid.append("release identity contracts are malformed")
        else:
            if identity.status == IdentityStatus.AMBIGUOUS:
                ambiguous.append("policy target identity is ambiguous")
            elif identity.canonical_id != expected_target:
                invalid.append("policy target does not match the trusted target")
            if owner_identity.status == IdentityStatus.AMBIGUOUS:
                ambiguous.append("ownership target identity is ambiguous")
            elif owner_identity.canonical_id != expected_target:
                invalid.append("ownership target does not match the trusted target")
        references = target.get("references", [])
        if not isinstance(references, list) or not references:
            invalid.append("trust root target references are invalid")
        else:
            for reference in references:
                resolved = resolve_release_identity(
                    (str(reference),), identity_contract
                )
                if resolved.canonical_id != expected_target:
                    invalid.append(
                        f"trusted target reference does not resolve: {reference}"
                    )

    if invalid:
        state = ContractTrustState.INVALID
        issues = invalid + missing + stale + ambiguous
    elif missing:
        state = ContractTrustState.MISSING
        issues = missing
    elif stale:
        state = ContractTrustState.STALE
        issues = stale + ambiguous
    elif ambiguous:
        state = ContractTrustState.AMBIGUOUS
        issues = ambiguous
    else:
        state = ContractTrustState.VERIFIED
        issues = []
    return (
        ContractTrustReport(
            state=state,
            trust_root_id=trust_root_id,
            authority_id=authority_id,
            trust_root_digest=trust_digest,
            expected_target=expected_target,
            active_policy_id=active_policy_id,
            policy_epoch=policy_epoch,
            minimum_policy_epoch=minimum_epoch,
            authorized_owner_ids=authorized_owners,
            verified_contract_paths=tuple(verified),
            issues=tuple(issues),
        ),
        documents,
        identity,
        owner_identity,
    )


def _evaluate_requirement(root: Path, rule: Mapping[str, Any]) -> EvidenceRecord:
    requirement_id = str(rule["id"])
    check = str(rule["check"])
    source = str(rule["source"])
    evidence_id = f"evidence:{requirement_id.split(':', 1)[-1]}"
    sources: tuple[str, ...] = ()
    source_digests: tuple[str, ...] = ()
    observed: Any = "<missing>"
    expected: Any = rule.get("expected", "path exists")
    state = RequirementState.INDETERMINATE
    finding = "requirement could not be evaluated"
    try:
        path = _resolve(root, source)
        if not path.exists():
            state = RequirementState.MISSING
            finding = "required governed evidence is absent"
        elif not path.is_file():
            state = RequirementState.BLOCKED
            observed = "not a file"
            finding = "governed evidence path is not a file"
        else:
            sources = (source,)
            source_digests = (_file_digest(path),)
            if check == "path_exists":
                observed = "present"
                state = RequirementState.SATISFIED
                finding = "required artifact exists"
            elif check == "toml_field_equals":
                document = tomllib.loads(path.read_text(encoding="utf-8"))
                observed = str(_select(document, str(rule["selector"])))
                state = (
                    RequirementState.SATISFIED
                    if observed == str(expected)
                    else RequirementState.BLOCKED
                )
                finding = (
                    "package identity matches the governed release"
                    if state == RequirementState.SATISFIED
                    else "package identity conflicts with the governed release"
                )
            elif check == "json_fields_equal":
                document = _load_json(path)
                expected_fields = dict(rule["expected_fields"])
                observed_fields: dict[str, str] = {}
                mismatches: list[str] = []
                for selector, expected_value in sorted(expected_fields.items()):
                    try:
                        actual = str(_select(document, selector))
                    except KeyError:
                        actual = "<missing>"
                    observed_fields[selector] = actual
                    if actual != str(expected_value):
                        mismatches.append(selector)
                expected = expected_fields
                observed = observed_fields
                state = (
                    RequirementState.SATISFIED
                    if not mismatches
                    else RequirementState.BLOCKED
                )
                finding = (
                    "structured evidence matches the governed coordinates"
                    if not mismatches
                    else "structured evidence conflicts with the governed coordinates"
                )
            elif check == "json_array_contains":
                document = _load_json(path)
                values = _select(document, str(rule["selector"]))
                if not isinstance(values, list):
                    raise ValueError("selected JSON coordinate is not an array")
                field = str(rule["match_field"])
                matched = any(
                    isinstance(item, dict) and str(item.get(field)) == str(expected)
                    for item in values
                )
                observed = "present" if matched else "absent"
                state = (
                    RequirementState.SATISFIED
                    if matched
                    else RequirementState.BLOCKED
                )
                finding = (
                    "release manifest registers the governed artifact"
                    if matched
                    else "release manifest omits the governed artifact"
                )
            elif check == "text_contains_all":
                text = path.read_text(encoding="utf-8")
                expected_values = tuple(str(item) for item in rule["expected_values"])
                missing = tuple(item for item in expected_values if item not in text)
                expected = list(expected_values)
                observed = {"missing": list(missing)}
                state = (
                    RequirementState.SATISFIED
                    if not missing
                    else RequirementState.BLOCKED
                )
                finding = (
                    "all governed textual witnesses are present"
                    if not missing
                    else "governed textual witnesses are incomplete"
                )
            else:
                raise ValueError(f"unsupported requirement check: {check}")
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        state = RequirementState.INDETERMINATE
        finding = f"evidence evaluation failed closed: {type(exc).__name__}"
    return EvidenceRecord(
        evidence_id=evidence_id,
        requirement_id=requirement_id,
        check=check,
        state=state,
        source_paths=sources,
        source_digests=source_digests,
        expected=expected,
        observed=observed,
        finding=finding,
    )


def _validate_graph(graph: Mapping[str, Any], ontology: Mapping[str, Any]) -> None:
    node_kinds = {node["id"]: node["kind"] for node in graph["nodes"]}
    allowed = {
        (item["source_kind"], item["relation"], item["target_kind"])
        for item in ontology["allowed_relations"]
    }
    for edge in graph["edges"]:
        triple = (
            node_kinds[edge["source"]],
            edge["relation"],
            node_kinds[edge["target"]],
        )
        if triple not in allowed:
            raise ValueError(f"ontology rejects relationship: {triple}")


def evaluate_context(
    repository_root: str | Path,
    *,
    contract_root: str | Path,
    repository_label: str = "orion-demo",
) -> ContextReport:
    root = Path(repository_root).resolve()
    contracts = Path(contract_root).resolve()
    trust, documents, identity, owner_identity = _verify_contracts(contracts)
    if trust.state != ContractTrustState.VERIFIED:
        ownership = documents.get("ownership.json", {})
        graph = {
            "ontology_id": documents.get("ontology.json", {}).get(
                "id", "<untrusted>"
            ),
            "nodes": [],
            "edges": [],
            "decision_paths": [],
        }
        return ContextReport(
            repository_label=repository_label,
            target_release=trust.expected_target,
            policy_id=trust.active_policy_id,
            owner_id=str(ownership.get("owner_id", "<untrusted>")),
            contract_trust=trust,
            identity=identity,
            decision=Decision.INDETERMINATE,
            requirements=(),
            evidence=(),
            graph=graph,
        )

    policy = documents["policy.json"]
    ownership = documents["ownership.json"]
    ontology = documents["ontology.json"]
    if identity.canonical_id is None or owner_identity.canonical_id is None:
        raise AssertionError("verified contracts must resolve one release identity")

    evidence = tuple(
        sorted(
            (_evaluate_requirement(root, rule) for rule in policy["requirements"]),
            key=lambda item: item.evidence_id,
        )
    )
    labels = {str(rule["id"]): str(rule["label"]) for rule in policy["requirements"]}
    requirements = tuple(
        sorted(
            (
                RequirementEvaluation(
                    requirement_id=item.requirement_id,
                    label=labels[item.requirement_id],
                    state=item.state,
                    evidence_id=item.evidence_id,
                    finding=item.finding,
                )
                for item in evidence
            ),
            key=lambda item: item.requirement_id,
        )
    )
    states = {item.state for item in requirements}
    if requirements and states == {RequirementState.SATISFIED}:
        decision = Decision.READY
    elif states & {RequirementState.BLOCKED, RequirementState.MISSING}:
        decision = Decision.HOLD
    else:
        decision = Decision.INDETERMINATE

    release_id = identity.canonical_id
    policy_id = f"policy:{policy['id']}"
    owner_id = str(ownership["owner_id"])
    nodes = [
        {
            "id": trust.authority_id,
            "kind": "authority",
            "label": "Orion Governance Board",
        },
        {"id": owner_id, "kind": "owner", "label": ownership["owner_label"]},
        {"id": policy_id, "kind": "policy", "label": policy["label"]},
        {"id": release_id, "kind": "release", "label": policy["target_label"]},
        {
            "id": trust.trust_root_id,
            "kind": "trust-root",
            "label": "Orion release governance trust root",
        },
    ]
    edges = [
        {
            "id": "edge:authority-attests-trust-root",
            "relation": "ATTESTS",
            "source": trust.authority_id,
            "target": trust.trust_root_id,
        },
        {
            "id": "edge:trust-root-authorizes-owner",
            "relation": "AUTHORIZES_OWNER",
            "source": trust.trust_root_id,
            "target": owner_id,
        },
        {
            "id": "edge:trust-root-authorizes-policy",
            "relation": "AUTHORIZES_POLICY",
            "source": trust.trust_root_id,
            "target": policy_id,
        },
        {
            "id": "edge:policy-governs-release",
            "relation": "GOVERNS",
            "source": policy_id,
            "target": release_id,
        },
        {
            "id": "edge:release-owned-by",
            "relation": "OWNED_BY",
            "source": release_id,
            "target": owner_id,
        },
    ]
    decision_paths = []
    for item in requirements:
        nodes.extend(
            [
                {"id": item.requirement_id, "kind": "requirement", "label": item.label},
                {"id": item.evidence_id, "kind": "evidence", "label": item.finding},
            ]
        )
        suffix = item.requirement_id.split(":", 1)[-1]
        relation = (
            "EVIDENCED_BY"
            if item.state == RequirementState.SATISFIED
            else "BLOCKED_BY"
        )
        required_edge = f"edge:release-requires:{suffix}"
        evidence_edge = f"edge:requirement-{relation.casefold()}:{suffix}"
        edges.extend(
            [
                {
                    "id": required_edge,
                    "relation": "RELEASE_REQUIRES",
                    "source": release_id,
                    "target": item.requirement_id,
                },
                {
                    "id": evidence_edge,
                    "relation": relation,
                    "source": item.requirement_id,
                    "target": item.evidence_id,
                },
            ]
        )
        decision_paths.append(
            {
                "requirement_id": item.requirement_id,
                "state": item.state.value,
                "node_ids": [release_id, item.requirement_id, item.evidence_id],
                "edge_ids": [required_edge, evidence_edge],
            }
        )
    graph = {
        "ontology_id": ontology["id"],
        "nodes": sorted(nodes, key=lambda item: item["id"]),
        "edges": sorted(edges, key=lambda item: item["id"]),
        "decision_paths": sorted(
            decision_paths, key=lambda item: item["requirement_id"]
        ),
    }
    _validate_graph(graph, ontology)
    return ContextReport(
        repository_label=repository_label,
        target_release=release_id,
        policy_id=str(policy["id"]),
        owner_id=owner_id,
        contract_trust=trust,
        identity=identity,
        decision=decision,
        requirements=requirements,
        evidence=evidence,
        graph=graph,
    )


def _git_output(root: Path, *arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def observe_execution_context(
    repository_root: str | Path, *, environ: Mapping[str, str] | None = None
) -> ExecutionContext:
    root = Path(repository_root).resolve()
    environment = os.environ if environ is None else environ
    raw_commit = _git_output(root, "rev-parse", "HEAD")
    local_commit = (
        raw_commit.casefold()
        if raw_commit is not None and GIT_SHA.fullmatch(raw_commit.casefold())
        else None
    )
    git_ref = _git_output(root, "symbolic-ref", "--short", "-q", "HEAD")
    raw_status = _git_output(
        root, "status", "--porcelain=v1", "--untracked-files=normal"
    )
    if raw_status is None:
        worktree_state = "unknown"
        dirty_paths: tuple[str, ...] = ()
    else:
        dirty_paths = tuple(
            sorted(
                {
                    line[3:].strip()
                    for line in raw_status.splitlines()
                    if len(line) >= 4 and line[3:].strip()
                }
            )
        )
        worktree_state = "dirty" if dirty_paths else "clean"

    github_active = environment.get("GITHUB_ACTIONS", "").casefold() == "true"
    ci_provider = "github" if github_active else None
    ci_run_id = environment.get("GITHUB_RUN_ID") if github_active else None
    raw_ci_commit = environment.get("GITHUB_SHA", "").casefold()
    ci_commit = (
        raw_ci_commit
        if github_active and GIT_SHA.fullmatch(raw_ci_commit)
        else None
    )
    if local_commit and ci_commit and local_commit != ci_commit:
        freshness = Freshness.STALE
    elif worktree_state == "dirty":
        freshness = Freshness.DIRTY
    elif local_commit and worktree_state == "clean" and (
        ci_provider is None or ci_commit == local_commit
    ):
        freshness = Freshness.CURRENT
    else:
        freshness = Freshness.UNKNOWN
    return ExecutionContext(
        local_commit_sha=local_commit,
        git_ref=git_ref,
        worktree_state=worktree_state,
        dirty_paths=dirty_paths,
        ci_provider=ci_provider,
        ci_run_id=ci_run_id,
        ci_commit_sha=ci_commit,
        freshness=freshness,
    )


def evaluate_context_envelope(
    repository_root: str | Path,
    *,
    contract_root: str | Path,
    repository_label: str = "orion-demo",
    environ: Mapping[str, str] | None = None,
) -> ContextEnvelope:
    execution = observe_execution_context(repository_root, environ=environ)
    report = evaluate_context(
        repository_root,
        contract_root=contract_root,
        repository_label=repository_label,
    )
    return ContextEnvelope(execution_context=execution, report=report)
