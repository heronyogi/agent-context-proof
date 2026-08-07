import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_system_manifest_preserves_independence_and_claim_boundary() -> None:
    manifest = json.loads((ROOT / "system.manifest.json").read_text(encoding="utf-8"))

    assert manifest["contract_version"] == "0.1.0"
    assert manifest["system_id"] == "agent-context-integrity"
    assert manifest["repository_role"] == "system-root"
    assert manifest["dependencies"] == {
        "runtime_systems": [],
        "evaluation_systems": [],
    }
    assert manifest["interfaces"]["consumes"] == []
    assert manifest["claim_boundary"]["does_not_claim"]
    assert manifest["ip_boundary"]["excluded"]
