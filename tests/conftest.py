from __future__ import annotations

import shutil
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def complete_repository(tmp_path: Path) -> Path:
    target = tmp_path / "repository"
    shutil.copytree(PROJECT_ROOT / "demo" / "repository", target)
    return target
