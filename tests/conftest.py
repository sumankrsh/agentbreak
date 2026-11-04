from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "src" / "agentbreak" / "scenarios"
EXAMPLES = ROOT / "examples"


@pytest.fixture
def root() -> Path:
    return ROOT
