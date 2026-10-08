from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "alerts.sample.json"


@pytest.fixture(scope="session")
def sample_path() -> Path:
    return SAMPLE


@pytest.fixture(scope="session")
def results():
    from wazuh_triage.pipeline import run
    return run(SAMPLE, force_stub=True)
