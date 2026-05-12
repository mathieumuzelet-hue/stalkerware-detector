from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_text():
    """Load a fixture file as text."""
    def _load(relative: str) -> str:
        return (FIXTURES / relative).read_text(encoding="utf-8")
    return _load


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
