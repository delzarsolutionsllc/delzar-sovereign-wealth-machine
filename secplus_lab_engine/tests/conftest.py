"""Pytest fixtures shared across the suite."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.loader import load_data, load_policies  # noqa: E402
from utils.terminal_ui import UI  # noqa: E402


@pytest.fixture(scope="session")
def policies():
    return load_policies()


@pytest.fixture
def quiet_ui():
    return UI(plain=True, quiet=True)


@pytest.fixture
def data():
    return load_data
