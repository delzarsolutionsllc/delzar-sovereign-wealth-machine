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
    pol = load_policies()
    # TEMPORARY (lab build): merge policy fragments listed in SECPLUS_POLICY_FRAGMENTS (os.pathsep-separated)
    import json, os
    for f in filter(None, os.environ.get("SECPLUS_POLICY_FRAGMENTS", "").split(os.pathsep)):
        pol.update(json.loads(Path(f).read_text()))
    return pol


@pytest.fixture
def quiet_ui():
    return UI(plain=True, quiet=True)


@pytest.fixture
def data():
    return load_data
