"""Locate and load the engine's JSON config and sample data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
DEFAULT_POLICY_PATH = CONFIG_DIR / "default_policies.json"


def load_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_policies(path: str | Path | None = None) -> dict:
    """Load the policy file (defaults to ``config/default_policies.json``)."""
    return load_json(path or DEFAULT_POLICY_PATH)


def load_data(name: str, data_dir: str | Path | None = None) -> Any:
    """Load ``data/<name>`` (e.g. ``sample_logs.json``)."""
    return load_json(Path(data_dir or DATA_DIR) / name)
