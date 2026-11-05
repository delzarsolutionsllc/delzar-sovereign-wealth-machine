"""Locate and load the engine's JSON config and sample data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
DEFAULT_POLICY_PATH = CONFIG_DIR / "default_policies.json"
POLICY_FRAGMENTS_DIR = CONFIG_DIR / "policies"


def load_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_policies(path: str | Path | None = None) -> dict:
    """Load the policy file (defaults to ``config/default_policies.json``).

    Labs added later keep their policy in ``config/policies/<name>.json`` (one top-level
    section per file); a section is merged in only when the main file does not define it,
    so a custom policy file can still override any lab."""
    pol = load_json(path or DEFAULT_POLICY_PATH)
    for f in sorted(POLICY_FRAGMENTS_DIR.glob("*.json")):
        for k, v in load_json(f).items():
            pol.setdefault(k, v)
    return pol


def load_data(name: str, data_dir: str | Path | None = None) -> Any:
    """Load ``data/<name>`` (e.g. ``sample_logs.json``)."""
    return load_json(Path(data_dir or DATA_DIR) / name)
