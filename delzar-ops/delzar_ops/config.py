"""Configuration: paths and regulatory thresholds.

All regulatory values live in regulatory.json with a citation and a
last_verified date. Nothing else in the codebase may hard-code them.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

_REG_PATH = Path(__file__).parent / "regulatory.json"


def data_dir() -> Path:
    """Where the database and generated PDFs live. Override with DELZAR_HOME."""
    d = Path(os.environ.get("DELZAR_HOME", Path.home() / ".delzar"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path() -> Path:
    return Path(os.environ.get("DELZAR_DB", data_dir() / "delzar.db"))


def output_dir() -> Path:
    d = data_dir() / "output"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass(frozen=True)
class Threshold:
    key: str
    value: float
    unit: str
    citation: str
    note: str


class Regulatory:
    """Loads regulatory.json once; exposes thresholds by attribute."""

    def __init__(self, path: Path = _REG_PATH):
        raw = json.loads(path.read_text())
        self.last_verified: str = raw["last_verified"]
        self.policy_notes: dict[str, str] = raw.get("policy_notes", {})
        self._thresholds: dict[str, Threshold] = {
            k: Threshold(key=k, **v)
            for k, v in raw["thresholds"].items()
            if not k.startswith("_")
        }

    def get(self, key: str) -> Threshold:
        return self._thresholds[key]

    def value(self, key: str) -> float:
        return self._thresholds[key].value

    def all(self) -> dict[str, Threshold]:
        return dict(self._thresholds)


_reg: Regulatory | None = None


def reg() -> Regulatory:
    global _reg
    if _reg is None:
        _reg = Regulatory()
    return _reg
