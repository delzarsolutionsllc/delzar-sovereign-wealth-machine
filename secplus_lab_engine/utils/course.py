"""
Course registry: which certification the engine is serving.

Each course has ``data/courses/<code>/course.json`` (name, vendor, exam code, domains with
weights, objectives, pass mark and scale, exam dates with their source, data folders, which
labs apply and with which objectives). The active course is chosen once per process:

* ``DELZAR_COURSE=sc300`` in the environment, or
* ``python main.py --course sc300 ...`` (main.py sets the variable before importing the engine).

The default is ``secplus`` (CompTIA Security+ SY0-701), whose data stays in its original
folders (``data/exam_bank``, ``data/glossary``) so nothing about it changes.

    from utils import course
    course.code()               # "sc300"
    course.domain_weights()     # {"1": 0.24, ...}
    course.objectives()         # {"1.1": "Configure and manage a Microsoft Entra tenant", ...}
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

from utils.loader import ROOT

COURSES_DIR = ROOT / "data" / "courses"
DEFAULT = "secplus"
ENV = "DELZAR_COURSE"


def available() -> list[str]:
    return sorted(p.parent.name for p in COURSES_DIR.glob("*/course.json"))


@lru_cache(maxsize=None)
def load(code: str) -> dict:
    f = COURSES_DIR / code / "course.json"
    if not f.exists():
        raise ValueError(f"unknown course '{code}' (available: {', '.join(available())})")
    return json.loads(f.read_text(encoding="utf-8"))


def code() -> str:
    return os.environ.get(ENV) or DEFAULT


def active() -> dict:
    return load(code())


def domain_weights(c: dict | None = None) -> dict[str, float]:
    return {d["id"]: d["weight"] for d in (c or active())["domains"]}


def domain_names(c: dict | None = None) -> dict[str, str]:
    return {d["id"]: d["name"] for d in (c or active())["domains"]}


def objectives(c: dict | None = None) -> dict[str, str]:
    return dict((c or active())["objectives"])


def objectives_per_domain(c: dict | None = None) -> dict[str, int]:
    out: dict[str, int] = {}
    for o in objectives(c):
        out[o.split(".")[0]] = out.get(o.split(".")[0], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: int(kv[0])))


def data_dir(kind: str, c: dict | None = None) -> Path:
    """``exam_bank`` or ``glossary`` folder of the course."""
    return ROOT / (c or active())["data"][kind]


def lab_numbers(all_labs, c: dict | None = None) -> list[int]:
    """The labs this course uses. ``"all"`` (Security+) means every lab built for it: a lab module
    may set ``COURSES = ("sc300",)`` to belong to other courses only."""
    c = c or active()
    labs = c.get("labs", "all")
    if labs == "all":
        def mine(n):
            mod = all_labs[n][0] if isinstance(all_labs, dict) and isinstance(all_labs[n], tuple) else None
            return c["code"] in getattr(mod, "COURSES", (c["code"],))
        return sorted(n for n in all_labs if mine(n))
    return sorted(int(n) for n in labs if int(n) in all_labs)


def lab_objectives(n: int, default: list[str], c: dict | None = None) -> list[str]:
    """The course's objective codes for a lab (Security+: the lab's own SY0-701 codes)."""
    labs = (c or active()).get("labs", "all")
    return list(default) if labs == "all" else list(labs.get(str(n), []))


def summary(c: dict | None = None) -> dict:
    """What the web app needs to label itself and offer the course switcher."""
    c = c or active()
    keys = ("code", "name", "short", "vendor", "exam_code", "exam_name", "aligned", "notice", "pass_scaled", "scale",
            "exam_questions", "exam_minutes", "pass_label")
    return {**{k: c.get(k) for k in keys}, "courses": [{k: load(x).get(k) for k in ("code", "name", "short")} for x in available()]}
