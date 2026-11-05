#!/usr/bin/env python3
"""
Build web/course_data.json: the pre-computed course used by the hosted
(Python-free) version of the web app.

For every lab it stores the lesson, the sample scenario's report and its
challenge questions; for labs with a random generator it also stores
``--variants`` generated scenarios (report + questions) so "New random
scenario" and the practice exam still vary. Everything comes from the same
engine and webapi functions the local app calls live.

    python tools/build_web_bundle.py               # 12 variants per generator lab
    python tools/build_web_bundle.py --variants 5 --out /tmp/course_data.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def _early_course(argv) -> None:
    """--course CODE builds that course's bundle (the engine reads the course at import)."""
    import os
    for i, a in enumerate(argv):
        if a == "--course" and i + 1 < len(argv):
            os.environ["DELZAR_COURSE"] = argv[i + 1]


_early_course(sys.argv[1:])

import webapi  # noqa: E402
from labs import LABS  # noqa: E402
from utils.loader import load_policies  # noqa: E402
from utils.scenario_generator import GENERATORS  # noqa: E402


def build(variants: int = 12, seed_base: int = 1000) -> dict:
    policies = load_policies()
    bundle = {"version": 1, "catalog": webapi.catalog(policies), "labs": {}}
    for n in webapi.course_labs():
        entry = {"sample": {"run": webapi.run(policies, n)["text"],
                            "questions": webapi.challenge(policies, n, seed=0)["questions"]},
                 "variants": []}
        if n in GENERATORS:
            for k in range(variants):
                seed = seed_base + n * 100 + k
                entry["variants"].append({"seed": seed,
                                          "run": webapi.run(policies, n, True, seed)["text"],
                                          "questions": webapi.challenge(policies, n, True, seed)["questions"]})
        from utils.portfolio import case_study
        entry["case_study"] = case_study(n, policies)
        bundle["labs"][str(n)] = entry
    from utils.exam_bank import load_bank
    bundle["exam_bank"] = [dict(q) for q in load_bank()]          # every field (id, type-specific keys)
    from utils import glossary
    bundle["glossary"] = list(glossary.entries())                 # the entries, with their playlist video
    bundle["glossary_questions"] = list(glossary.questions().values())
    return bundle


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--variants", type=int, default=12)
    ap.add_argument("--out", default=str(ROOT / "web" / "course_data.json"))
    ap.add_argument("--course", help="course code (default: secplus, or DELZAR_COURSE)")
    args = ap.parse_args(argv)
    bundle = build(args.variants)
    Path(args.out).write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
    nq = sum(len(l["sample"]["questions"]) + sum(len(v["questions"]) for v in l["variants"]) for l in bundle["labs"].values())
    print(f"wrote {args.out}: {len(bundle['labs'])} labs, {nq} questions, {Path(args.out).stat().st_size / 1e6:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
