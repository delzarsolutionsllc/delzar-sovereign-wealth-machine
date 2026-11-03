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

import webapi  # noqa: E402
from labs import LABS  # noqa: E402
from utils.loader import load_policies  # noqa: E402
from utils.scenario_generator import GENERATORS  # noqa: E402


def build(variants: int = 12, seed_base: int = 1000) -> dict:
    policies = load_policies()
    bundle = {"version": 1, "catalog": webapi.catalog(policies), "labs": {}}
    for n in LABS:
        entry = {"sample": {"run": webapi.run(policies, n)["text"],
                            "questions": webapi.challenge(policies, n)["questions"]},
                 "variants": []}
        if n in GENERATORS:
            for k in range(variants):
                seed = seed_base + n * 100 + k
                entry["variants"].append({"seed": seed,
                                          "run": webapi.run(policies, n, True, seed)["text"],
                                          "questions": webapi.challenge(policies, n, True, seed)["questions"]})
        bundle["labs"][str(n)] = entry
    return bundle


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--variants", type=int, default=12)
    ap.add_argument("--out", default=str(ROOT / "web" / "course_data.json"))
    args = ap.parse_args(argv)
    bundle = build(args.variants)
    Path(args.out).write_text(json.dumps(bundle, separators=(",", ":")), encoding="utf-8")
    nq = sum(len(l["sample"]["questions"]) + sum(len(v["questions"]) for v in l["variants"]) for l in bundle["labs"].values())
    print(f"wrote {args.out}: {len(bundle['labs'])} labs, {nq} questions, {Path(args.out).stat().st_size / 1e6:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
