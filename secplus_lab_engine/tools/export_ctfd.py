#!/usr/bin/env python3
"""
Export the course as a CTFd challenge set (a self-hosted scoreboard / "CTF").

Every challenge question becomes a CTFd challenge, categorised by exam domain
(``D1 General Security Concepts`` ... ``D5 Security Program Management``) and
tagged with its objective and lab. Two outputs, same challenges:

* ``dist/ctfd/challenges.csv`` - import in the CTFd admin panel:
  Admin Panel -> Config -> Backup -> Import CSV -> type "Challenges".
* ``dist/ctfd/challenges/<slug>/challenge.yml`` - for ctfcli
  (``pip install ctfcli``), which can also re-sync challenges after an update.

How a challenge plays: the description shows the scenario and lettered
choices; the player submits the letter (``B``) or the answer text, case does
not matter. A free hint points back to the lab's lesson and Professor Messer's video for
the objective; a paid hint (default
25 points) reveals the engine's explanation.

CTFd itself is free and open source (Apache-2.0, https://github.com/CTFd/CTFd);
run it on your own machine, e.g. ``docker run -p 8000:8000 ctfd/ctfd``.
Only standard library here, so no extra install is needed.

    python tools/export_ctfd.py                     # sample-scenario questions (~300)
    python tools/export_ctfd.py --variants 3        # + generated variants
    python tools/export_ctfd.py --points 100 --hint-cost 25 --attempts 2
    python tools/export_ctfd.py --mc-plugin         # hosted CTFd / paid multiple-choice plugin
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs import LABS  # noqa: E402
from tools.export_anki import OBJECTIVE_NAMES, collect, question_key  # noqa: E402
from utils import videos  # noqa: E402
from utils.exam import DOMAIN_NAMES  # noqa: E402

CSV_FIELDS = ["name", "description", "category", "value", "type", "state", "max_attempts", "flags", "tags", "hints"]
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|])")


def _md(text: str) -> str:
    """Escape Markdown so engine text (paths, wildcards like *.example.com) renders literally."""
    return _MD_SPECIAL.sub(r"\\\1", text)


def _fence(text: str) -> str:
    fence = "~~~~" if "~~~" in text else "~~~"
    return f"{fence}\n{text}\n{fence}"


def category(objective: str) -> str:
    d = objective.split(".")[0]
    return f"D{d} {DOMAIN_NAMES.get(d, '')}".strip()


def challenge_id(q: dict) -> str:
    """Short stable id: the same question always gets the same name, so ctfcli can re-sync it."""
    return hashlib.sha256("|".join(question_key(q)).encode()).hexdigest()[:6]


def letters_ok(q: dict) -> bool:
    """A letter flag would be ambiguous if a choice's own text is a single letter."""
    return not any(len(c.strip()) == 1 and c.strip().isalpha() for c in q["choices"])


def describe(q: dict, mc_plugin: bool) -> str:
    parts = [f"**Objective {q['objective']} {OBJECTIVE_NAMES.get(q['objective'], '')}** · "
             f"{_md(LABS[q['lab']][0].TITLE) if q['lab'] else 'Exam-style question'}", ""]
    if q["context"]:
        parts += [_fence(q["context"]), ""]
    parts += [_md(q["prompt"]), ""]
    if mc_plugin:
        parts += [f"* () {c}" for c in q["choices"]]
    else:
        if letters_ok(q):
            parts += [f"{string.ascii_uppercase[i]}. {_md(c)}  " for i, c in enumerate(q["choices"])]
            parts += ["", "*Submit the letter or the exact answer text (case does not matter).*"]
        else:
            parts += [f"- {_md(c)}" for c in q["choices"]]
            parts += ["", "*Submit the exact answer text (case does not matter).*"]
    return "\n".join(parts)


def flags(q: dict, mc_plugin: bool) -> list[dict]:
    out = [{"type": "static", "content": q["answer"], "data": "case_insensitive"}]
    if not mc_plugin and letters_ok(q):
        letter = string.ascii_uppercase[q["choices"].index(q["answer"])]
        if letter.lower() != q["answer"].lower():
            out.append({"type": "static", "content": letter, "data": "case_insensitive"})
    return out


def hints(q: dict, hint_cost: int) -> list[dict]:
    watch = videos.link_text(q["objective"])
    if q["lab"]:
        lab = LABS[q["lab"]][0]
        first = f"Revisit {lab.TITLE}: read its Lesson, then run the scenario (python main.py lab {q['lab']})."
    else:
        labs = videos.labs_for_objective(q["objective"])
        first = (f"Objective {q['objective']} {OBJECTIVE_NAMES.get(q['objective'], '')}"
                 + (f": practise it in Lab {', Lab '.join(map(str, labs))}." if labs else "."))
    return [{"content": first + (f" {watch}" if watch else ""), "cost": 0},
            {"content": f"Explanation: {q['explanation']}", "cost": hint_cost}]


def build_challenges(variants: int = 0, points: int = 100, hint_cost: int = 25, attempts: int = 2,
                     mc_plugin: bool = False) -> list[dict]:
    out, seen = [], set()
    for q in collect(variants):
        cid = challenge_id(q)
        assert cid not in seen, f"challenge id collision: {cid}"
        seen.add(cid)
        out.append({
            "name": f"{'Lab ' + str(q['lab']) if q['lab'] else 'Exam'} · {q['objective']} · {cid}",
            "description": describe(q, mc_plugin),
            "category": category(q["objective"]),
            "value": points,
            "type": "multiple_choice" if mc_plugin else "standard",
            "state": "visible",
            "max_attempts": attempts,
            "flags": flags(q, mc_plugin),
            "tags": [f"SY0-701 {q['objective']}", f"lab{q['lab']}" if q["lab"] else "exam-style"],
            "hints": hints(q, hint_cost),
            "_slug": f"{'lab%02d' % q['lab'] if q['lab'] else 'exam'}-{q['objective'].replace('.', '_')}-{cid}",
            "_question": q,
        })
    return out


def write_csv(challenges: list[dict], path: Path) -> None:
    # CTFd's CSV importer accepts JSON lists in the flags/hints columns (so answers
    # may contain commas); tags are a plain comma-separated list.
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for c in challenges:
            w.writerow({**{k: c[k] for k in CSV_FIELDS},
                        "flags": json.dumps(c["flags"]), "hints": json.dumps(c["hints"]),
                        "tags": ",".join(c["tags"])})


def challenge_yml(c: dict) -> str:
    """ctfcli challenge.yml. Written as JSON, which every YAML parser reads as YAML."""
    spec = {"name": c["name"], "author": "Security+ Lab Engine", "category": c["category"],
            "description": c["description"], "value": c["value"], "type": c["type"], "state": c["state"],
            "attempts": c["max_attempts"], "flags": c["flags"], "tags": c["tags"], "hints": c["hints"],
            "version": "0.1"}
    return "# Generated by tools/export_ctfd.py - edit the lab engine, not this file.\n" + json.dumps(spec, indent=2) + "\n"


README = """Security+ SY0-701 challenges for CTFd ({n} challenges, {points} points each)
==========================================================================

Option A - admin panel (easiest)
  1. Start CTFd on your own machine:   docker run -p 8000:8000 ctfd/ctfd
  2. Open http://localhost:8000 and finish the setup wizard (you become the admin).
  3. Admin Panel -> Config -> Backup -> Import CSV, choose type "Challenges",
     pick challenges.csv and import.

Option B - ctfcli (can re-sync after you regenerate)
  pip install ctfcli
  cd this folder, run:  ctf init          (enter your CTFd URL and an admin access token)
  then:                 for d in challenges/*/; do ctf challenge add "$d"; done
                        ctf challenge install
  after regenerating:   ctf challenge sync

Playing: submit the letter or the answer text (case does not matter). The free
hint points to the lab; the {cost}-point hint shows the explanation.
Categories are the five exam domains, so the scoreboard shows your strength by domain.
Keep access tokens out of chat, screenshots and git.
"""


def write_all(out_dir: Path, challenges: list[dict], points: int, hint_cost: int) -> None:
    if (out_dir / "challenges").exists():
        shutil.rmtree(out_dir / "challenges")
    (out_dir / "challenges").mkdir(parents=True)
    write_csv(challenges, out_dir / "challenges.csv")
    for c in challenges:
        d = out_dir / "challenges" / c["_slug"]
        d.mkdir()
        (d / "challenge.yml").write_text(challenge_yml(c), encoding="utf-8")
    (out_dir / "README.txt").write_text(README.format(n=len(challenges), points=points, cost=hint_cost),
                                        encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export the course as a CTFd challenge set")
    ap.add_argument("--variants", type=int, default=0, help="generated scenarios per generator lab (default 0)")
    ap.add_argument("--points", type=int, default=100)
    ap.add_argument("--hint-cost", type=int, default=25)
    ap.add_argument("--attempts", type=int, default=2, help="max attempts per challenge (0 = unlimited)")
    ap.add_argument("--mc-plugin", action="store_true",
                    help="use CTFd's multiple_choice type (hosted CTFd or the paid plugin)")
    ap.add_argument("--out", default=str(ROOT / "dist" / "ctfd"))
    a = ap.parse_args(argv)
    challenges = build_challenges(a.variants, a.points, a.hint_cost, a.attempts, a.mc_plugin)
    out = Path(a.out)
    write_all(out, challenges, a.points, a.hint_cost)
    by_cat: dict[str, int] = {}
    for c in challenges:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    print(f"wrote {out}: {len(challenges)} challenges (challenges.csv + challenges/*/challenge.yml)")
    for cat in sorted(by_cat):
        print(f"  {cat}: {by_cat[cat]}")
    print(f"next: see {out / 'README.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
