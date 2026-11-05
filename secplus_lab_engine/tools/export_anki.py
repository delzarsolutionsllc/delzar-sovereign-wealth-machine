#!/usr/bin/env python3
"""
Export the course's challenge questions as an Anki deck (spaced repetition).

Builds dist/SecurityPlus_SY0-701.apkg from the same questions the course uses
(sample scenarios + generated variants), organised as
``Security+ SY0-701::<domain>::<objective>``. Import it with Anki
(free: https://apps.ankiweb.net) on desktop, or AnkiMobile/AnkiDroid on a phone.

Cards have stable IDs, so importing a newer export updates existing cards
(and keeps your review history) instead of duplicating them.

Uses genanki (MIT, https://github.com/kerrickstaley/genanki):
    pip install genanki
    python tools/export_anki.py [--variants 12] [--out FILE]
"""

from __future__ import annotations

import argparse
import html
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_web_bundle import build  # noqa: E402
from utils import videos  # noqa: E402
from utils.exam import DOMAIN_NAMES  # noqa: E402

MODEL_ID = 1_707_000_701          # fixed IDs keep re-imports stable
DECK_BASE_ID = 2_070_000_000

OBJECTIVE_NAMES = {
    "1.1": "Security controls", "1.2": "Security concepts & Zero Trust", "1.3": "Change management",
    "1.4": "Cryptography & PKI", "2.1": "Threat actors & motivations", "2.2": "Threat vectors & attack surfaces",
    "2.3": "Types of vulnerabilities", "2.4": "Indicators of malicious activity", "2.5": "Mitigation techniques",
    "3.1": "Architecture models", "3.2": "Secure enterprise infrastructure", "3.3": "Data protection",
    "3.4": "Resilience & recovery", "4.1": "Secure baselines & hardening", "4.2": "Asset management",
    "4.3": "Vulnerability management", "4.4": "Alerting & monitoring", "4.5": "Enterprise security capabilities",
    "4.6": "Identity & access management", "4.7": "Automation & orchestration", "4.8": "Incident response",
    "4.9": "Investigation data sources", "5.1": "Security governance", "5.2": "Risk management",
    "5.3": "Third-party risk", "5.4": "Compliance", "5.5": "Audits & assessments", "5.6": "Security awareness",
}

CSS = """
.card { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; font-size: 17px; text-align: left; color: #17202b; background: #f6f7f9; }
.nightMode .card, .card.nightMode { color: #e3e9f0; background: #151c25; }
.obj { font-size: 12px; letter-spacing: .06em; text-transform: uppercase; opacity: .7; }
.ctx { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; background: rgba(127,127,127,.12); padding: 8px 10px; border-radius: 6px; }
.prompt { font-weight: 600; margin: 10px 0; }
ol.choices { padding-left: 22px; } .answer { font-weight: 700; color: #1d7348; } .nightMode .answer { color: #63c993; }
.why { margin-top: 8px; }
.watch { margin-top: 10px; font-size: 14px; opacity: .85; }
"""


def _watch_html(objective: str) -> str:
    """Links to Professor Messer's free videos for the card's objective (they open on YouTube)."""
    vs = videos.for_objective(objective)[:2]
    if not vs:
        return ""
    links = " · ".join(f'<a href="{html.escape(videos.url(v, False))}">{html.escape(v["title"])}</a> '
                       f'({videos.duration(v["seconds"])})' for v in vs)
    return f'<div class="watch">Watch: {links}</div>'


def _model():
    import genanki
    return genanki.Model(
        MODEL_ID, "Security+ Lab Engine question",
        fields=[{"name": "Objective"}, {"name": "Context"}, {"name": "Prompt"}, {"name": "Choices"},
                {"name": "Answer"}, {"name": "Explanation"}, {"name": "Key"}],
        templates=[{
            "name": "Predict the decision",
            "qfmt": ('<div class="obj">{{Objective}}</div>{{#Context}}<div class="ctx">{{Context}}</div>{{/Context}}'
                     '<div class="prompt">{{Prompt}}</div><ol class="choices">{{Choices}}</ol>'),
            "afmt": '{{FrontSide}}<hr id="answer"><div class="answer">{{Answer}}</div><div class="why">{{Explanation}}</div>',
        }],
        css=CSS, sort_field_index=2)


def question_key(q: dict) -> tuple:
    """Identity of a question. The same prompt can come with different choices
    (e.g. 'which do you collect first?' over different evidence pairs), so the
    choices are part of it."""
    return (q["prompt"], q["context"], *q["choices"])


def collect(variants: int = 12, include_bank: bool = True) -> list[dict]:
    """Unique questions: the labs' (sample + generated variants) and the exam-style bank."""
    bundle = build(variants)
    seen, out = set(), []
    for lab_n, lab in bundle["labs"].items():
        for src in [lab["sample"], *lab["variants"]]:
            for q in src["questions"]:
                key = question_key(q)
                if key in seen:
                    continue
                seen.add(key)
                out.append({**q, "lab": int(lab_n)})
    if include_bank:
        from utils.exam_bank import load_bank
        for r in load_bank():                                  # exam-style questions, lab 0 = "exam-style"
            q = {"prompt": r["stem"], "context": "", "choices": list(r["choices"]), "answer": r["answer"],
                 "explanation": r["explanation"], "objective": r["objective"], "lab": 0}
            if question_key(q) not in seen:
                seen.add(question_key(q))
                out.append(q)
    return out


def source_label(q: dict) -> str:
    return "Exam-style question" if q["lab"] == 0 else f"Lab {q['lab']}"


def build_package(variants: int = 12):
    import genanki
    model, decks = _model(), {}
    questions = collect(variants)
    for q in questions:
        obj = q["objective"]
        dom = obj.split(".")[0]
        name = f"Security+ SY0-701::{dom} {DOMAIN_NAMES.get(dom, '')}::{obj} {OBJECTIVE_NAMES.get(obj, '')}".strip()
        if name not in decks:
            decks[name] = genanki.Deck(DECK_BASE_ID + int(obj.replace(".", "")), name)
        esc = html.escape
        note = genanki.Note(
            model=model,
            fields=[f"{esc(obj)} {esc(OBJECTIVE_NAMES.get(obj, ''))} · {source_label(q)}", esc(q["context"]), esc(q["prompt"]),
                    "".join(f"<li>{esc(c)}</li>" for c in q["choices"]), esc(q["answer"]),
                    esc(q["explanation"]) + _watch_html(obj),
                    esc("|".join(question_key(q)))],
            guid=genanki.guid_for(*question_key(q)),
            tags=[f"SY0-701::{obj.replace('.', '_')}", "exam_style" if q["lab"] == 0 else f"lab{q['lab']}"])
        decks[name].add_note(note)
    return genanki.Package(list(decks.values())), len(questions), len(decks)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Export the course as an Anki deck")
    ap.add_argument("--variants", type=int, default=12)
    ap.add_argument("--out", default=str(ROOT / "dist" / "SecurityPlus_SY0-701.apkg"))
    a = ap.parse_args(argv)
    try:
        pkg, n_cards, n_decks = build_package(a.variants)
    except ImportError:
        print("genanki is not installed. Run: pip install genanki")
        return 1
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    pkg.write_to_file(str(out))
    print(f"wrote {out}: {n_cards} cards in {n_decks} decks. Open it with Anki (File → Import).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
