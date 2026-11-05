#!/usr/bin/env python3
"""
Security+ SY0-701 Python Lab Engine & AI Agent Governor
=======================================================

Offline, CLI-driven simulator for manual security operations.

Usage
-----
    python main.py                      # interactive menu
    python main.py list                 # list labs
    python main.py lab 3                # run one lab's example scenario
    python main.py challenge 4          # predict-the-outcome quiz for a lab (or "challenge all")
    python main.py lab 4 --challenge    # same thing
    python main.py progress             # scores per SY0-701 objective, weakest first
    python main.py review               # today's spaced-repetition session (due reviews + weakest objectives)
    python main.py challenge 9 --random --seed 42   # fresh generated scenario (labs with a generator)
    python main.py lab 12 --random      # run a lab on a generated scenario
    python main.py exam                 # timed 90-question practice exam weighted by SY0-701 domain
    python main.py exam --domain 3      # domain test: 30 questions from one domain, scored per objective
    python main.py videos               # Professor Messer's free video course, mapped to the labs
    python main.py videos --lab 17      # the videos for one lab (or --objective 1.4, --mark ID, --open N)
    python main.py case-study 1         # portfolio case study (Markdown + HTML) in dist/portfolio/ (or --all)
    python main.py web                  # open the course web app in your browser (live engine, offline)
    python main.py install-shortcut     # put a double-click launcher on your desktop
    python main.py lab 4 --file x.json  # run a lab against your own data
    python main.py all                  # run every lab back-to-back
    python main.py test                 # run the pytest suite
    python main.py --plain lab 1        # no colour (for logs / screen readers)
    python main.py --policies my.json lab 2   # use a custom policy file
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

# Allow ``python main.py`` from any directory.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from labs import LABS  # noqa: E402
from utils.challenge import Progress, run_challenge  # noqa: E402
from utils.exam import DOMAIN_NAMES, DOMAIN_TEST_TARGET, build_domain_test, build_exam, run_exam  # noqa: E402
from utils.scenario_generator import GENERATORS, generate  # noqa: E402
from utils.loader import load_data, load_json, load_policies  # noqa: E402
from utils.terminal_ui import UI  # noqa: E402
from utils import videos as vids  # noqa: E402

log = logging.getLogger("secplus_lab_engine")

BANNER = "Security+ SY0-701 Lab Engine & AI Agent Governor"
SUBTITLE = "Offline, first-principles practice for manual security operations → governed automation"


def lab_data(number: int, policies: dict, data_file: str | None = None, randomize: bool = False,
             seed: int | None = None) -> dict:
    """Scenario data for a lab: --file, a generated scenario (--random), or the bundled sample."""
    if number not in LABS:
        raise SystemExit(f"Unknown lab {number}. Choose from {sorted(LABS)}.")
    if data_file:
        return load_json(data_file)
    if randomize:
        if number not in GENERATORS:
            raise SystemExit(f"Lab {number} has no random generator (supported: {sorted(GENERATORS)}).")
        return generate(number, policies, seed)
    return load_data(LABS[number][1])


def run_lab(ui: UI, number: int, policies: dict, data_file: str | None = None,
            randomize: bool = False, seed: int | None = None) -> dict:
    """Run one lab's example scenario and return its summary dict."""
    data = lab_data(number, policies, data_file, randomize, seed)
    module, default_file = LABS[number]
    ui.header(module.TITLE, module.OBJECTIVES + (f" · generated scenario (seed {seed})" if randomize else ""))
    log.info("running lab %s with data=%s", number, data_file or default_file)
    summary = module.run_demo(ui, policies, data)
    ui.panel("Lab summary", "\n".join(f"{k}: {v}" for k, v in summary.items()), style="cyan")
    return summary


def challenge_lab(ui: UI, number: int, policies: dict, data_file: str | None = None,
                  progress_path: str | None = None, ask=None, seed: int | None = None, randomize: bool = False):
    """Run challenge mode for one lab and record the score."""
    data = lab_data(number, policies, data_file, randomize, seed)
    module = LABS[number][0]
    ui.header(f"CHALLENGE · {module.TITLE}", "Predict the engine's verdict, then see why. Answer with the option number."
              + (f" Generated scenario (seed {seed})." if randomize else ""))
    questions = module.build_challenges(policies, data)
    progress = Progress(progress_path) if progress_path is not None else Progress()
    return run_challenge(ui, number, questions, ask=ask, progress=progress, seed=seed)


def show_progress(ui: UI, progress_path: str | None = None) -> None:
    p = Progress(progress_path) if progress_path is not None else Progress()
    rows = p.rows()
    if not rows:
        ui.print("No challenge results yet. Try: python main.py challenge 1", style="yellow")
        return
    ui.table("Progress by SY0-701 objective (weakest first)", ["Objective", "Attempted", "Correct", "Score", "Status"], rows)
    recent = p.data.get("sessions", [])[-5:]
    if recent:
        ui.table("Recent sessions", ["When (UTC)", "Lab", "Score"], [[s["ts"], s["lab"], s["score"]] for s in recent])
    recs = vids.recommend(rows)
    if recs:
        ui.table("Watch next: videos for your weakest objectives", ["Objective", "Status", "Video", "Length", "Link"],
                 [[r["objective"], r["status"], v["title"], vids.duration(v["seconds"]), vids.url(v, False)]
                  for r in recs for v in r["videos"][:2]])


def show_videos(ui: UI, lab: int | None = None, objective: str | None = None, mark: str | None = None,
                unmark: str | None = None, open_n: int | None = None, progress_path: str | None = None) -> int:
    """The video course: full study plan, or the videos for one lab / objective."""
    import webapi
    if mark or unmark:
        try:
            webapi.progress_watch(mark or unmark, bool(mark), progress_path)
        except ValueError:
            ui.print(f"No video with ID '{mark or unmark}'. IDs are in the last column of: python main.py videos",
                     style="yellow")
            return 1
    watched = set(webapi.progress_get(progress_path)["watched"])
    if open_n is not None:
        match = [v for v in vids.videos() if v["n"] == open_n]
        if not match:
            ui.print(f"No video #{open_n} (1-{len(vids.videos())})", style="yellow")
            return 1
        import webbrowser
        webbrowser.open(vids.url(match[0]))
        ui.print(f"Opening #{open_n} {match[0]['title']}: {vids.url(match[0])}")
        return 0
    src = vids.course()["source"]

    def rows(vs):
        return [[v["n"], "✓" if v["id"] in watched else "", v["title"], v["objective"], vids.duration(v["seconds"]), v["id"]]
                for v in vs]
    head = ["#", "Seen", "Video", "Obj.", "Length", "ID"]
    if lab is not None:
        mod = LABS[lab][0]
        vs = vids.for_lab(mod)
        ui.header(f"VIDEOS FOR {mod.TITLE}", f"{len(vs)} videos · {vids.duration(sum(v['seconds'] for v in vs))} · "
                                             f"objectives {', '.join(vids.lab_objectives(mod))}")
        ui.table("Watch, then run the lab and practise", head, rows(vs))
    elif objective:
        vs = vids.for_objective(objective)
        labs_ = vids.labs_for_objective(objective)
        ui.header(f"VIDEOS FOR OBJECTIVE {objective}", f"{len(vs)} videos · labs: {', '.join(map(str, labs_)) or 'none yet'}")
        ui.table("Videos", head, rows(vs))
    else:
        all_v = vids.videos()
        ui.header("VIDEO COURSE · " + src["title"],
                  f"{src['author']} · {len(all_v)} videos · {vids.duration(sum(v['seconds'] for v in all_v))} · "
                  f"watched {len(watched & {v['id'] for v in all_v})}/{len(all_v)} · {src['url']}")
        ui.table("Study plan: watch the videos, then practise in the lab",
                 ["Objective", "Videos", "Length", "Seen", "Practise in"],
                 [[step["objective"], len(step["videos"]), vids.duration(step["seconds"]),
                   f"{sum(v['id'] in watched for v in step['videos'])}/{len(step['videos'])}",
                   ", ".join(f"Lab {n}" for n in step["labs"]) or ("start here" if step["objective"] == "intro" else "videos only")]
                  for step in vids.study_plan()])
    ui.print("Open one: python main.py videos --open N · mark it watched: python main.py videos --mark ID · "
             "videos © Professor Messer, watched on YouTube.", style="dim")
    return 0


def domain_test(ui: UI, policies: dict, domain: str, count: int = 30, minutes: float | None = None,
                seed: int | None = None, randomize: bool = True, ask=None, progress_path: str | None = None,
                source: str = "bank"):
    questions, per_obj = build_domain_test(policies, str(domain), count, seed, randomize, source)
    minutes = minutes if minutes is not None else float(len(questions))
    ui.header(f"DOMAIN {domain} TEST · {DOMAIN_NAMES[str(domain)]}",
              f"{len(questions)} questions · {minutes:g} minutes · per objective {per_obj} · "
              f"target {DOMAIN_TEST_TARGET}% · no feedback until the end")
    progress = Progress(progress_path) if progress_path is not None else Progress()
    return run_exam(ui, questions, minutes, ask=ask, progress=progress, domain=str(domain))


def exam(ui: UI, policies: dict, count: int = 90, minutes: float = 90, seed: int | None = None,
         randomize: bool = True, ask=None, progress_path: str | None = None, source: str = "bank"):
    questions, alloc, shortfall = build_exam(policies, count, seed, randomize, source)
    ui.header("PRACTICE EXAM · SY0-701", f"{len(questions)} questions · {minutes:g} minutes · per domain {alloc} · "
                                         "no feedback until the end")
    progress = Progress(progress_path) if progress_path is not None else Progress()
    return run_exam(ui, questions, minutes, ask=ask, progress=progress, shortfall=shortfall)


def review(ui: UI, count: int = 15, seed: int | None = None, ask=None, progress_path: str | None = None,
           today=None):
    """Today's daily review: answer, see the right answer and why at once, then a summary."""
    from datetime import date
    from utils import review as srs
    from utils.challenge import _resolve
    from utils.exam_bank import load_bank
    ask = ask or ui.ask
    day = srs.as_date(today) if today is not None else date.today()
    progress = Progress(progress_path) if progress_path is not None else Progress()
    session = srs.build_session(progress.data, load_bank(), day, max(1, min(int(count), 50)), seed)
    qs = session["questions"]
    ui.header("DAILY REVIEW", f"{day.isoformat()} · {session['review_count']} due for review · "
                              f"{session['new_count']} new from your weakest objectives · "
                              f"streak {session['streak']['current']} day(s)")
    if not qs:
        ui.print("Nothing to review and no new questions left. Take a practice exam: python main.py exam", style="yellow")
        return {"done": 0, "correct": 0, "due_by_day": session["due_by_day"]}
    done = correct = 0
    for i, q in enumerate(qs, 1):
        ui.section(f"Question {i}/{len(qs)}  ·  SY0-701 {q['objective']}  ·  {q['reason']}")
        ui.print(f"[bold]{q['prompt']}[/bold]")
        for n, c in enumerate(q["choices"], 1):
            ui.print(f"  {n}) {c}")
        try:
            raw = ask("Your answer:").strip()
        except (EOFError, KeyboardInterrupt):
            ui.print("\n  Review stopped early. Your answers so far are saved.", style="yellow")
            break
        chosen = _resolve(raw, q["choices"])
        ok = chosen == q["answer"]
        done += 1
        correct += ok
        if ok:
            ui.status("Your answer", "PASS", q["answer"])
        else:
            ui.status("Your answer", "FAIL", f"you said '{chosen or raw}', the answer is '{q['answer']}'")
        ui.print(f"  [dim]Why:[/dim] {q['explanation']}")
        progress.record(q["objective"], ok, q["id"], day, review=True)
    if done:
        from datetime import datetime, timezone
        progress.data["sessions"].append({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                          "lab": "daily review", "score": f"{correct}/{done}"})
        progress.save()
    ids = {r["id"] for r in load_bank() if srs.is_single(r)}
    by_day = srs.due_by_day(progress.data["srs"], day, 7, ids)
    ui.panel("Review summary",
             f"Done {done} · correct {correct}"
             + (f" ({100 * correct // done}%)" if done else "")
             + f" · streak {srs.current_streak(progress.data['streak'], day)} day(s)\n\nNext due:\n"
             + "\n".join(f"  {d}{' (today, incl. overdue)' if d == day.isoformat() else ''}: {n}"
                         for d, n in by_day.items()),
             style="green" if done and correct * 100 >= 85 * done else "yellow")
    return {"done": done, "correct": correct, "due_by_day": by_day}


def progress_file(ui: UI, export: str | None = None, import_: str | None = None, replace: bool = False,
                  progress_path: str | None = None) -> int:
    """Export progress to a file, or import (merge / replace) one, e.g. from the web app on another device."""
    import json
    import webapi
    from utils import sync
    if export:
        Path(export).write_text(json.dumps(webapi.progress_export(progress_path), indent=2), encoding="utf-8")
        ui.print(f"Saved your progress to {export}. Import it on another device: My progress → Import, "
                 f"or python main.py progress --import {export}", style="green")
        return 0
    try:
        got = webapi.progress_import(sync.read_file(import_), replace, progress_path)
    except (OSError, ValueError) as e:
        ui.print(f"Could not import {import_}: {e}", style="red")
        return 1
    ui.print(f"{'Replaced your progress with' if replace else 'Merged'} {import_}: {len(got['objectives'])} objectives, "
             f"{len(got['srs'])} review cards, {len(got['quizzes'])} quiz scores.", style="green")
    return 0


def quiz(ui: UI, objective: str | None = None, set_n: int | None = None, topic_n: int | None = None, ask=None,
         progress_path: str | None = None, seed: int | None = None, today=None) -> dict | None:
    """Objective quizzes: list them, or take one with the answer and the reason after each question."""
    from datetime import date
    import webapi
    from utils import quizzes
    from utils.challenge import check
    from utils.exam import describe_answer, parse_answer, show_question
    cat = quizzes.catalog()
    prog = Progress(progress_path) if progress_path is not None else Progress()
    scores = prog.data.get("quizzes", {})
    best = lambda qid: f"best {scores[qid]['best']}%" if qid in scores else "not taken"
    if objective and objective not in cat:
        ui.print(f"Unknown objective '{objective}'. Use one like 2.4 (python main.py quiz lists them).", style="red")
        return None
    if not objective:
        ui.table("Objective quizzes (python main.py quiz X.Y to see one objective's quizzes)",
                 ["Objective", "Name", "Questions", "Sets", "Concept quizzes", "Done"],
                 [[o, c["name"], c["count"], sum(q["kind"] == "set" for q in c["quizzes"]),
                   sum(q["kind"] == "topic" for q in c["quizzes"]),
                   f"{sum(q['id'] in scores for q in c['quizzes'])}/{len(c['quizzes'])}"] for o, c in cat.items()])
        return None
    c = cat[objective]
    if set_n is None and topic_n is None:
        ui.table(f"{objective} {c['name']}: quizzes", ["Take it with", "Quiz", "Questions", "Score"],
                 [[f"--set {q['id'].rsplit('set', 1)[1]}" if q["kind"] == "set" else f"--topic {q['id'].rsplit('-t', 1)[1]}",
                   q["title"] if q["kind"] == "set" else f"Concept: {q['title']}", len(q["qids"]), best(q["id"])]
                  for q in c["quizzes"]])
        return None
    qid = f"{objective}-set{set_n}" if set_n is not None else f"{objective}-t{topic_n}"
    try:
        quiz_def = quizzes.find(qid)
    except ValueError:
        ui.print(f"No such quiz for {objective}. See: python main.py quiz {objective}", style="red")
        return None
    ask = ask or ui.ask
    qs = quizzes.questions(qid, seed)
    title = quiz_def["title"] if quiz_def["kind"] == "set" else f"Concept: {quiz_def['title']}"
    ui.header(f"QUIZ {objective} {c['name']}", f"{title} · {len(qs)} questions · the answer and why after each one")
    results = []
    for i, q in enumerate(qs, 1):
        ui.section(f"Question {i}/{len(qs)}")
        ui.print(f"[bold]{q.prompt}[/bold]")
        show_question(ui, q)
        try:
            raw = ask("Your answer:").strip()
        except (EOFError, KeyboardInterrupt):
            ui.print("\n  Quiz stopped early. Scoring the questions answered so far.", style="yellow")
            break
        resp = parse_answer(q, raw)
        ok = check(q, resp)
        ui.status("Your answer", "PASS" if ok else "FAIL",
                  q.answer if ok else f"you said '{describe_answer(q, resp) or raw}', the answer is '{q.answer}'")
        ui.print(f"  [dim]Why:[/dim] {q.explanation}")
        results.append({"objective": q.objective, "correct": ok, "qid": q.qid})
    if not results:
        return None
    day = today or date.today().isoformat()
    got = webapi.quiz_record(qid, results, day, progress_path)
    n_ok = sum(r["correct"] for r in results)
    ui.panel("Quiz score", f"{n_ok}/{len(results)} correct ({100 * n_ok // len(results)}%) · best {got['quiz_score']['best']}%"
             "\nMissed questions come back in your daily review: python main.py review",
             style="green" if n_ok * 100 >= 85 * len(results) else "yellow")
    return {"quiz": qid, "correct": n_ok, "total": len(results), "best": got["quiz_score"]["best"]}


def list_labs(ui: UI) -> None:
    ui.table("Available labs", ["#", "Lab", "Objectives", "Default data", "Random"],
             [[n, m.TITLE, m.OBJECTIVES, f, "yes" if n in GENERATORS else "-"] for n, (m, f) in LABS.items()])


def run_tests(extra: list[str] | None = None) -> int:
    cmd = [sys.executable, "-m", "pytest", str(ROOT / "tests"), "-q", *(extra or [])]
    return subprocess.call(cmd, cwd=ROOT)


def interactive_menu(ui: UI, policies: dict) -> None:
    ui.header(BANNER, SUBTITLE)
    while True:
        list_labs(ui)
        ui.print(f"  [bold]1-{len(LABS)}[/bold] run a lab   [bold]C<n>[/bold] challenge (e.g. C3)   "
                 "[bold]R<n>[/bold] challenge on a random scenario   [bold]E[/bold] practice exam   [bold]D<n>[/bold] domain test (D1-D5)   "
                 "[bold]RV[/bold] daily review   [bold]P[/bold] progress   "
                 "[bold]V[/bold] videos   [bold]W[/bold] web app   [bold]A[/bold] run all   [bold]T[/bold] run tests   [bold]Q[/bold] quit")
        try:
            choice = ui.ask(">").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ui.print("\nbye")
            return
        if choice in {"q", "quit", "exit"}:
            return
        if choice in {"a", "all"}:
            for n in LABS:
                run_lab(ui, n, policies)
        elif choice in {"t", "test", "tests"}:
            run_tests()
        elif choice in {"p", "progress"}:
            show_progress(ui)
        elif choice in {"rv", "review"}:
            review(ui)
        elif choice in {"v", "videos"}:
            show_videos(ui)
        elif choice.startswith("c") and choice[1:].strip().isdigit() and int(choice[1:]) in LABS:
            challenge_lab(ui, int(choice[1:]), policies)
        elif choice.startswith("r") and choice[1:].strip().isdigit() and int(choice[1:]) in GENERATORS:
            challenge_lab(ui, int(choice[1:]), policies, randomize=True)
        elif choice in {"e", "exam"}:
            exam(ui, policies)
        elif len(choice) == 2 and choice[0] == "d" and choice[1] in "12345":
            domain_test(ui, policies, choice[1])
        elif choice in {"w", "web"}:
            from utils.webserver import serve
            serve(open_browser=True, policies=policies)
        elif choice.isdigit() and int(choice) in LABS:
            run_lab(ui, int(choice), policies)
        else:
            ui.print(f"Unrecognised option '{choice}'", style="yellow")
            continue
        try:
            ui.ask("Press Enter to return to the menu…")
        except (EOFError, KeyboardInterrupt):
            return


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secplus_lab_engine", description=BANNER)
    p.add_argument("--plain", action="store_true", help="disable colour / rich formatting")
    p.add_argument("--policies", metavar="FILE", help="path to an alternative policy JSON file")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging to stderr")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("menu", help="interactive menu (default)")
    sub.add_parser("list", help="list labs")
    lab = sub.add_parser("lab", help="run a single lab")
    lab.add_argument("number", type=int, choices=sorted(LABS))
    lab.add_argument("--file", metavar="JSON", help="custom scenario data for this lab")
    lab.add_argument("--challenge", action="store_true", help="quiz mode: predict outcomes before they are revealed")
    lab.add_argument("--random", action="store_true", help="use a freshly generated scenario (labs with a generator)")
    lab.add_argument("--seed", type=int, help="seed for --random / question order")
    ch = sub.add_parser("challenge", help="predict-the-outcome quiz for a lab")
    ch.add_argument("target", help="lab number, or 'all'")
    ch.add_argument("--file", metavar="JSON", help="custom scenario data (single lab only)")
    ch.add_argument("--seed", type=int, help="fix the question order (and the generated scenario with --random)")
    ch.add_argument("--random", action="store_true", help="generate a fresh scenario so answers can't be memorised")
    ex = sub.add_parser("exam", help="timed practice exam weighted by SY0-701 domain")
    ex.add_argument("--count", type=int, help="number of questions (default 90; 30 for a domain test)")
    ex.add_argument("--minutes", type=float, help="time limit in minutes (default: one per question)")
    ex.add_argument("--seed", type=int, help="make the exam reproducible")
    ex.add_argument("--fixed", action="store_true", help="use bundled sample data only (no generated scenarios)")
    ex.add_argument("--source", choices=["bank", "labs"], default="bank",
                    help="bank = exam-style questions (default); labs = the labs' hands-on scenario questions")
    ex.add_argument("--domain", choices=list("12345"),
                    help="domain test: questions from one domain only (default 30 questions, 1 minute each)")
    pr = sub.add_parser("progress", help="show scores per SY0-701 objective; export / import them between devices")
    pr.add_argument("--export", metavar="FILE", help="save your progress to a file")
    pr.add_argument("--import", metavar="FILE", dest="import_", help="merge progress from an exported file")
    pr.add_argument("--replace", action="store_true", help="with --import: overwrite instead of merging")
    qz = sub.add_parser("quiz", help="several short quizzes per objective (sets and one per concept)")
    qz.add_argument("objective", nargs="?", help="objective, e.g. 2.4 (omit to list every objective)")
    qg = qz.add_mutually_exclusive_group()
    qg.add_argument("--set", type=int, dest="set_n", metavar="N", help="take mixed Set N")
    qg.add_argument("--topic", type=int, dest="topic_n", metavar="N", help="take the concept quiz for topic N")
    qz.add_argument("--seed", type=int, help="fix the question and option order")
    rv = sub.add_parser("review", help="today's spaced-repetition review: due questions, then your weakest objectives")
    rv.add_argument("--count", type=int, default=15, help="questions in the session (default 15, max 50)")
    rv.add_argument("--seed", type=int, help="fix which new questions are picked (default: today's date)")
    vi = sub.add_parser("videos", help="Professor Messer's free SY0-701 video course, mapped to the labs")
    vi.add_argument("--lab", type=int, choices=sorted(LABS), help="only the videos for this lab's objectives")
    vi.add_argument("--objective", metavar="X.Y", help="only the videos for one objective, e.g. 1.4")
    vi.add_argument("--mark", metavar="ID", help="mark a video watched (ID from the last column)")
    vi.add_argument("--unmark", metavar="ID", help="mark a video not watched")
    vi.add_argument("--open", type=int, metavar="N", dest="open_n", help="open video #N on YouTube")
    cs = sub.add_parser("case-study", help="write portfolio case studies (Markdown + HTML) to dist/portfolio/")
    cs.add_argument("labs", nargs="*", type=int, help="lab numbers (default: all)")
    cs.add_argument("--all", action="store_true", help="every lab")
    cs.add_argument("--out", metavar="DIR", help="output folder (default dist/portfolio)")
    w = sub.add_parser("web", help="open the course web app in your browser (runs locally)")
    w.add_argument("--port", type=int, default=8765, help="local port (default 8765; a free one is used if busy)")
    w.add_argument("--no-browser", action="store_true", help="don't open a browser window")
    sc = sub.add_parser("install-shortcut", help="create a desktop launcher for the web app")
    sc.add_argument("--desktop", metavar="DIR", help="folder to put the shortcut in (default: your desktop)")
    sub.add_parser("all", help="run every lab")
    t = sub.add_parser("test", help="run the pytest suite")
    t.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    ui = UI(plain=args.plain)
    policies = load_policies(args.policies)

    if args.command in (None, "menu"):
        interactive_menu(ui, policies)
    elif args.command == "list":
        list_labs(ui)
    elif args.command == "lab":
        if args.challenge:
            challenge_lab(ui, args.number, policies, args.file, seed=args.seed, randomize=args.random)
        else:
            run_lab(ui, args.number, policies, args.file, randomize=args.random, seed=args.seed)
    elif args.command == "challenge":
        if args.target == "all":
            for n in LABS:
                challenge_lab(ui, n, policies, seed=args.seed, randomize=args.random and n in GENERATORS)
        elif args.target.isdigit():
            challenge_lab(ui, int(args.target), policies, args.file, seed=args.seed, randomize=args.random)
        else:
            raise SystemExit("challenge target must be a lab number or 'all'")
    elif args.command == "progress":
        if args.export or args.import_:
            return progress_file(ui, args.export, args.import_, args.replace)
        show_progress(ui)
    elif args.command == "quiz":
        quiz(ui, args.objective, args.set_n, args.topic_n, seed=args.seed)
    elif args.command == "review":
        review(ui, args.count, args.seed)
    elif args.command == "videos":
        return show_videos(ui, args.lab, args.objective, args.mark, args.unmark, args.open_n)
    elif args.command == "case-study":
        from utils.portfolio import write_case_studies
        labs = sorted(LABS) if args.all or not args.labs else args.labs
        bad = [n for n in labs if n not in LABS]
        if bad:
            raise SystemExit(f"unknown lab(s): {bad}")
        files = write_case_studies(labs, args.out, policies)
        ui.print(f"Wrote {len(files)} files to {files[0].parent}: one Markdown + one HTML page per lab. "
                 "Open the HTML in a browser and use Print → Save as PDF, or put the Markdown on GitHub.")
    elif args.command == "web":
        from utils.webserver import serve
        serve(args.port, open_browser=not args.no_browser, policies=policies)
    elif args.command == "install-shortcut":
        from utils.desktop import install_shortcut
        path = install_shortcut(Path(args.desktop) if args.desktop else None)
        ui.print(f"Created {path}\nDouble-click it to open IdentityOps Lab in your browser.", style="green")
    elif args.command == "exam":
        if args.domain:
            domain_test(ui, policies, args.domain, args.count or 30, args.minutes, args.seed, randomize=not args.fixed,
                        source=args.source)
        else:
            count = args.count or 90
            exam(ui, policies, count, args.minutes if args.minutes is not None else float(count), args.seed,
                 randomize=not args.fixed, source=args.source)
    elif args.command == "all":
        ui.header(BANNER, SUBTITLE)
        for n in LABS:
            run_lab(ui, n, policies)
    elif args.command == "test":
        return run_tests(args.pytest_args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
