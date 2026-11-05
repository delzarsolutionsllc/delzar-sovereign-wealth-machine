---
name: add-certification-module
description: Add a new certification training module (e.g. CompTIA Network+, Microsoft SC-300, SY0-801) to the Delzar Certification Academy platform in secplus_lab_engine/ - exam research, objective/topic map, exam-style question bank with parallel writers and independent review, PBQs, glossary with acronym/vocabulary/definition quizzes and video links, objective quizzes, optional hands-on labs, verification (tests, validators, browser and accessibility checks), desktop app, PR, publish and Drive hand-off. Use whenever the owner asks to add, build or start a new certification course, module or track.
---

# Add a certification training module

The repeatable process used to build the Security+ SY0-701 course in **Delzar Certification Academy** (repo folder `secplus_lab_engine/`, live at https://delzarsolutionsllc.github.io/delzar-sovereign-wealth-machine/). Follow the phases in order. Each phase lists what to produce, how to check it, and the gate before moving on. The briefs in `references/` are the exact prompts that worked; fill in the placeholders and hand them to parallel subagents.

## Ground rules (always)

- **Owner approvals:** anything public (publishing, merging to `main`, which auto-deploys Pages) or that costs money needs the owner's explicit yes. Never ask for, paste or commit secrets.
- **Original content only.** No exam dumps, no copied questions or definitions from vendors, Professor Messer, Sybex, Dion, Geekus Maximus, Wikipedia. Link free videos (store titles/IDs only); never embed or copy them.
- **Trademarks:** the product name never contains the vendor's certification mark. Say "aligned to the <Vendor> <Exam> exam objectives" plus the not-affiliated notice (see the `.tm` notice in `web/index.html`).
- **Facts with dates:** exam launch/retirement dates and objective versions come from the vendor's site, fetched this session, with the access date written next to them. Mark anything inferred as PROJECTED.
- **Accuracy beats volume.** Every generated question set gets an independent review pass by agents that did not write it. Prefer the standard industry name when a vendor list misprints an expansion; note the vendor wording in the definition.
- **Commits:** run `python -m pytest tests -q` before every commit; commit messages end with the session's Co-Authored-By / Claude-Session trailers; push to the designated branch; draft PR; subscribe to it; merge only when the owner says so.

## Phase 0: Intake (ask only what you cannot look up)

Collect, then summarise back in 5 lines:
1. Certification, vendor, exam code and version (e.g. CompTIA Network+ N10-009).
2. Official objectives document: domains, weights, objective list, acronym list. Fetch it (Firecrawl / web); if blocked, use two or more public copies and say so.
3. Exam logistics from the vendor site: question count, time, pass mark/scale, launch and retirement dates (record source + access date).
4. Learner goal and career path (e.g. IAM: Security+ -> SC-300 -> SailPoint) to drive work tickets, case studies and the career page.
5. Free video course(s) to map (e.g. a Professor Messer playlist) and any acronym playlist.

Gate: dates and domain weights verified from the vendor site.

## Phase 1: Register the course (the platform is already multi-course)

The engine became multi-course when SC-300 was added (2026-11-05). For a new course:
1. Create `secplus_lab_engine/data/courses/<code>/course.json` by copying `data/courses/sc300/course.json`: code, name, short, vendor, exam_code, exam_name, aligned line, not-affiliated notice, domains (id, name, weight; weights must sum to 1 - normalise the vendor's ranges and record them in `weights_note`), objectives (code -> name), pass_scaled and scale, exam_questions / exam_minutes (mark unpublished numbers PROJECTED in a note), exam_target (dates or null, note, source URL), data folders (`data/courses/<code>/exam_bank`, `.../glossary`), labs (`{"25": ["2.2", "4.3"]}` maps shared labs to this course's objectives, or `{}`), videos (true only if a video index exists for the course), facts_checked date.
2. Everything is course-aware through `utils/course.py`: run any tool with `--course <code>` (or `DELZAR_COURSE=<code>`), e.g. `DELZAR_COURSE=<code> python -m utils.exam_bank <file>`. Progress is kept per course (`progress-<code>.json`; browser key `delzar-progress-<code>`).
3. `tools/build_site.py` builds every registered course automatically (`courses/<code>/course_data.json` and `download/Delzar-Certification-Academy-<short>.html`); the hosted site's course picker appears when there are 2+ courses.
4. Copy `tests/test_courses.py`'s SC-300 checks for the new course (they run in a subprocess with the course active).

Gate: `python -m pytest tests -q` green; `python tools/build_site.py --out <scratch>/site` builds the new course.

## Phase 2: Objective and topic map

- Write the objective list (code, name, domain) into the course registry.
- For each objective define 3-7 **concept topics** that follow the official sub-bullets (these drive the "one concept at a time" quizzes). Topic files: `data/exam_bank/topics/<file>.json` = `{"topics": {obj: [names]}, "tags": {qid: topic}}`.

Gate: every objective has topics; names are short Title Case without objective numbers.

## Phase 3: Exam-style question bank (the core)

Targets per objective: **>= 30 single-answer questions**, every topic **>= 5**, answer letters balanced (about 25 % each), correct answer uniquely longest in **<= 25 %**, ~30 % recall / ~70 % scenario, BEST / MOST likely / FIRST qualifiers, 4 options of the same kind, no "all/none of the above", no bare numbers, no lab jargon or the word "lab", explanation says why the answer is right and why the most tempting distractor is wrong.

1. Split by domain (split large domains in two). One subagent per slice, launched in parallel in the background, each with `references/question_writer_brief.md` filled in (file names, ID ranges like `D4-101..199` / `D4-201..299` so slices never collide, current counts per objective).
2. Each writer creates only two files: `data/exam_bank/domainN-extra*.json` and `data/exam_bank/topics/<slice>.json`, and must pass `python -m utils.exam_bank <file>`.
3. Independent review: 3 reviewer subagents with `references/question_reviewer_brief.md`, each owning different files; they fix in place and report every change. Then grep all new files for forbidden words (e.g. `\blabs?\b`) because reviewers can reintroduce them.
4. Run `python -m utils.exam_bank` (all files OK) and the full test suite. Fix topic-count shortfalls by writing a question, not by relaxing tests.

Gate: validator OK, tests green, reviewer reports read and any "unsure" items listed for the owner.

## Phase 4: Performance-based questions

- Hand-written PBQs (`type` multi / order / match) in `data/exam_bank/pbq.json` style: aim for >= 2 per objective.
- If the course has labs: lab-backed PBQs whose answers the engines compute (`tools/build_lab_pbqs.py` pattern; brief in `references/lab_pbq_brief.md`), with a `--check` mode and a test that the file is up to date.

## Phase 5: Hands-on labs (optional but this platform's differentiator)

Each lab is a pure, deny-by-default engine module with `TITLE`, `OBJECTIVES`, `INSIGHT`, `run_demo`, `build_challenges`, sample data in `data/`, policy in `config/default_policies.json`, a seeded generator in `utils/scenario_generator.py`, tests, a plain-English work ticket (`data/briefings/labNN.json`) and a case study. Build labs for the objectives that are about doing (configuring, triaging, deciding), not memorising.

## Phase 6: Glossary, acronyms and vocabulary

- Writers (parallel): acronyms split alphabetically (A-D, E-M, N-Z) and one vocabulary writer (~35 terms per domain), using `references/glossary_brief.md`. Entries: term, kind, expansion, original definition (12-45 words, must not contain the term or its expansion words in sequence), one domain, 1-3 objectives. Multiple meanings (MAC, PAM, RA, SAN, SOC/SoC) get separate entries.
- Video index: one subagent with `references/playlist_index_brief.md` builds `data/glossary/videos.json` from the playlist via the Firecrawl Alexandria `youtube-com` `videos/playlist_videos` capability (follow `continuation`). `utils/glossary.py` matches acronyms to videos (normalised letters + expansion overlap for multi-meaning acronyms).
- Quizzes are generated automatically per domain: Acronyms ("What does X stand for?"), Vocabulary (definition -> term), Definitions (term -> definition), distractors from the same domain/objective. They keep a score but do not count toward objective mastery.
- Standardise misprinted vendor expansions (keep the standard name as the answer; note the vendor wording in the definition).

Gate: `tests/test_glossary.py` green (entry format, give-away check, quiz partitions, unique answers, video matching).

## Phase 7: Study features that come for free

Once the data exists these work without new code (verify each): objective quizzes (`utils/quizzes.py`: concept quizzes then mixed sets dealt topic by topic), domain tests, the timed exam with flag/grid/review, daily spaced review, progress export/import, video course page, IAM/career page (update `data/career_tracks.json`), Anki and CTFd exports, the MCP AI tutor (`python main.py mcp`).

## Phase 8: Verify like a learner

Run all of these and fix what fails:
1. `python -m pytest tests -q` and `python -m utils.exam_bank`.
2. `python tools/build_web_bundle.py`, `python tools/build_site.py --out <scratch>/site`, `python tools/build_desktop_app.py`.
3. Serve the site (`python -m http.server -d <site> 8811`) and drive it with Playwright (Chromium is pre-installed; `require('playwright')`): take a concept quiz end to end, a mixed set, a glossary quiz, a domain test with flag + grid + review, export then import progress, the desktop file from `file://`, phone width 390 px with no horizontal scroll. Read the screenshots yourself.
4. Accessibility: axe-core (npm `axe-core`, pinned version) on every new screen in light and dark mode, desktop and phone: 0 violations. See `references/verification_scripts.md` for the scripts used.

## Phase 9: Ship and hand off

1. Update `README.md`, `docs/ROADMAP.md` (status lines), and any counts quoted in docs.
2. Commit (tests first), push, draft PR with Summary / Testing sections, subscribe, keep a 50-minute safety-net check-in. Report to the owner in plain language with what is still open.
3. On the owner's "merge": mark ready, squash-merge with the expected head SHA, confirm the Pages workflow succeeds and the live page shows the new course (Firecrawl scrape), then reset the working branch to `origin/main` and `git merge -s ours` the old branch tip (force-push is not allowed).
4. Hand-off: send the desktop file to the owner; in Google Drive create a dated folder with a "Start here" Google Doc (live link, desktop download link, what is new, how to study) and copies of the key docs. Large binaries cannot go through the Drive connector inline; link them from the site instead.

## References

- `references/question_writer_brief.md` - exam-style question writer (Phase 3)
- `references/question_reviewer_brief.md` - independent reviewer (Phase 3)
- `references/glossary_brief.md` - acronym / vocabulary writer (Phase 6)
- `references/playlist_index_brief.md` - YouTube playlist indexer (Phase 6)
- `references/lab_pbq_brief.md` - lab-backed PBQ generator (Phase 4)
- `references/platform_checklist.md` - generalising the engine for a second course (Phase 1)
- `references/verification_scripts.md` - Playwright and axe-core checks (Phase 8)
