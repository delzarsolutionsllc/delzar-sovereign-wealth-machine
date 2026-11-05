# Platform audit: Security+ Lab Engine (2026-11-05)

**Summary.** The engineering is the strongest part of the platform. 997 tests pass in 10.6 s, CI runs on Python 3.10–3.13, and the seeded engines behave deterministically. The 26 labs give real hands-on "predict the engine's decision" practice, which commercial Security+ products rarely offer. The work-ticket and case-study framing also gives the IAM career track something concrete to show. As a study product, though, it is a well-built question player rather than a learning system:
- nothing schedules review;
- nothing adapts to the learner;
- the exam lacks the item types and navigation of SY0-701;
- progress is stored separately in each of the three modes, with no way to move it between devices.

It has no AI help and shows no trademark disclaimer.

Evidence was gathered with `python main.py --plain list`, `lab 25`, `exam --count 5 --minutes 5 --seed 1` with piped answers, `pytest`, and Playwright against `dist/Security+ Lab Engine.html` at 1280 px and 390 px.

| Dimension | Score | Evidence (OBSERVED) | Highest-impact change |
|---|---|---|---|
| Learning science | 4 | **Strengths:** Lab Practice gives retrieval with immediate, reasoned feedback. Answering moves focus to "Next question", and the verdict and explanation render inline. **Weaknesses:** `Progress` (`utils/challenge.py`) stores only per-objective `attempted`/`correct` counts, with no per-question history, so spacing, error re-queueing and mastery are impossible. Spacing exists only by exporting to Anki. One Lab 25 session has 43 questions, all from a single lab, with no interleaving. | Add a per-question review log and a spaced "Due today" queue (Leitner) across the bank and the lab questions, in every mode. |
| Exam realism | 5 | **Strengths:** 364 original 4-option questions with BEST/FIRST qualifiers, weighted 12/22/18/28/20. The answer key is balanced (91 per position), and the right answer is the longest option only 28% of the time. The web exam has Previous and Skip and a live timer. **Weaknesses:** there are 0 select-two items and no PBQs in the exam, and no flag-for-review or question grid. Clicking an option auto-advances (`web/index.html` around line 595), so a misclick is easy. "Finish and score" is a primary button beside Skip and needs no confirmation. The scaled score is linear, `100+8×%` (`utils/exam.py:69`), so the pass mark sits at 81.25%. In the CLI, answering A–D is silently marked wrong: `c,c,c,c,d` scored 0/5 although it was 4/5 correct by position, and the review prints "(you: C)" next to the correct option C. | Add flag-for-review, a question grid, select-two items, and PBQs built from the lab engines. Accept letters in the CLI. |
| Engagement/motivation | 4 | **Strengths:** the plain-English work tickets from fictional colleagues and the case studies give the labs a purpose. **Weaknesses:** there are no goals, no exam-date countdown, no streaks and no daily plan. The overview shows "not practised yet" on all five domain cards, with nothing that tells the learner what to do today. Practice sessions are long and cannot be split up. | Add a "Today" panel with an exam date, a daily target of due reviews plus one weak-objective set, and visible streaks or progress toward readiness. |
| Personalization/adaptivity | 3 | **Strengths:** *My progress* sorts objectives weakest first and suggests videos (`utils/videos.py`). **Weaknesses:** the exam draws questions randomly within each domain's weight (`utils/exam.py` `allocate`) and ignores the learner's history. There is no diagnostic, no difficulty model and no "drill my weakest objective" button. | Add a weak-spot drill that builds a 15-question set from the learner's worst objectives and the questions they missed before. |
| AI help | 1 | None. The hosted mode already calls `window.claude.use("db")`, so the runtime is available. | Add an opt-in "Explain differently" or "Why is my answer wrong?" tutor in hosted mode. Ground it on the item's explanation and objective, and label it as AI-generated. |
| Accessibility & mobile | 6 | **Strengths:** at 390 px there is no horizontal scroll (`scrollWidth` = 390 on the home page and on the lab Run tab). The page has `:focus-visible`, `lang=en`, a `<main>` landmark and one `h1`. Number keys answer questions. Muted text measures 5.67:1 on the background. **Weaknesses:** `aria-live` regions: 0, so verdicts, the timer and the score are never announced. Tabs use `role=tab` with no `tablist` or arrow-key support. The exam re-renders the whole panel on each question and loses focus. There is no skip link: the first Tab lands on the nav. Lab context shows raw Python dicts (`device={'platform': 'windows', 'compliant': True}`), which is unreadable to non-coders. | Add `aria-live="polite"` for verdicts and timer warnings, move focus to the question heading on each render, and add a proper tablist. |
| Career/portfolio value | 7 | **Strengths:** the IAM track maps labs to SC-300 and SailPoint concepts (`data/career_tracks.json`), with Oklahoma and remote job-search tips. Labs 1, 2, 25 and 26 are identity-specific. Lab 25 models CA policy states, including report-only, and impossible travel credibly. **Weaknesses:** only `dist/portfolio/lab01` and `lab02` case studies exist. Case studies show the engine's output, not the learner's own reasoning, which hiring managers value more. | Let the learner write their own decision notes and post-mortem into the case study, and export it to a GitHub Pages portfolio. |
| Content coverage | 6 | **Strengths:** all 28 objectives are in the bank. **Weaknesses:** the bank is thin. Objectives 1.3, 4.2, 4.7 and 4.9 have 8 questions each, so 364 items are used up after about 4 full exams. Term scan of the bank: TACACS+ 0, DNS sinkhole 0, Bluetooth 0, Kerberos 1, honeypot 1, GDPR 1, BYOD 1. There are no ports/protocols or acronym drills. | Grow the bank to about 800 items, starting with the thinnest objectives. Add a coverage checker that compares the bank against the SY0-701 acronym and term list. |
| Reliability/quality | 7 | **Strengths:** 997 tests pass. The CI matrix includes plain-mode and no-`rich` smoke runs. Seeds reproduce the same exam. A corrupt `progress.json` falls back to a fresh start. **Weaknesses:** the CLI letter-answer bug above. `Progress.save` writes in place, not atomically. No browser or E2E test runs in CI, and the desktop and hosted bundles are not rebuilt in CI to catch drift. The README is stale: it says "565 pytest tests" and "run all 24 labs". | Add a Playwright smoke test and a bundle-freshness check to CI. Fix the letter parsing and make the progress write atomic. |
| Distribution | 4 | **Strengths:** there are launchers for Windows, macOS and Linux. The desktop app is one 5.07 MB offline HTML file that showed 0 console errors. It can also be hosted on claude.ai, and Anki and CTFd exports exist. **Weaknesses:** progress lives in three separate stores (`progress.json`, `localStorage`, and the claude.ai db) with no export, import or merge, so a learner's history does not move between laptop and phone. There is no PWA manifest or service worker for installing it on a phone. Live mode needs Python. | Add progress export/import with merge in every mode, then a PWA build of the static site. |

## Top 5 improvements ranked by impact/effort

1. **Accept A–D in the CLI and confirm before finishing an exam.** About an hour of work. It removes silent wrong scoring, which is a correctness bug in a scoring product.
2. **Add a per-question review log and a spaced "Due today" queue.** A medium-sized job. It turns the 364 bank questions and about 1,000 lab questions into a real spaced-retrieval system and unlocks the weak-spot drills and the "Today" panel.
3. **Add progress export/import with merge.** A small job. It bridges the three silos and gives a backup and device moves without needing a server.
4. **Make the exam navigation match the real exam.** A small-to-medium job:
   - flag-for-review and a question grid;
   - no auto-advance;
   - select-two items;
   - label the scaled score as "approximate, not CompTIA's formula".
5. **Build PBQs from the lab engines into the exam.** A medium-sized job. Examples: classify firewall rules, order incident-response steps, match CA policy outcomes. This is the platform's unique strength, and it is currently kept outside the exam.

## Risks

- **Legal and trademark.**
  - The UI header reads "COMPTIA SY0-701" and the product is named "Security+ Lab Engine".
  - A search of `web/index.html`, `README.md` and `career_tracks.json` found no "not affiliated / trademarks of" disclaimer.
  - Add a nominative-use disclaimer before any public or product use, and consider renaming the product (for example, "Lab Engine for Security+ SY0-701").
  - Professor Messer content is linked, not embedded, which is fine; ask before any commercial use.
  - Microsoft and SailPoint references must stay descriptive.
- **Content accuracy.**
  - Lab "correct answers" are computed from the policy file (`utils/challenge.py` docstring), so editing the policies silently changes what counts as correct.
  - The bank was reviewed once but has no versioned errata process.
  - The linear scaled score implies a precision CompTIA does not publish.
  - An AI tutor would add a hallucination risk and must stay grounded on the item's own explanation.
- **Privacy.**
  - Progress stays local or in the user's own claude.ai store, and there are no network calls. That is good.
  - Exported or shared case studies and CTFd instances could leak study data or employer-like details, so keep all data fictional.
  - A future sync or product version would need consent, a retention policy and a deletion path.
