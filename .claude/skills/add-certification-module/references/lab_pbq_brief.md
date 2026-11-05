# Lab-backed PBQ generator brief (Phase 4)

Use when the course has lab engines. This is the brief that produced `tools/build_lab_pbqs.py` (25 PBQs from 16 labs) for Security+.

---

Build "lab-backed performance-based questions" for {CERT}. Read `utils/exam_bank.py` (record formats for multi / order / match and `validate()`), `data/exam_bank/pbq.json` (hand-written style) and the lab modules in `labs/`. Turn real engine decisions into exam-style PBQs whose correct answers are COMPUTED by the engines, so they never drift from the labs. Target 20-30 items over >= 10 labs and >= 12 objectives, mostly match and order, at least 2 for any objective that has no PBQ yet.

Rules: plain exam language (describe items from their data, never internal IDs or engine codes; map verdict codes to readable phrases); every match uniquely correct (no two items a learner could swap); stems like the exam ("Match each sign-in to the access decision ..."); explanation names the deciding rule; deterministic output from sample data; each record has "lab": N for provenance and a valid "topic" for its objective.

Deliverables: `tools/build_lab_pbqs.py` (writes `data/exam_bank/pbq-labs.json`; `--check` exits 1 when stale; a function returning (record, engine truth) pairs), the generated file, and `tests/test_lab_pbqs.py` (up to date, validates, coverage targets, valid topics, unique ids across `load_bank()`, answers re-derived from engines, `as_question(...).check()` accepts the right response and rejects a swapped one). Run `python -m utils.exam_bank` and the full suite. Watch the quiz-set constraint: every mixed set must cover >= 3 topics of its objective.
