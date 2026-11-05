# Question writer brief (Phase 3)

Fill in {NEWFILE}, {TOPICFILE}, {D}, {SCOPE_SHORT}, {IDFMT}, {IDRULE}, {COUNTS}, {CERT} and prepend `YOUR SCOPE: objectives ... (Domain N).` Give each slice its own files and ID range.

---

You are writing original exam-style practice questions for Delzar Certification Academy, a free study app aligned to the {CERT} (e.g. CompTIA Security+ SY0-701) exam objectives. Repo: <repo>/secplus_lab_engine (Python, standard library). The owner wants MULTIPLE QUIZZES PER OBJECTIVE ("subdomain", e.g. 2.4) so they can learn each concept one by one. Your job covers only the objectives listed under YOUR SCOPE below.

## What to produce (two NEW files only; do not edit any other file, do not git commit)

1. NEW QUESTIONS file: `data/exam_bank/{NEWFILE}` with exactly this shape:
   {"domain": "{D}", "title": "Domain {D} extra questions ({SCOPE_SHORT})", "note": "Original questions written for Delzar Certification Academy. Not from exam dumps or commercial banks.", "questions": [ ... ]}
   Each question (single-answer only):
   {"id": "{IDFMT}", "objective": "X.Y", "topic": "<one topic name from your topic list, exact spelling>",
    "stem": "...?", "choices": ["...","...","...","..."], "answer": "<one of the choices, exact>",
    "explanation": "Why the answer is right, and why the most tempting wrong option is wrong."}
   IDs: {IDRULE}

2. TOPICS file: `data/exam_bank/topics/{TOPICFILE}` with this shape:
   {"topics": {"X.Y": ["Topic A", "Topic B", ...], ...},      // only your objectives
    "tags": {"D2-001": "Topic A", ...}}                         // EVERY existing question of your objectives -> one topic
   Existing questions of your objectives live in `data/exam_bank/domain{D}.json` and `data/exam_bank/pbq.json` (filter by "objective"). Tag every one of them (pbq.json items too). Do NOT modify those files; tags go only in your topics file. New questions carry their topic inline (the "topic" field) and need not be repeated in "tags".

## Topics
For each objective, define 3 to 7 topics that follow the official SY0-701 sub-bullets for that objective, grouped into teachable concepts (e.g. 1.1 -> "Control categories", "Control types"; 2.4 -> "Malware", "Physical attacks", "Network attacks", "Application attacks", "Cryptographic attacks", "Password attacks", "Indicators of malicious activity"). Short Title-case names, no objective numbers in the name. Objective names are in `tools/export_anki.py` (OBJECTIVE_NAMES). Use your knowledge of the published SY0-701 exam objectives (v5.0) to cover every sub-bullet somewhere.

## How many
After your additions, for EVERY objective in your scope: existing + new single-answer questions >= 30, and every topic has >= 5 questions (existing tagged + new). Write new questions to fill the thinnest topics first and to cover sub-bullets with no question yet. Current counts of existing questions per objective (domain files + pbq): {COUNTS}

## Style (the owner complained that earlier questions were full of lab jargon; keep these exam-realistic)
- Short realistic workplace scenario in plain language, then a question ending with "?" using a qualifier where natural: BEST, MOST likely, FIRST, PRIMARY, Which of the following...
- Exactly 4 distinct options of the same kind (all control types, all attack names, all tools...), each plausible. No "all/none of the above", no bare numbers (write "3 days"), no lab IDs/codes (nothing like DF-5, IAC-T1, RULE_NAMES), never the word "lab".
- Exactly one defensible correct answer, accurate to SY0-701 terminology (CompTIA's meanings, e.g. CompTIA's control types: preventive, deterrent, detective, corrective, compensating, directive).
- Spread the answer position evenly over A/B/C/D across your new questions (about 25% each). Avoid making the correct answer the longest option: it should be uniquely longest in no more than ~25% of your questions.
- Mix difficulty: ~30% recall/definition, ~70% applied scenario. Vary stems; no near-duplicates of each other or of existing questions in domain{D}.json (read them first).
- Explanation 1-3 sentences: why the answer is right AND why the most tempting distractor is wrong.
- 100% original wording. Do not copy from exam dumps, Professor Messer, Sybex, Dion, etc.

## Check your work (required)
Run:  cd <repo>/secplus_lab_engine && python -m utils.exam_bank data/exam_bank/{NEWFILE}
It must print OK (it checks format, 4 choices, answer present, stem length 40-600, explanation length, jargon, duplicates). Also write and run a small throwaway script (in <scratchpad>, not in the repo) that checks: every existing question of your objectives is tagged; every tag/topic value is in that objective's topic list; per-objective totals >= 30; per-topic totals >= 5; no new stem duplicates an existing stem; answer-position spread; share where the answer is uniquely longest. Then re-read every new question once as a strict reviewer and fix any with a debatable answer.

## Report back (short)
Per objective: topic list with counts (existing+new), totals, answer-position spread, longest-answer share, and the validator output line. Mention any existing question you think has a wrong answer (do not change it).
