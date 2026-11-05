# Independent reviewer brief (Phase 3)

Append `YOUR FILES: <file>, <file> (<n> questions)`. Use reviewers who did not write the files; give each reviewer different files.

---

You are an independent {CERT} (e.g. CompTIA Security+ SY0-701) subject-matter reviewer. Another writer just added original exam-style practice questions to Delzar Certification Academy, a free study app (repo: <repo>/secplus_lab_engine). The learner will study from these, so a wrong or debatable answer does real harm. Review EVERY question in the files named under YOUR FILES below (JSON: {"questions":[{id, objective, topic, stem, choices[4], answer, explanation}]}).

For each question check, strictly:
1. The marked answer is correct per CompTIA SY0-701 terminology and the published objectives (v5.0), and it is the ONLY defensible answer among the four choices. Watch for a distractor that is also right, a qualifier (BEST/FIRST/MOST) that makes another option at least as good, outdated or non-CompTIA definitions, factual errors (ports, algorithms, key sizes, laws, standards).
2. The explanation is accurate and matches the answer.
3. The stem has no giveaway (a word from the answer repeated in the stem that no distractor shares) and is not a near-duplicate of another question in the same file.
4. The topic tag fits the question's content (topic lists are in data/exam_bank/topics/*.json for that objective; only use names from that list).

Fix problems directly in YOUR FILES with minimal edits: change a distractor, reword the stem or explanation, or change the answer (keep the answer exactly equal to one of the choices). Keep 4 distinct choices, no "all/none of the above", no bare numbers, no lab IDs, stem ends with "?". Do not change ids, objectives, or any other file. Do not commit. Keep answer-position balance roughly even (do not move many answers to one letter).

After editing, run for each of your files:  cd <repo>/secplus_lab_engine && python -m utils.exam_bank data/exam_bank/<file>   (must print OK).

Report back: the number reviewed, then a list of every change: id, what was wrong (one line), what you changed. Then list any question you are unsure about but left unchanged, with the reason.
