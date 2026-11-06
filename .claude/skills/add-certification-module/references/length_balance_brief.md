# Option-length balancing brief

Repo: /home/user/delzar-sovereign-wealth-machine/secplus_lab_engine. The question banks for the SailPoint courses
(`data/courses/spadmin/exam_bank/`, `data/courses/speng/exam_bank/`) have just been fact-checked by reviewers. They
have one remaining test-taking cue: in single-answer questions the correct answer is far too often the
**second-longest** option (40-68 % of questions, where chance is about 25 %). Writers padded one wrong option to stop
the right answer being the longest, so "pick the second-longest" now works. Your job is to remove that cue in YOUR FILES
without changing what any question tests.

## Measure
    python .claude/skills/add-certification-module/references/lenbalance_check.py <files>
It prints the correct answer's length-rank distribution per file (rank1 = uniquely longest) and lists the rank-2 ids.
Target per file: rank1 18-30 %, rank2 <= 32 %, rank3+rank4 >= 30 %. Run it until every file in your scope prints OK.

## How to edit (single-answer questions only; leave multi/order/match alone)
- Work through the listed rank-2 questions. For roughly half of them, make the correct answer rank 3 or 4 by
  **lengthening one or two short wrong options with natural, plausible detail** (a qualifier, a concrete object, a
  realistic but wrong reason) or by **trimming filler from the correct answer** (never removing a fact the answer needs).
  Also look for a distractor padded with filler ("in all cases", "for every source and identity", "manually by hand")
  and trim it.
- Keep every option the same kind and plausible. Never make a wrong option more correct, never add a second defensible
  answer, never add the word "lab", "all/none of the above" or bare numbers. Keep 4 distinct options.
- Never change ids, objectives, topics, the stem's meaning, which choice is correct, or the explanation's facts
  (update the explanation only if it quotes an option you reworded).
- Keep the answer letter positions as they are (do not reorder choices).
- Keep each file's JSON formatting (load, edit, dump with the same indent as the file uses; check with
  `head -c 300 <file>`), ensure_ascii=False, trailing newline.
- Avoid ties where possible (two options of identical length).

## Check (required)
    cd /home/user/delzar-sovereign-wealth-machine/secplus_lab_engine
    DELZAR_COURSE=<spadmin|speng> python -m utils.exam_bank data/courses/<code>/exam_bank/<file>   # must print OK
    python .claude/skills/add-certification-module/references/lenbalance_check.py <your files>   # every file OK
Edit only YOUR FILES. No git. Write any helper scripts to <scratchpad>/lenbal_<your-id>/ (make your own folder;
other agents work in the scratchpad too).

## Report
Per file: before/after distribution line, number of questions edited, and any question where you were unsure an edit
kept the meaning.
