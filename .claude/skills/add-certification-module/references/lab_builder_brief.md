# Lab builder brief (Phase 5)

Fill in the `<...>` placeholders and give one copy to each parallel subagent. Used for SC-300 Labs 27-35.

---

You are building **Lab <NN>: <TITLE>** for Delzar Certification Academy, an offline training platform in
`/home/user/delzar-sovereign-wealth-machine/secplus_lab_engine/` (Python 3, standard library only, no network
calls, no new dependencies). The lab is part of the **<COURSE NAME> (<EXAM CODE>)** course and covers objectives
<OBJECTIVE CODES AND NAMES>.

## What the lab simulates
<2-6 sentences: the real job task, the decisions the engine makes, the outcome vocabulary.>

## Read first (do not edit)
- `labs/lab25_conditional_access.py` and `labs/lab26_identity_governance.py`: the contract and house style
  (module docstring = the lesson, `TITLE`, `OBJECTIVES`, `INSIGHT` dict with `objective`, `concepts`,
  `failure_modes`, `ai_governance`, `exam_tips`; `run_demo(ui, policies, data)`; `build_challenges(policies, data)`).
- `utils/challenge.py` (`Question`, `choices_with`), `utils/terminal_ui.py` (`UI`: `ui.section/table/bullet/status/print/insight`).
- `tests/test_lab26_identity_governance.py` and `data/briefings/lab26.json` for test and work-ticket style.

## Files you create (and only these; never edit any other file, never run git commands)
1. `labs/lab<NN>_<slug>.py`
   - Module docstring: lesson in plain English: `<EXAM CODE> objectives` list, `How it works` (numbered rules,
     in evaluation order), `Run it` (`python main.py --course <code> lab <NN>`).
   - `TITLE = "Lab <NN> — <Title>"`, `OBJECTIVES = "<EXAM CODE> <code> <short name> · <code> <short name>"`,
     `COURSES = ("<code>",)` (keeps the lab out of other courses).
   - Pure engine functions (no I/O, no printing), **deny by default**: missing or unknown input gives the
     safest outcome, with a reason saying so. Every result carries `reasons: list[str]`.
   - `run_demo(ui, policies, data) -> dict`: 2-4 `ui.section` steps with tables and reason bullets, then
     `ui.insight(INSIGHT)`; returns a JSON-safe summary dict (ids -> outcome, plus metrics).
   - `build_challenges(policies, data) -> list[Question]`: at least 12 questions, answers computed by the
     engine (never hard-coded where the engine decides), every `objective` one of <OBJECTIVE CODES>,
     choices unique, no bare-number choices, explanation from the engine's reasons. Mix: predict-the-outcome
     per scenario item, "which rule fired", concept questions from the policy's `concepts`.
   - `generate_scenario(rng, policies) -> dict`: a seeded random scenario in the same shape as the sample data
     (use only `rng`, never `random` directly, so a seed always gives the same data); include at least one item
     for every outcome when possible.
2. `data/sample_<slug>.json`: a realistic scenario with `"_description"`, 8-16 items that between them produce
   **every** outcome at least once and at least one tricky case per rule. Fictional company and people only.
3. `config/policies/lab<NN>.json`: `{"<policy_section>": {...}}`: thresholds, rule lists, `concepts`
   (term -> one-sentence original definition, 4-8 terms) and any definitions. The engine reads only
   `policies["<policy_section>"]`.
4. `data/briefings/lab<NN>.json`: same keys as `lab26.json` (`lab`, `ticket`, `type`, `priority`,
   `requested_by`, `title`, `situation`, `your_task`, `why_it_matters`, `done_when`, `glossary`, `job_roles`,
   `talking_point`). Plain English, every acronym expanded once. The `talking_point` numbers must match what
   `run_demo` prints for the sample data.
5. `tests/test_lab<NN>_<slug>.py`: at least 15 tests: each rule and outcome, deny-by-default on missing input,
   the sample data's expected outcomes, determinism of `generate_scenario` for a seed and that its output runs
   through `run_demo` and `build_challenges`, and that answering every challenge with its own answer scores 100 %.
   Load policies with `from utils.loader import load_policies` (it merges `config/policies/*.json`).

## Content rules
- Original content only. Use current product names (Microsoft Entra ID, not Azure AD, except when explaining
  the rename). Be technically accurate to Microsoft Learn documentation as of 2026; when unsure, keep the rule
  generic and say so in a code comment.
- Do not use the word "lab" inside questions or choices.

## Check before you finish
```
cd /home/user/delzar-sovereign-wealth-machine/secplus_lab_engine
python -m pytest tests/test_lab<NN>_<slug>.py -q
python - <<'EOF'
import random, json
from utils.loader import load_policies, load_json
from utils.terminal_ui import UI
from utils.challenge import run_challenge
import labs.lab<NN>_<slug> as m
pol = load_policies(); data = load_json("data/sample_<slug>.json")
s = m.run_demo(UI(plain=True), pol, data); json.dumps(s)
qs = m.build_challenges(pol, data); assert len(qs) >= 12
g = m.generate_scenario(random.Random(7), pol); assert g == m.generate_scenario(random.Random(7), pol)
m.run_demo(UI(plain=True), pol, g); m.build_challenges(pol, g)
print("OK", len(qs))
EOF
```
Then reply with: the files created, the outcome counts for the sample data, the briefing's talking point,
and anything you were unsure about (technical accuracy) for the owner to check.
