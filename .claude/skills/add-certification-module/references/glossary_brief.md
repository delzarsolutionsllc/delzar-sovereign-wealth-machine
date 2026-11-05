# Glossary writer brief (Phase 6)

Fill in {FILE} (acronyms_a_d.json, acronyms_e_m.json, acronyms_n_z.json or vocabulary.json), {PART}, {KIND} (acronym or term) and {SCOPE} (the acronyms of that letter range from the official list, or the vocabulary scope with ~35 terms per domain). Say which multi-meaning acronyms need one entry per meaning.

---

You are writing part of the GLOSSARY for a free study app aligned to the {CERT} (e.g. CompTIA Security+ SY0-701) exam objectives (repo: <repo>/secplus_lab_engine, Python). Learners will study from it and be quizzed on it (acronym -> expansion, term -> definition, definition -> term), so accuracy matters more than anything. Do NOT commit and do NOT edit any file except the one you are told to write.

## Output
Write exactly one file: data/glossary/{FILE} with this shape (json, indent 2, ensure_ascii False, trailing newline):
{"part": "{PART}", "entries": [ ... ]}
Each entry:
{"term": "CASB", "kind": "{KIND}", "expansion": "Cloud Access Security Broker",
 "definition": "Original plain-English definition, 1-2 sentences, 12-45 words, that explains what it is AND what it is for in security. Must make sense on its own.",
 "domain": "3", "objectives": ["3.1", "4.5"]}
- kind "acronym": "expansion" is the official expansion as CompTIA writes it in the SY0-701 acronym list. kind "term": omit "expansion" (or null).
- "domain" = the ONE SY0-701 domain (1-5) where the learner meets it most; "objectives" = 1-3 SY0-701 objective codes (1.1-1.4, 2.1-2.5, 3.1-3.4, 4.1-4.9, 5.1-5.6) where it appears. Objective names are in tools/export_anki.py (OBJECTIVE_NAMES) if you need them.
- The definition must NOT contain the term itself or (for acronyms) the expanded words in a way that gives the answer away in a "which term matches this definition" quiz: e.g. for CASB do not write "A cloud access security broker is...". Describe it instead ("A policy enforcement point between users and cloud services that ...").
- Original wording only; do not copy from CompTIA, Professor Messer, Geekus Maximus, Wikipedia or study guides.
- Definitions must be distinct from each other (no two entries with near-identical definitions); where two acronyms are related (DHE vs ECDHE, RTO vs RPO, MTTR vs MTBF), say what distinguishes them.

## Scope
{SCOPE}

## Check
Write a small script in <scratchpad> (not the repo) that verifies: valid JSON; required fields; kind correct; domain in 1-5; objectives valid; definition 12-45 words; definition does not contain the term (case-insensitive, whole word) nor, for acronyms, more than one of the significant words of the expansion in sequence; no duplicate terms; terms sorted alphabetically (case-insensitive, digits first). Fix until clean. Then re-read every entry once as a strict Security+ reviewer and fix anything inaccurate.

## Report
Count of entries, count per domain, and any acronym you were unsure about (with why).
