# Security+ SY0-701 Lab Engine & AI Agent Governor

An **offline, CLI-driven Python lab** for practising the manual security operations behind CompTIA Security+ SY0-701, from identity lifecycle and Zero Trust to log forensics, change control and **governing autonomous AI agents**.

It's meant for building first-principles skill: work through each operation by hand and see exactly where manual processes fail. Only then design the guardrails that automated agents must operate within.

* Pure Python 3.10+ standard library (`dataclasses`, `json`, `hashlib`, `hmac`, `argparse`, `logging`)
* `rich` is **optional** for coloured tables and panels. Without it you get clean plain-text output.
* No network, no API keys, no cloud services
* 81 pytest tests

---

## Install

```bash
cd secplus_lab_engine
python3 -m venv .venv && source .venv/bin/activate   # optional
pip install -r requirements.txt                       # rich + pytest (both optional for running labs)
```

## Usage

```bash
python main.py                       # interactive menu
python main.py list                  # list labs
python main.py lab 1                 # run a lab's example scenario
python main.py lab 3 --file my.json  # run a lab against your own scenario data
python main.py all                   # run all five labs
python main.py test                  # run the pytest suite  (= python -m pytest tests -q)
python main.py --plain lab 4         # plain text, no colour
python main.py --policies alt.json lab 2   # swap in a different policy file
```

Every lab finishes with an **Exam & Architectural Insight** panel, which covers:
* the SY0-701 objective
* key concepts
* manual failure modes
* how an AI agent should be governed in that scenario
* exam tips

---

## The labs

| # | Lab | SY0-701 | What you practise |
|---|-----|---------|-------------------|
| 1 | **Joiner-Mover-Leaver & Access Governance** (`labs/lab1_jml_governance.py`) | 4.6, 5.1, 2.4 | Provision from an HR feed; RBAC + ABAC (clearance, department, hours, status); privilege creep from sloppy movers and "temporary" grants; SoD scans (`po:create`+`po:approve`, ghost-vendor, etc.); leaver deprovisioning tickets with SLA (P1 for termination-for-cause); access recertification |
| 2 | **Zero Trust Access Evaluator** (`labs/lab2_zero_trust_evaluator.py`) | 1.2, 4.6 | **Policy Engine** trust scoring (device posture, IP reputation, MFA, geo, time, user risk) → ALLOW / STEP_UP / DENY; **Policy Administrator** mints short-lived HMAC-signed scoped tokens and revokes them; **PEP** blocks expired, forged, revoked, out-of-scope and token-less requests |
| 3 | **Log Forensic Inspector & Hash Verifier** (`labs/lab3_log_inspector.py`) | 4.9, 2.4, 1.4, 4.8 | Parse firewall / Windows Event / web / EDR lines into one schema; detect brute force (4625→4624), password spray, impossible travel, port scans, SQLi, TI matches (IP/UA/hash), Event 1102 log clearing, logging gaps; extract IOCs; seal evidence with a **salted SHA-256 hash chain + HMAC manifest** and detect edited, deleted, injected lines or a forged manifest |
| 4 | **Change Control & Impact Analyzer** (`labs/lab4_change_management.py`) | 1.3, 5.1 | CAB pre-review: maintenance windows & blackout dates, quorum and self-approval, staging tests, dependency **blast radius**, legacy breakage (e.g. disabling TLS 1.0), deny-list fallout; backout validation; auto-generated rollback runbooks; **rollback vs fail-forward**; *executes* each change in a sandbox, injects a failure and proves the backout restores state |
| 5 | **AI Agent Supervisor & Guardrail Governor** (`labs/lab5_ai_agent_governor.py`) | 4.7, 4.6, 1.3, 5.1 | Every agent action → ALLOW / REQUIRE_HUMAN_APPROVAL / BLOCK. Checks: least-privilege allow-lists, hallucinated assets/patches/CAB tickets, immutable firewall rule 0, admin grants without CAB, self-escalation, protected controls (MFA/EDR/audit), dangerous commands, prompt injection, rate limits, kill-switch quarantine, human-in-the-loop override rules and a tamper-evident decision ledger |

---

## Project layout

```
secplus_lab_engine/
├── main.py                       # CLI entrypoint & interactive menu
├── config/default_policies.json  # RBAC/SoD, Zero Trust weights, TI feed, CMDB, AI guardrails
├── data/
│   ├── sample_identities.json      # Lab 1 HR feed + access checks
│   ├── sample_access_requests.json # Lab 2 requests + PEP attack cases
│   ├── sample_logs.json            # Lab 3 raw multi-source log stream + offline GeoIP
│   ├── sample_rfcs.json            # Lab 4 change requests
│   └── sample_agent_actions.json   # Lab 5 agent proposals + human reviews
├── labs/                         # one module per lab (+ registry in __init__.py)
├── utils/
│   ├── crypto_helpers.py         # SHA-256, salting, PBKDF2, HMAC, hash chains
│   ├── terminal_ui.py            # rich / plain-text rendering, Insight panel
│   └── loader.py                 # config & data loading
└── tests/test_labs.py            # pytest suite
```

## Practise with your own scenarios

The labs are data-driven, so the best way to learn is to **break the sample data and predict the outcome before you run it**:

* **Lab 1**: Set a mover's `revoke_previous` to `true`. Does the SoD conflict disappear?
* **Lab 2**: Lower `thresholds.step_up` or change the `weights` in `config/default_policies.json`. Which requests flip?
* **Lab 3**: Add your own lines to `raw_stream` (format: `<ISO8601> <host> <source> key=value ...`). Can you evade the brute-force rule? What would catch you?
* **Lab 4**: Add `"compensating_controls": {"erp-legacy": "TLS proxy"}` to RFC-0412 and watch the decision change.
* **Lab 5**: Write an agent action that gets past every guardrail while still being harmful. Then add the check that stops it.

Then run your changes with `python main.py lab N --file your_copy.json`.

> All data is fictional and the signing keys are lab-only placeholders. This is a training simulator, not a production security control.
