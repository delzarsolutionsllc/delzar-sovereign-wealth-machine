# Security+ SY0-701 Lab Engine & AI Agent Governor

An **offline, CLI-driven Python lab** for practising the manual security operations behind CompTIA Security+ SY0-701, from identity lifecycle and Zero Trust to log forensics, change control and **governing autonomous AI agents**.

It's meant for building first-principles skill: work through each operation by hand and see exactly where manual processes fail. Only then design the guardrails that automated agents must operate within.

* Pure Python 3.10+ standard library (`dataclasses`, `json`, `hashlib`, `hmac`, `argparse`, `logging`)
* `rich` is **optional** for coloured tables and panels. Without it you get clean plain-text output.
* No network, no API keys, no cloud services
* 119 pytest tests, run in CI on Python 3.10–3.13

---

> **Technical handbook:** [`docs/HANDBOOK.pdf`](docs/HANDBOOK.pdf) explains the architecture, every lab's decision logic, the data formats and how to extend the engine. It includes a ready-to-paste prompt for another AI. To regenerate it from `docs/handbook.html`, run `NODE_PATH=$(npm root -g) node docs/render_handbook.js "$PWD/docs/handbook.html" docs/HANDBOOK.pdf` (needs Playwright).

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
python main.py all                   # run all eight labs
python main.py challenge 4           # quiz mode: predict each verdict before it is revealed
python main.py challenge all         # quiz every lab
python main.py lab 4 --challenge     # same as "challenge 4"
python main.py progress              # your scores per SY0-701 objective, weakest first
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

### Challenge mode

Watching a lab run teaches less than predicting it. `challenge N` turns that lab's scenarios into multiple-choice questions, for example:
* "ALLOW, STEP_UP or DENY?"
* "What should the CAB decide?"
* "What is the ALE?"
* "Which phase is this?"

You answer, and the engine reveals its own verdict with the reasoning. The questions are **computed from the engines**, so if you edit the policies or data, the right answers change too. Scores are saved per objective in `progress.json` (git-ignored), and `python main.py progress` lists your weakest areas first.

---

## The labs

| # | Lab | SY0-701 | What you practise |
|---|-----|---------|-------------------|
| 1 | **Joiner-Mover-Leaver & Access Governance** (`labs/lab1_jml_governance.py`) | 4.6, 5.1, 2.4 | Provision from an HR feed; RBAC + ABAC (clearance, department, hours, status); privilege creep from sloppy movers and "temporary" grants; SoD scans (`po:create`+`po:approve`, ghost-vendor, etc.); leaver deprovisioning tickets with SLA (P1 for termination-for-cause); access recertification |
| 2 | **Zero Trust Access Evaluator** (`labs/lab2_zero_trust_evaluator.py`) | 1.2, 4.6 | **Policy Engine** trust scoring (device posture, IP reputation, MFA, geo, time, user risk) → ALLOW / STEP_UP / DENY; adaptive step-up MFA (fixes *who*, not an unhealthy device); **Policy Administrator** mints short-lived HMAC-signed scoped tokens and revokes them; **PEP** blocks expired, forged, revoked, out-of-scope and token-less requests |
| 3 | **Log Forensic Inspector & Hash Verifier** (`labs/lab3_log_inspector.py`) | 4.9, 2.4, 1.4, 4.8 | Parse firewall / Windows Event / web / EDR lines into one schema; detect brute force (4625→4624), password spray, impossible travel, port scans, SQLi, TI matches (IP/UA/hash), Event 1102 log clearing, logging gaps; extract IOCs; seal evidence with a **salted SHA-256 hash chain + HMAC manifest** and detect edited, deleted, injected lines or a forged manifest |
| 4 | **Change Control & Impact Analyzer** (`labs/lab4_change_management.py`) | 1.3, 5.1 | CAB pre-review: maintenance windows & blackout dates, quorum and self-approval, staging tests, dependency **blast radius**, legacy breakage (e.g. disabling TLS 1.0), deny-list fallout; backout validation; auto-generated rollback runbooks; **rollback vs fail-forward**; *executes* each change in a sandbox, injects a failure and proves the backout restores state |
| 5 | **AI Agent Supervisor & Guardrail Governor** (`labs/lab5_ai_agent_governor.py`) | 4.7, 4.6, 1.3, 5.1 | Every agent action → ALLOW / REQUIRE_HUMAN_APPROVAL / BLOCK. Checks: least-privilege allow-lists, hallucinated assets/patches/CAB tickets, immutable firewall rule 0, admin grants without CAB, self-escalation, protected controls (MFA/EDR/audit), dangerous commands, prompt injection, rate limits, kill-switch quarantine, human-in-the-loop override rules and a tamper-evident decision ledger |
| 6 | **Risk Management Calculator & BIA** (`labs/lab6_risk_management.py`) | 5.2 | SLE = AV × EF, ALE = SLE × ARO; cost-benefit of mitigate / transfer / avoid vs. risk appetite → ACCEPT / MITIGATE / TRANSFER / AVOID / EXCEPTION; 5×5 heat map; BIA checks of backup interval vs RPO, restore time vs RTO, availability from MTBF/MTTR |
| 7 | **Incident Response Runner & Chain of Custody** (`labs/lab7_incident_response.py`) | 4.8, 4.9 | Grades an ordered response playbook: lifecycle order, order of volatility (RFC 3227), evidence destroyed by power-off/reimage, prerequisites (legal hold before reimage), unhashed evidence; builds a hash-chained custody ledger. Rookie vs expert comparison |
| 8 | **End-to-End SOC Pipeline** (`labs/lab8_soc_pipeline.py`) | 4.7, 4.8, 1.3, 4.6, 1.2 | Lab 3 detections → simulated AI SOC agent proposals → Lab 5 Governor → human review → execution through the owning control: Lab 1 account suspension + Lab 2 session revocation, Lab 4 emergency RFC for IP blocks, Lab 7 evidence capture before host isolation. Includes an agent overreach that gets blocked and a false positive a human rejects |
| 9 | **Vulnerability Triage & Remediation** (`labs/lab9_vulnerability_triage.py`) | 4.3, 2.3 | Priority = CVSS × CMDB criticality × KEV × exposure → P1–P4 with SLAs (KEV capped at 14 days); overdue tracking; unknown assets scored worst-case; exceptions validated (authorised approver, expiry, ≤180 days, residual after compensating controls); vulnerability-type classification |
| 10 | **Email Security Analyzer** (`labs/lab10_email_security.py`) | 4.5, 2.2 | Parses raw RFC 5322 mail; recomputes SPF (IP vs record, `include:`), DKIM (real body hash vs `bh=`, published selector) and DMARC alignment against an offline DNS table; never trusts sender-supplied `Authentication-Results`; scores lookalike domains, executive/brand display-name impersonation, Reply-To mismatch, pressure language, risky links and double-extension attachments → DELIVER / BANNER / QUARANTINE / REJECT + attack category |
| 11 | **Firewall Rule & Segmentation Auditor** (`labs/lab11_firewall_auditor.py`) | 3.2, 4.5 | Models every rule as a set (zones/CIDRs × protocol × port ranges) and proves SHADOWED / REDUNDANT rules by coverage; flags any/any, any-service, segmentation-policy violations (e.g. internet → internal, DMZ → internal), cleartext/remote-admin exposure, overly broad CIDRs, missing explicit default deny, unlogged denies and undocumented rules; scores 0–100 with a fix for each finding (current edge-fw = F, remediated = A) |
| 12 | **Secure Baseline & Hardening Checker** (`labs/lab12_baseline_checker.py`) | 4.1 | CIS-style Windows/Linux baselines as data (`eq/ge/le/between/includes/excludes`, fail-closed on unknown operators or types); PASS / FAIL / MISSING (unreported = non-compliant) / EXCEPTION (ticketed, unexpired); severity-weighted compliance with "no high failures" rule; drift vs the last approved scan (regressed / remediated); remediation commands per check |
| 13 | **Threat Actor & Attack Vector Classifier** (`labs/lab13_threat_classifier.py`) | 2.1, 2.2, 2.5 | Weighted indicator scoring picks the actor (nation-state, organized crime, hacktivist, insider, unskilled attacker, shadow IT) only when it wins by a configured margin, otherwise "Undetermined"; ordered motivation rules (blackmail before generic financial gain); initial-access indicator → 2.2 vector → primary 2.5 mitigation plus an actor-specific add-on |
| 14 | **Resilience & Recovery Planner** (`labs/lab14_resilience_planner.py`) | 3.4 | Computes achieved RTO/RPO for host failure (clustering failover vs rebuild + full/differential/incremental restore) and site loss (offsite copy + hot/warm/cold site, replication); checks RAID fault tolerance, UPS + generator runtime and restore/DR test currency; recommends the cheapest catalog option that closes each gap |

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
│   ├── sample_agent_actions.json   # Lab 5 agent proposals + human reviews
│   ├── sample_risks.json           # Lab 6 risk scenarios + BIA targets
│   ├── sample_incident.json        # Lab 7 incident, action catalog, rookie/expert playbooks
│   └── sample_pipeline.json        # Lab 8 directory, live sessions, simulated human decisions
├── labs/                         # one module per lab (+ registry in __init__.py)
├── utils/
│   ├── crypto_helpers.py         # SHA-256, salting, PBKDF2, HMAC, hash chains
│   ├── challenge.py              # challenge mode + progress.json tracking
│   ├── terminal_ui.py            # rich / plain-text rendering, Insight panel
│   └── loader.py                 # config & data loading
└── tests/                        # pytest suite (test_labs.py, test_extensions.py)
```

## Practise with your own scenarios

The labs are data-driven, so the best way to learn is to **break the sample data and predict the outcome before you run it**:

* **Lab 1**: Set a mover's `revoke_previous` to `true`. Does the SoD conflict disappear?
* **Lab 2**: Lower `thresholds.step_up` or change the `weights` in `config/default_policies.json`. Which requests flip?
* **Lab 3**: Add your own lines to `raw_stream` (format: `<ISO8601> <host> <source> key=value ...`). Can you evade the brute-force rule? What would catch you?
* **Lab 4**: Add `"compensating_controls": {"erp-legacy": "TLS proxy"}` to RFC-0412 and watch the decision change.
* **Lab 5**: Write an agent action that gets past every guardrail while still being harmful. Then add the check that stops it.
* **Lab 6**: Raise R-03's flood ARO to 0.1. Does insurance still beat relocation?
* **Lab 7**: Write your own playbook into `playbooks` and try to score 100. Then remove `legal_hold` and see what breaks.
* **Lab 8**: Empty `human_reviews` and watch every user-impacting action wait in the queue. Replace `soc_agent_propose()` with your own logic (or a real model) and see which guardrails it trips.

Then run your changes with `python main.py lab N --file your_copy.json`.

> All data is fictional and the signing keys are lab-only placeholders. This is a training simulator, not a production security control.
