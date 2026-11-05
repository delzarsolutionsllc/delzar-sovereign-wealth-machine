# Security+ SY0-701 Lab Engine & AI Agent Governor

An **offline, CLI-driven Python lab** for practising the manual security operations behind CompTIA Security+ SY0-701, across **all five exam domains**: identity, Zero Trust, log forensics, change control, vulnerability triage, email security, firewall auditing, hardening, threat actors, resilience, vendor risk, control types, and **governing autonomous AI agents**.

It's meant for building first-principles skill: work through each operation by hand and see exactly where manual processes fail. Only then design the guardrails that automated agents must operate within.

* Pure Python 3.10+ standard library (`dataclasses`, `json`, `hashlib`, `hmac`, `argparse`, `logging`)
* `rich` is **optional** for coloured tables and panels. Without it you get clean plain-text output.
* No network, no API keys, no cloud services
* 26 labs (every SY0-701 objective has one, plus two identity-governance labs for an IAM career), a random scenario generator, a timed, domain-weighted practice exam, and a **test for each of the five domains** (questions spread across that domain's objectives, scored per objective)
* **396 exam-style practice questions** (`data/exam_bank/`): 364 four-option questions plus 32 in the exam's other formats (**Select TWO**, and performance-based **put-in-order** and **match** questions) for the exams and domain tests. They use short workplace scenarios in plain language, four options, BEST / MOST likely / FIRST qualifiers and an explanation for each. They are original, written in the style of SY0-701 (not real exam questions), and every one was checked by an independent reviewer
* A **course web app** you can open from your desktop or from claude.ai
* **Daily review**: questions you miss come back on a spaced-repetition schedule (tomorrow, then 1, 3, 7 days and longer), plus new questions from your weakest objectives (`python main.py review` or the *Daily review* page)
* **Installs as an app** on phone and laptop and works offline (`python tools/build_site.py`, see below)
* 1,000+ pytest tests, run in CI on Python 3.10–3.13

> Independent study project, not affiliated with or endorsed by CompTIA. CompTIA and Security+ are trademarks of CompTIA, Inc.; Microsoft, Entra and SailPoint are trademarks of their owners. Practice questions are original and are not real exam questions.

**Heads-up on exam versions:** CompTIA says Security+ V8 (SY0-801) launches on or around November 17, 2026, and the English SY0-701 exam (what this platform teaches) retires on June 11, 2027 ([V8](https://www.comptia.org/en-us/certifications/security/v8/), [SY0-701](https://www.comptia.org/en-us/certifications/security/v7/), checked 2026-11-05). See `docs/ROADMAP.md` for the plan, `docs/PLATFORM_AUDIT.md` for an honest audit and `docs/PRODUCT_PATHS.md` for ways to turn this into a site, app or product.

---

## Open it as an app

**On your computer (offline, live engine):**

1. Install Python 3.10+ ([python.org](https://www.python.org/downloads/)) and download this repository (GitHub → *Code* → *Download ZIP*, then unzip).
2. Double-click the launcher for your system in `launch/`:
   * Windows: `Start Security+ Lab (Windows).bat`
   * macOS: `Start Security+ Lab (macOS).command` (first time: right-click → *Open*)
   * Linux: `launch/start-secplus-lab.sh`
3. Your browser opens the course. Keep the small terminal window open while you study; close it to stop.

To put a launcher **on your desktop**, run once from this folder:

```bash
python main.py install-shortcut     # creates "Security+ Lab Engine" on your desktop
python main.py web                  # or start it directly
```

**Install it as an app (phone or laptop, works offline):**

```bash
python tools/build_site.py                       # writes the app to dist/site/
python -m http.server -d dist/site 8000          # then open http://localhost:8000
```

In Chrome or Edge, click the *Install* icon in the address bar (on Android: menu → *Install app*; on iPhone, Safari: Share → *Add to Home Screen*). Installing needs a web address (localhost or HTTPS), not a double-clicked file. To use it on your phone, put `dist/site/` on free static hosting such as GitHub Pages or Cloudflare Pages. **That makes it public**, so do it only when you decide to (see `docs/ROADMAP.md`, Phase 2). Progress is saved in each browser.

**Hosted (no Python needed):** the same app is published as a private page on claude.ai, using a pre-built course bundle (`web/course_data.json`). After changing labs, data or policies, rebuild it with `python tools/build_web_bundle.py`.

**On-the-job format and your IAM portfolio:** every lab opens with a plain-English **work ticket** from a fictional colleague (the situation, your task, why it matters, done-when criteria, a glossary and the job titles that do this work) and ends with a one-page **Case study** tab you can screenshot or save as a PDF. The **IAM career & portfolio** page maps the labs to Microsoft SC-300 skill areas and SailPoint-style identity-governance concepts (lead with Labs 1, 2, 25 and 26), with a screenshot and screen-recording guide and Oklahoma/remote job-search tips. `python main.py case-study --all` writes every case study as Markdown + HTML to `dist/portfolio/` for a GitHub portfolio. Everything is clearly labelled as a simulated lab with fictional data.

**Video course:** the app's *Video course* page (or `python main.py videos`) lays out [Professor Messer's free SY0-701 course](https://www.youtube.com/playlist?list=PLG49S3nxzAnl4QDVqK-hOnoqcSKEIDDuv) (121 videos, about 15 hours) in exam-objective order. Next to each objective it names the lab that practises it. Each lab's Lesson tab starts with a "Watch first" list, *My progress* suggests videos for your weakest objectives, and you can tick videos off as you watch them. Flashcards and CTFd hints link the matching video. The videos stay on YouTube: the course stores only titles, IDs and lengths (`data/video_course.json`). CLI: `python main.py videos [--lab N | --objective 1.4 | --open N | --mark ID]`.

**Flashcards on your phone:** `python tools/export_anki.py` writes `dist/SecurityPlus_SY0-701.apkg`, about 3,900 cards (lab questions plus the exam-style bank) sorted into decks by domain and objective. Import it into the free Anki app ([apps.ankiweb.net](https://apps.ankiweb.net), AnkiMobile or AnkiDroid) for spaced-repetition review. Re-importing a newer export updates your cards and keeps your review history.

**Your own scoreboard (CTFd):** `python tools/export_ctfd.py` turns every challenge question into a scored [CTFd](https://github.com/CTFd/CTFd) challenge (about 990: lab questions plus the exam-style bank, 100 points each), with the five exam domains as categories so the scoreboard shows your strength per domain. It writes `dist/ctfd/challenges.csv` and `dist/ctfd/challenges/*/challenge.yml` (for ctfcli). To play:

```
docker run -p 8000:8000 ctfd/ctfd          # then open http://localhost:8000 and finish setup
# Admin Panel -> Config -> Backup -> Import CSV -> type "Challenges" -> dist/ctfd/challenges.csv
```

Submit the letter or the answer text. Each challenge has a free hint that points to its lab and a 25-point hint that shows the explanation. Options: `--variants 3` adds generated scenarios, `--attempts`, `--points`, `--hint-cost`, and `--mc-plugin` for hosted CTFd's multiple-choice type. Full steps are in `dist/ctfd/README.txt`.

Inside the app every lab has three tabs: **Lesson**, **Run the scenario** and **Practice** (instant feedback; number keys answer). There's also a timed **Practice exam** and **My progress**, which lists your weakest objectives first.

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
python main.py all                   # run all 24 labs
python main.py challenge 4           # quiz mode: predict each verdict before it is revealed
python main.py challenge all         # quiz every lab
python main.py lab 4 --challenge     # same as "challenge 4"
python main.py progress              # your scores per SY0-701 objective, weakest first
python main.py videos                # Professor Messer's free video course, mapped to the labs (--lab N, --open N, --mark ID)
python main.py challenge 9 --random  # quiz on a freshly generated scenario (labs 2, 6, 9, 11–15, 17–24)
python main.py lab 12 --random --seed 7   # run a lab on a generated scenario (same seed = same scenario)
python main.py exam                  # 90 exam-style questions / 90 minutes, weighted 12/22/18/28/20 % by domain
python main.py exam --source labs    # the same, using the labs' hands-on scenario questions instead
python main.py exam --count 30 --minutes 30 --seed 3
python main.py exam --domain 4         # domain test: 30 questions from Domain 4 only, scored per objective (target 80%)
python main.py review                # today's daily review: due questions first, then your weakest objectives
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
| 15 | **Third-Party / Vendor Risk Assessor** (`labs/lab15_vendor_risk.py`) | 5.3 | Inherent risk = data sensitivity × access level × criticality; weighted questionnaire (unanswered = no) reduces it to residual risk; required clauses depend on exposure (MSA/NDA, SLA, right-to-audit, breach notification, DPA, security schedule, BPA); hard REJECT for unverifiable sensitive vendors and undisclosed conflicts of interest; SLA uptime/notification checks; monitoring cadence; agreement-type (SLA/MSA/SOW/NDA/MOU/MOA/BPA) drills |
| 16 | **Security Control Classifier** (`labs/lab16_control_classifier.py`) | 1.1 | Classifies control descriptions by category (technical/managerial/operational/physical) and type (preventive/detective/corrective/deterrent/compensating/directive) with whole-word weighted phrases; a unique winner is required, otherwise "Unclassified"; shows evidence and agreement with an answer key (19/19 on the sample) |
| 17 | **PKI & Certificate Validator** (`labs/lab17_pki_validator.py`) | 1.4 | Browser-style TLS chain validation: path building + CA flags + trusted roots (incomplete chain, self-signed, untrusted root, leaf-as-CA), validity windows and 398-day limit, SAN/wildcard hostname matching (one label only), key length and SHA-2 signatures, serverAuth EKU, CRL/OCSP revocation with soft/hard-fail policy, SPKI pinning (detects TLS interception); generator applies random faults to healthy chains |
| 18 | **Data Protection & DLP Gate** (`labs/lab18_data_protection.py`) | 3.3, 4.5, 5.4 | Scans outbound data flows for PII, card numbers (Luhn-checked), secrets and trade-secret/IP/legal markings; raises the label to the effective classification; ALLOW / ALLOW_WITH_PROTECTION (mask, tokenize, encrypt, hash) / BLOCK by destination, region, data sovereignty and state of data |
| 19 | **SIEM Correlation & Alert Tuning** (`labs/lab19_siem_alerting.py`) | 4.4, 4.9 | Correlates auth/firewall/EDR/DNS/app events (brute force, spraying, impossible travel, after-hours privilege, log-source silence, threat intel, port scan, malware); owned, expiring suppressions (critical never suppressed); response per alert; precision/recall before and after tuning |
| 20 | **Cloud Architecture & IaC Gate** (`labs/lab20_iac_scanner.py`) | 3.1, 3.3, 4.1, 4.6 | Policy-as-code scan of a Terraform-like plan (public buckets, internet-open admin ports, unencrypted data, IAM `*` on `*`, privileged containers, single-AZ critical resources, missing tags, unreviewed types) → BLOCK / WARN / PASS with a fix per finding; shared-responsibility matrix and architecture-model trade-offs |
| 21 | **Asset Inventory & Secure Disposal** (`labs/lab21_asset_management.py`) | 4.2, 3.3, 4.5 | Reconciles the CMDB against a discovery scan (unmanaged / missing / no owner / unclassified); approves or rejects media disposal with NIST SP 800-88 Clear/Purge/Destroy, media-method fit, certificates of destruction, legal hold and retention |
| 22 | **Compliance & Privacy Tracker** (`labs/lab22_compliance_privacy.py`) | 5.4, 5.1 | Data subject requests, breach notifications, retention and attestations against configurable (illustrative) deadlines → COMPLIANT / AT_RISK / NON_COMPLIANT / EXEMPT, with consequence and internal/external reporting; controller vs processor |
| 23 | **Pen-Test RoE Gate & Audit Planner** (`labs/lab23_audit_roe.py`) | 5.5, 4.3, 5.3 | Gates each planned pen-test action against the signed rules of engagement (authorization, scope, prohibited/unknown techniques, window, passive-recon rule) → ALLOW / NEEDS_APPROVAL / BLOCK; maps assessment needs to internal audit, self-assessment, examination, third-party audit or attestation |
| 24 | **Security Awareness Analyzer** (`labs/lab24_awareness.py`) | 5.6, 2.2 | Phishing-simulation outcomes and training actions per employee and department, program KPIs, anomalous-behaviour classification (risky / unexpected / unintentional) and phishing-indicator checks on messages |
| 25 | **Conditional Access & Just-in-Time Privileged Access** (`labs/lab25_conditional_access.py`) | 4.6, 1.2, 2.4 | Evaluates sign-ins against Conditional-Access-style policies (any block wins, otherwise every applicable policy's controls must be met, exclusions win, report-only is logged, deny-by-default for sensitive apps) and decides just-in-time admin role activations (eligibility, max duration, justification, ticket, MFA, approval, no self-approval); flags standing admin rights and mis-configured break-glass accounts. The SC-300 core |
| 26 | **Identity Governance: Reconciliation & Access Certification** (`labs/lab26_identity_governance.py`) | 4.6, 5.1, 4.2 | Correlates application accounts to the HR source (orphaned, terminated-with-access, dormant, duplicate, unowned privileged accounts), then runs an access-review campaign (self-review, SoD, comments on high-risk approvals, rubber-stamp detection, no decision means revoke) and produces a de-provisioning list. The SailPoint-style IGA core |

---

## Project layout

```
secplus_lab_engine/
├── main.py                       # CLI entrypoint & interactive menu
├── config/default_policies.json  # all policy: RBAC/SoD, Zero Trust, TI feed, CMDB, AI guardrails, baselines, catalogs…
├── data/
│   ├── sample_identities.json      # Lab 1 HR feed + access checks
│   ├── sample_access_requests.json # Lab 2 requests + PEP attack cases
│   ├── sample_logs.json            # Lab 3 raw multi-source log stream + offline GeoIP
│   ├── sample_rfcs.json            # Lab 4 change requests
│   ├── sample_agent_actions.json   # Lab 5 agent proposals + human reviews
│   ├── sample_risks.json           # Lab 6 risk scenarios + BIA targets
│   ├── sample_incident.json        # Lab 7 incident, action catalog, rookie/expert playbooks
│   ├── sample_pipeline.json        # Lab 8 directory, live sessions, simulated human decisions
│   ├── sample_vulns.json           # Lab 9 scan findings + exceptions
│   ├── sample_emails.json          # Lab 10 raw messages + offline DNS (SPF/DMARC/DKIM keys)
│   ├── sample_firewall.json        # Lab 11 current vs remediated rule sets
│   ├── sample_hosts.json           # Lab 12 host config snapshots + previous scan
│   ├── sample_threat_scenarios.json # Lab 13 incident scenarios with indicators
│   ├── sample_resilience.json      # Lab 14 systems: RTO/RPO targets vs current design
│   ├── sample_vendors.json         # Lab 15 vendor questionnaires + contracts
│   ├── sample_controls.json        # Lab 16 control descriptions + answer key
│   ├── sample_certificates.json    # Lab 17 TLS chains + CRL/OCSP data
│   ├── sample_data_flows.json      # Lab 18 outbound data flows for the DLP gate
│   ├── sample_security_events.json # Lab 19 SIEM events, suppressions, ground truth
│   ├── sample_iac.json             # Lab 20 Terraform-like cloud plan
│   ├── sample_assets.json          # Lab 21 CMDB, discovery scan, disposal requests
│   ├── sample_privacy_cases.json   # Lab 22 DSRs, breaches, retention, attestations
│   ├── sample_engagement.json      # Lab 23 pen-test RoE + planned actions + audit needs
│   ├── sample_awareness.json       # Lab 24 phishing simulation, behaviours, messages
│   ├── sample_signins.json         # Lab 25 conditional access policies, sign-ins, admin role requests
│   ├── sample_governance.json      # Lab 26 HR source, app accounts, access-review campaign
│   ├── briefings/labNN.json        # plain-English work ticket for each lab
│   ├── career_tracks.json          # IAM career path: SC-300 / SailPoint skill areas -> labs
│   ├── exam_bank/domainN.json      # 364 exam-style practice questions
│   └── video_course.json           # Professor Messer video index (titles/IDs only)
├── labs/                         # one module per lab (+ registry in __init__.py)
├── utils/
│   ├── crypto_helpers.py         # SHA-256, salting, PBKDF2, HMAC, hash chains
│   ├── challenge.py              # challenge mode + progress.json tracking
│   ├── scenario_generator.py     # seeded random scenarios (--random)
│   ├── exam.py                   # timed, domain-weighted practice exam + per-domain tests
│   ├── webserver.py              # local server for the web app (127.0.0.1 only)
│   ├── desktop.py                # desktop shortcut installer
│   ├── terminal_ui.py            # rich / plain-text rendering, Insight panel
│   └── loader.py                 # config & data loading
├── webapi.py                     # JSON API shared by the local server and the bundle builder
├── web/                          # index.html (course app) + course_data.json (hosted bundle)
├── tools/build_web_bundle.py     # rebuilds web/course_data.json
├── launch/                       # double-click launchers for Windows / macOS / Linux
├── docs/                         # HANDBOOK.pdf (+ HTML source and render script)
└── tests/                        # pytest suite: one file per lab 9–24, web app, generator/exam, labs 1–8
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

* **Lab 9**: Make `ws-9999` a CMDB asset with criticality 1. Does it drop out of P1?
* **Lab 10**: Change E-02's DKIM selector to one that isn't published. Which verdict flips, and why does SPF not save it?
* **Lab 11**: Move rule 4 (the Tor block) above rule 1. Which finding disappears?
* **Lab 13**: Give T-07 the indicator `political_message`. Is the actor still decisive?
* **Lab 17**: Set `revocation_hard_fail` to `true`. Which connection flips to UNTRUSTED, and why is soft-fail risky?
* **Lab 18**: Change DF-4's destination region to `us`. Does the SSN-bearing backup pass now, and which protection rule still applies at rest?
* **Lab 19**: Remove the owner from SUP-1. Why does the scanner alert come back, and what does that do to precision?
* **Lab 20**: Fix every critical finding. Is the plan now WARN or BLOCK, and how does `max_high_before_block` decide?
* **Lab 21**: Try `degauss` on an HDD that is leaving the organisation with restricted data. Why is Purge not enough?
* **Lab 23**: Add `web_app_test` to the allowed techniques. Which action changes from NEEDS_APPROVAL to ALLOW?

Then run your changes with `python main.py lab N --file your_copy.json`.

> All data is fictional and the signing keys are lab-only placeholders. This is a training simulator, not a production security control.
