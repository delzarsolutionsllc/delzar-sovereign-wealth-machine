# Roadmap

Built from `docs/PLATFORM_AUDIT.md` (where the platform is weak) and `docs/PRODUCT_PATHS.md` (where it could go). The recommended direction is to make it **your public IAM portfolio and an installable study app first**, keep it free, and grow it into an open-source project with an AI tutor. Selling it or running funded training programmes waits until you are working in IAM.

## Two dates that shape everything (OBSERVED, CompTIA, accessed 2026-11-05)

- **Security+ V8 (SY0-801)** launches on or around **November 17, 2026** ([source](https://www.comptia.org/en-us/certifications/security/v8/)).
- **SY0-701 (English) retires June 11, 2027** ([source](https://www.comptia.org/en-us/certifications/security/v7/)).

This platform teaches SY0-701, so you can take that exam any time before June 11, 2027. Once SY0-801's objectives are published, the content needs a V8 update (Phase 4).

## Phase 1: study smarter, and install it as an app (BUILT in this release)

| Scope | Success metric |
|---|---|
| **Installable offline app (PWA):** `python tools/build_site.py` writes a static site with a manifest, icons and a service worker. Chrome reports it installable, and it reloads with the network off. | Installs on phone and laptop; works in airplane mode |
| **Daily review (spaced repetition):** missed questions come back on a schedule (`utils/review.py`). The daily session starts with due reviews, then adds new questions from your weakest objectives. Web *Daily review* page; CLI `python main.py review`. | A 15-question daily session in under 15 minutes; exam misses reappear |
| **Real exam question types:** "Select TWO", plus performance-based questions (put steps in order, match items) in the exam bank and the practice exam. | Each exam includes some of the new types; they are scored all-or-nothing |
| **Fixes from the audit:** the CLI accepts A–D letter answers, and the app carries a "not affiliated with CompTIA" notice. | No silent wrong scoring |

## Phase 2: go public as your portfolio (BUILT, 2026-11-05)

Status: renamed to Delzar Certification Academy and published at https://delzarsolutionsllc.github.io/delzar-sovereign-wealth-machine/ (owner's go-ahead), progress export/import with merge, exam realism (no auto-advance, flag for review, question grid, review screen, "approximate" scaled score) and accessibility (skip link, live announcements, arrow-key tabs, focus management). Added at the owner's request: **objective quizzes**, 251 short quizzes across all 28 objectives (concept quizzes per topic plus mixed sets), backed by 550 new reviewed questions (bank: 946). Accessibility audit done 2026-11-05 (docs/ACCESSIBILITY.md): axe-core WCAG 2.2 AA, 0 violations on 22 screens in light and dark mode, keyboard, reflow and text-spacing checks. Still open: screen-reader passes on real devices (VoiceOver, TalkBack, NVDA).

| Scope | Success metric |
|---|---|
| **Rename** away from "Security+ …", as CompTIA's trademark rules require. Use a neutral product name and say "aligned to the CompTIA Security+ SY0-701 exam objectives". Add trademark notices to the app, README and site. | Name and pages pass CompTIA's trademark guidance |
| **Publish the PWA site** on GitHub Pages (free; 1 GB site limit) or Cloudflare Pages, and link the IAM labs' case studies. **This makes it public, so it needs your explicit go-ahead.** | A public HTTPS link on your résumé and LinkedIn |
| **Export and import your progress** (a file you can move between laptop, phone and the hosted page), with merge. | Switching devices keeps your history |
| **Exam realism:** flag-for-review, a question grid, no auto-advance, and "approximate" on the scaled score. | Feels like the Pearson VUE exam interface |
| **Accessibility:** `aria-live` announcements for verdicts and the timer, proper tabs with arrow keys, a skip link, and keeping focus after re-renders. | WCAG 2.2 AA keyboard and screen-reader checks pass |

## Phase 3: AI tutor and lab-based exam questions (BUILT, 2026-11-05)

Status: AI tutor MCP server (`python main.py mcp`, docs/AI_TUTOR.md) with deny-by-default scopes, hidden answers, schema validation and an audit log, tested with the official MCP SDK client; 25 lab-backed PBQs from 16 labs (`tools/build_lab_pbqs.py`, answers computed by the engines), including 2 for 4.2 and 4 for 4.7; every objective has 30+ items.

| Scope | Success metric |
|---|---|
| **MCP server / AI tutor:** expose `webapi` methods (catalog, run, challenge, case_study, review) as MCP tools with a fixed allow-list and deny by default. An AI assistant can then quiz you, explain a lab or plan your day. This doubles as an identity and authorization showcase. | Claude (or another MCP client) runs a lab and explains it |
| **PBQs from the labs:** turn firewall-rule, incident-order and Conditional Access decisions from the engines into exam performance-based questions. | 20+ lab-backed PBQs in the exam |
| **Content gaps:** DONE: every objective has 30+ exam-style items, tagged by topic, and 4.2 / 4.7 now have PBQs. Next: 2+ PBQs for every objective. | 2+ PBQs per objective |

## Multi-course platform and SC-300 (BUILT, 2026-11-05)

The engine is multi-course (`data/courses/<code>/course.json`, `--course`, course picker, per-course progress, data and desktop builds). Second course: **Microsoft SC-300 Identity and Access Administrator** (skills measured as of October 28, 2026; checked on Microsoft Learn 2026-11-05): 16 objectives, a reviewed exam-style bank with performance-based items, objective quizzes, glossary (acronyms + vocabulary) with per-domain quizzes, the identity labs mapped to SC-300 skills, 50-question / 100-minute practice exam on the 1-1000 scale. SC-300 labs added 2026-11-05: nine SC-300-only labs (27-35: entitlement management, app consent, workload identities, hybrid identity, identity monitoring, external identities, authentication methods, Global Secure Access, tenant delegation), so all 16 objectives have a hands-on lab; per-lab policy files in `config/policies/`, labs scoped to a course with `COURSES`. Next for SC-300: a free video course index and lab-backed PBQs from the new labs.

## Phase 4: V8 (SY0-801) update (after CompTIA publishes the objectives)

- Map SY0-801 objectives onto the labs and bank. Keep SY0-701 available until June 11, 2027, and label each question with its exam version.
- **Success:** every SY0-801 objective has a lab or question set by spring 2027.

## Phase 5: open source and community (optional)

- Choose a license, write a contributing guide and an errata process for questions, then add GitHub Sponsors.
- Treat sponsorship income as small: $0–$50 a month in year 1 (PROJECTED).
- **Success:** outside contributors fix or add questions; a "maintainer" line on your résumé.

## Deferred: paid product, and workforce or tribal training programmes

- Wait until you are employed in IAM and V8 content exists.
- **Paid course:** competes with free and low-cost prep, and carries trademark risk.
- **Approved training provider:** takes 3–12+ months, a $1,284 Oklahoma school licence fee plus a bond, insurance and CPA costs, and outcome reporting. Details and sources are in `docs/PRODUCT_PATHS.md`.
- A low-cost first step later: offer the labs as free supplementary material to an Oklahoma technology centre or a tribal career-services office.
