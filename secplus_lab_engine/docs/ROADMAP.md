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

## Phase 2: go public as your portfolio (needs your yes; about 1–2 days)

| Scope | Success metric |
|---|---|
| **Rename** away from "Security+ …", as CompTIA's trademark rules require. Use a neutral product name and say "aligned to the CompTIA Security+ SY0-701 exam objectives". Add trademark notices to the app, README and site. | Name and pages pass CompTIA's trademark guidance |
| **Publish the PWA site** on GitHub Pages (free; 1 GB site limit) or Cloudflare Pages, and link the IAM labs' case studies. **This makes it public, so it needs your explicit go-ahead.** | A public HTTPS link on your résumé and LinkedIn |
| **Export and import your progress** (a file you can move between laptop, phone and the hosted page), with merge. | Switching devices keeps your history |
| **Exam realism:** flag-for-review, a question grid, no auto-advance, and "approximate" on the scaled score. | Feels like the Pearson VUE exam interface |
| **Accessibility:** `aria-live` announcements for verdicts and the timer, proper tabs with arrow keys, a skip link, and keeping focus after re-renders. | WCAG 2.2 AA keyboard and screen-reader checks pass |

## Phase 3: AI tutor and lab-based exam questions (about 3–5 days)

| Scope | Success metric |
|---|---|
| **MCP server / AI tutor:** expose `webapi` methods (catalog, run, challenge, case_study, review) as MCP tools with a fixed allow-list and deny by default. An AI assistant can then quiz you, explain a lab or plan your day. This doubles as an identity and authorization showcase. | Claude (or another MCP client) runs a lab and explains it |
| **PBQs from the labs:** turn firewall-rule, incident-order and Conditional Access decisions from the engines into exam performance-based questions. | 20+ lab-backed PBQs in the exam |
| **Content gaps:** more items on the thinnest objectives (1.3, 4.2, 4.7 and 4.9 have 8 each), plus topics with no question yet (TACACS+, DNS sinkhole, Bluetooth attacks). | At least 12 exam-style items per objective |

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
