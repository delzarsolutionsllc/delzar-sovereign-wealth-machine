# Product paths for the Lab Engine

This note compares six ways to turn the Lab Engine into something useful beyond the owner's own study: a personal app, a website, an open-source project, a paid product, a workforce training program, or an AI tutor. It then recommends one main path and one backup path.

**How to read it.** Every outside fact (a price, a fee, a limit, a date) has a source link. All sources were accessed on **2026-11-05**. Facts taken from a source are marked **OBSERVED**. Estimates are marked **PROJECTED**. Nothing was bought or signed up for.

**What the platform is (from the repo):** 26 offline labs, 364 original exam-style questions, domain tests, a progress store, and a single-page web app that runs in live, hosted and desktop modes. It also exports Anki and CTFd files and has an IAM portfolio page with case studies.

**Two facts affect every path:**

- **The exam changes this month.** CompTIA says Security+ V8 (SY0-801) is expected to launch on or around **Nov 17, 2026**. The current exam, English SY0-701, retires on **June 11, 2027**. OBSERVED. Sources: https://www.comptia.org/en-us/certifications/security/v8/ and https://www.comptia.org/en-us/certifications/security/v7/
- **The name breaks CompTIA's trademark rules.** CompTIA's guidelines say:
  - a certification name must not appear without the word "CompTIA";
  - no CompTIA trademark may be used in a domain name;
  - do not name or promote a product with the trademarks in a misleading way. Its own example of what not to do is naming a course "CompTIA A+ Certification".

  OBSERVED. Source: https://www.comptia.org/en-us/legal/trademarks/

  "Security+ Lab Engine" therefore needs a new name before anything goes public. One option is "IdentityOps Lab: practice aligned to the CompTIA Security+ SY0-701 exam objectives". The repo currently has no "not affiliated with CompTIA" notice.

## Comparison

| Path | What the owner gets | Effort | Cost | Revenue potential (PROJECTED) | Legal/brand risk | Fit with IAM career |
|---|---|---|---|---|---|---|
| 1. Personal offline PWA | An installable study app on phone and laptop that works offline | Low (1–3 days: manifest, icons, service worker) | $0 | $0 (not for sale) | Very low (private use) | Medium: helps the owner pass the exam, but nobody else sees it |
| 2. Public portfolio site (GitHub Pages / Cloudflare Pages) | A public link for résumés and LinkedIn, plus the PWA served over HTTPS | Low–medium (rename, disclaimer, deploy) | $0 (an optional domain costs about $10–15/yr, PROJECTED) | $0 direct; indirect value is interviews | Low, if renamed and given a disclaimer | **High**: shows real identity-governance work (access requests, conditional access, access reviews) |
| 3. Open source + GitHub Sponsors | Public repo, contributors, a "maintainer" credential | Medium (license, contributing guide, issue triage) | $0 | $0–$50 a month in year 1 | Low, if renamed; must not accept recalled exam questions | High: public code review and maintainer experience |
| 4. Paid course or digital product (Gumroad / Teachable) | Direct sales of the lab pack or question bank | High (sales page, support, V8 rewrite, refunds) | Gumroad $0/month; Teachable $29–$189/month | About $15.75 kept from each $19 sale. Likely $0–$1,000 in year 1 | **Medium–high**: CompTIA name rules, competing with free Professor Messer and $30 practice packs, SY0-701 retiring | Low–medium: selling time instead of studying IAM |
| 5. Workforce / tribal / WIOA / apprenticeship training | A funded cohort program, employer partners | Very high (state license, approval, outcome reporting) | $1,284 Oklahoma school license fee, plus a bond, insurance and a CPA | High per cohort, but 6–18+ months away | Medium (compliance, accuracy of outcome claims) | High in the long run; too slow for the current job search |
| 6. MCP server / AI tutor over the labs | Labs and questions that any MCP-capable AI assistant can call as a tutor | Medium (wrap the `webapi.dispatch` methods as MCP tools) | $0 | $0 directly; strong portfolio piece | Low | **High**: it is itself an identity and authorization exercise (scoped tools, deny by default) |

## Path 1: Personal installable offline PWA

- MDN says an installable web app needs a web app manifest with `name`, 192 px and 512 px icons, `start_url` and `display`. It must be served over HTTPS or localhost; `file://` does not count. A service worker is optional but is what makes the app work offline. Firefox desktop does not install apps from a manifest. iOS 16.4 and later can install from the Share menu. OBSERVED. Source: https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable
- What this means here: the desktop build that opens from `file://` cannot be installed as a PWA. The HOSTED mode (`web/course_data.json`) behind HTTPS can. The repo has no manifest or service worker today. Progress stays in localStorage, which already works.

## Path 2: Public portfolio and learning site on free static hosting

**GitHub Pages** (OBSERVED, source: https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits):
- the published site can be at most 1 GB;
- the bandwidth limit is soft, at 100 GB a month;
- the build limit is soft, at 10 builds an hour, and does not apply to a custom Actions workflow;
- deployments time out after 10 minutes;
- GitHub says Pages should not be used for sensitive transactions such as passwords or card numbers.

**Cloudflare Pages Free plan** (OBSERVED, source: https://developers.cloudflare.com/pages/platform/limits/):
- 500 builds a month, one at a time;
- 20,000 files per site;
- 25 MiB per file;
- 100 custom domains per project.

A secondary summary reports unlimited static bandwidth on the free plan. OBSERVED. Source: https://www.cloudhim.com/cloudflare/cloudflare-pages-free-tier-small-saas (third party; confirm on the Cloudflare plans page).

The app is one HTML file plus a JSON bundle, well inside both sets of limits. Hosting needs no server and no API keys, so the "no network calls" rule still holds.

## Path 3: Open-source learning platform with optional sponsorship

- GitHub Sponsors charges **no fee** on sponsorships from personal accounts. Sponsorships from organization accounts carry a fee of up to **6%** (3% card processing plus 3% GitHub). OBSERVED. Source: https://docs.github.com/en/sponsors/sponsoring-open-source-contributors/about-sponsorships-fees-and-taxes
- Sponsorship revenue for a new, single-maintainer exam-prep repo is usually small. PROJECTED: $0–$50 a month in year 1. The bigger value is career evidence: public commits, tests (997 passing) and reviewed pull requests.
- **Risk:** the bank must stay original. Accept no "recalled" exam items from contributors, and state that rule in CONTRIBUTING.

## Path 4: Paid course or digital product

**Gumroad** (OBSERVED, source: https://gumroad.com/help/article/66-gumroads-fees):
- direct sales cost 10% + $0.50 plus card processing of 2.9% + $0.30;
- sales through the Discover marketplace cost a flat 30%;
- there is no monthly fee.

Worked example (arithmetic on the observed fees): a $19 sale leaves about **$15.75**.

**Teachable** (OBSERVED, source: https://www.teachable.com/pricing):
- Starter costs $39 a month ($29 billed yearly) with a 7.5% transaction fee;
- Builder costs $89 a month with a 0% fee;
- Growth costs $189 a month;
- there is no free plan.

Card processing is 2.9% + $0.30 for US cards. OBSERVED. Source: https://support.teachable.com/en/articles/11682553-teachable-fees

**Problems with selling now:**
- SY0-701 English retires on June 11, 2027, so a SY0-701 product has roughly seven months of shelf life.
- The bank would need a V8 rewrite, because the domain weights change (for example, Program Management drops from 20% to 14%). OBSERVED. Source: https://blog.troytec.com/security-sy0-801-release-date-sy0-701-retirement/ (third party, citing CompTIA)
- Paid sales would have to follow CompTIA's naming rules.

## Path 5: IAM training for employers, tribal and workforce programs (Oklahoma)

**WIOA Eligible Training Provider List (ETPL).**
- Providers apply through EmployOklahoma.
- The local workforce board recommends approval, then the state approves.
- Initial eligibility lasts 1 year per program. After that, programs are reviewed every 2 years.
- Each program needs a cost breakdown, performance data, O*NET-SOC and CIP codes, and evidence that it leads to a recognized credential.

OBSERVED. Source: https://wioaplans.dol.gov/node/608166

- Providers must upload current state licensing.
- Performance data covers employment in the 2nd and 4th quarter after exit, median earnings, and credential attainment.
- Providers should apply at least 60 days before the first class.

OBSERVED. Source: https://oklahoma.gov/content/dam/ok/en/workforce/documents/policies/directives/2024/WSD-07-2024-Eligible-Training-Provider-List-Policy-and-Procedures.pdf

**Oklahoma private school license.**
- The Oklahoma Board of Private Vocational Schools (OBPVS) also licenses **online** schools that charge Oklahomans for vocational training.
- A new school pays a **$1,284** fee, plus costs for a bond, insurance and a CPA.
- Review takes "3 or 4 months to a year-plus".

OBSERVED. Sources: https://oklahoma.gov/obpvs/schools/applying-for-license.html and https://oklahoma.gov/obpvs/about/faqs.html

**Tribal programs.**
- Cherokee Nation Career Services funds approved short-term training that leads to an industry-recognized credential. Training must be at an **approved training provider**, and priority goes to healthcare, manufacturing, construction and transportation.
- Cherokee Nation also builds custom cohorts with employers, for example its Business Technology program.

OBSERVED. Source: https://www.cherokee.org/all-services/career-services/career-readiness-act-vocational-training-programs/

- The Choctaw and Chickasaw nations run similar credential-funding programs. OBSERVED. Sources: https://www.choctawnation.com/services/career-development/ and https://www.chickasaw.net/Our-Nation/Careers/Chickasaw-Employment-Access

**Apprenticeships.**
- A US Department of Labor Registered Apprenticeship needs at least 2,000 hours of on-the-job learning and 144 hours of related instruction.
- A CareerTech Apprenticeship needs 510 hours of on-the-job learning and 90 hours of related instruction. Its sponsor should be a technology center.

OBSERVED. Source: https://oklahoma.gov/careertech/business-and-industry/apprenticeship-oklahoma.html

**Realistic route:** do not become a provider. Offer the labs, free, as supplementary lab material to an existing technology center, tribal career services office or apprenticeship sponsor. That fits the owner's job search and needs no license. PROJECTED.

## Path 6 (surfaced by research): MCP server / AI tutor

- MCP servers expose **tools** (functions the model can call), **resources** (read-only data) and **prompts** (templates). Tools can require the user's consent before they run. OBSERVED. Source: https://modelcontextprotocol.io/docs/2025-11-25/learn/server-concepts
- `webapi.dispatch()` already has a fixed METHODS allow-list, so wrapping it as MCP tools is a natural fit: "start lab", "grade answer" and "explain question". An allow-listed, deny-by-default tool surface is itself an IAM talking point. Keep it in a separate package so product code still makes no network calls.
- A TryHackMe-style "room" export, or B2B lab simulations, are later variants of Path 3 or Path 5. They are not separate first steps.

## Benchmarks (OBSERVED unless noted)

- **Professor Messer:** the SY0-701 video course is free (121 videos, 15 h 11 min). Source: https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/ Paid add-ons are notes $30, practice exams $30 and the bundle $119. Source: https://certup.com/learning-providers/professor-messer (third party)
- **Dion Training:** the full course costs $349 and the practice exam pack $29.99. Source: https://www.diontraining.com/products/comptia-security-sy0-701 and https://www.diontraining.com/
- **CompTIA CertMaster Learn (Security+):** resellers list it at about $445–$599 for 12 months. Source: https://it-master.co/products/comptia-security-certmaster-learn-sy0-701 (reseller; CompTIA's own store price was not checked)
- **TryHackMe:** Premium costs about $18.11 a month, or about $11.19 a month billed yearly (US). Source: https://epicdetect.io/blogs/tryhackme-vs-hack-the-box-blue-team-2026 (third party). TryHackMe's own page showed €16.99 / €10.50. Source: https://tryhackme.com/pricing
- **Pocket Prep:** Premium costs $20.99 a month or $124.99 a year, with 1,330 Security+ questions. Source: https://exam-tips.com/guides/prep/best-security-plus-practice-tests (third party)
- **What this platform does that they don't:**
  - fully offline, with no account;
  - the labs grade real decisions (deny by default, with a reason for each), not only multiple-choice answers;
  - every lab is mapped to the Professor Messer free videos;
  - IAM-specific labs and case studies mapped to SC-300 and SailPoint-style governance;
  - exports to Anki and CTFd;
  - original questions, with videos as links only (no hosted video content).

  The closest competitors are a $30 practice pack and free videos. That makes paid differentiation hard and portfolio differentiation easy.

## Legal and brand notes

- **Rename the product** so that "Security+" is not the product name. Use "CompTIA Security+" only in descriptive lines such as "aligned to the CompTIA Security+ SY0-701 exam objectives". Put no CompTIA mark in the domain or repo name, and use no logos. Source: https://www.comptia.org/en-us/legal/trademarks/
- **Add a footer notice:** "CompTIA and Security+ are registered trademarks of CompTIA, Inc. This project is not affiliated with, endorsed by or sponsored by CompTIA. Practice questions are original and are not real exam questions." Do the same for Microsoft and SailPoint.
- **Keep videos as YouTube links only.** Do not re-host them.
- This is a plain-English risk note, not legal advice. Before selling anything (Path 4 or 5), ask a lawyer to review the name.

## Recommendation

**Primary: Path 2, a public IAM portfolio site that is also an installable PWA (Path 1), on free static hosting.**

Reasons:
- It costs $0.
- It fits the hosting limits easily.
- It serves the owner's real goal, an IAM job, right away.
- It sidesteps both the SY0-701 retirement on June 11, 2027 and the risks of selling under CompTIA's name.
- Building the PWA comes along at no extra cost, because installability needs HTTPS hosting anyway.

**Next 30 days:**
1. **Week 1:** pick a new name, add the trademark and not-affiliated footer, and add a manifest, icons and a service worker to the hosted build.
2. **Week 2:** deploy `web/` and `course_data.json` to GitHub Pages, or to Cloudflare Pages if bandwidth matters. Publish the `dist/portfolio/` case studies, leading with Labs 1, 2, 25 and 26.
3. **Week 3:** record 3 short screen captures of the identity labs and link them from LinkedIn and the résumé. Write one post: "What building deny-by-default access labs taught me about SC-300."
4. **Week 4:** decide whether the question bank should be tagged for V8 (SY0-801). Ask one Oklahoma technology center or tribal career services office whether they would use the labs as free supplementary material.

**Secondary: Path 3 (open source + GitHub Sponsors) and then Path 6 (MCP tutor).**

Reasons:
- Opening the repo turns the site into visible engineering work.
- Sponsors costs nothing on personal sponsorships.
- An allow-listed MCP tutor is a distinctive, IAM-flavoured portfolio piece.

**Revisit Paths 4 and 5 only after the owner is employed in IAM and the V8 content exists.**
