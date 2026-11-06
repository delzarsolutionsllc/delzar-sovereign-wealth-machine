# Private hosting: Cloudflare Pages behind a Cloudflare Access login

Goal: only people you approve can open the academy. You pay nothing at this size (checked 2026-11-06):
- Cloudflare's Zero Trust Free plan covers up to **50 users** (https://www.cloudflare.com/plans/zero-trust-services/).
- Cloudflare Pages hosts the static site. The largest file in the build is about 7 MB, under Pages' 25 MiB per-file limit.

This setup also works as an IAM portfolio piece. You run a real identity-aware proxy with an allow-list policy,
one-time-PIN sign-in, an audit log, and joiner/leaver steps when you add or remove a customer.

## 1. Make the GitHub repository private (about 1 minute)
1. Go to github.com → the `delzar-sovereign-wealth-machine` repo → **Settings** → **General** → **Danger Zone** →
   **Change repository visibility** → **Make private**.
2. Expect two effects:
   - The free GitHub Pages site (`delzarsolutionsllc.github.io/...`) goes offline, because publishing Pages from a
     private repo needs a paid plan. The deploy workflow now only runs by hand, so it will not keep failing.
   - Public forks stay public: GitHub detaches them instead of making them private. Check the **Forks** count on
     the repo page. If anyone forked it, those copies keep the old content.

## 2. Create the Cloudflare Pages project (about 10 minutes)
1. Sign up for a free account at dash.cloudflare.com. No card is needed for these steps.
2. Go to **Workers & Pages** → **Create** → **Pages** → **Connect to Git**. Authorise Cloudflare's GitHub app for this
   private repository only, not all repositories (least privilege).
3. Fill in the build settings:
   - Production branch: `main`
   - Framework preset: None
   - Root directory (advanced): `secplus_lab_engine`. This also deploys the AI tutor function in `functions/`.
   - Build command: `python3 tools/build_site.py --out dist/site`
   - Build output directory: `dist/site`
   - Environment variable: `PYTHON_VERSION` = `3.12`
4. Deploy. You get an address like `delzar-academy.pages.dev`. Every merge to `main` redeploys it automatically.

## 3. Put the login in front (about 10 minutes)
1. In the Cloudflare dashboard, go to **Zero Trust** → **Access controls** → **Applications** → **Create new application** →
   **Self-hosted**.
2. Application domain: your `*.pages.dev` address. Add a second entry for the preview deployments, `*.delzar-academy.pages.dev`,
   so preview links are locked too.
3. Policy: **Allow**, Include → **Emails** → your own email. Sign-in method: **One-time PIN**. Cloudflare emails each
   visitor a code, so you don't need a password database.
4. Open the site in a private window. You should see the Cloudflare sign-in page. Anyone not on the list is refused.

## 4. Give or remove access (your joiner/leaver process)
- **New customer (joiner):** add their email to the Allow policy. They sign in with a code sent to that address.
- **Customer leaves or stops paying (leaver):** remove the email. Their session ends when it expires. Set the
  application's session duration, for example 24 hours, to control how long that takes.
- **Review:** Zero Trust → Logs → Access shows who signed in and when. Check it monthly, like an access review.
- **Up to 50 people are free.** Beyond that, you need a paid Zero Trust plan or a different sign-in method. Decide that when
  sales justify it.

## 5. Optional, and paid: switch on the in-app AI tutor
The site includes an AI grader at `/api/tutor` (`functions/api/tutor.js`). It stays **off and free** until you add a key.
When it is on, a "Grade with AI tutor" button appears under each interview answer.
1. Create an API key in the Claude Console (platform.claude.com) and set a **monthly spend limit** there first.
2. In the Pages project, go to **Settings** → **Variables and Secrets** → add a secret `ANTHROPIC_API_KEY`, then redeploy.
   Never put the key in the repository or in chat.
3. Each graded answer costs a few US cents (Claude Opus 5.5 at low effort, answers up to 4,000 characters,
   replies up to 1,500 tokens). Only signed-in users can call it, and it grades only the academy's own questions,
   so nobody can use it as a free general AI.
4. To switch it off, delete the secret.

The free alternative works today: "Copy for Claude" on each question, or the MCP tutor (`docs/AI_TUTOR.md`).

## What this protects, and what it does not
- **Protected:** the website, the question banks, the labs, and the downloadable desktop files. Nobody can reach them
  without an approved email.
- **Not protected:** what an approved user copies or downloads after signing in. No web app can fully prevent that.
  Your protections there are the licence (`LICENSE` at the repo root), the Terms of Use (`docs/TERMS.md`, which
  customers accept when they buy), revoking access, and the copyright notice inside the app.
  Before selling, have a lawyer review the terms.
- **Already public:** anything pushed while the repo was public may have been copied or cached. Copyright still
  belongs to you, which is what the licence relies on.
