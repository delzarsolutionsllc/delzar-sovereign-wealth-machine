# Verification scripts (Phase 8)

Copies of the Playwright scripts used for Security+ sit next to this file:

- `check_quiz_exam_progress.js`: quiz end to end, exam no-auto-advance + flag + grid + review + score, progress export -> clear -> import, arrow-key tabs, 390 px overflow. Run: `node check_quiz_exam_progress.js <outdir>` against `python -m http.server -d <site> 8811`.
- `axe_audit.js`: axe-core WCAG 2.2 AA on ~22 screens in light and dark mode. Needs `npm install axe-core@4.10.2` in `<outdir>/axe/`. Run: `node axe_audit.js <outdir>`. Expect `TOTAL rule violations: 0`.

Also check by hand (scripted): first Tab reaches the skip link; focus is visible; reflow at 320 px; WCAG 1.4.12 text spacing; the desktop file opens from `file://` and shows the new course. Read the screenshots yourself before reporting.

Chromium and Playwright are pre-installed in cloud sessions: `require('playwright')` works from any directory; do not run `playwright install`.
