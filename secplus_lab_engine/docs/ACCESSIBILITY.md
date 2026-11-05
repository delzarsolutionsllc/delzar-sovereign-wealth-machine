# Accessibility audit (WCAG 2.2 AA)

Audit of the IdentityOps Lab web app (`web/index.html`, as published by `tools/build_site.py`), 2026-11-05.

## Automated: axe-core 4.10.2, 0 violations

Rules: WCAG 2.0/2.1/2.2 A and AA plus axe best practices, in **light and dark** colour schemes, on 22 screens each:

- Overview, Daily review (start page and a question), Video course, Objective quizzes, an objective page and a quiz (before and after answering).
- My progress (with export/import), IAM career.
- A lab's Lesson, Practice (before and after answering) and Case study tabs.
- Practice exam: setup, a question, the review screen and the result.
- Phone width (390 px), with the course map closed and open.

The first run found 2 rules failing; both are fixed:

| Rule | Where | Fix |
|---|---|---|
| page-has-heading-one | exam question and review screens | a visually hidden `<h1>` ("Practice exam in progress") |
| color-contrast | warning notice (4.47:1); dark-mode dropdown on My progress (2.19:1) | warning colour darkened to `#865606`; every `<select>` uses the theme colours |

## Checked by script in Chromium

- **Keyboard:**
  - The first Tab reaches "Skip to content", which moves focus to the page's `<h1>`.
  - Focus is always visible (2 px outline).
  - Quizzes and the exam work with the keyboard alone: 1–4 to answer, Enter for next; in the exam N next, P previous, F flag.
  - Lab tabs are WAI-ARIA tabs: one tab stop, arrow keys, Home and End.
  - Picking an answer never moves focus away unexpectedly.
- **Focus management:** after navigating, focus goes to the new page's heading. After answering, it goes to "Next". On the next question it goes to the question text, and at the end to the result heading.
- **Announcements:** answer verdicts use `role="status"`. A polite live region announces quiz results, exam scoring, flagging, and the exam timer at 10, 5 and 1 minutes left (not every second).
- **Reflow (1.4.10):** no horizontal scrolling at 320 px on 8 screens, or at 640 px (200% zoom of 1280).
- **Text spacing (1.4.12):** no loss of content with 1.5 line height, 0.12 em letter spacing and 0.16 em word spacing.
- **Motion:** progress-bar animations run only when `prefers-reduced-motion` is not set.
- **Colour:** status is never shown by colour alone; every pill and meter also has text.

## Not yet done (needs people and devices)

- Screen-reader passes with **VoiceOver on iPhone**, **TalkBack on Android** and **NVDA or JAWS on Windows**. Listen to a full quiz, the exam navigator and the drag-to-order question (its ↑/↓ buttons are the keyboard and screen-reader path).
- Voice control (Voice Control / Voice Access) on the installed app.
- A usability check with at least one person who relies on assistive technology.

How to re-run the automated audit: build the site, serve it, then run axe-core in Playwright on each screen. The scenario list above is the one to cover.
