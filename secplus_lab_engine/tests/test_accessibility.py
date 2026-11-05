"""Accessibility guards for the web app (full audit: docs/ACCESSIBILITY.md, axe-core 0 violations)."""

from __future__ import annotations

import re

import pytest

from utils.loader import ROOT

PAGE = (ROOT / "web" / "index.html").read_text(encoding="utf-8")


def _tokens(block: str) -> dict:
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", block))


LIGHT = _tokens(PAGE[PAGE.index(":root {"):PAGE.index("}", PAGE.index(":root {"))])
DARK = _tokens(PAGE[PAGE.index(':root[data-theme="dark"] {'):PAGE.index("}", PAGE.index(':root[data-theme="dark"] {'))])


def _lum(hex_: str) -> float:
    def ch(c):
        c = int(c, 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(hex_[i:i + 2]) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


PAIRS = [("ink", "bg"), ("ink", "surface"), ("muted", "bg"), ("muted", "surface"), ("muted", "sunken"),
         ("accent", "surface"), ("accent", "accent-soft"), ("on-accent", "accent"), ("pass", "pass-soft"),
         ("warn", "warn-soft"), ("fail", "fail-soft"), ("ink", "sunken")]


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_text_colour_pairs_meet_aa(theme):
    t = LIGHT if theme == "light" else DARK
    for fg, bg in PAIRS:
        assert contrast(t[fg], t[bg]) >= 4.5, f"{theme}: --{fg} on --{bg} is {contrast(t[fg], t[bg]):.2f}:1"


def test_dark_theme_defined_twice_identically():
    media = PAGE[PAGE.index("@media (prefers-color-scheme: dark)"):PAGE.index(':root[data-theme="dark"]')]
    assert _tokens(media) == DARK


def test_landmarks_skip_link_and_live_region():
    assert re.search(r'<a class="skip" href="#view" id="skiplink">Skip to content</a>', PAGE)
    assert 'id="announcer" aria-live="polite"' in PAGE
    assert '<nav class="nav" aria-label="Main">' in PAGE and '<main class="main" id="main">' in PAGE
    assert 'aria-expanded="false" aria-controls="domains"' in PAGE


def test_tabs_follow_wai_aria():
    for s in ('role: "tablist"', 'role: "tab"', 'role: "tabpanel"', '"aria-controls": "labbody"', 'ArrowRight', 'Home: 0', "tabindex: k === tab"):
        assert s in PAGE, s


def test_focus_and_announcements():
    for s in ("h.focus({ preventScroll: true })", 'role: "status"', "announce(`${m} minute", 'class: "sr-only", tabindex: "-1"',
              '"aria-pressed"', '"aria-current"', ":focus-visible { outline: 2px solid", "prefers-reduced-motion: no-preference"):
        assert s in PAGE, s


def test_every_screen_has_an_h1():
    # every view function renders an h1 (exam in progress uses a visually hidden one)
    for fn in ("viewHome", "viewLab", "viewExam", "viewReview", "viewProgress", "viewVideos", "viewCareer", "viewQuizzes", "viewObjective", "startObjectiveQuiz"):
        body = PAGE[PAGE.index(f"function {fn}("):]
        body = body[:body.index("\nfunction ", 10) if "\nfunction " in body[10:] else len(body)]
        assert 'el("h1"' in body, fn
    assert "Practice exam in progress" in PAGE
