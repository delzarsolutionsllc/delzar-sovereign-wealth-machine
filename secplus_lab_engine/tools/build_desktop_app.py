#!/usr/bin/env python3
"""
Build a single-file desktop app: dist/IdentityOps Lab.html

The course page with the whole course bundle embedded, so it opens by
double-click (file://), works offline and needs no Python. Progress is kept
in the browser that opens it.

    python tools/build_desktop_app.py [--variants 12] [--out FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_web_bundle import build  # noqa: E402

SKELETON = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"></head><body>'
            '{data}{page}</body></html>')


def build_html(variants: int = 12) -> str:
    bundle = json.dumps(build(variants), separators=(",", ":"))
    bundle = bundle.replace("</", "<\\/")            # never close the <script> early
    page = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    return SKELETON.format(data=f"<script>window.SECPLUS_BUNDLE = {bundle};</script>", page=page)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the single-file desktop app")
    ap.add_argument("--variants", type=int, default=12)
    ap.add_argument("--out", default=str(ROOT / "dist" / "IdentityOps Lab.html"))
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_html(a.variants), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size / 1e6:.2f} MB). Double-click it to open the course.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
