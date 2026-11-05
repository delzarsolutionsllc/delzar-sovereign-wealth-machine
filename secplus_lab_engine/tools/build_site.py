#!/usr/bin/env python3
"""
Build the installable offline web app (a PWA) as a static site: dist/site/

    python tools/build_site.py            # then: python -m http.server -d dist/site 8000
                                          # open http://localhost:8000 and choose "Install"

What you get:
* index.html            the course page (hosted mode: reads course_data.json)
* course_data.json      the pre-built course (labs, questions, exam bank, videos)
* manifest.webmanifest  name, colours and icons so browsers offer "Install app"
* sw.js                 a service worker that caches everything for offline use
* icons/*.png           app icons, drawn here with the standard library
* .nojekyll             lets GitHub Pages serve the files as they are

Progress is saved in the browser on each device. Nothing is uploaded anywhere:
the site is static files. Putting it on the public internet (GitHub Pages,
Cloudflare Pages) is a separate, deliberate step: see README "Install it as an app".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_web_bundle import build  # noqa: E402

APP_NAME = "IdentityOps Lab"
SHORT_NAME = "IdentityOps"
THEME = "#1d5c8f"
BACKGROUND = "#f4f6f9"
ICON_SIZES = (192, 512)

HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="{theme}">
<meta name="description" content="IdentityOps Lab: offline security and IAM labs with exam-style practice aligned to the CompTIA Security+ SY0-701 objectives. Not affiliated with CompTIA.">
<link rel="manifest" href="manifest.webmanifest">
<link rel="icon" href="icons/icon-192.png" type="image/png">
<link rel="apple-touch-icon" href="icons/icon-192.png">
</head><body>
{page}
<script>
/* Offline support: cache the app the first time it loads (only over http/https). */
if ("serviceWorker" in navigator && /^https?:$/.test(location.protocol)) {{
  window.addEventListener("load", () => navigator.serviceWorker.register("sw.js").catch(() => {{}}));
}}
</script>
</body></html>
"""

SERVICE_WORKER = """/* IdentityOps Lab service worker, version {version}.
   Precaches the app so it works offline; course pages are network-first so updates
   show up when online, everything else is cache-first. Fonts are cached on first use. */
const CACHE = "secplus-{version}";
const PRECACHE = {precache};

self.addEventListener("install", event => {{
  event.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
}});

self.addEventListener("activate", event => {{
  event.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(k => k.startsWith("secplus-") && k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
}});

self.addEventListener("fetch", event => {{
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  const sameOrigin = url.origin === self.location.origin;
  const isFont = /fonts\\.(googleapis|gstatic)\\.com$/.test(url.hostname);
  if (!sameOrigin && !isFont) return;                       // never touch other sites
  if (req.mode === "navigate" || url.pathname.endsWith("course_data.json")) {{
    event.respondWith(fetch(req).then(res => {{                 // network first: pick up new versions
      const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); return res;
    }}).catch(() => caches.match(req).then(r => r || caches.match("index.html"))));
    return;
  }}
  event.respondWith(caches.match(req).then(hit => hit || fetch(req).then(res => {{
    if (res.ok || res.type === "opaque") {{ const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); }}
    return res;
  }})));
}});
"""


# --------------------------------------------------------------------------- icons
def _png(width: int, height: int, rgba_rows: list[bytes]) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + row for row in rgba_rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _hex(c: str) -> tuple[int, int, int]:
    return int(c[1:3], 16), int(c[3:5], 16), int(c[5:7], 16)


def _shield(x: float, y: float) -> bool:
    """Unit-square shield outline (0..1): flat top, straight sides, curved point at the bottom."""
    if not (0.22 <= x <= 0.78 and 0.18 <= y <= 0.86):
        return False
    if y <= 0.52:
        return True
    # lower part narrows to a point at (0.5, 0.86)
    half = 0.28 * math.cos((y - 0.52) / 0.34 * math.pi / 2)
    return abs(x - 0.5) <= half


def _keyhole(x: float, y: float) -> bool:
    return (x - 0.5) ** 2 + (y - 0.42) ** 2 <= 0.075 ** 2 or (abs(x - 0.5) <= 0.035 and 0.42 <= y <= 0.64)


def draw_icon(size: int, maskable: bool = False) -> bytes:
    """App icon: a white shield with a keyhole on the theme colour (maskable = full-bleed background)."""
    bg, fg, hole = _hex(THEME), (255, 255, 255), _hex(THEME)
    radius = 0.0 if maskable else 0.22
    scale = 0.80 if maskable else 1.0                       # keep the shield inside the maskable safe zone
    ss = 3                                                  # 3x3 supersampling for smooth edges
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    u, v = (px + (sx + 0.5) / ss) / size, (py + (sy + 0.5) / ss) / size
                    # rounded square background
                    cx, cy = min(max(u, radius), 1 - radius), min(max(v, radius), 1 - radius)
                    inside_bg = radius == 0 or (u - cx) ** 2 + (v - cy) ** 2 <= radius ** 2
                    if not inside_bg:
                        continue
                    su, sv = 0.5 + (u - 0.5) / scale, 0.5 + (v - 0.5) / scale
                    col = (hole if _keyhole(su, sv) else fg) if _shield(su, sv) else bg
                    acc[0] += col[0]; acc[1] += col[1]; acc[2] += col[2]; acc[3] += 255
            n = ss * ss
            row += bytes((acc[0] // n, acc[1] // n, acc[2] // n, acc[3] // n)) if acc[3] else b"\x00\x00\x00\x00"
        rows.append(bytes(row))
    return _png(size, size, rows)


# --------------------------------------------------------------------------- site
def manifest() -> dict:
    return {
        "name": APP_NAME, "short_name": SHORT_NAME, "id": "./", "start_url": "./", "scope": "./",
        "display": "standalone", "background_color": BACKGROUND, "theme_color": THEME,
        "description": "Offline security and IAM labs, exam-style practice aligned to the CompTIA Security+ SY0-701 objectives, daily review and an IAM career track. "
                       "Not affiliated with or endorsed by CompTIA.",
        "categories": ["education"],
        "icons": [{"src": f"icons/icon-{s}.png", "sizes": f"{s}x{s}", "type": "image/png", "purpose": "any"}
                  for s in ICON_SIZES]
                 + [{"src": "icons/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}],
    }


def build_site(out: Path, variants: int = 12) -> list[Path]:
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "icons").mkdir(parents=True)
    page = (ROOT / "web" / "index.html").read_text(encoding="utf-8").replace("<!--SECPLUS_MODE-->", "")
    (out / "index.html").write_text(HEAD.format(theme=THEME, page=page), encoding="utf-8")
    data = json.dumps(build(variants), separators=(",", ":"))
    (out / "course_data.json").write_text(data, encoding="utf-8")
    (out / "manifest.webmanifest").write_text(json.dumps(manifest(), indent=2), encoding="utf-8")
    for s in ICON_SIZES:
        (out / "icons" / f"icon-{s}.png").write_bytes(draw_icon(s))
    (out / "icons" / "icon-maskable-512.png").write_bytes(draw_icon(512, maskable=True))
    (out / ".nojekyll").write_text("", encoding="utf-8")
    precache = ["./", "index.html", "course_data.json", "manifest.webmanifest",
                *[f"icons/icon-{s}.png" for s in ICON_SIZES], "icons/icon-maskable-512.png"]
    digest = hashlib.sha256()
    for rel in precache[1:]:
        digest.update((out / rel).read_bytes())
    version = digest.hexdigest()[:12]                       # new content -> new cache -> users get the update
    (out / "sw.js").write_text(SERVICE_WORKER.format(version=version, precache=json.dumps(precache)), encoding="utf-8")
    return sorted(p for p in out.rglob("*") if p.is_file())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the installable offline web app (PWA) as a static site")
    ap.add_argument("--variants", type=int, default=12)
    ap.add_argument("--out", default=str(ROOT / "dist" / "site"))
    a = ap.parse_args(argv)
    files = build_site(Path(a.out), a.variants)
    size = sum(f.stat().st_size for f in files) / 1e6
    print(f"wrote {a.out}: {len(files)} files, {size:.1f} MB.\n"
          f"Try it:  python -m http.server -d {a.out} 8000   then open http://localhost:8000 and choose Install.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
