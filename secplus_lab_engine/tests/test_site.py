"""Installable offline web app (PWA) static-site build."""

from __future__ import annotations

import json
import re
import struct

import pytest

from tools.build_site import build_site, draw_icon, manifest


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    out = tmp_path_factory.mktemp("site")
    build_site(out, variants=0)
    return out


def _png_size(data: bytes) -> tuple[int, int]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR"
    return struct.unpack(">II", data[16:24])


def test_site_files(site):
    names = {p.relative_to(site).as_posix() for p in site.rglob("*") if p.is_file()}
    assert {"index.html", "course_data.json", "manifest.webmanifest", "sw.js", ".nojekyll",
            "icons/icon-192.png", "icons/icon-512.png", "icons/icon-maskable-512.png"} <= names


def test_index_is_installable_and_hosted_mode(site):
    page = (site / "index.html").read_text()
    assert page.startswith("<!doctype html>") and '<link rel="manifest" href="manifest.webmanifest">' in page
    assert 'register("sw.js")' in page and "<!--SECPLUS_MODE-->" not in page
    assert not re.search(r"window\.SECPLUS_API\s*=\s*[\"']", page)  # hosted mode: reads course_data.json
    assert "Not affiliated with CompTIA" in page


def test_manifest_meets_install_criteria(site):
    m = json.loads((site / "manifest.webmanifest").read_text())
    assert m == manifest() and m["display"] == "standalone" and m["start_url"] == "./"
    sizes = {i["sizes"] for i in m["icons"]}
    assert {"192x192", "512x512"} <= sizes and any(i["purpose"] == "maskable" for i in m["icons"])
    for icon in m["icons"]:
        w, h = _png_size((site / icon["src"]).read_bytes())
        assert f"{w}x{h}" == icon["sizes"]


def test_service_worker_precaches_existing_files_only(site):
    sw = (site / "sw.js").read_text()
    precache = json.loads(re.search(r"const PRECACHE = (\[.*?\]);", sw).group(1))
    for rel in precache:
        assert rel == "./" or (site / rel).is_file(), rel
    assert re.search(r'const CACHE = "secplus-[0-9a-f]{12}"', sw)
    assert "if (!sameOrigin && !isFont) return;" in sw          # never intercepts other sites


def test_icon_is_valid_png():
    assert _png_size(draw_icon(48)) == (48, 48)
    assert _png_size(draw_icon(48, maskable=True)) == (48, 48)


def test_site_offers_the_one_file_desktop_app(site):
    app = site / "download" / "Delzar-Certification-Academy.html"
    html = app.read_text(encoding="utf-8")
    assert app.parent.name == "download" and "window.SECPLUS_BUNDLE = {" in html and html.count("</script>") == 2
    assert "glossary_questions" in html and "Delzar Certification Academy" in html
    sw = (app.parent.parent / "sw.js").read_text(encoding="utf-8")
    assert "Delzar-Certification-Academy" not in sw                    # not precached: it is the same course again
    page = (app.parent.parent / "index.html").read_text(encoding="utf-8")
    assert '"download/Delzar-Certification-Academy.html"' in page and "download/Delzar-Certification-Academy-${" in page
    sc = site / "download" / "Delzar-Certification-Academy-SC-300.html"          # every other course gets its own file
    assert sc.exists() and '"code": "sc300"' in sc.read_text(encoding="utf-8").replace('"code":"sc300"', '"code": "sc300"')
    assert (site / "courses" / "sc300" / "course_data.json").exists() and "courses/sc300/course_data.json" in sw
