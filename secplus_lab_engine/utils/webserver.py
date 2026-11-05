"""
Local web server for the course app (``python main.py web``).

Standard library only. Serves ``web/index.html`` and answers
``POST /api/<method>`` with JSON from :func:`webapi.dispatch`, using the live
engine and your local ``progress.json``. It is meant for one person on one
machine, so it is deliberately locked down:

* binds to 127.0.0.1 only (not reachable from the network);
* rejects requests whose Host header is not localhost/127.0.0.1 (stops DNS
  rebinding, where a website points its own name at 127.0.0.1);
* API calls must be ``POST`` with ``Content-Type: application/json``, which a
  foreign page cannot send without a CORS preflight, and no CORS headers are
  ever returned.
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import webapi
from utils.loader import ROOT, load_policies

INDEX = ROOT / "web" / "index.html"
MODE_MARKER = "<!--SECPLUS_MODE-->"
# The page is written as a fragment (claude.ai adds the document skeleton when it is published);
# locally we add the same skeleton so the browser renders in standards mode.
SKELETON = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"></head><body>{}</body></html>')
MAX_BODY = 1_000_000


def make_handler(policies: dict, progress_path=None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecPlusLab/1.0"

        def log_message(self, fmt, *args):     # keep the terminal quiet
            pass

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
            return host in {"127.0.0.1", "localhost", "::1"}

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, b"forbidden host", "text/plain")
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                page = INDEX.read_text(encoding="utf-8").replace(
                    MODE_MARKER, '<script>window.SECPLUS_API = "/api";</script>', 1)
                if not page.lstrip().lower().startswith("<!doctype"):
                    page = SKELETON.format(page)
                return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            if path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            return self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if not self._host_ok():
                return self._json(403, {"error": "forbidden host"})
            if not self.path.startswith("/api/"):
                return self._json(404, {"error": "not found"})
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                return self._json(415, {"error": "Content-Type must be application/json"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"error": "request too large"})
            try:
                args = json.loads(self.rfile.read(length) or b"{}")
                result = webapi.dispatch(self.path[len("/api/"):], args, policies, progress_path)
            except (ValueError, KeyError, TypeError) as exc:
                return self._json(400, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001 - report, don't crash the server
                return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
            return self._json(200, result)

    return Handler


def make_server(port: int = 8765, policies: dict | None = None, progress_path=None) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(policies or load_policies(), progress_path))


def serve(port: int = 8765, open_browser: bool = True, policies: dict | None = None) -> None:
    try:
        httpd = make_server(port, policies)
    except OSError:
        httpd = make_server(0, policies)                      # port busy: pick a free one
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"Delzar Certification Academy is running at {url}")
    print("Leave this window open while you study. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
