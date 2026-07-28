"""Digest rendering and best-effort desktop notification.

No paid services: desktop notification uses notify-send if present
(Linux) or osascript (macOS); otherwise it just prints. The daily
digest is written to ~/.delzar/output/digest-YYYY-MM-DD.txt so it can
be attached to any email client or read directly.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import date
from pathlib import Path

from ..config import output_dir


def build_digest_text(ranked: list[dict], poll_stats: dict | None = None) -> str:
    lines = [f"DELZAR OPS daily digest - {date.today().isoformat()}", "=" * 60]
    if poll_stats:
        lines.append(
            f"Poll: {poll_stats.get('new', 0)} new, {poll_stats.get('amended', 0)} amended, "
            f"{poll_stats.get('unchanged', 0)} unchanged"
        )
        lines.append("")
    if not ranked:
        lines.append("No open opportunities on the watch list.")
    for i, o in enumerate(ranked, 1):
        lines.append(
            f"{i:2d}. [{o.get('score') or 0:5.1f}] {(o.get('title') or '')[:70]}"
        )
        lines.append(
            f"     {o.get('solicitation_no') or o.get('notice_id')} | "
            f"{o.get('set_aside') or 'no set-aside'} | NAICS {o.get('naics') or '?'} | "
            f"{o.get('place_city') or '?'}, {o.get('place_state') or '?'}"
        )
        lines.append(
            f"     due {o.get('response_deadline') or '?'}"
            + (f" | AMENDED {o['amended_at'][:10]}" if o.get("amended_at") else "")
            + (f" | {o['piid_type']}" if o.get("piid_type") else "")
        )
        if o.get("url"):
            lines.append(f"     {o['url']}")
        lines.append("")
    return "\n".join(lines)


def write_digest(text: str) -> Path:
    p = output_dir() / f"digest-{date.today().isoformat()}.txt"
    p.write_text(text)
    return p


def desktop_notify(title: str, body: str) -> bool:
    try:
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", title, body[:200]], timeout=5, check=False)
            return True
        if shutil.which("osascript"):
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{body[:150]}" with title "{title}"'],
                timeout=5, check=False)
            return True
    except Exception:
        pass
    return False
