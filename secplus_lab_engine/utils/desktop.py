"""
Desktop shortcut installer (``python main.py install-shortcut``).

Puts a double-clickable launcher on your desktop that starts the course web
app (``python main.py web``) and opens it in your browser:

* Windows: ``Delzar Certification Academy.bat`` (uses the ``py`` launcher, else ``python``)
* macOS:   ``Delzar Certification Academy.command`` (opens in Terminal)
* Linux:   ``security-plus-lab-engine.desktop`` (runs in a terminal window)

The launcher keeps a small terminal window open while you study; closing it
(or pressing Ctrl+C) stops the app. Nothing is installed system-wide.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from utils.loader import ROOT

APP_NAME = "Delzar Certification Academy"


def detect_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def desktop_dir(platform: str, home: Path | None = None) -> Path:
    home = home or Path.home()
    if platform == "windows":
        for env in ("OneDrive",):                      # Desktop is often redirected into OneDrive
            od = os.environ.get(env)
            if od and (Path(od) / "Desktop").is_dir():
                return Path(od) / "Desktop"
        return Path(os.environ.get("USERPROFILE", home)) / "Desktop"
    if platform == "linux":
        xdg = os.environ.get("XDG_DESKTOP_DIR")
        if xdg:
            return Path(os.path.expandvars(xdg.replace("$HOME", str(home))))
    return home / "Desktop"


def launcher(platform: str, root: Path) -> tuple[str, str]:
    """Return (filename, file contents) for the platform's launcher."""
    if platform == "windows":
        body = (
            "@echo off\r\n"
            f"title {APP_NAME}\r\n"
            f'cd /d "{root}"\r\n'
            "where py >nul 2>nul && (py -3 main.py web) || (python main.py web)\r\n"
            "if errorlevel 1 (echo. & echo Python 3.10+ is required: https://www.python.org/downloads/ & pause)\r\n"
        )
        return f"{APP_NAME}.bat", body
    if platform == "macos":
        body = f'#!/bin/bash\ncd "{root}" || exit 1\nexec python3 main.py web\n'
        return f"{APP_NAME}.command", body
    body = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        "Comment=CompTIA Security+ SY0-701 labs, practice and exams\n"
        f"Exec=sh -c 'cd \"{root}\" && python3 main.py web'\n"
        "Terminal=true\n"
        "Icon=accessories-dictionary\n"
        "Categories=Education;\n"
    )
    return "security-plus-lab-engine.desktop", body


def install_shortcut(desktop: Path | None = None, platform: str | None = None, root: Path = ROOT) -> Path:
    platform = platform or detect_platform()
    target_dir = desktop or desktop_dir(platform)
    target_dir.mkdir(parents=True, exist_ok=True)
    name, body = launcher(platform, Path(root).resolve())
    path = target_dir / name
    path.write_text(body, encoding="utf-8", newline="")
    if platform in ("macos", "linux"):
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
