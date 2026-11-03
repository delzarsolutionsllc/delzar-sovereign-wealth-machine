#!/bin/bash
# Double-click in Finder. Starts the course and opens it in your browser.
cd "$(dirname "$0")/.." || exit 1
exec python3 main.py web
