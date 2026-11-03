#!/bin/sh
# Run: ./launch/start-secplus-lab.sh  (or double-click and choose "Run in Terminal")
cd "$(dirname "$0")/.." || exit 1
exec python3 main.py web
