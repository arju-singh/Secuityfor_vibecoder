#!/bin/bash
# SentryScan launcher for macOS — double-click this file to install deps,
# start the server, and open the app in your browser.
cd "$(dirname "$0")" || exit 1

echo "=============================================="
echo "  SentryScan — Website Tester"
echo "=============================================="

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Install it from https://nodejs.org (LTS) and run this again."
  read -r -p "Press Enter to close..."
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing dependencies (first run only)…"
  npm install || { echo "npm install failed."; read -r -p "Press Enter to close..."; exit 1; }
fi

# Install the Chromium engine for the render test (first run only). Non-fatal.
if [ ! -d "$HOME/.cache/ms-playwright" ] && [ ! -d "$HOME/Library/Caches/ms-playwright" ]; then
  echo "Installing the headless browser for the render test (first run only)…"
  npx playwright install chromium || echo "Note: Chromium install skipped — the render suite will show as unavailable."
fi

PORT="${PORT:-3000}"
echo "Starting server on http://localhost:$PORT …"

# Open the browser shortly after the server starts.
( sleep 2; open "http://localhost:$PORT" ) &

PORT="$PORT" npm start
