#!/usr/bin/env bash
# Foreground SearXNG (for debugging). Prefer launchd in production.
set -euo pipefail
ROOT="${SEARXNG_ROOT:-$HOME/.dsh/searxng}"
export SEARXNG_SETTINGS_PATH="${SEARXNG_SETTINGS_PATH:-$ROOT/settings.yml}"
cd "$ROOT/src"
exec "$ROOT/venv/bin/python" -m searx.webapp
