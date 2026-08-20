#!/usr/bin/env bash
# Install SearXNG for Harness on this machine (Python venv, no Docker).
# Usage: ./install.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${SEARXNG_ROOT:-$HOME/.dsh/searxng}"
SRC="$ROOT/src"
VENV="$ROOT/venv"
SETTINGS="$ROOT/settings.yml"

echo "==> clone SearXNG → $SRC"
mkdir -p "$ROOT"
if [[ ! -d "$SRC/.git" ]]; then
  git clone --depth 1 https://github.com/searxng/searxng.git "$SRC"
else
  git -C "$SRC" pull --ff-only || true
fi

echo "==> venv + pip"
python3 -m venv "$VENV"
"$VENV/bin" pip install -U pip wheel setuptools
"$VENV/bin" pip install -r "$SRC/requirements.txt"

echo "==> settings"
if [[ ! -f "$SETTINGS" ]]; then
  cp "$HERE/settings.yml" "$SETTINGS"
  KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  # portable in-place
  python3 - <<PY
from pathlib import Path
p = Path("$SETTINGS")
t = p.read_text()
p.write_text(t.replace("CHANGE_ME", "$KEY", 1))
PY
  echo "wrote $SETTINGS (new secret_key)"
else
  echo "keep existing $SETTINGS"
fi

echo "==> launchd (login start)"
PLIST="$HOME/Library/LaunchAgents/ai.local.searxng.plist"
cp "$HERE/ai.local.searxng.plist" "$PLIST"
python3 - <<PY
from pathlib import Path
import os
p = Path(os.path.expanduser("$PLIST"))
home = str(Path.home())
p.write_text(p.read_text().replace("__HOME__", home).replace("/Users/YOU", home))
PY
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
echo "loaded $PLIST"

echo "==> wait for :8888"
for i in $(seq 1 20); do
  if curl -sf "http://127.0.0.1:8888/healthz" >/dev/null 2>&1 || curl -sf "http://127.0.0.1:8888/" >/dev/null 2>&1; then
    echo "SearXNG is up: http://127.0.0.1:8888"
    echo "JSON test:"
    curl -sf "http://127.0.0.1:8888/search?q=ghidra+sbpf&format=json" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d.get("results") or []), "results")'
    exit 0
  fi
  sleep 1
done
echo "WARN: nothing on :8888 yet — check: launchctl list | grep searxng"
echo "logs: $ROOT/searxng.log"
exit 1
