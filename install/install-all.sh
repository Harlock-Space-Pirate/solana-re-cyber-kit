#!/usr/bin/env bash
# Generic install: sBPF processor + Harness kit + SearXNG + smoke tests.
set -euo pipefail
KIT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra}"
export DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
export PENTEST_LAB="${PENTEST_LAB:-$DSH_HOME/pentest-lab}"
export CYBER_HOME="${CYBER_HOME:-$HOME/.cyber}"
export OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"

echo "KIT_ROOT=$KIT_ROOT"
echo "GHIDRA_HOME=$GHIDRA_HOME"
echo "DSH_HOME=$DSH_HOME"
echo "PENTEST_LAB=$PENTEST_LAB"
echo "OLLAMA_HOST=$OLLAMA_HOST"

if [[ -x "$GHIDRA_HOME/support/sleigh" ]]; then
  "$KIT_ROOT/install/install-sbpf-processor.sh"
else
  echo "SKIP Ghidra processor (set GHIDRA_HOME to a Ghidra tree)"
fi

mkdir -p "$DSH_HOME/plugins" "$PENTEST_LAB/jobs" "$DSH_HOME/profiles/web" "$CYBER_HOME"
rsync -a "$KIT_ROOT/harness-kit/plugins/" "$DSH_HOME/plugins/"
cp "$KIT_ROOT/harness-kit/pentest-lab/"*.py "$PENTEST_LAB/"
chmod +x "$PENTEST_LAB/subenum.py" "$PENTEST_LAB/connect_probe.py" "$PENTEST_LAB/org_ranges.py" 2>/dev/null || true
cp "$KIT_ROOT/harness-kit/profiles-web/cordis.patch.yml" "$DSH_HOME/profiles/web/cordis.patch.yml"

PKG="$DSH_HOME/profiles/web/package.json"
if [[ ! -f "$PKG" ]]; then
  python3 - <<PY
from pathlib import Path
home = Path.home()
dsh = Path("$DSH_HOME")
Path("$PKG").write_text("""{
  "name": "dsh-profile-web",
  "private": true,
  "dependencies": {
    "dsh-tool-pentest-lab": "file:%s/plugins/dsh-tool-pentest-lab",
    "dsh-web-search-local": "file:%s/plugins/dsh-web-search-local"
  },
  "dsh": {
    "profile": {
      "bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-web-app"]
    }
  }
}
""" % (dsh, dsh))
print("wrote", "$PKG")
PY
fi
( cd "$DSH_HOME/profiles/web" && npm install )

if [[ ! -f "$CYBER_HOME/execution-policy" ]]; then
  echo lab > "$CYBER_HOME/execution-policy"
  printf '%s\n' '# host, CIDR, or *.example.org' > "$CYBER_HOME/domains.txt"
fi

if [[ -x "$KIT_ROOT/searxng/install.sh" ]]; then
  "$KIT_ROOT/searxng/install.sh" || echo "WARN: SearXNG install failed (optional)"
fi

echo
echo "==> smokes"
if command -v python3 >/dev/null; then
  python3 "$PENTEST_LAB/preflight.py" || true
  python3 "$PENTEST_LAB/subenum.py" example.com || echo "WARN: subenum smoke failed (network?)"
fi
echo "Next: configure Ollama at \$OLLAMA_HOST and ~/.dsh/settings.yaml (see QWEN-CYBER-HARNESS.md)"
echo "Start UI: dsh --profile web --host 127.0.0.1 --port 3080"
