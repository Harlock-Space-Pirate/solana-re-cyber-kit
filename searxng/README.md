# SearXNG for Harness

Local metasearch. Harness `web_search` hits this first; DuckDuckGo HTML is fallback.

## New machine

```bash
export SEARXNG_ROOT="${SEARXNG_ROOT:-$HOME/.dsh/searxng}"
export SEARXNG_URL="${SEARXNG_URL:-http://127.0.0.1:8888}"
cd "$KIT_ROOT/searxng"    # this folder in the clone
chmod +x install.sh run.sh
./install.sh
curl -sS "$SEARXNG_URL/search?q=ghidra+sbpf&format=json" \
  | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["results"]), "hits")'
```

`install.sh` clones into `$SEARXNG_ROOT/src`, venv, writes `$SEARXNG_ROOT/settings.yml` (JSON **on**, bind **127.0.0.1:8888**), and on macOS loads a LaunchAgent (paths rewritten to `$HOME`).

UI: `$SEARXNG_URL`

## Failures

| Symptom | Fix |
|---------|-----|
| json 403 | `search.formats` must include `json` |
| Port busy | change `server.port`; set `SEARXNG_URL` |
| Harness wants `DEEPSEEK_API_KEY` | `searchProvider: local-ddg` missing; new session |
