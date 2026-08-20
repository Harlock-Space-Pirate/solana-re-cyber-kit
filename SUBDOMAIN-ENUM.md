# Subdomain enum for Qwen Cyber / Harness

C99-style coverage = **union of sources**, not one tool. Qwen must not use `web_search` as the subdomain finder.

## How Qwen should work

1. **Immediately** `subdomain_enum` with `{ "domain": "example.com" }`  
   → ~8s parallel OSINT (crt.sh, Cert Spotter, HackerTarget, OTX, urlscan, Wayback, JLDC, ThreatMiner).  
   → print unique names + `job_id`.
2. Tell the operator: “fast set is in; background still running.”
3. After 20–60s: `subdomain_enum_status` with that `job_id`.  
   → Amass passive + smart permutations + DNS resolve.
4. Repeat status until `status=complete`. Full JSON is on disk.

Speed: first card in ~8s. Completeness: background, no blocking the chat.

## Tools

| Tool | Args |
|------|------|
| `subdomain_enum` | `domain` (apex) |
| `subdomain_enum_status` | `job_id`, optional `detail` |

CLI (same engine):

```bash
python3 ~/.dsh/pentest-lab/subenum.py example.com
python3 ~/.dsh/pentest-lab/subenum.py --status <job_id>
```

Jobs: `~/.dsh/pentest-lab/jobs/<id>.json`

## Phases

| Phase | Time | Hits |
|-------|------|------|
| A fast | ≤8s | CT + passive HTTP APIs (no brute against target NS) |
| B background | ~1–2 min | `amass enum -d`, prefix/permute of what A found, `getaddrinfo` |

Needs `/set-executionpolicy allowlist` (domain in `domains.txt`) or `bypass`.

## Install on a new computer

Files live in this repo under `harness-kit/` and must land in `~/.dsh/` on the new machine.

### 1. Binaries (Colossus / coding Mac)

```bash
brew install amass bind jq
python3 --version   # 3.12–3.14
# optional later: go install subfinder (needs Go ≥ 1.21; this Mac had 1.18 → skip)
```

`amass` is the background phase. Fast phase is **stdlib only** (urllib) and works without brew.

### 2. Copy the kit

```bash
export KIT_ROOT="${KIT_ROOT:-$(pwd)}"
export DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
export PENTEST_LAB="${PENTEST_LAB:-$DSH_HOME/pentest-lab}"
./install/install-all.sh
```

Or by hand:

```bash
mkdir -p "$PENTEST_LAB/jobs" "$DSH_HOME/plugins" "$DSH_HOME/profiles/web"
cp "$KIT_ROOT/harness-kit/pentest-lab/"*.py "$PENTEST_LAB/"
chmod +x "$PENTEST_LAB/subenum.py"
rsync -a "$KIT_ROOT/harness-kit/plugins/" "$DSH_HOME/plugins/"
```

`package.json` `file:` URLs must use **`$DSH_HOME/plugins/...`** (absolute path on that machine).

Then:

```bash
cd ~/.dsh/profiles/web
npm install
```

See [QWEN-CYBER-HARNESS.md](QWEN-CYBER-HARNESS.md) for Ollama, settings.yaml, SearXNG.

### 3. Prove it before opening Harness

```bash
python3 ~/.dsh/pentest-lab/subenum.py example.com
# expect: unique≥1, job=…, status=fast_done, NEXT: subdomain_enum_status
python3 ~/.dsh/pentest-lab/subenum.py --status <job_id>
```

Via dispatch (same path Qwen uses):

```bash
python3 ~/.dsh/pentest-lab/dispatch.py subdomain_enum '{"domain":"example.com"}'
```

Policy must be `allowlist` or `bypass` (`~/.cyber/execution-policy`). `lab` refuses live enum.

### 4. Harness check

1. Restart `dsh --profile web --host 127.0.0.1 --port 3080`
2. **New session**, model Cyber
3. Ask: “enumerate subdomains of example.com”
4. First tool card ≈ 8s with `job_id`. Second card = `subdomain_enum_status`.

If Qwen uses `web_search` instead, the plugin prompt is missing — confirm Settings → Plugins → `tool-pentest-lab` **Mounted**.

## Why this matches C99 + “other tools find different names”

- Fast APIs ≈ C99’s passive pile (not identical APIs; C99 has paid feeds we don’t).
- Amass + permute ≈ the *other* names (never in CT).
- Union is stored in one job file with `sources[]` per host.

Paid keys (SecurityTrails, VT, Chaos) can be added later as extra sources in `subenum.py` without changing the Qwen tools.
