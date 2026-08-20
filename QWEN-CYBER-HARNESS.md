# Qwen / DeepSeek Harness on a new machine

Two roles (can be one box):

| Role | Env | What |
|------|-----|------|
| **GPU host** | `$OLLAMA_HOST` (default `http://127.0.0.1:11434`) | Ollama + weights |
| **Agent host** | `$DSH_HOME` (default `$HOME/.dsh`) | Harness UI, pentest-lab, SearXNG |

Set:

```bash
export OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
export DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
export PENTEST_LAB="${PENTEST_LAB:-$DSH_HOME/pentest-lab}"
export CYBER_HOME="${CYBER_HOME:-$HOME/.cyber}"
```

## 1. GPU host — Ollama

Need Ollama **≥ 0.32.14** (older builds reject Qwen 3.8).

```bash
# bind so the agent host can reach it (LAN or localhost)
export OLLAMA_HOST=0.0.0.0:11434
ollama pull qwen3.8:27b
ollama pull orcarouter/Qwen3.8-27B-Uncensored
ollama pull hf.co/hotdogs/Qwen3.8-27B-abliterated-cyber-preview-MTP-GGUF:Q4_K_M
printf 'FROM hf.co/hotdogs/Qwen3.8-27B-abliterated-cyber-preview-MTP-GGUF:Q4_K_M\n' \
  | ollama create qwen38-cyber -f -
curl -sS "$OLLAMA_HOST/api/tags"
```

Smoke:

```bash
curl -sS "$OLLAMA_HOST/api/generate" \
  -d '{"model":"qwen38-cyber","prompt":"Reply with exactly: pong","stream":false,"think":false}'
```

## 2. Agent host — Harness files

Do **not** copy someone else’s `settings.yaml` / `.credentials.yaml`. Recreate:

`$DSH_HOME/settings.yaml` (example):

```yaml
llm-pi-ai:
  providers:
    local-ollama:
      displayName: Local Ollama
      api: openai-completions
      baseURL: ${OLLAMA_HOST}/v1    # write the real URL, YAML does not expand env
      apiKeyEnv: OLLAMA_API_KEY
      timeoutMs: 600000
      models:
        - id: qwen38-cyber
          name: Qwen 3.8 27B Cyber
          contextWindow: 32768
          maxTokens: 8192
          input: [text]
agent-default-model:
  provider: local-ollama
  model: qwen38-cyber
```

`$DSH_HOME/.credentials.yaml` (mode `600`):

```yaml
OLLAMA_API_KEY: ollama
```

Ollama ignores the token; pi-ai still wants a Bearer header.

Kit install (from this clone):

```bash
./install/install-all.sh
```

That copies `harness-kit/` into `$DSH_HOME` and `npm install`s the profile.

**Render contract:** tool `output.render` must return `[{ type: "text", text: "..." }]`. A string crashes with `content.some is not a function`.

**Policy HOME:** tool subprocesses must not use a fake `HOME`. Policy files are `$CYBER_HOME` via `pwd.getpwuid` + env.

## 3. Execution policy

| File | Role |
|------|------|
| `$CYBER_HOME/execution-policy` | `lab` \| `allowlist` \| `bypass` |
| `$CYBER_HOME/domains.txt` | host, CIDR, `*.example.org` |
| `$PWD/.cyber/` | per-workspace overlay (`CYBER_WORKSPACE`) |

```
/set-executionpolicy lab|allowlist|bypass|status
```

`bypass` = live, any target, no subnet filter.

## 4. SearXNG

```bash
./searxng/install.sh
curl -sS "${SEARXNG_URL:-http://127.0.0.1:8888}/search?q=test&format=json"
```

Harness `searchProvider` is `local-ddg` (plugin tries SearXNG, then DuckDuckGo HTML). No `DEEPSEEK_API_KEY`.

## 5. Tool preflight (before recon)

Qwen must **not** discover missing `dnspython` mid-job. At session start of recon:

1. Tool `recon_preflight` → table OK/MISSING  
2. You: `/recon-install dnspython amass` **or** install by hand  
3. Then `subdomain_enum`

Catalog (only these ids): `python3` `dig` `dnspython` `amass` `curl` `nmap` `jq` `git` `node` `masscan`.

Live internet after names: **`org_ranges` then `connect_probe`**. Never `nmap`/`masscan` on the public net from this harness (raw SYN dropped; curl/TLS still works). `nmap` is lab-net `10.42.0.0/24` only.

## 6. Subdomain enum

See [SUBDOMAIN-ENUM.md](SUBDOMAIN-ENUM.md). Smoke:

```bash
python3 "$PENTEST_LAB/subenum.py" example.com
```

## 7. Start UI

```bash
# Node 22.19+
dsh --profile web --host 127.0.0.1 --port 3080
```

New session → model **qwen38-cyber**.
