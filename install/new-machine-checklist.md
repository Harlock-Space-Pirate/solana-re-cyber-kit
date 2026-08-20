# New machine (print and tick)

Use env from the root README (`GHIDRA_HOME`, `DSH_HOME`, `OLLAMA_HOST`, …).

- [ ] Java 17
- [ ] Ghidra unpacked; `$GHIDRA_HOME` set
- [ ] `./install/install-sbpf-processor.sh` → `sBPF:v1`
- [ ] Headless import of a `.so` (not stock eBPF)
- [ ] Ollama ≥ 0.32.14 on `$OLLAMA_HOST`
- [ ] `ollama pull` qwen3.8:27b, uncensored, cyber GGUF; `ollama create qwen38-cyber`
- [ ] Agent host can `curl "$OLLAMA_HOST/api/tags"`
- [ ] `./install/install-all.sh`
- [ ] Plugin `tool-pentest-lab` Mounted
- [ ] `$CYBER_HOME/execution-policy` exists
- [ ] `/set-executionpolicy status` works
- [ ] Tool results are cards, not `content.some is not a function`
- [ ] SearXNG JSON: `"$SEARXNG_URL/search?q=test&format=json"` has hits
- [ ] `web_search` does not ask for `DEEPSEEK_API_KEY`
- [ ] `brew install amass` (optional; fast subdomain phase works without it)
- [ ] `python3 "$PENTEST_LAB/subenum.py" example.com` → `fast_done` + `job_id`
- [ ] New session: Qwen calls `recon_preflight` **first**, then waits
- [ ] `/recon-install dnspython` (or hand `pip install --user dnspython`) if MISSING
- [ ] Then `subdomain_enum` / `subdomain_enum_status` — not silent pip/brew
- [ ] `which masscan` is `/opt/homebrew/bin/masscan` (install-all.sh brew-installs it)
- [ ] After names: **masscan → nmap -sV** on the live IP; never `10.42.0.0/24` when policy is allowlist/bypass
- [ ] Missing tool: Qwen shows `[PREFERRED TOOL MISSING]`, **asks** `/recon-install` or brew/sudo, waits ~**10 min**, then named fallback; **asks again at end of job**
- [ ] New session after `dsh` restart (prompt is injected at session start; old tabs keep the old prompt)
