# Solana RE + local Ghidra sBPF + Harness / Qwen Cyber kit

Reinstallable tooling for reverse-engineering **Solana sBPF** programs and driving a **local** coding agent (DeepSeek Harness + Ollama) without vendor search keys.

Clone this repo on a **new machine**. Do not copy home directories or API keys from an old box.

| Doc | What |
|-----|------|
| [INSTALL.md](INSTALL.md) | Ghidra, Java 17, sBPF processor |
| [GHIDRA-SOLANA.md](GHIDRA-SOLANA.md) | Why stock eBPF fails; R10; ELF hash; soup |
| [PIPELINE.md](PIPELINE.md) | Dump `.so` → import → decompile → live RPC |
| [RECON-DATAMINING.md](RECON-DATAMINING.md) | Passive recon / formula pinning lessons |
| [QWEN-CYBER-HARNESS.md](QWEN-CYBER-HARNESS.md) | Ollama + Harness + pentest-lab + policy |
| [searxng/README.md](searxng/README.md) | Local SearXNG as `web_search` |
| [SUBDOMAIN-ENUM.md](SUBDOMAIN-ENUM.md) | Fast CT/OSINT then background Amass |
| [install/new-machine-checklist.md](install/new-machine-checklist.md) | Tick list |

## Environment (set once)

```bash
export GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra}"
export DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
export PENTEST_LAB="${PENTEST_LAB:-$DSH_HOME/pentest-lab}"
export CYBER_HOME="${CYBER_HOME:-$HOME/.cyber}"
export OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"   # or http://gpu-box:11434
export SEARXNG_URL="${SEARXNG_URL:-http://127.0.0.1:8888}"
export KIT_ROOT="$(cd "$(dirname "$0")" && pwd)"               # this clone
```

Optional: `DSH_TOOLS_ENTRY` = absolute path to `@deepseek-ai/dsh-tools/lib/index.js` if auto-detect fails.

## One-shot (after Ghidra + Node 22 + Python 3.12+ exist)

```bash
git clone https://github.com/<you>/solana-re-cyber-kit.git
cd solana-re-cyber-kit
./install/install-all.sh
```

Processor snapshot: `processors/sBPF/` (NWMonster/Ghidra_sBPF lineage). Headless language id: **`sBPF:v1`**.
