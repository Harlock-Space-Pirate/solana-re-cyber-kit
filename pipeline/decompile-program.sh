#!/usr/bin/env bash
# Generic Solana program decompile (sBPF:v1).
# Usage:
#   ./pipeline/decompile-program.sh /path/to/program.so ./out [handlers.csv]
# handlers.csv: name,elf_vaddr_hex,sol_addr_hex,disc8
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra}"
SO="${1:?path to .so}"
OUT="${2:?output dir}"
CSV="${3:-}"
NAME="${GHIDRA_PROJ_NAME:-$(basename "$SO" .so)}"
PROJ="${GHIDRA_PROJ:-$OUT/ghidra-proj}"
SCRIPTS="$HERE/scripts"

export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 17 2>/dev/null || true)}"
[[ -n "${JAVA_HOME:-}" ]] && export PATH="$JAVA_HOME/bin:$PATH"

if [[ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]]; then
  echo "set GHIDRA_HOME" >&2
  exit 1
fi
SLA="$GHIDRA_HOME/Ghidra/Processors/sBPF/data/languages/sBPFv1.sla"
if [[ ! -f "$SLA" ]]; then
  echo "sBPF processor missing — run install/install-sbpf-processor.sh" >&2
  exit 1
fi

mkdir -p "$PROJ" "$OUT"
SO_ABS="$(cd "$(dirname "$SO")" && pwd)/$(basename "$SO")"

echo "IMPORT $SO_ABS as sBPF:v1 → $PROJ/$NAME"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PROJ" "$NAME" \
  -import "$SO_ABS" \
  -processor sBPF:v1 \
  -cspec default \
  -scriptPath "$SCRIPTS" \
  ${CSV:+-postScript DecompileSbfHandlers.java "$OUT" "$CSV"} \
  -log "$OUT/ghidra-headless.log"

echo "done. log: $OUT/ghidra-headless.log"
echo "addr note: Ghidra text = sol_addr - 0x100000000"
