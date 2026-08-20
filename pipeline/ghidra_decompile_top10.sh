#!/usr/bin/env bash
# Ghidra headless: decompile handlers listed in a CSV (sBPF:v1).
# Usage (from your analysis tree):
#   ANALYSIS_ROOT=$PWD PROGRAM_NAME=myprog ./pipeline/ghidra_decompile_top10.sh
# Optional: FORCE_REIMPORT=1
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
ANALYSIS_ROOT="${ANALYSIS_ROOT:-$PWD}"
PROGRAM_NAME="${PROGRAM_NAME:-program}"
GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra}"
PROJ="${GHIDRA_PROJ:-$ANALYSIS_ROOT/artifacts/ghidra-proj}"
OUT="${GHIDRA_OUT:-$ANALYSIS_ROOT/artifacts/decomp/${PROGRAM_NAME}-ghidra}"
SO="${PROGRAM_SO:-$ANALYSIS_ROOT/artifacts/bytecode/${PROGRAM_NAME}.so}"
if [[ -f "$OUT/live29-handlers.csv" ]]; then
  CSV="$OUT/live29-handlers.csv"
else
  CSV="${HANDLERS_CSV:-$OUT/top10-handlers.csv}"
fi
SCRIPTS="${GHIDRA_SCRIPTS:-$KIT/scripts}"
NAME="${GHIDRA_PROJ_NAME:-${PROGRAM_NAME}-headless}"

export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 17 2>/dev/null || true)}"
if [[ -n "${JAVA_HOME:-}" ]]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi

mkdir -p "$PROJ" "$OUT"

if [[ ! -f "$CSV" ]]; then
  echo "missing $CSV — regenerate from top10-handlers.json" >&2
  exit 1
fi

# Ensure sBPF .sla exists
SLA_DIR="$GHIDRA_HOME/Ghidra/Processors/sBPF/data/languages"
if [[ ! -f "$SLA_DIR/sBPFv1.sla" ]]; then
  echo "compiling sBPF .sla ..."
  (cd "$SLA_DIR" && "$GHIDRA_HOME/support/sleigh" -a .)
fi

# shellcheck source=ghidra_so_guard.sh
source "$KIT/pipeline/ghidra_so_guard.sh"
ELF_BASENAME="$(basename "$SO")"
if [[ "${FORCE_REIMPORT:-0}" == "1" ]] || [[ "$NEED_REIMPORT" == "1" ]]; then
  rm -rf "$PROJ/${NAME}" "$PROJ/${NAME}.rep" "$PROJ/${NAME}.gpr" "$PROJ/${NAME}.so.sha256" 2>/dev/null || true
  echo "IMPORT + analyze + decompile  (ELF $(ghidra_so_sha "$SO" | cut -c1-16)…)"
  "$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJ" "$NAME" \
    -import "$SO" \
    -processor sBPF:v1 \
    -cspec default \
    -scriptPath "$SCRIPTS" \
    -postScript DecompileSbfHandlers.java "$OUT" "$CSV" \
    -log "$OUT/ghidra-headless.log"
  ghidra_write_so_sidecar
else
  echo "REUSE project + decompile only  (ELF matches $SIDECAR)"
  "$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJ" "$NAME" \
    -process "$ELF_BASENAME" \
    -noanalysis \
    -scriptPath "$SCRIPTS" \
    -postScript DecompileSbfHandlers.java "$OUT" "$CSV" \
    -log "$OUT/ghidra-headless.log"
fi

echo "done → $OUT/INDEX.md"
