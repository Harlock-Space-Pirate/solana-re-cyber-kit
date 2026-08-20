#!/usr/bin/env bash
# Decompile one handler + callees (not the rodata soup file).
# Usage: PROGRAM_NAME=myprog ./pipeline/ghidra_calltree.sh handler_name 0x10013ec68 2
set -euo pipefail
KIT="$(cd "$(dirname "$0")/.." && pwd)"
ANALYSIS_ROOT="${ANALYSIS_ROOT:-$PWD}"
PROGRAM_NAME="${PROGRAM_NAME:-program}"
GHIDRA_HOME="${GHIDRA_HOME:-$HOME/ghidra}"
PROJ="${GHIDRA_PROJ:-$ANALYSIS_ROOT/artifacts/ghidra-proj}"
NAME="${GHIDRA_PROJ_NAME:-${PROGRAM_NAME}-headless}"
IX="${1:?name}"
ADDR="${2:?sol_addr e.g. 0x10013ec68}"
DEPTH="${3:-2}"
OUT="${GHIDRA_OUT:-$ANALYSIS_ROOT/artifacts/decomp/${PROGRAM_NAME}-ghidra}/ct-${IX}"
export JAVA_HOME="${JAVA_HOME:-$(/usr/libexec/java_home -v 17 2>/dev/null || true)}"
[[ -n "${JAVA_HOME:-}" ]] && export PATH="$JAVA_HOME/bin:$PATH"
mkdir -p "$OUT"
SO="${PROGRAM_SO:-$ANALYSIS_ROOT/artifacts/bytecode/${PROGRAM_NAME}.so}"
# shellcheck source=ghidra_so_guard.sh
source "$KIT/pipeline/ghidra_so_guard.sh"
if [[ "$NEED_REIMPORT" == "1" ]]; then
  echo "ghidra_calltree: project ELF is stale or missing." >&2
  echo "  Re-import first:  FORCE_REIMPORT=1 ./pipeline/ghidra_decompile_top10.sh" >&2
  exit 2
fi
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PROJ" "$NAME" \
  -process "$(basename "$SO")" \
  -noanalysis \
  -scriptPath "${GHIDRA_SCRIPTS:-$KIT/scripts}" \
  -postScript DecompileCallTree.java "$OUT" "$ADDR" "$DEPTH" \
  -log "$OUT/ghidra-ct.log"
echo "done → $OUT"
ls "$OUT" | head
