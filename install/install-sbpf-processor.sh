#!/usr/bin/env bash
# Install the Solana sBPF processor into an existing Ghidra tree.
# Usage: GHIDRA_HOME=/path/to/ghidra ./install/install-sbpf-processor.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
GHIDRA_HOME="${GHIDRA_HOME:-${HOME}/ghidra}"
SRC="$HERE/processors/sBPF"
DST="$GHIDRA_HOME/Ghidra/Processors/sBPF"

if [[ ! -d "$GHIDRA_HOME/Ghidra/Processors" ]]; then
  echo "Not a Ghidra install: $GHIDRA_HOME" >&2
  exit 1
fi
if [[ ! -d "$SRC/data/languages" ]]; then
  echo "Missing processor pack: $SRC" >&2
  exit 1
fi

mkdir -p "$DST"
rsync -a "$SRC/" "$DST/"
SLA_DIR="$DST/data/languages"
if [[ ! -x "$GHIDRA_HOME/support/sleigh" ]]; then
  echo "missing $GHIDRA_HOME/support/sleigh" >&2
  exit 1
fi
echo "compiling SLEIGH in $SLA_DIR"
(cd "$SLA_DIR" && "$GHIDRA_HOME/support/sleigh" -a .)
echo "installed sBPF → $DST"
echo "languages: sBPF:v1  sBPF:v2  sBPF:v3"
echo "headless import: analyzeHeadless <projDir> <name> -import foo.so -processor sBPF:v1 -cspec default"
