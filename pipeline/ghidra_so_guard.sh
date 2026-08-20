#!/usr/bin/env bash
# Compare artifacts/bytecode/c4-sage.so to the last Ghidra import.
# Source this after ROOT / PROJ / NAME / SO are set.
# Sets NEED_REIMPORT=1 when the project is missing or the ELF changed.
#
# Do NOT retune sBPF.cspec / R10 / SLEIGH to "fix" decompile.
# Re-import the live ELF instead (FORCE_REIMPORT=1).
ghidra_so_sha() {
  shasum -a 256 "$1" | awk '{print $1}'
}

NEED_REIMPORT=0
SIDECAR="$PROJ/${NAME}.so.sha256"
if [[ ! -f "$SO" ]]; then
  echo "ghidra_so_guard: missing $SO" >&2
  NEED_REIMPORT=1
elif [[ ! -d "$PROJ/$NAME.rep" && ! -f "$PROJ/$NAME.gpr" ]]; then
  NEED_REIMPORT=1
elif [[ ! -f "$SIDECAR" ]]; then
  echo "ghidra_so_guard: no sidecar — treat project as stale (imported before hash guard)" >&2
  NEED_REIMPORT=1
else
  want="$(ghidra_so_sha "$SO")"
  have="$(tr -d '[:space:]' < "$SIDECAR")"
  if [[ "$want" != "$have" ]]; then
    echo "ghidra_so_guard: ELF changed" >&2
    echo "  disk    $want  $SO" >&2
    echo "  project $have  $SIDECAR" >&2
    NEED_REIMPORT=1
  fi
fi

ghidra_write_so_sidecar() {
  ghidra_so_sha "$SO" > "$SIDECAR"
  echo "ghidra_so_guard: wrote $SIDECAR"
}
